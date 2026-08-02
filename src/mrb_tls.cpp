/*
 * mruby-tls -- mbedTLS backend.
 *
 * The Ruby API matches the old LibreSSL/libtls backend; mismatches are
 * marked "DIVERGENCE".
 */

#include "mruby/tls.h"
#include "mrb_tls.h"

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <wincrypt.h>
#else
#include <dirent.h>
#include <limits.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#ifndef PATH_MAX
#define PATH_MAX 4096 /* not guaranteed by POSIX (e.g. GNU/Hurd) */
#endif
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef _WIN32
/* fork() duplicates the PSA RNG's state byte for byte; without this every
 * child would derive session keys from the same RNG state. deplete (not
 * reseed) just marks it for reseeding on next use -- cheap and doc'd not
 * to fail, both of which matter in an atfork child handler. */
static void
mrb_tls_atfork_child(void)
{
  psa_random_deplete();
}

/* pthread_atfork() has no "unregister", and gem_init() runs once per
 * mrb_open(), not once per process -- pthread_once() keeps registration
 * itself to once per process. Its return value is checked on every call
 * since a failed registration silently loses the fork-RNG guarantee above. */
static pthread_once_t mrb_tls_atfork_once = PTHREAD_ONCE_INIT;
static int mrb_tls_atfork_register_ret = 0;

static void
mrb_tls_atfork_register(void)
{
  mrb_tls_atfork_register_ret = pthread_atfork(NULL, NULL, mrb_tls_atfork_child);
}
#endif

/* ------------------------------------------------------------------------ */
/* Errors                                                                    */
/* ------------------------------------------------------------------------ */

/* errno set before a call means a real syscall failed -> SystemCallError;
 * otherwise it's a protocol/config error -> Tls::Error/Tls::Config::Error.
 * mbedtls_strerror() has no documented max length; 4 KiB covers real
 * outliers in this pin without hand-tuning. */
#define MRB_TLS_ERRMSG_BUFLEN 4096
#define MRB_TLS_FAIL_MSG_BUFLEN 4096

static void
mrb_tls_errmsg(char *out, size_t outlen, int ret, const char *what)
{
  if (ret != 0) {
    char eb[MRB_TLS_ERRMSG_BUFLEN];
    eb[0] = '\0';
    mbedtls_strerror(ret, eb, sizeof(eb));
    if (eb[0] == '\0') {
      snprintf(out, outlen, "%s: error -0x%04x", what, (unsigned)-ret);
    } else {
      snprintf(out, outlen, "%s: %s", what, eb);
    }
  } else {
    snprintf(out, outlen, "%s", what);
  }
}

static mrb_value
mrb_tls_fail(mrb_state *mrb, int ret, const char *what)
{
  char msg[MRB_TLS_FAIL_MSG_BUFLEN];

  mrb_tls_errmsg(msg, sizeof(msg), ret, what);
  if (errno) {
    mrb_sys_fail(mrb, msg);
  } else {
    mrb_raise(mrb, E_TLS_ERROR, msg);
  }

  return mrb_nil_value(); /* not reached */
}

static mrb_value
mrb_tls_config_fail(mrb_state *mrb, int ret, const char *what)
{
  char msg[MRB_TLS_FAIL_MSG_BUFLEN];

  mrb_tls_errmsg(msg, sizeof(msg), ret, what);
  if (errno) {
    mrb_sys_fail(mrb, msg);
  } else {
    mrb_raise(mrb, E_TLS_CONFIG_ERROR, msg);
  }

  return mrb_nil_value(); /* not reached */
}

/* ------------------------------------------------------------------------ */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------ */

static void
mrb_tls_ivar_str_set(mrb_state *mrb, mrb_value obj, mrb_sym sym, const char *src)
{
  mrb_iv_set(mrb, obj, sym, src != NULL ? mrb_str_new_cstr(mrb, src) : mrb_nil_value());
}

/* Wipes cert_mem/key_mem in place on every explicit replace/clear (not on
 * GC). Writes through RSTRING_PTR() directly rather than mrb_str_modify(),
 * which would copy shared/NOFREE strings instead of wiping the one
 * actually holding the secret; frozen strings are wiped too. */
static void
mrb_tls_ivar_buf_clear(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  mrb_value old = mrb_iv_get(mrb, obj, sym);
  if (mrb_string_p(old) && RSTRING_LEN(old) > 0) {
    mrb_secure_wipe_memory(RSTRING_PTR(old), (size_t)RSTRING_LEN(old));
  }
  mrb_iv_set(mrb, obj, sym, mrb_nil_value());
}

/* Adopts the caller's own String (no copy) so it can be wiped in place
 * later -- their reference goes blank too when it is replaced/cleared.
 * Falls back to a copy only if the bytes are in real read-only memory
 * (mrb_ro_data_p(), e.g. a literal compiled into test/tls.rb's bytecode),
 * since that can't be wiped or written to at all. */
static mrb_value
mrb_tls_ivar_buf_set(mrb_state *mrb, mrb_value obj, mrb_sym sym, mrb_value str)
{
  if (RSTRING_LEN(str) > 0 && mrb_ro_data_p(RSTRING_PTR(str))) {
    str = mrb_str_new(mrb, RSTRING_PTR(str), RSTRING_LEN(str));
  }

  mrb_tls_ivar_buf_clear(mrb, obj, sym);
  mrb_iv_set(mrb, obj, sym, str);

  return str;
}

/*
 * NULL if `sym` isn't set on `obj`; the private cert/key copy's pointer
 * otherwise, with `*len_out` set to its length. `*len_out` is written on
 * every path, so a caller that only looks at the length after a non-NULL
 * return can never read it uninitialised.
 */
static const uint8_t *
mrb_tls_ivar_buf_get(mrb_state *mrb, mrb_value obj, mrb_sym sym, size_t *len_out)
{
  mrb_value v = mrb_iv_get(mrb, obj, sym);

  *len_out = 0;
  if (!mrb_string_p(v)) {
    return NULL;
  }
  *len_out = (size_t)RSTRING_LEN(v);
  return (const uint8_t *)RSTRING_PTR(v);
}

/* Does the blob look like PEM?  Deliberately scans the whole buffer instead of
 * using strstr(), because a DER blob may contain embedded NUL bytes. */
static int
mrb_tls_is_pem(const uint8_t *buf, size_t len)
{
  static const char marker[] = "-----BEGIN ";
  const size_t mlen = sizeof(marker) - 1;
  size_t i;

  if (len < mlen) {
    return 0;
  }
  for (i = 0; i + mlen <= len; i++) {
    if (memcmp(buf + i, marker, mlen) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Length to hand to the mbedTLS parsers: PEM needs the NUL, DER must not have
 * it (mbedtls_x509_crt_parse() would otherwise feed the extra byte to the DER
 * parser and fail). */
static size_t
mrb_tls_parse_len(const uint8_t *buf, size_t len)
{
  return mrb_tls_is_pem(buf, len) ? len + 1 : len;
}

static int
mrb_tls_tokeq(const char *tok, size_t toklen, const char *lit)
{
  size_t i;

  if (strlen(lit) != toklen) {
    return 0;
  }
  for (i = 0; i < toklen; i++) {
    char a = tok[i], b = lit[i];
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
    if (a != b) {
      return 0;
    }
  }
  return 1;
}

/* ------------------------------------------------------------------------ */
/* Default trust store                                                       */
/* ------------------------------------------------------------------------ */

/* DIVERGENCE: mbedTLS ships no trust store, so we use the platform's,
 * honouring SSL_CERT_FILE/SSL_CERT_DIR first (same as curl/Python/Go). */
#ifdef _WIN32
/* No PEM/DER trust store file on disk -- root CAs live in the system
 * certificate store via CryptoAPI. */
static int
mrb_tls_load_ca_system_store_win32(mbedtls_x509_crt *chain, int *loaded)
{
  HCERTSTORE store;
  PCCERT_CONTEXT cert = NULL;

  *loaded = 0;
  store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV_LEGACY)NULL,
                        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                        "ROOT");
  if (store == NULL) {
    return -1;
  }
  while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
    if (mbedtls_x509_crt_parse_der(chain, cert->pbCertEncoded, cert->cbCertEncoded) == 0) {
      (*loaded)++;
    }
  }
  CertCloseStore(store, 0);
  return 0;
}
#endif

static const char *
mrb_tls_default_ca_file(void)
{
#ifndef _WIN32
  static const char *const candidates[] = {
    "/etc/ssl/certs/ca-certificates.crt",     /* Debian, Ubuntu, Alpine  */
    "/etc/pki/tls/certs/ca-bundle.crt",       /* Fedora, RHEL            */
    "/etc/ssl/ca-bundle.pem",                 /* openSUSE                */
    "/etc/pki/tls/cacert.pem",                /* OpenELEC                */
    "/etc/ssl/cert.pem",                      /* OpenBSD, macOS, LibreSSL */
    "/usr/local/etc/ssl/cert.pem",            /* FreeBSD                 */
    "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD ports           */
    NULL
  };
  int i;
#endif
  const char *env = getenv("SSL_CERT_FILE");
  struct stat st;

  if (env != NULL && *env != '\0' && stat(env, &st) == 0) {
    return env;
  }
#ifndef _WIN32
  for (i = 0; candidates[i] != NULL; i++) {
    if (stat(candidates[i], &st) == 0) {
      return candidates[i];
    }
  }
#endif
  return NULL;
}

static const char *
mrb_tls_default_ca_dir(void)
{
  const char *env = getenv("SSL_CERT_DIR");
  struct stat st;

  if (env != NULL && *env != '\0' && stat(env, &st) == 0 && S_ISDIR(st.st_mode)) {
    return env;
  }
#ifndef _WIN32
  if (stat("/etc/ssl/certs", &st) == 0 && S_ISDIR(st.st_mode)) {
    return "/etc/ssl/certs";
  }
#endif
  return NULL;
}

/* ------------------------------------------------------------------------ */
/* Protocol bitmask handling                                                 */
/* ------------------------------------------------------------------------ */

/* mbedTLS can't negotiate TLS 1.0/1.1 (RFC 8996) -- a request for either
 * clamps up to 1.2, matching LibreSSL's own documented behavior for these
 * bits. No usable version selected at all is a hard error. */
static int
mrb_tls_protocols_to_versions(uint32_t protocols, int *min_ver, int *max_ver,
                              const char **errmsg)
{
  int want_12 = (protocols & (MRB_TLS_PROTOCOL_TLSv1_2 |
                              MRB_TLS_PROTOCOL_TLSv1_1 |
                              MRB_TLS_PROTOCOL_TLSv1_0)) != 0;
  int want_13 = (protocols & MRB_TLS_PROTOCOL_TLSv1_3) != 0;

  if (!want_12 && !want_13) {
    *errmsg = "no supported protocol versions selected";
    return -1;
  }
  *min_ver = want_12 ? MBEDTLS_SSL_VERSION_TLS1_2 : MBEDTLS_SSL_VERSION_TLS1_3;
  *max_ver = want_13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2;
  return 0;
}

/* ------------------------------------------------------------------------ */
/* Cipher suite and group selection                                          */
/* ------------------------------------------------------------------------ */

/* Tokenizing/keyword-dispatch for Config#ciphers= now lives in Ruby
 * (mrblib/config.rb); this is just the part that has to be C -- looking
 * mbedTLS suite names up by their actual mbedtls_ssl_get_ciphersuite_id()
 * and packing the result into the 0-terminated native `int` array
 * mbedtls_ssl_conf_ciphersuites() expects. Packing here (not via
 * Array#pack in Ruby) sidesteps any risk of a pack-directive/native-`int`
 * size mismatch. */
static mrb_value
mrb_tls_pack_ciphersuites(mrb_state *mrb, mrb_value self)
{
  mrb_value names;
  mrb_get_args(mrb, "A", &names);

  std::vector<int> list;
  mrb_int len = RARRAY_LEN(names);
  for (mrb_int i = 0; i < len; i++) {
    mrb_value name_v = mrb_ary_ref(mrb, names, i);
    int id = mbedtls_ssl_get_ciphersuite_id(mrb_str_to_cstr(mrb, name_v));
    if (id == 0) {
      mrb_raise(mrb, E_TLS_CONFIG_ERROR, "unknown cipher suite");
    }
    list.push_back(id);
  }
  if (list.empty()) {
    mrb_raise(mrb, E_TLS_CONFIG_ERROR, "no cipher suites selected");
  }
  list.push_back(0);
  return mrb_str_new(mrb, (const char *)list.data(), (mrb_int)(list.size() * sizeof(int)));
}

/* Alias substitution / tokenizing / "auto"/"default"/"none" keyword dispatch
 * for Config#ecdhecurve= now lives in Ruby (mrblib/config.rb); this is just
 * the part that has to be C -- looking already-aliased mbedTLS curve names
 * up by IANA id and packing the result into the 0-terminated native
 * `uint16_t` array mbedtls_ssl_conf_groups() expects (same ABI-safety
 * reasoning as mrb_tls_pack_ciphersuites()). ecp.h is gone from mbedTLS 4.x's
 * public API, so known_groups[] reproduces the name<->IANA-id table by
 * hand, each entry gated by the PSA_WANT_* macro that actually controls
 * whether this build compiled that curve in -- sub-250-bit curves
 * (secp192, secp224) have no entry at all, mbedTLS 4.0 dropped them. */
static mrb_value
mrb_tls_pack_groups(mrb_state *mrb, mrb_value self)
{
  static const struct { const char *name; uint16_t tls_id; } known_groups[] = {
#if defined(PSA_WANT_ECC_MONTGOMERY_255)
    { "x25519", MBEDTLS_SSL_IANA_TLS_GROUP_X25519 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
    { "secp256r1", MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 },
#endif
#if defined(PSA_WANT_ECC_SECP_K1_256)
    { "secp256k1", MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
    { "secp384r1", MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 },
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_448)
    { "x448", MBEDTLS_SSL_IANA_TLS_GROUP_X448 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
    { "secp521r1", MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
    { "brainpoolP256r1", MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
    { "brainpoolP384r1", MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
    { "brainpoolP512r1", MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1 },
#endif
#if defined(PSA_WANT_DH_RFC7919_2048)
    { "ffdhe2048", MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048 },
#endif
#if defined(PSA_WANT_DH_RFC7919_3072)
    { "ffdhe3072", MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072 },
#endif
#if defined(PSA_WANT_DH_RFC7919_4096)
    { "ffdhe4096", MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096 },
#endif
#if defined(PSA_WANT_DH_RFC7919_6144)
    { "ffdhe6144", MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144 },
#endif
#if defined(PSA_WANT_DH_RFC7919_8192)
    { "ffdhe8192", MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192 },
#endif
  };
  mrb_value names;
  mrb_get_args(mrb, "A", &names);

  std::vector<uint16_t> list;
  mrb_int len = RARRAY_LEN(names);
  for (mrb_int i = 0; i < len; i++) {
    mrb_value name_v = mrb_ary_ref(mrb, names, i);
    const char *name = mrb_str_to_cstr(mrb, name_v);
    uint16_t tls_id = 0;
    for (size_t j = 0; j < sizeof(known_groups) / sizeof(known_groups[0]); j++) {
      if (mrb_tls_tokeq(name, strlen(name), known_groups[j].name)) {
        tls_id = known_groups[j].tls_id;
        break;
      }
    }
    if (tls_id == 0) {
      mrb_raise(mrb, E_TLS_CONFIG_ERROR, "unknown ecdhe curve");
    }
    list.push_back(tls_id);
  }
  if (list.empty()) {
    mrb_raise(mrb, E_TLS_CONFIG_ERROR, "no ecdhe curves selected");
  }
  list.push_back(0);
  return mrb_str_new(mrb, (const char *)list.data(), (mrb_int)(list.size() * sizeof(uint16_t)));
}

/* ------------------------------------------------------------------------ */
/* Tls::Config                                                               */
/* ------------------------------------------------------------------------ */

/* Allocates cfg and attaches it to `self` (mrb_data_init) before anything
 * else runs, so it's GC-owned from the start instead of sitting as a bare,
 * unowned pointer between allocation and attachment. */
static mrb_tls_config_t *
mrb_tls_config_alloc(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)mrb_calloc(mrb, 1, sizeof(mrb_tls_config_t));
  mrb_data_init(self, cfg, &tls_config_type);

  cfg->protocols = MRB_TLS_PROTOCOLS_DEFAULT;
  cfg->verify_depth = MRB_TLS_DEFAULT_VERIFY_DEPTH;
  cfg->verify_cert = 1;
  cfg->verify_name = 1;
  cfg->verify_time = 1;
  mbedtls_x509_crt_init(&cfg->cert);
  mbedtls_pk_init(&cfg->pk);
  return cfg;
}

/* Seed a config with the platform trust store, the way tls_config_new() seeded
 * it with tls_default_ca_cert_file(). `self` is the Ruby-visible Config
 * object being initialized -- ca_file/ca_path live as its ivars now. */
static void
mrb_tls_config_default_ca(mrb_state *mrb, mrb_value self)
{
  const char *file = mrb_tls_default_ca_file();

  if (file != NULL) {
    mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_file), file);
    return;
  }
  const char *dir = mrb_tls_default_ca_dir();
  if (dir != NULL) {
    mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_path), dir);
    return;
  }
#ifdef _WIN32
  /* Neither SSL_CERT_FILE/_DIR nor a PEM bundle applies -- fall back to the
   * Windows system "ROOT" store, loaded lazily in mrb_tls_ctx_setup() (a
   * fresh Tls::Config is built long before it's known whether it will ever
   * be used, and CertOpenStore() is not free). */
  mrb_iv_set(mrb, self, MRB_SYM(ca_system_store), mrb_true_value());
#endif
}

static mrb_tls_config_t *
mrb_tls_config_ptr(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)mrb_data_get_ptr(mrb, self, &tls_config_type);

  if (cfg == NULL) {
    mrb_raise(mrb, E_TLS_CONFIG_ERROR, "uninitialized config");
  }
  return cfg;
}

static mrb_value
mrb_tls_config_new(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_alloc(mrb, self);
  mrb_tls_config_default_ca(mrb, self);

  return self;
}

static mrb_value
mrb_tls_config_set_ca_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self); /* "uninitialized config" guard only */
  char *ca_file;

  mrb_get_args(mrb, "z", &ca_file);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_file), ca_file);
  /* An explicit ca_file replaces the default ca_path, otherwise the two would
   * be merged and the caller would still trust the system store. */
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_path), NULL);

  return self;
}

static mrb_value
mrb_tls_config_set_ca_path(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);
  char *ca_path;

  mrb_get_args(mrb, "z", &ca_path);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_path), ca_path);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(ca_file), NULL);

  return self;
}

static mrb_value
mrb_tls_config_set_cert_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);
  char *cert_file;

  mrb_get_args(mrb, "z", &cert_file);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(cert_file), cert_file);
  mrb_tls_ivar_buf_clear(mrb, self, MRB_SYM(cert_mem));

  return self;
}

static mrb_value
mrb_tls_config_set_cert_mem(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);
  mbedtls_x509_crt probe;
  mrb_value cert;
  int ret;

  mrb_get_args(mrb, "S", &cert);

  mrb_tls_ivar_buf_set(mrb, self, MRB_SYM(cert_mem), cert);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(cert_file), NULL);

  size_t cert_mem_len;
  const uint8_t *cert_mem = mrb_tls_ivar_buf_get(mrb, self, MRB_SYM(cert_mem), &cert_mem_len);

  /* libtls parsed the certificate right here (it needs the public key hash),
   * so a malformed blob was reported at assignment time.  Keep that by
   * parsing into a throwaway chain. */
  mbedtls_x509_crt_init(&probe);
  errno = 0;
  ret = mbedtls_x509_crt_parse(&probe, cert_mem, mrb_tls_parse_len(cert_mem, cert_mem_len));
  mbedtls_x509_crt_free(&probe);
  if (ret < 0) {
    return mrb_tls_config_fail(mrb, ret, "cert_mem");
  }

  return self;
}

static mrb_value
mrb_tls_config_set_key_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);
  char *key_file;

  mrb_get_args(mrb, "z", &key_file);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(key_file), key_file);
  mrb_tls_ivar_buf_clear(mrb, self, MRB_SYM(key_mem));

  return self;
}

static mrb_value
mrb_tls_config_set_key_mem(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);
  mbedtls_pk_context probe;
  mrb_value key;
  int ret;

  mrb_get_args(mrb, "S", &key);

  mrb_tls_ivar_buf_set(mrb, self, MRB_SYM(key_mem), key);
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(key_file), NULL);

  size_t key_mem_len;
  const uint8_t *key_mem = mrb_tls_ivar_buf_get(mrb, self, MRB_SYM(key_mem), &key_mem_len);

  mbedtls_pk_init(&probe);
  errno = 0;
  ret = mbedtls_pk_parse_key(&probe, key_mem, mrb_tls_parse_len(key_mem, key_mem_len),
                             NULL, 0);
  mbedtls_pk_free(&probe);
  if (ret != 0) {
    return mrb_tls_config_fail(mrb, ret, "key_mem");
  }

  return self;
}

static mrb_value
mrb_tls_config_set_protocols(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = mrb_tls_config_ptr(mrb, self);
  mrb_int protocols;

  mrb_get_args(mrb, "i", &protocols);
  cfg->protocols = (uint32_t)protocols;

  return self;
}

static mrb_value
mrb_tls_config_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = mrb_tls_config_ptr(mrb, self);
  mrb_int verify_depth;

  mrb_get_args(mrb, "i", &verify_depth);
  cfg->verify_depth = (int)verify_depth;

  return self;
}

static mrb_value
mrb_tls_config_clear_keys(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_ptr(mrb, self);

  /* tls_config_clear_keys() wipes the in-memory private keys and leaves every
   * other setting (including key_file) alone. */
  mrb_tls_ivar_buf_clear(mrb, self, MRB_SYM(key_mem));

  return self;
}

static mrb_value
mrb_tls_config_verify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = mrb_tls_config_ptr(mrb, self);

  cfg->verify_cert = 1;
  cfg->verify_name = 1;
  cfg->verify_time = 1;

  return self;
}

static mrb_value
mrb_tls_config_noverify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = mrb_tls_config_ptr(mrb, self);
  char *mode;

  mrb_get_args(mrb, "z", &mode);

  if (strcmp(mode, "cert") == 0) {
    cfg->verify_cert = 0;
  } else if (strcmp(mode, "name") == 0) {
    cfg->verify_name = 0;
  } else if (strcmp(mode, "time") == 0) {
    cfg->verify_time = 0;
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "unknown noverify mode");
  }

  return self;
}

/* ------------------------------------------------------------------------ */
/* Tls.load_file                                                             */
/* ------------------------------------------------------------------------ */

static mrb_value
mrb_tls_load_file(mrb_state *mrb, mrb_value self)
{
  char *file, *password = NULL;

  mrb_get_args(mrb, "z|z!", &file, &password);

  if (password == NULL) {
    struct stat st;
    mrb_value str;
    FILE *fp;
    size_t size, nread;
    int bad;

    errno = 0;
    if (stat(file, &st) != 0) {
      mrb_sys_fail(mrb, "tls_load_file");
    }
    /*
     * st_size is off_t, which is wider than mrb_int on an MRB_INT32 build.
     * Truncating it into the mrb_str_new_capa() below while fread() kept
     * using the untruncated value would under-allocate the destination and
     * overflow it, so reject anything that does not fit up front and use
     * one value for both from here on.
     */
    if (st.st_size < 0 || (uintmax_t)st.st_size > (uintmax_t)MRB_INT_MAX) {
      errno = 0;
      return mrb_tls_fail(mrb, 0, "tls_load_file: file too large");
    }
    size = (size_t)st.st_size;
    /* Allocate the result before opening so that an allocation failure cannot
     * leak the FILE*. */
    str = mrb_str_new_capa(mrb, (mrb_int)size);

    errno = 0;
    fp = fopen(file, "rb");
    if (fp == NULL) {
      mrb_sys_fail(mrb, "tls_load_file");
    }
    errno = 0;
    nread = fread(RSTRING_PTR(str), 1, size, fp);
    bad = ferror(fp);
    fclose(fp);
    if (bad) {
      if (errno == 0) {
        errno = EIO;
      }
      mrb_sys_fail(mrb, "tls_load_file");
    }

    return mrb_str_resize(mrb, str, (mrb_int)nread);
  } else {
    /*
     * DIVERGENCE (documented, deliberate): libtls's tls_load_file() handed the
     * password to OpenSSL's generic PEM reader, so it could decrypt *any*
     * encrypted PEM object.  mbedTLS has no such primitive -- the only
     * password aware parsers it exposes are the private key ones.
     *
     * Silently ignoring the password would be the worst possible outcome: the
     * caller would get an encrypted blob back and believe it was decrypted.
     * So the password path is implemented faithfully for the (overwhelmingly
     * common) private key case via mbedtls_pk_parse_keyfile(), re-serialised
     * to PEM, and everything else is rejected with an explicit error.
     */
    mbedtls_pk_context pk;
    unsigned char out[16000];
    mrb_value str;
    int ret;

    mbedtls_pk_init(&pk);
    errno = 0;
    ret = mbedtls_pk_parse_keyfile(&pk, file, password);
    if (ret != 0) {
      mbedtls_pk_free(&pk);
      return mrb_tls_fail(mrb, ret,
        "tls_load_file: the mbedTLS backend can only decrypt password "
        "protected private keys, not arbitrary encrypted PEM data");
    }

    errno = 0;
    ret = mbedtls_pk_write_key_pem(&pk, out, sizeof(out));
    mbedtls_pk_free(&pk);
    if (ret != 0) {
      mrb_secure_wipe_memory(out, sizeof(out));
      return mrb_tls_fail(mrb, ret, "tls_load_file");
    }

    str = mrb_str_new_cstr(mrb, (const char *)out);
    mrb_secure_wipe_memory(out, sizeof(out));

    return str;
  }
}

/* ------------------------------------------------------------------------ */
/* Certificate verification policy                                           */
/* ------------------------------------------------------------------------ */

/*
 * libtls has three independent verify switches; mbedTLS has one coarse
 * authmode axis + a callback. authmode is REQUIRED whenever the chain must
 * be validated, so mbedtls_ssl_handshake() itself fails closed on any flag
 * the callback below doesn't clear. mrb_tls_verify_cb() clears only the
 * bits for switches explicitly turned off. The one case REQUIRED can't
 * express -- noverify('cert') with hostname checking still on -- drops to
 * OPTIONAL, whose residual flags are then checked by hand in
 * mrb_tls_ctx_after_handshake() (OPTIONAL without that check is the
 * classic way to silently accept an invalid cert).
 */
static int
mrb_tls_verify_cb(void *p_vrfy, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)p_vrfy;

  (void)crt;

  /*
   * verify_depth.  OpenSSL (and thus libtls) counts the maximum number of
   * intermediate CAs it is willing to walk; mbedTLS numbers the chain from the
   * leaf (depth 0) upwards and has no runtime equivalent, so enforce it here.
   * Seeing a certificate above the configured depth means the chain is longer
   * than allowed -> not trusted.
   */
  if (ctx->verify_depth >= 0 && depth > ctx->verify_depth) {
    *flags |= (uint32_t)MBEDTLS_X509_BADCERT_NOT_TRUSTED;
  }

  /* noverify('time'): ignore validity period problems, nothing else. */
  if (!ctx->verify_time) {
    *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED |
                          MBEDTLS_X509_BADCERT_FUTURE |
                          MBEDTLS_X509_BADCRL_EXPIRED |
                          MBEDTLS_X509_BADCRL_FUTURE);
  }

  /* noverify('name'): ignore a hostname mismatch, nothing else.  The hostname
   * is still handed to mbedtls_ssl_set_hostname() so that SNI keeps working. */
  if (!ctx->verify_name) {
    *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
  }

  /*
   * noverify('cert'): drop every chain validation verdict (untrusted issuer,
   * bad signature, missing/!CA basic constraints, weak key/hash, revocation,
   * ...) but keep the hostname verdict, because libtls's
   * tls_config_insecure_noverifycert() only disables chain verification while
   * tls_check_name() keeps running.
   */
  if (!ctx->verify_cert) {
    uint32_t keep = *flags & (uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
    if (!ctx->verify_name) {
      keep = 0;
    }
    *flags = keep;
  }

  return 0;
}

static int
mrb_tls_authmode_for(const mrb_tls_ctx_t *ctx)
{
  if (ctx->endpoint == MBEDTLS_SSL_IS_SERVER) {
    /* The gem never exposed tls_config_verify_client(), and libtls servers do
     * not ask for or verify client certificates unless you do.  Keep that. */
    return MBEDTLS_SSL_VERIFY_NONE;
  }
  if (!ctx->verify_cert && !ctx->verify_name) {
    return MBEDTLS_SSL_VERIFY_NONE;
  }
  if (!ctx->verify_cert) {
    /* See the block comment above mrb_tls_verify_cb(). */
    return MBEDTLS_SSL_VERIFY_OPTIONAL;
  }
  return MBEDTLS_SSL_VERIFY_REQUIRED;
}

/* ------------------------------------------------------------------------ */
/* Tls::Context internals                                                    */
/* ------------------------------------------------------------------------ */

#ifdef _WIN32
/*
 * Winsock never sets errno -- send()/recv() failures are reported through
 * WSAGetLastError() instead, on a separate error number space from the CRT's
 * errno/EAGAIN/EINTR/EPIPE. Translating that into the same three buckets the
 * POSIX branch below produces (would-block, reset, hard failure) keeps
 * mrb_tls_bio_send()/_recv() themselves platform agnostic.
 */
static int
mrb_tls_wsa_bucket(int werr)
{
  switch (werr) {
  case WSAEWOULDBLOCK:
  case WSAEINTR:
    return 1; /* WANT_WRITE / WANT_READ */
  case WSAECONNRESET:
  case WSAECONNABORTED:
  case WSAESHUTDOWN:
  case WSAENETRESET:
    return 2; /* CONN_RESET */
  default:
    return 3; /* SEND_FAILED / RECV_FAILED */
  }
}
#endif

/* ------------------------------------------------------------------------ */
/* Ruby-socket dispatch for mrb_tls_bio_send()/_recv()                       */
/* ------------------------------------------------------------------------ */

/* connect_socket/accept_socket/connect_fds all accept either a real
 * Ruby object (Socket, IO, ...) OR a bare Integer fd (the old, still-
 * supported calling convention -- e.g. `accept_socket tcp_client.fileno`);
 * @socket/@fd_read/@fd_write hold back whatever was actually passed in.
 * Only dispatch through the Ruby method when it's a real object -- a bare
 * Integer has no #send/#recv/#read/#write to call, and must keep using the
 * raw fd syscall path exactly as before, unchanged. Plain #connect owns its
 * fd directly (mbedtls_net_connect) and never sets either ivar, so all
 * three helpers below return nil there too. */
static mrb_value
mrb_tls_bio_writer(mrb_state *mrb, mrb_value self, mrb_sym *method)
{
  mrb_value sock = mrb_iv_get(mrb, self, MRB_SYM(socket));
  if (!mrb_nil_p(sock) && !mrb_integer_p(sock)) {
    *method = MRB_SYM(send);
    return sock;
  }
  mrb_value io = mrb_iv_get(mrb, self, MRB_SYM(fd_write));
  if (!mrb_nil_p(io) && !mrb_integer_p(io)) {
    *method = MRB_SYM(write);
    return io;
  }
  return mrb_nil_value();
}

static mrb_value
mrb_tls_bio_reader(mrb_state *mrb, mrb_value self, mrb_sym *method)
{
  mrb_value sock = mrb_iv_get(mrb, self, MRB_SYM(socket));
  if (!mrb_nil_p(sock) && !mrb_integer_p(sock)) {
    *method = MRB_SYM(recv);
    return sock;
  }
  mrb_value io = mrb_iv_get(mrb, self, MRB_SYM(fd_read));
  if (!mrb_nil_p(io) && !mrb_integer_p(io)) {
    *method = MRB_SYM(read);
    return io;
  }
  return mrb_nil_value();
}

/* Passed as the block argument to #send/#recv so that, on an async socket
 * (e.g. IO::Uring) where the call returns an in-flight Operation instead of
 * completing synchronously, the *eventual* completion -- delivered whenever
 * the caller's own event loop (ring.wait, for io_uring) reaps it -- has
 * somewhere to land. Their only job is to stash the finished Operation as
 * @pending_recv/@pending_send; the next mrb_tls_bio_recv()/_send() call
 * picks it up from there instead of submitting a new op. Built once per
 * mrb_tls_ctx_setup() and reused for the whole connection rather than
 * allocating a fresh Proc per I/O call. */
static mrb_value
mrb_tls_bio_recv_resume(mrb_state *mrb, mrb_value)
{
  mrb_value op;
  mrb_get_args(mrb, "o", &op);
  mrb_iv_set(mrb, mrb_proc_cfunc_env_get(mrb, 0), MRB_SYM(pending_recv), op);
  return mrb_nil_value();
}

static mrb_value
mrb_tls_bio_send_resume(mrb_state *mrb, mrb_value)
{
  mrb_value op;
  mrb_get_args(mrb, "o", &op);
  mrb_iv_set(mrb, mrb_proc_cfunc_env_get(mrb, 0), MRB_SYM(pending_send), op);
  return mrb_nil_value();
}

static void
mrb_tls_bio_install_resume_blocks(mrb_state *mrb, mrb_value self)
{
  mrb_value env[] = { self };
  struct RProc *recv_p = mrb_proc_new_cfunc_with_env(mrb, mrb_tls_bio_recv_resume, 1, env);
  struct RProc *send_p = mrb_proc_new_cfunc_with_env(mrb, mrb_tls_bio_send_resume, 1, env);
  mrb_iv_set(mrb, self, MRB_SYM(_recv_resume), mrb_obj_value(recv_p));
  mrb_iv_set(mrb, self, MRB_SYM(_send_resume), mrb_obj_value(send_p));
}

/* Classifies a SystemCallError (e.g. Errno::EAGAIN) raised by a blocking
 * socket's #send/#recv/#write/#read the same way the raw-fd path's own
 * errno switch already does -- EAGAIN/EWOULDBLOCK/EINTR mean "not ready,
 * try again" (WANT_READ/WANT_WRITE), EPIPE/ECONNRESET mean a clean reset --
 * so a blocking socket dispatched through here behaves identically to the
 * old raw syscalls. Returns 0 (never a valid mbedTLS error code) if exc
 * isn't a recognized SystemCallError, meaning the caller should treat it as
 * a genuine, unexpected failure and capture it via @pending_exception. */
static int
mrb_tls_bio_classify_error(mrb_state *mrb, mrb_value exc, int want_code)
{
  /* A *recognized* errno (EAGAIN included) reclasses the exception object
   * to its specific Errno::EAGAIN-style subclass instead of stashing an
   * @errno ivar (see mruby-errno's mrb_sce_init) -- #errno itself already
   * knows to look in the right place either way, so go through it rather
   * than assume where the value lives. */
  struct RClass *sce = mrb_class_get_id(mrb, MRB_SYM(SystemCallError));
  if (!mrb_obj_is_kind_of(mrb, exc, sce)) {
    return 0;
  }
  mrb_value errno_val = mrb_funcall_id(mrb, exc, MRB_SYM(errno), 0);
  if (!mrb_integer_p(errno_val)) {
    return 0;
  }
  mrb_int e = mrb_integer(errno_val);
  if (e == EAGAIN || e == EINTR
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
      || e == EWOULDBLOCK
#endif
     ) {
    return want_code;
  }
  if (e == EPIPE || e == ECONNRESET) {
    return MBEDTLS_ERR_NET_CONN_RESET;
  }
  return 0;
}

typedef struct {
  mrb_value sock;
  mrb_sym method;
  mrb_value argv[2];
  mrb_int argc;
  mrb_value block;
} mrb_tls_io_call_t;

static mrb_value
mrb_tls_io_call_body(mrb_state *mrb, void *data)
{
  mrb_tls_io_call_t *c = (mrb_tls_io_call_t *)data;
  return mrb_funcall_with_block(mrb, c->sock, c->method, c->argc, c->argv, c->block);
}

static int
mrb_tls_bio_send(void *p_bio, const unsigned char *buf, size_t len)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)p_bio;
  mrb_state *mrb = ctx->mrb;
  mrb_sym method;
  mrb_value sock = mrb_tls_bio_writer(mrb, ctx->self, &method);
  ssize_t n;

  if (mrb_nil_p(sock)) {
    if (ctx->fd_write < 0) {
      return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
#ifdef _WIN32
    WSASetLastError(0);
    n = (ssize_t)send((SOCKET)ctx->fd_write, (const char *)buf, (int)len, 0);
    if (n >= 0) {
      return (int)n;
    }
    switch (mrb_tls_wsa_bucket(WSAGetLastError())) {
    case 1: return MBEDTLS_ERR_SSL_WANT_WRITE;
    case 2: return MBEDTLS_ERR_NET_CONN_RESET;
    default: return MBEDTLS_ERR_NET_SEND_FAILED;
    }
#else
    errno = 0;
    n = write(ctx->fd_write, buf, len);
    if (n >= 0) {
      return (int)n;
    }
    switch (errno) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    case EPIPE:
    case ECONNRESET:
      return MBEDTLS_ERR_NET_CONN_RESET;
    default:
      return MBEDTLS_ERR_NET_SEND_FAILED;
    }
#endif
  }

  mrb_value pending = mrb_iv_get(mrb, ctx->self, MRB_SYM(pending_send));
  if (!mrb_nil_p(pending)) {
    if (mrb_symbol_p(pending)) {
      /* Already submitted, just not complete yet -- do NOT submit a second
       * op on top of it (two overlapping sends on the same stream socket
       * would race and corrupt the byte order). Keep returning WANT_WRITE
       * until the resume block overwrites this with the real Operation. */
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    mrb_iv_remove(mrb, ctx->self, MRB_SYM(pending_send));
    /* .errno/.res are read through their real accessor methods, not raw
     * ivars -- an Operation-like object's public API is the contract here,
     * not whatever internal ivar-symbol convention it happens to use. */
    mrb_value errv = mrb_funcall_id(mrb, pending, MRB_SYM(errno), 0);
    if (!mrb_nil_p(errv)) {
      mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), errv);
      return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)mrb_integer(mrb_funcall_id(mrb, pending, MRB_SYM(res), 0));
  }

  mrb_tls_io_call_t call;
  call.sock = sock;
  call.method = method;
  call.argv[0] = mrb_str_new(mrb, (const char *)buf, (mrb_int)len);
  call.argv[1] = mrb_fixnum_value(0);
  call.argc = (method == MRB_SYM(send)) ? 2 : 1;
  call.block = mrb_iv_get(mrb, ctx->self, MRB_SYM(_send_resume));

  mrb_bool error = FALSE;
  mrb_value result = mrb_protect_error(mrb, mrb_tls_io_call_body, &call, &error);
  if (error) {
    int code = mrb_tls_bio_classify_error(mrb, result, MBEDTLS_ERR_SSL_WANT_WRITE);
    if (code != 0) {
      return code;
    }
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), result);
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  if (mrb_integer_p(result)) {
    return (int)mrb_integer(result);
  }
  /* Not an Integer: a genuinely async Operation, still in flight. Mark
   * @pending_send with the in-flight sentinel (checked above) so a retry
   * before completion doesn't submit a second, overlapping send -- the
   * resume block overwrites this with the real Operation once reaped. */
  mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_send), mrb_symbol_value(MRB_SYM(_io_in_flight)));
  return MBEDTLS_ERR_SSL_WANT_WRITE;
}

/* Hands mbedTLS up to `len` bytes from `data` (already-available plaintext
 * -- a synchronous #recv/#read result, a completed io_uring Operation's
 * .buf, or bytes left over from a previous call here), buffering anything
 * past `len` as a plain String in @pending_recv for the very next
 * mrb_tls_bio_recv() call instead of discarding it. This matters because
 * the underlying io_uring buffer's actual capacity can exceed the logical
 * length requested (mrb_str_new_capa can round up), so a single completion
 * legitimately can carry more bytes than mbedTLS's current request --
 * dropping the excess would silently corrupt the TLS record stream. */
static int
mrb_tls_bio_recv_consume(mrb_state *mrb, mrb_tls_ctx_t *ctx, mrb_value data, unsigned char *buf, size_t len)
{
  mrb_int total = mrb_string_p(data) ? RSTRING_LEN(data) : 0;
  if (total <= 0) {
    return 0;
  }
  if ((size_t)total > len) {
    memcpy(buf, RSTRING_PTR(data), len);
    mrb_value leftover = mrb_str_new(mrb, RSTRING_PTR(data) + len, total - (mrb_int)len);
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_recv), leftover);
    return (int)len;
  }
  memcpy(buf, RSTRING_PTR(data), (size_t)total);
  return (int)total;
}

static int
mrb_tls_bio_recv(void *p_bio, unsigned char *buf, size_t len)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)p_bio;
  mrb_state *mrb = ctx->mrb;
  mrb_sym method;
  mrb_value sock = mrb_tls_bio_reader(mrb, ctx->self, &method);
  ssize_t n;

  if (mrb_nil_p(sock)) {
    if (ctx->fd_read < 0) {
      return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
#ifdef _WIN32
    WSASetLastError(0);
    n = (ssize_t)recv((SOCKET)ctx->fd_read, (char *)buf, (int)len, 0);
    if (n >= 0) {
      /* n == 0 is a clean EOF at the transport level; mbedTLS turns that into
       * MBEDTLS_ERR_SSL_CONN_RESET, which is what we want: a stream that ends
       * without a close_notify is a truncation, not a normal end of data. */
      return (int)n;
    }
    switch (mrb_tls_wsa_bucket(WSAGetLastError())) {
    case 1: return MBEDTLS_ERR_SSL_WANT_READ;
    case 2: return MBEDTLS_ERR_NET_CONN_RESET;
    default: return MBEDTLS_ERR_NET_RECV_FAILED;
    }
#else
    errno = 0;
    n = read(ctx->fd_read, buf, len);
    if (n >= 0) {
      return (int)n;
    }
    switch (errno) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
      return MBEDTLS_ERR_SSL_WANT_READ;
    case EPIPE:
    case ECONNRESET:
      return MBEDTLS_ERR_NET_CONN_RESET;
    default:
      return MBEDTLS_ERR_NET_RECV_FAILED;
    }
#endif
  }

  mrb_value pending = mrb_iv_get(mrb, ctx->self, MRB_SYM(pending_recv));
  if (!mrb_nil_p(pending)) {
    if (mrb_symbol_p(pending)) {
      /* Already submitted, just not complete yet -- see the matching
       * comment in mrb_tls_bio_send(). */
      return MBEDTLS_ERR_SSL_WANT_READ;
    }
    mrb_iv_remove(mrb, ctx->self, MRB_SYM(pending_recv));
    if (mrb_string_p(pending)) {
      /* Leftover bytes an earlier completion carried beyond what that call
       * asked for -- hand them out directly, no I/O involved. */
      return mrb_tls_bio_recv_consume(mrb, ctx, pending, buf, len);
    }
    /* .errno/.buf are read through their real accessor methods, not raw
     * ivars -- see the matching comment in mrb_tls_bio_send(). */
    mrb_value errv = mrb_funcall_id(mrb, pending, MRB_SYM(errno), 0);
    if (!mrb_nil_p(errv)) {
      mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), errv);
      return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    mrb_value data = mrb_funcall_id(mrb, pending, MRB_SYM(buf), 0);
    return mrb_tls_bio_recv_consume(mrb, ctx, data, buf, len);
  }

  mrb_tls_io_call_t call;
  call.sock = sock;
  call.method = method;
  call.argv[0] = mrb_fixnum_value((mrb_int)len);
  call.argc = 1;
  call.block = mrb_iv_get(mrb, ctx->self, MRB_SYM(_recv_resume));

  mrb_bool error = FALSE;
  mrb_value result = mrb_protect_error(mrb, mrb_tls_io_call_body, &call, &error);
  if (error) {
    int code = mrb_tls_bio_classify_error(mrb, result, MBEDTLS_ERR_SSL_WANT_READ);
    if (code != 0) {
      return code;
    }
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), result);
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  if (mrb_nil_p(result)) {
    /* Clean EOF -- see the WIN32 branch's comment above for why 0 is right. */
    return 0;
  }
  if (mrb_string_p(result)) {
    return mrb_tls_bio_recv_consume(mrb, ctx, result, buf, len);
  }
  /* Not a String and not nil: a genuinely async Operation, still in flight.
   * Same as the send side -- mark the in-flight sentinel so a retry doesn't
   * submit a second, overlapping recv; the resume block overwrites this
   * with the real completion once reaped. */
  mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_recv), mrb_symbol_value(MRB_SYM(_io_in_flight)));
  return MBEDTLS_ERR_SSL_WANT_READ;
}

/* mbedTLS has no ca_path equivalent: walk the directory, feed every regular
 * file to mbedtls_x509_crt_parse_file(), skip files that don't parse (a
 * c_rehash dir has symlinks/.0/.r0 CRLs). An unreadable dir or zero
 * certificates loaded is an error rather than a silent empty trust store. */
static int
mrb_tls_load_ca_dir(mbedtls_x509_crt *chain, const char *path, int *loaded)
{
#ifdef _WIN32
  struct _finddata_t fd;
  intptr_t h;
  /* No portable Windows path-length constant to use here: legacy MAX_PATH
   * is 260, smaller than paths this can realistically see. */
  char pattern[4096], full[4096];

  *loaded = 0;
  if (snprintf(pattern, sizeof(pattern), "%s\\*", path) >= (int)sizeof(pattern)) {
    return -1;
  }
  h = _findfirst(pattern, &fd);
  if (h == -1) {
    return -1;
  }
  do {
    if (strcmp(fd.name, ".") == 0 || strcmp(fd.name, "..") == 0) {
      continue;
    }
    if (fd.attrib & _A_SUBDIR) {
      continue;
    }
    if (snprintf(full, sizeof(full), "%s\\%s", path, fd.name) >= (int)sizeof(full)) {
      continue;
    }
    if (mbedtls_x509_crt_parse_file(chain, full) == 0) {
      (*loaded)++;
    }
  } while (_findnext(h, &fd) == 0);
  _findclose(h);
  return 0;
#else
  DIR *dir;
  struct dirent *ent;
  char full[PATH_MAX];
  struct stat st;

  *loaded = 0;
  errno = 0;
  dir = opendir(path);
  if (dir == NULL) {
    return -1;
  }
  while ((ent = readdir(dir)) != NULL) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
      continue;
    }
    if (snprintf(full, sizeof(full), "%s/%s", path, ent->d_name) >= (int)sizeof(full)) {
      continue;
    }
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
      continue;
    }
    if (mbedtls_x509_crt_parse_file(chain, full) == 0) {
      (*loaded)++;
    }
  }
  closedir(dir);
  errno = 0;
  return 0;
#endif
}

static void
mrb_tls_ctx_teardown_ssl(mrb_state *mrb, mrb_tls_ctx_t *ctx)
{
  (void)mrb;
  mbedtls_ssl_free(&ctx->ssl);
  mbedtls_ssl_init(&ctx->ssl);
  mbedtls_ssl_config_free(&ctx->conf);
  mbedtls_ssl_config_init(&ctx->conf);
  mbedtls_x509_crt_free(&ctx->ca);
  mbedtls_x509_crt_init(&ctx->ca);
  mbedtls_x509_crt_free(&ctx->cert);
  mbedtls_x509_crt_init(&ctx->cert);
  mbedtls_pk_free(&ctx->pk);
  mbedtls_pk_init(&ctx->pk);
  /* ciphersuites/groups used to be freed here -- they are ivars on the
   * Ruby-visible Context now (see mrb_tls_ctx_setup()), so the next setup
   * replacing them is enough; nothing to free by hand. */
  ctx->setup = 0;
  ctx->handshaked = 0;
  ctx->close_sent = 0;
}

static void
mrb_tls_ctx_close_fd(mrb_tls_ctx_t *ctx)
{
  if (ctx->own_fd && ctx->fd_read >= 0) {
#ifdef _WIN32
    closesocket((SOCKET)ctx->fd_read);
#else
    shutdown(ctx->fd_read, SHUT_RDWR);
    close(ctx->fd_read);
#endif
  }
  ctx->fd_read = -1;
  ctx->fd_write = -1;
  ctx->own_fd = 0;
}

void
mrb_tls_ctx_destroy(mrb_state *mrb, mrb_tls_ctx_t *ctx)
{
  (void)mrb;
  mbedtls_ssl_free(&ctx->ssl);
  mbedtls_ssl_config_free(&ctx->conf);
  mbedtls_x509_crt_free(&ctx->ca);
  mbedtls_x509_crt_free(&ctx->cert);
  mbedtls_pk_free(&ctx->pk);
  /* ciphersuites/groups/hostname/own_cfg are all ivars on the Ruby-visible
   * Context now (see mrb_tls_ctx_setup()/mrb_tls_client()) -- GC frees
   * them once this DATA object (and therefore its ivar table) becomes
   * unreachable, same as it already does for @config. */
  mrb_tls_ctx_close_fd(ctx);
  memset(ctx, 0, sizeof(*ctx));
}

/* Frees the SNI-selected certificate cache -- see mrb_tls_config_ensure_cert()
 * and mrb_tls_config_t's own comment. A no-op (mbedtls_x509_crt_free/
 * mbedtls_pk_free on a never-initialized struct) for the overwhelmingly
 * common Tls::Config that is never handed to an SNI callback at all. */
void
mrb_tls_config_destroy(mrb_state *mrb, mrb_tls_config_t *cfg)
{
  (void)mrb;
  mbedtls_x509_crt_free(&cfg->cert);
  mbedtls_pk_free(&cfg->pk);
}

/* Allocates ctx and attaches it to `self` (mrb_data_init) before anything
 * else runs, so it's GC-owned from the start instead of sitting as a bare,
 * unowned pointer between allocation and attachment. */
static mrb_tls_ctx_t *
mrb_tls_ctx_new(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)mrb_calloc(mrb, 1, sizeof(mrb_tls_ctx_t));
  mrb_data_init(self, ctx, &tls_type);

  mbedtls_ssl_init(&ctx->ssl);
  mbedtls_ssl_config_init(&ctx->conf);
  mbedtls_x509_crt_init(&ctx->ca);
  mbedtls_x509_crt_init(&ctx->cert);
  mbedtls_pk_init(&ctx->pk);
  ctx->fd_read = -1;
  ctx->fd_write = -1;
  ctx->verify_depth = MRB_TLS_DEFAULT_VERIFY_DEPTH;
  return ctx;
}

static mrb_tls_ctx_t *
mrb_tls_ctx_ptr(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)mrb_data_get_ptr(mrb, self, &tls_type);

  if (ctx == NULL) {
    mrb_raise(mrb, E_TLS_ERROR, "uninitialized context");
  }
  return ctx;
}

/* NULL if `sym` isn't set on `obj` or isn't a String; RSTRING_PTR otherwise.
 * Only for the plain-C-string ivars (ca_file, ca_path, ...), NUL-clean via
 * mrb_get_args's "z". cert_mem/key_mem are binary and read separately. */
static const char *
mrb_tls_ivar_cstr(mrb_state *mrb, mrb_value obj, mrb_sym sym)
{
  mrb_value v = mrb_iv_get(mrb, obj, sym);
  return mrb_string_p(v) ? RSTRING_PTR(v) : NULL;
}

/*
 * Lazily parses `cfg_obj`'s own cert_file/cert_mem + key_file/key_mem ivars
 * into cfg->cert/cfg->pk, exactly once no matter how many connections
 * resolve to this same Config afterward (see mrb_tls_config_t's own
 * comment) -- used only by the SNI dispatch path (mrb_tls_sni_cb()); the
 * ordinary default-certificate path in mrb_tls_ctx_setup() is untouched by
 * this and keeps parsing straight into the Context's own ctx->cert/ctx->pk
 * as before.
 *
 * Returns 1 if cfg->cert/cfg->pk are now usable, 0 if this Config carries
 * no cert/key material at all (not an error by itself -- mirrors
 * mrb_tls_ctx_setup()'s own have_cert/have_key optionality), or -1 on a
 * genuine parse failure, with *errmsg set to what failed. Deliberately does
 * not raise: called from mrb_tls_sni_cb(), deep inside mbedTLS's C call
 * stack, where raising directly is not safe -- see that function's own
 * comment.
 */
static int
mrb_tls_config_ensure_cert(mrb_state *mrb, mrb_value cfg_obj, mrb_tls_config_t *cfg, const char **errmsg)
{
  if (cfg->cert_loaded) {
    return 1;
  }

  const char *cert_file = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(cert_file));
  const char *key_file = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(key_file));
  size_t cert_mem_len = 0, key_mem_len = 0;
  const uint8_t *cert_mem = mrb_tls_ivar_buf_get(mrb, cfg_obj, MRB_SYM(cert_mem), &cert_mem_len);
  const uint8_t *key_mem = mrb_tls_ivar_buf_get(mrb, cfg_obj, MRB_SYM(key_mem), &key_mem_len);
  int have_cert = 0, have_key = 0;
  int ret;

  if (cert_mem != NULL) {
    ret = mbedtls_x509_crt_parse(&cfg->cert, cert_mem, mrb_tls_parse_len(cert_mem, cert_mem_len));
    if (ret < 0) {
      *errmsg = "cert_mem";
      return -1;
    }
    have_cert = 1;
  } else if (cert_file != NULL) {
    ret = mbedtls_x509_crt_parse_file(&cfg->cert, cert_file);
    if (ret < 0) {
      *errmsg = "cert_file";
      return -1;
    }
    have_cert = 1;
  }

  if (key_mem != NULL) {
    ret = mbedtls_pk_parse_key(&cfg->pk, key_mem, mrb_tls_parse_len(key_mem, key_mem_len), NULL, 0);
    if (ret != 0) {
      *errmsg = "key_mem";
      return -1;
    }
    have_key = 1;
  } else if (key_file != NULL) {
    ret = mbedtls_pk_parse_keyfile(&cfg->pk, key_file, NULL);
    if (ret != 0) {
      *errmsg = "key_file";
      return -1;
    }
    have_key = 1;
  }

  if (have_cert != have_key) {
    *errmsg = "both a certificate and a key are required";
    return -1;
  }
  if (!have_cert) {
    return 0;
  }

  cfg->cert_loaded = 1;
  return 1;
}

/* ------------------------------------------------------------------------ */
/* SNI (Tls::Server.new(config) { |hostname| ... })                          */
/* ------------------------------------------------------------------------ */

typedef struct {
  mrb_value block;
  const char *name;
  size_t name_len;
} mrb_tls_sni_call_t;

static mrb_value
mrb_tls_sni_call_body(mrb_state *mrb, void *data)
{
  mrb_tls_sni_call_t *c = (mrb_tls_sni_call_t *)data;
  mrb_value hostname = mrb_str_new(mrb, c->name, (mrb_int)c->name_len);
  return mrb_yield(mrb, c->block, hostname);
}

/*
 * mbedTLS's SNI hook (mbedtls_ssl_conf_sni()), fired mid-handshake -- after
 * ClientHello's SNI extension is parsed, before the certificate goes out --
 * with the requested hostname. `p_info` is the mrb_tls_ctx_t* for the
 * accepted connection whose handshake is in progress (registered as such
 * in mrb_tls_ctx_setup(), same pattern as mrb_tls_verify_cb()).
 *
 * Unlike mrb_tls_verify_cb(), this one has to call back into Ruby (the
 * hostname -> Tls::Config lookup lives there, e.g. a plain Hash) -- and
 * that call happens deep inside mbedTLS's plain-C call stack, where a Ruby
 * exception unwinding straight through would be undefined behavior. Same
 * discipline as mrb_tls_bio_send()/_recv(): the call goes through
 * mrb_protect_error(), and any exception raised by the block is stashed as
 * @pending_exception (checked by mrb_tls_check_pending_exception() right
 * after mbedtls_ssl_handshake() returns in mrb_tls_handshake_step(), the
 * next safe-to-raise point) rather than propagated here. Every failure path
 * below returns a negative code, which fails the handshake outright --
 * matching a real client presenting no cert (mbedTLS handles this the same
 * way for a hard SNI failure) rather than silently falling back to
 * whichever cert this connection's Context happened to load by default.
 */
static int
mrb_tls_sni_cb(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len)
{
  mrb_tls_ctx_t *ctx = (mrb_tls_ctx_t *)p_info;
  mrb_state *mrb = ctx->mrb;

  mrb_value block = mrb_iv_get(mrb, ctx->self, MRB_SYM(sni));
  if (mrb_nil_p(block)) {
    /* No SNI handler installed on this connection after all (copied from
     * the Tls::Server that accepted it, in mrb_tls_accept_socket() -- see
     * its own comment) -- keep whatever default cert ctx_setup already
     * configured. */
    return 0;
  }

  mrb_tls_sni_call_t call;
  call.block = block;
  call.name = (const char *)name;
  call.name_len = name_len;

  mrb_bool error = FALSE;
  mrb_value result = mrb_protect_error(mrb, mrb_tls_sni_call_body, &call, &error);
  if (error) {
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), result);
    return -1;
  }

  if (mrb_nil_p(result)) {
    /* The block explicitly chose the default cert for this hostname. */
    return 0;
  }
  if (mrb_type(result) != MRB_TT_DATA || DATA_TYPE(result) != &tls_config_type) {
    mrb_value exc = mrb_exc_new_str(mrb, E_TLS_ERROR,
        mrb_str_new_cstr(mrb, "sni block must return a Tls::Config or nil"));
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), exc);
    return -1;
  }

  mrb_tls_config_t *sel_cfg = (mrb_tls_config_t *)DATA_PTR(result);
  const char *errmsg = NULL;
  int have = mrb_tls_config_ensure_cert(mrb, result, sel_cfg, &errmsg);
  if (have <= 0) {
    char msg[MRB_TLS_FAIL_MSG_BUFLEN];
    mrb_tls_errmsg(msg, sizeof(msg), 0,
        have < 0 ? errmsg : "sni-selected config has no certificate");
    mrb_value exc = mrb_exc_new_str(mrb, E_TLS_ERROR, mrb_str_new_cstr(mrb, msg));
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), exc);
    return -1;
  }

  int ret = mbedtls_ssl_set_hs_own_cert(ssl, &sel_cfg->cert, &sel_cfg->pk);
  if (ret != 0) {
    char msg[MRB_TLS_FAIL_MSG_BUFLEN];
    mrb_tls_errmsg(msg, sizeof(msg), ret, "mbedtls_ssl_set_hs_own_cert");
    mrb_value exc = mrb_exc_new_str(mrb, E_TLS_ERROR, mrb_str_new_cstr(mrb, msg));
    mrb_iv_set(mrb, ctx->self, MRB_SYM(pending_exception), exc);
    return -1;
  }

  return 0;
}

/* Builds the mbedtls_ssl_config/SSL context from the attached Tls::Config,
 * called from #connect/#connect_fds/#connect_socket/#accept_socket -- late
 * enough that mutating the config after Tls::Client.new still takes effect. */
static void
mrb_tls_ctx_setup(mrb_state *mrb, mrb_value self, mrb_tls_ctx_t *ctx)
{
  mrb_tls_config_t *cfg = ctx->cfg;
  mrb_value cfg_obj = mrb_iv_get(mrb, self, MRB_SYM(cfg));
  const char *errmsg = NULL;
  int have_ca = 0, have_cert = 0, have_key = 0;
  int min_ver, max_ver;
  int ret;

  /*
   * ctx->cfg is only ever a Tls::Config's DATA_PTR, kept alive by the `cfg`
   * ivar read just above -- but both are set by #initialize, and #initialize
   * can raise after mrb_data_init() has already made this object usable
   * (Tls::Config.new failing, or the type check in mrb_tls_client()).  A
   * program that reaches that state on purpose -- Tls::Client.allocate, then
   * a rescued send(:initialize) -- would otherwise get a NULL dereference on
   * cfg->protocols below.  Refuse the operation instead.
   */
  if (cfg == NULL || mrb_type(cfg_obj) != MRB_TT_DATA ||
      DATA_TYPE(cfg_obj) != &tls_config_type) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "no configuration attached to this context");
  }

  mrb_tls_ctx_teardown_ssl(mrb, ctx);

  errno = 0;
  ret = mbedtls_ssl_config_defaults(&ctx->conf, ctx->endpoint,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    mrb_tls_fail(mrb, ret, "mbedtls_ssl_config_defaults");
  }

  if (mrb_tls_protocols_to_versions(cfg->protocols, &min_ver, &max_ver, &errmsg) != 0) {
    errno = 0;
    mrb_tls_fail(mrb, 0, errmsg);
  }
  mbedtls_ssl_conf_min_tls_version(&ctx->conf, (mbedtls_ssl_protocol_version)min_ver);
  mbedtls_ssl_conf_max_tls_version(&ctx->conf, (mbedtls_ssl_protocol_version)max_ver);

  const char *ca_file = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(ca_file));
  const char *ca_path = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(ca_path));
  const char *cert_file = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(cert_file));
  const char *key_file = mrb_tls_ivar_cstr(mrb, cfg_obj, MRB_SYM(key_file));
  size_t cert_mem_len = 0, key_mem_len = 0;
  const uint8_t *cert_mem = mrb_tls_ivar_buf_get(mrb, cfg_obj, MRB_SYM(cert_mem), &cert_mem_len);
  const uint8_t *key_mem = mrb_tls_ivar_buf_get(mrb, cfg_obj, MRB_SYM(key_mem), &key_mem_len);

  /* Trust anchors. */
  if (ca_file != NULL) {
    errno = 0;
    ret = mbedtls_x509_crt_parse_file(&ctx->ca, ca_file);
    if (ret < 0) {
      mrb_tls_fail(mrb, ret, "ca_file");
    }
    have_ca = 1;
  }
  if (ca_path != NULL) {
    int loaded = 0;
    errno = 0;
    if (mrb_tls_load_ca_dir(&ctx->ca, ca_path, &loaded) != 0) {
      mrb_tls_fail(mrb, 0, "ca_path");
    }
    if (loaded == 0) {
      errno = 0;
      mrb_tls_fail(mrb, 0, "ca_path: no usable certificates found");
    }
    have_ca = 1;
  }
#ifdef _WIN32
  if (!have_ca && mrb_bool(mrb_iv_get(mrb, cfg_obj, MRB_SYM(ca_system_store)))) {
    int loaded = 0;
    errno = 0;
    if (mrb_tls_load_ca_system_store_win32(&ctx->ca, &loaded) != 0) {
      mrb_tls_fail(mrb, 0, "ca_system_store: could not open the Windows ROOT certificate store");
    }
    if (loaded == 0) {
      errno = 0;
      mrb_tls_fail(mrb, 0, "ca_system_store: no usable certificates found");
    }
    have_ca = 1;
  }
#endif
  if (have_ca) {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca, NULL);
  }

  /* Our own keypair. */
  if (cert_mem != NULL) {
    errno = 0;
    ret = mbedtls_x509_crt_parse(&ctx->cert, cert_mem, mrb_tls_parse_len(cert_mem, cert_mem_len));
    if (ret < 0) {
      mrb_tls_fail(mrb, ret, "cert_mem");
    }
    have_cert = 1;
  } else if (cert_file != NULL) {
    errno = 0;
    ret = mbedtls_x509_crt_parse_file(&ctx->cert, cert_file);
    if (ret < 0) {
      mrb_tls_fail(mrb, ret, "cert_file");
    }
    have_cert = 1;
  }
  if (key_mem != NULL) {
    errno = 0;
    ret = mbedtls_pk_parse_key(&ctx->pk, key_mem, mrb_tls_parse_len(key_mem, key_mem_len),
                               NULL, 0);
    if (ret != 0) {
      mrb_tls_fail(mrb, ret, "key_mem");
    }
    have_key = 1;
  } else if (key_file != NULL) {
    errno = 0;
    ret = mbedtls_pk_parse_keyfile(&ctx->pk, key_file, NULL);
    if (ret != 0) {
      mrb_tls_fail(mrb, ret, "key_file");
    }
    have_key = 1;
  }
  if (have_cert != have_key) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "both a certificate and a key are required");
  }
  if (ctx->endpoint == MBEDTLS_SSL_IS_SERVER && !have_cert) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "no certificate or key provided");
  }
  if (have_cert) {
    errno = 0;
    ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->pk);
    if (ret != 0) {
      mrb_tls_fail(mrb, ret, "mbedtls_ssl_conf_own_cert");
    }
  }

  /*
   * Cipher suites and ECDHE groups. mbedtls_ssl_conf_ciphersuites()/
   * _conf_groups() just remember the pointer they are given -- it has to
   * stay valid for as long as ctx->conf does, i.e. at least until the next
   * #reset/re-#connect. Stashing the packed array as an ivar on `self`
   * (rather than the old mrb_malloc'd ctx->ciphersuites/ctx->groups) makes
   * that automatic: it lives exactly as long as this Context does.
   */
  mrb_value ciphersuites = mrb_iv_get(mrb, cfg_obj, MRB_SYM(ciphersuites));
  mrb_iv_set(mrb, self, MRB_SYM(ciphersuites), ciphersuites);
  if (mrb_string_p(ciphersuites)) {
    mbedtls_ssl_conf_ciphersuites(&ctx->conf, (const int *)RSTRING_PTR(ciphersuites));
  }

  mrb_value groups = mrb_iv_get(mrb, cfg_obj, MRB_SYM(groups));
  mrb_iv_set(mrb, self, MRB_SYM(groups), groups);
  if (mrb_string_p(groups)) {
    mbedtls_ssl_conf_groups(&ctx->conf, (const uint16_t *)RSTRING_PTR(groups));
  }

  /* Verification policy -- snapshot it so the callback cannot race with a
   * later mutation of the Tls::Config object. */
  ctx->verify_cert = cfg->verify_cert;
  ctx->verify_name = cfg->verify_name;
  ctx->verify_time = cfg->verify_time;
  ctx->verify_depth = cfg->verify_depth;
  ctx->authmode = mrb_tls_authmode_for(ctx);
  mbedtls_ssl_conf_authmode(&ctx->conf, ctx->authmode);
  if (ctx->authmode != MBEDTLS_SSL_VERIFY_NONE) {
    mbedtls_ssl_conf_verify(&ctx->conf, mrb_tls_verify_cb, ctx);
  }

  /* SNI: only ever meaningful for a server, and only when this connection
   * actually has an @sni block (copied from the accepting Tls::Server onto
   * the accepted Tls::Client in mrb_tls_accept_socket() -- a plain
   * #accept_socket call with no SNI configured never sets it, so this stays
   * a no-op for every server that hasn't opted in). Registering the
   * callback here, rather than checking @sni again inside it, keeps
   * mrb_tls_sni_cb() itself simple: by the time it can possibly run,
   * @sni is already known to be present. ctx->mrb/ctx->self, which the
   * callback reads, are set a few lines below -- safe regardless, since
   * mbedtls_ssl_conf_sni() only stores the callback for a *later* handshake
   * call, it does not invoke it immediately. */
  if (ctx->endpoint == MBEDTLS_SSL_IS_SERVER && !mrb_nil_p(mrb_iv_get(mrb, self, MRB_SYM(sni)))) {
    mbedtls_ssl_conf_sni(&ctx->conf, mrb_tls_sni_cb, ctx);
  }

  errno = 0;
  ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
  if (ret != 0) {
    mrb_tls_fail(mrb, ret, "mbedtls_ssl_setup");
  }
  ctx->setup = 1;

  ctx->mrb = mrb;
  ctx->self = self;
  /* Stale from a previous connection on this same Context (#reset then
   * re-#connect) -- must not leak into the new one. */
  mrb_iv_remove(mrb, self, MRB_SYM(pending_recv));
  mrb_iv_remove(mrb, self, MRB_SYM(pending_send));
  mrb_iv_remove(mrb, self, MRB_SYM(pending_exception));
  mrb_tls_bio_install_resume_blocks(mrb, self);
  mbedtls_ssl_set_bio(&ctx->ssl, ctx, mrb_tls_bio_send, mrb_tls_bio_recv, NULL);

  const char *hostname = mrb_tls_ivar_cstr(mrb, self, MRB_SYM(hostname));
  if (hostname != NULL) {
    errno = 0;
    ret = mbedtls_ssl_set_hostname(&ctx->ssl, hostname);
    if (ret != 0) {
      mrb_tls_fail(mrb, ret, "mbedtls_ssl_set_hostname");
    }
  }
}

/* Runs once, right after the handshake completes. */
static void
mrb_tls_ctx_after_handshake(mrb_state *mrb, mrb_tls_ctx_t *ctx)
{
  if (ctx->handshaked) {
    return;
  }

  if (ctx->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&ctx->ssl);

    if (flags != 0) {
      char info[384], msg[448];
      size_t i;

      if (mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags) < 0) {
        snprintf(info, sizeof(info), "flags 0x%08lx", (unsigned long)flags);
      }
      for (i = 0; info[i] != '\0'; i++) {
        if (info[i] == '\n') {
          info[i] = ' ';
        }
      }
      snprintf(msg, sizeof(msg), "certificate verification failed: %s", info);
      errno = 0;
      mrb_raise(mrb, E_TLS_ERROR, msg);
    }
  }

  ctx->handshaked = 1;
}

static int
mrb_tls_want(int ret)
{
  return ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
         ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
         ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
}

static mrb_value
mrb_tls_want_symbol(int ret)
{
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return mrb_symbol_value(MRB_SYM(tls_want_pollout));
  }
  return mrb_symbol_value(MRB_SYM(tls_want_pollin));
}

/* mrb_tls_bio_send()/_recv() never let a Ruby exception raised by the
 * underlying socket's #send/#recv/#write/#read unwind straight through
 * mbedTLS's C call frames -- it's caught at that boundary (mrb_protect_error)
 * and stashed as @pending_exception instead, with a plain mbedTLS I/O error
 * code returned in its place so mbedTLS's own state machine stays consistent.
 * Call this right after every mbedtls_ssl_handshake()/read()/write() call
 * that could have gone through the BIO layer, before interpreting its return
 * code -- once back at a clean Ruby boundary, the real exception can be
 * re-raised safely. */
static void
mrb_tls_check_pending_exception(mrb_state *mrb, mrb_value self)
{
  mrb_value exc = mrb_iv_get(mrb, self, MRB_SYM(pending_exception));
  if (!mrb_nil_p(exc)) {
    mrb_iv_remove(mrb, self, MRB_SYM(pending_exception));
    mrb_exc_raise(mrb, exc);
  }
}

/*
 * Drive the handshake one step.  Returns 0 when it is done, a WANT_* code when
 * it needs more I/O, or a negative mbedTLS error.  mbedtls_ssl_read()/write()
 * would drive the handshake implicitly, but going through here explicitly
 * gives a single choke point where the post-handshake verification check in
 * mrb_tls_ctx_after_handshake() is guaranteed to run.
 */
static int
mrb_tls_handshake_step(mrb_state *mrb, mrb_tls_ctx_t *ctx)
{
  int ret;

  if (!ctx->setup) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "invalid operation for context");
  }
  if (ctx->handshaked) {
    return 0;
  }

  errno = 0;
  ret = mbedtls_ssl_handshake(&ctx->ssl);
  mrb_tls_check_pending_exception(mrb, ctx->self);
  if (ret != 0) {
    return ret;
  }
  mrb_tls_ctx_after_handshake(mrb, ctx);

  return 0;
}

/* ------------------------------------------------------------------------ */
/* Tls::Context, Tls::Client, Tls::Server                                    */
/* ------------------------------------------------------------------------ */

static mrb_value
mrb_tls_client(mrb_state *mrb, mrb_value self)
{
  mrb_value config_obj = mrb_nil_value();
  mrb_tls_ctx_t *ctx;
  mrb_int argc;

  argc = mrb_get_args(mrb, "|o", &config_obj);

  ctx = mrb_tls_ctx_new(mrb, self);
  ctx->endpoint = MBEDTLS_SSL_IS_CLIENT;

  if (argc == 0) {
    /*
     * tls_configure(ctx, NULL) let libtls build a default config
     * internally; do the same -- a real Tls::Config instance, so it gets
     * the same default-CA seeding and mrb_tls_ctx_setup() can read it
     * exactly like an explicit one -- but keep it out of @config (read by
     * the public Context#config) so that reader stays nil here, same as
     * with the libtls backend. The hidden `cfg` ivar mrb_tls_ctx_setup()
     * actually reads is set either way, just below.
     */
    struct RClass *config_cls = mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Tls)), MRB_SYM(Config));
    mrb_value own_cfg = mrb_obj_new(mrb, config_cls, 0, NULL);
    /*
     * Tls::Config#initialize is ordinary Ruby (mrblib/config.rb) and can be
     * redefined, so what comes back here is not automatically a Tls::Config.
     * Taking DATA_PTR() of, say, a String would read past the end of that
     * object and leave ctx->cfg pointing at whatever happened to be there --
     * check the type before trusting it.
     */
    mrb_data_check_type(mrb, own_cfg, &tls_config_type);
    mrb_iv_set(mrb, self, MRB_SYM(cfg), own_cfg);
    ctx->cfg = (mrb_tls_config_t *)DATA_PTR(own_cfg);
  } else {
    mrb_data_check_type(mrb, config_obj, &tls_config_type);
    ctx->cfg = (mrb_tls_config_t *)DATA_PTR(config_obj);
    mrb_iv_set(mrb, self, MRB_IVSYM(config), config_obj);
    mrb_iv_set(mrb, self, MRB_SYM(cfg), config_obj);
  }

  return self;
}

static mrb_value
mrb_tls_server(mrb_state *mrb, mrb_value self)
{
  mrb_value config_obj;
  mrb_value sni_block = mrb_nil_value();
  mrb_tls_ctx_t *ctx;

  mrb_get_args(mrb, "o&", &config_obj, &sni_block);

  ctx = mrb_tls_ctx_new(mrb, self);
  ctx->endpoint = MBEDTLS_SSL_IS_SERVER;

  mrb_data_check_type(mrb, config_obj, &tls_config_type);
  ctx->cfg = (mrb_tls_config_t *)DATA_PTR(config_obj);
  mrb_iv_set(mrb, self, MRB_IVSYM(config), config_obj);
  mrb_iv_set(mrb, self, MRB_SYM(cfg), config_obj);
  /* @sni stays nil (never set) when no block is given -- see
   * mrb_tls_ctx_setup()'s own check. */
  if (!mrb_nil_p(sni_block)) {
    mrb_iv_set(mrb, self, MRB_SYM(sni), sni_block);
  }

  return self;
}

static mrb_value
mrb_tls_set_config(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_value config_obj;

  mrb_get_args(mrb, "o", &config_obj);
  mrb_data_check_type(mrb, config_obj, &tls_config_type);

  ctx->cfg = (mrb_tls_config_t *)DATA_PTR(config_obj);
  mrb_iv_set(mrb, self, MRB_IVSYM(config), config_obj);
  mrb_iv_set(mrb, self, MRB_SYM(cfg), config_obj);

  /* Like tls_configure(), this only records the config; it is materialised on
   * the next connect/accept.  An already running connection keeps the settings
   * it was built with. */

  return self;
}

static mrb_value
mrb_tls_reset(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);

  mrb_tls_ctx_teardown_ssl(mrb, ctx);
  mrb_tls_ctx_close_fd(ctx);
  mrb_iv_remove(mrb, self, MRB_SYM(hostname));

  return self;
}

/* Ruby-visible #connect(host, port = nil) splits a combined "host:port"/
 * "[v6::addr]:port" string in mrblib/context.rb before calling this --
 * host/port are always both present here. */
static mrb_value
mrb_tls_connect(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mbedtls_net_context net;
  char *host, *port;
  const char *failmsg = NULL;
  int failret = 0, saved_errno = 0;
  int ret;

  mrb_get_args(mrb, "zz", &host, &port);

  if (ctx->endpoint != MBEDTLS_SSL_IS_CLIENT) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "not a client context");
  }

  mbedtls_net_init(&net);
  errno = 0;
  ret = mbedtls_net_connect(&net, host, port, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    saved_errno = errno;
    failmsg = "connect";
    failret = ret;
  } else {
    /* Release a socket a previous #connect may have left behind before
     * overwriting the descriptors, otherwise reconnecting on the same object
     * would leak it. */
    mrb_tls_ctx_close_fd(ctx);
    /* Take ownership of the socket before anything else can raise, so that
     * the GC finaliser closes it if setup fails. */
    ctx->fd_read = net.fd;
    ctx->fd_write = net.fd;
    ctx->own_fd = 1;
    mrb_tls_ivar_str_set(mrb, self, MRB_SYM(hostname), host);
  }

  if (failmsg != NULL) {
    errno = saved_errno;
    mrb_tls_fail(mrb, failret, failmsg);
  }

  mrb_tls_ctx_setup(mrb, self, ctx);

  return self;
}

static mrb_value
mrb_tls_connect_fds(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_value fd_read, fd_write;
  char *hostname;
  int r, w;

  mrb_get_args(mrb, "ooz", &fd_read, &fd_write, &hostname);

  if (ctx->endpoint != MBEDTLS_SSL_IS_CLIENT) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "not a client context");
  }

  r = (int)mrb_integer(mrb_type_convert(mrb, fd_read, MRB_TT_INTEGER, MRB_SYM(fileno)));
  w = (int)mrb_integer(mrb_type_convert(mrb, fd_write, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (r < 0 || w < 0) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "invalid file descriptors");
  }

  /* The caller owns these descriptors; libtls only ever closed the socket it
   * created itself in tls_connect(). */
  mrb_tls_ctx_close_fd(ctx);
  ctx->fd_read = r;
  ctx->fd_write = w;
  ctx->own_fd = 0;
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(hostname), hostname);

  mrb_tls_ctx_setup(mrb, self, ctx);

  mrb_iv_set(mrb, self, MRB_SYM(fd_read), fd_read);
  mrb_iv_set(mrb, self, MRB_SYM(fd_write), fd_write);

  return self;
}

static mrb_value
mrb_tls_connect_socket(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_value socket;
  char *hostname;
  int fd;

  mrb_get_args(mrb, "oz", &socket, &hostname);

  if (ctx->endpoint != MBEDTLS_SSL_IS_CLIENT) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "not a client context");
  }

  fd = (int)mrb_integer(mrb_type_convert(mrb, socket, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (fd < 0) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "invalid file descriptor");
  }

  mrb_tls_ctx_close_fd(ctx);
  ctx->fd_read = fd;
  ctx->fd_write = fd;
  ctx->own_fd = 0;
  mrb_tls_ivar_str_set(mrb, self, MRB_SYM(hostname), hostname);

  mrb_tls_ctx_setup(mrb, self, ctx);

  mrb_iv_set(mrb, self, MRB_SYM(socket), socket);

  return self;
}

static mrb_value
mrb_tls_accept_socket(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *sctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_tls_ctx_t *cctx;
  struct RData *client_data;
  mrb_value client, socket;
  int fd;

  mrb_get_args(mrb, "o", &socket);

  if (sctx->endpoint != MBEDTLS_SSL_IS_SERVER) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "not a server context");
  }

  fd = (int)mrb_integer(mrb_type_convert(mrb, socket, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (fd < 0) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "invalid file descriptor");
  }

  /* Yes, Tls::Client -- that is what the libtls backend handed back for an
   * accepted server side connection too. */
  client_data = mrb_data_object_alloc(mrb,
      mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Tls)), MRB_SYM(Client)),
      NULL, &tls_type);
  client = mrb_obj_value(client_data);

  cctx = mrb_tls_ctx_new(mrb, client);
  cctx->endpoint = MBEDTLS_SSL_IS_SERVER;
  cctx->cfg = sctx->cfg;
  cctx->fd_read = fd;
  cctx->fd_write = fd;
  cctx->own_fd = 0;

  /*
   * The accepted connection borrows the server's Tls::Config. Copying the
   * server's own hidden `cfg` ivar (whatever it resolved to -- an explicit
   * config, servers always require one, see mrb_tls_server()) directly onto
   * the client keeps that same Tls::Config object reachable for at least as
   * long as the connection, and is what mrb_tls_ctx_setup() reads from
   * regardless of which Context it is called on. @config itself is left
   * unset here so the public Context#config reader keeps returning nil,
   * exactly as with the libtls backend.
   */
  mrb_iv_set(mrb, client, MRB_SYM(cfg), mrb_iv_get(mrb, self, MRB_SYM(cfg)));
  mrb_iv_set(mrb, client, MRB_SYM(socket), socket);
  /* Same borrowing as @cfg just above, for the same reason: mrb_tls_sni_cb()
   * reads @sni off the *connection's* own Context (ctx->self), not the
   * Tls::Server that accepted it -- copy it across, or a server configured
   * with an sni block would silently never dispatch it for any connection
   * it accepts. Stays nil (i.e. genuinely absent, not just falsy) when the
   * server was never given one -- see mrb_tls_server(). */
  mrb_iv_set(mrb, client, MRB_SYM(sni), mrb_iv_get(mrb, self, MRB_SYM(sni)));

  mrb_tls_ctx_setup(mrb, client, cctx);

  return client;
}

static mrb_value
mrb_tls_read(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_int buf_len = 9000;
  mrb_value buf;

  mrb_get_args(mrb, "|i", &buf_len);

  errno = 0;
  buf = mrb_str_buf_new(mrb, buf_len);

  while (TRUE) {
    int rc = mrb_tls_handshake_step(mrb, ctx);

    if (rc != 0) {
      if (mrb_tls_want(rc)) {
        continue;
      }
      return mrb_tls_fail(mrb, rc, "handshake");
    }

    errno = 0;
    rc = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)RSTRING_PTR(buf),
                          (size_t)RSTRING_CAPA(buf));
    mrb_tls_check_pending_exception(mrb, self);
    if (rc >= 0) {
      return mrb_str_resize(mrb, buf, rc);
    }
    if (mrb_tls_want(rc) || rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      continue;
    }
    if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      /* Clean end of stream, like tls_read() returning 0. */
      return mrb_str_resize(mrb, buf, 0);
    }
    return mrb_tls_fail(mrb, rc, "read");
  }
}

static mrb_value
mrb_tls_read_nonblock(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  mrb_int buf_len = 9000;
  mrb_value buf;
  int rc;

  mrb_get_args(mrb, "|i", &buf_len);

  errno = 0;
  buf = mrb_str_buf_new(mrb, buf_len);

  rc = mrb_tls_handshake_step(mrb, ctx);
  if (rc != 0) {
    if (mrb_tls_want(rc)) {
      return mrb_tls_want_symbol(rc);
    }
    return mrb_tls_fail(mrb, rc, "handshake");
  }

  errno = 0;
  rc = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)RSTRING_PTR(buf),
                        (size_t)RSTRING_CAPA(buf));
  mrb_tls_check_pending_exception(mrb, self);
  if (rc >= 0) {
    return mrb_str_resize(mrb, buf, rc);
  }
  if (mrb_tls_want(rc)) {
    return mrb_tls_want_symbol(rc);
  }
  if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
    /* TLS 1.3 post-handshake message; there is no application data yet, so
     * tell the caller to poll for more input rather than reporting an error. */
    return mrb_symbol_value(MRB_SYM(tls_want_pollin));
  }
  if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    return mrb_str_resize(mrb, buf, 0);
  }

  return mrb_tls_fail(mrb, rc, "read");
}

static mrb_value
mrb_tls_write(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  char *buf;
  mrb_int len;
  mrb_int total = 0;

  mrb_get_args(mrb, "s", &buf, &len);

  while (len > 0) {
    int rc = mrb_tls_handshake_step(mrb, ctx);

    if (rc != 0) {
      if (mrb_tls_want(rc)) {
        continue;
      }
      return mrb_tls_fail(mrb, rc, "handshake");
    }

    errno = 0;
    rc = mbedtls_ssl_write(&ctx->ssl, (const unsigned char *)buf, (size_t)len);
    mrb_tls_check_pending_exception(mrb, self);
    if (rc > 0) {
      buf += rc;
      len -= rc;
      total += rc;
      continue;
    }
    if (rc == 0 || mrb_tls_want(rc)) {
      /* mbedTLS wants the very same buffer and length on the next attempt,
       * which is what this loop does. */
      continue;
    }
    return mrb_tls_fail(mrb, rc, "write");
  }

  return mrb_int_value(mrb, total);
}

static mrb_value
mrb_tls_write_nonblock(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  char *buf;
  mrb_int len;
  int rc;

  mrb_get_args(mrb, "s", &buf, &len);

  rc = mrb_tls_handshake_step(mrb, ctx);
  if (rc != 0) {
    if (mrb_tls_want(rc)) {
      return mrb_tls_want_symbol(rc);
    }
    return mrb_tls_fail(mrb, rc, "handshake");
  }

  errno = 0;
  rc = mbedtls_ssl_write(&ctx->ssl, (const unsigned char *)buf, (size_t)len);
  mrb_tls_check_pending_exception(mrb, self);
  if (rc >= 0) {
    return mrb_int_value(mrb, rc);
  }
  if (mrb_tls_want(rc)) {
    return mrb_tls_want_symbol(rc);
  }

  return mrb_tls_fail(mrb, rc, "write");
}

/* One step of the shutdown. Returns 0 when done or a WANT_* code. own_fd
 * tracks whether we own the socket (only true when #connect opened it) --
 * descriptors handed to connect_socket/connect_fds/accept_socket stay the
 * caller's responsibility, matching libtls. */
static int
mrb_tls_close_step(mrb_state *mrb, mrb_tls_ctx_t *ctx)
{
  if (!ctx->setup) {
    errno = 0;
    mrb_tls_fail(mrb, 0, "invalid operation for context");
  }

  if (!ctx->close_sent) {
    if (mbedtls_ssl_is_handshake_over(&ctx->ssl)) {
      int ret;
      errno = 0;
      ret = mbedtls_ssl_close_notify(&ctx->ssl);
      if (mrb_tls_want(ret)) {
        return ret;
      }
      /* Any other failure means the peer is already gone; there is nothing
       * useful left to report and the descriptor still has to be released.
       * Discard rather than re-raise any exception the BIO layer captured,
       * consistent with that -- but still clear the stash so it can't leak
       * into some later, unrelated check. */
      mrb_iv_remove(mrb, ctx->self, MRB_SYM(pending_exception));
    }
    ctx->close_sent = 1;
  }

  if (ctx->own_fd && ctx->fd_read >= 0) {
    int fd = ctx->fd_read;
    ctx->own_fd = 0;
    ctx->fd_read = -1;
    ctx->fd_write = -1;
#ifdef _WIN32
    errno = 0;
    if (closesocket((SOCKET)fd) != 0) {
      mrb_tls_fail(mrb, 0, "close");
    }
#else
    shutdown(fd, SHUT_RDWR);
    errno = 0;
    if (close(fd) != 0) {
      mrb_tls_fail(mrb, 0, "close");
    }
#endif
  } else {
    ctx->fd_read = -1;
    ctx->fd_write = -1;
  }

  return 0;
}

static mrb_value
mrb_tls_close(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);

  errno = 0;

  mrb_iv_remove(mrb, self, MRB_SYM(socket));
  mrb_iv_remove(mrb, self, MRB_SYM(fd_read));
  mrb_iv_remove(mrb, self, MRB_SYM(fd_write));

  while (TRUE) {
    int rc = mrb_tls_close_step(mrb, ctx);

    if (rc == 0) {
      return self;
    }
    if (mrb_tls_want(rc)) {
      continue;
    }
    return mrb_tls_fail(mrb, rc, "close");
  }
}

static mrb_value
mrb_tls_close_nonblock(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  int rc;

  errno = 0;
  rc = mrb_tls_close_step(mrb, ctx);
  if (rc == 0) {
    mrb_iv_remove(mrb, self, MRB_SYM(socket));
    mrb_iv_remove(mrb, self, MRB_SYM(fd_read));
    mrb_iv_remove(mrb, self, MRB_SYM(fd_write));
    return self;
  }
  if (mrb_tls_want(rc)) {
    return mrb_tls_want_symbol(rc);
  }

  return mrb_tls_fail(mrb, rc, "close");
}

static mrb_value
mrb_tls_handshake(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);

  errno = 0;

  while (TRUE) {
    int rc = mrb_tls_handshake_step(mrb, ctx);

    if (rc == 0) {
      return self;
    }
    if (mrb_tls_want(rc)) {
      continue;
    }
    return mrb_tls_fail(mrb, rc, "handshake");
  }
}

static mrb_value
mrb_tls_handshake_nonblock(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  int rc;

  errno = 0;
  rc = mrb_tls_handshake_step(mrb, ctx);
  if (rc == 0) {
    return self;
  }
  if (mrb_tls_want(rc)) {
    return mrb_tls_want_symbol(rc);
  }

  return mrb_tls_fail(mrb, rc, "handshake");
}

static mrb_value
mrb_tls_conn_version(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  const char *version;

  errno = 0;
  if (!ctx->setup || !mbedtls_ssl_is_handshake_over(&ctx->ssl)) {
    return mrb_tls_fail(mrb, 0, "handshake has not completed");
  }
  version = mbedtls_ssl_get_version(&ctx->ssl);
  if (version == NULL) {
    return mrb_tls_fail(mrb, 0, "no protocol version negotiated");
  }

  return mrb_str_new_cstr(mrb, version);
}

static mrb_value
mrb_tls_conn_cipher(mrb_state *mrb, mrb_value self)
{
  mrb_tls_ctx_t *ctx = mrb_tls_ctx_ptr(mrb, self);
  const char *cipher;

  errno = 0;
  if (!ctx->setup || !mbedtls_ssl_is_handshake_over(&ctx->ssl)) {
    return mrb_tls_fail(mrb, 0, "handshake has not completed");
  }
  /*
   * DIVERGENCE: mbedTLS names cipher suites the way the RFCs do
   * ("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"), OpenSSL/LibreSSL used its own
   * shorthand ("ECDHE-RSA-AES128-GCM-SHA256").  The string handed back by
   * Tls::Context#cipher therefore looks different than it did with the libtls
   * backend.  It is not faked up into OpenSSL spelling: that would be
   * inventing a name the library never negotiated under.
   */
  cipher = mbedtls_ssl_get_ciphersuite(&ctx->ssl);
  if (cipher == NULL || *cipher == '\0') {
    return mrb_tls_fail(mrb, 0, "no cipher suite negotiated");
  }

  return mrb_str_new_cstr(mrb, cipher);
}

/* ------------------------------------------------------------------------ */
/* Gem init / final                                                          */
/* ------------------------------------------------------------------------ */

MRB_BEGIN_DECL
void
mrb_mruby_tls_gem_init(mrb_state* mrb)
{
    struct RClass *tls_mod, *tls_proto_mod, *tls_conf_c, *tls_ctx_c, *tls_cli_c, *tls_server_c;

    /* psa_crypto_init() must run before any crypto/cert/key/handshake use;
     * once per process is enough, it's idempotent-safe.
     *
     * mrb_sys_fail(), not mrb_tls_fail(): Tls::Error isn't defined yet at
     * this point in gem_init() (mrblib/error.rb runs after every gem's C
     * init returns), and it's the semantically right call anyway --
     * psa_crypto_init() only really fails on the OS entropy source or an
     * allocation, so a real errno is expected to be set. Left alone (not
     * zeroed) so mrb_sys_fail() can read it. */
    {
      psa_status_t psa_ret = psa_crypto_init();
      if (psa_ret != PSA_SUCCESS) {
        char msg[MRB_TLS_FAIL_MSG_BUFLEN];
        mrb_tls_errmsg(msg, sizeof(msg), (int)psa_ret, "psa_crypto_init");
        mrb_sys_fail(mrb, msg);
      }
    }
#ifndef _WIN32
    /* See mrb_tls_atfork_register()'s own comment. */
    pthread_once(&mrb_tls_atfork_once, mrb_tls_atfork_register);
    if (mrb_tls_atfork_register_ret != 0) {
      errno = mrb_tls_atfork_register_ret;
      mrb_sys_fail(mrb, "pthread_atfork");
    }
#endif

    tls_mod = mrb_define_module_id(mrb, MRB_SYM(Tls));
    mrb_define_module_function_id(mrb, tls_mod, MRB_SYM(load_file), mrb_tls_load_file, MRB_ARGS_ARG(1, 1));

    tls_proto_mod = mrb_define_module_under_id(mrb, tls_mod, MRB_SYM(Protocol));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(TLSv1_0), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_0));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(TLSv1_1), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_1));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(TLSv1_2), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_2));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(TLSv1_3), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_3));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(TLSv1), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(All), mrb_int_value(mrb, MRB_TLS_PROTOCOLS_ALL));
    mrb_define_const_id(mrb, tls_proto_mod, MRB_SYM(Default), mrb_int_value(mrb, MRB_TLS_PROTOCOLS_DEFAULT));

    tls_conf_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Config), mrb->object_class);
    MRB_SET_INSTANCE_TT(tls_conf_c, MRB_TT_DATA);
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(initialize), mrb_tls_config_new, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(ca_file), mrb_tls_config_set_ca_file, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(ca_path), mrb_tls_config_set_ca_path, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(cert_file), mrb_tls_config_set_cert_file, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(cert_mem), mrb_tls_config_set_cert_mem, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(_pack_ciphersuites), mrb_tls_pack_ciphersuites, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(_pack_groups), mrb_tls_pack_groups, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(key_file), mrb_tls_config_set_key_file, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(key_mem), mrb_tls_config_set_key_mem, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(protocols), mrb_tls_config_set_protocols, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM_E(verify_depth), mrb_tls_config_set_verify_depth, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(clear_keys), mrb_tls_config_clear_keys, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(verify), mrb_tls_config_verify, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_conf_c, MRB_SYM(noverify), mrb_tls_config_noverify, MRB_ARGS_REQ(1));

    tls_ctx_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Context), mrb->object_class);
    MRB_SET_INSTANCE_TT(tls_ctx_c, MRB_TT_DATA);
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(configure), mrb_tls_set_config, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(reset), mrb_tls_reset, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(read), mrb_tls_read, MRB_ARGS_OPT(1));
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(read_nonblock), mrb_tls_read_nonblock, MRB_ARGS_OPT(1));
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(write), mrb_tls_write, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(write_nonblock), mrb_tls_write_nonblock, MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(close), mrb_tls_close, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(close_nonblock), mrb_tls_close_nonblock, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(handshake), mrb_tls_handshake, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(handshake_nonblock), mrb_tls_handshake_nonblock, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(version), mrb_tls_conn_version, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, tls_ctx_c, MRB_SYM(cipher), mrb_tls_conn_cipher, MRB_ARGS_NONE());

    tls_cli_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Client), tls_ctx_c);
    mrb_define_method_id(mrb, tls_cli_c, MRB_SYM(initialize), mrb_tls_client, MRB_ARGS_OPT(1));
    mrb_define_method_id(mrb, tls_cli_c, MRB_SYM(_connect), mrb_tls_connect, MRB_ARGS_REQ(2));
    mrb_define_method_id(mrb, tls_cli_c, MRB_SYM(connect_fds), mrb_tls_connect_fds, MRB_ARGS_REQ(3));
    mrb_define_method_id(mrb, tls_cli_c, MRB_SYM(connect_socket), mrb_tls_connect_socket, MRB_ARGS_REQ(2));

    tls_server_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Server), tls_ctx_c);
    mrb_define_method_id(mrb, tls_server_c, MRB_SYM(initialize), mrb_tls_server, MRB_ARGS_REQ(1)|MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, tls_server_c, MRB_SYM(accept_socket), mrb_tls_accept_socket, MRB_ARGS_REQ(1));
}

void
mrb_mruby_tls_gem_final(mrb_state* mrb)
{
    (void)mrb;
}
MRB_END_DECL
