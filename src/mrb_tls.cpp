/*
 * mruby-tls -- OpenSSL.
 *
 * The Ruby API here (Tls::Config, Tls::Context, Tls::Client, Tls::Server)
 * is libtls-shaped, inherited from this gem's LibreSSL origins and kept
 * unchanged across two backend rewrites since. The C API in
 * include/mruby/tls.h is deliberately free of OpenSSL types so a port to
 * another provider - Schannel on Windows - has a contract to implement
 * rather than a header to reproduce.
 *
 * Why OpenSSL: its AES-GCM runs about ten times faster than the mbedTLS
 * implementation this replaced (5.49 vs 0.52 GB/s measured on the same
 * cpu - mbedTLS encrypts one 16-byte block at a time where OpenSSL
 * pipelines eight), and it can hand the record layer to the kernel
 * outright with SSL_OP_ENABLE_KTLS, which measured ~4.3x on bulk file
 * transfer.
 *
 * ## Verification
 *
 * libtls exposes three independent verification axes and this gem
 * inherited them: certificate chain, hostname, validity period, each
 * separately waivable with Config#noverify. OpenSSL does not have three
 * switches, so rather than approximate them with SSL_VERIFY_* modes this
 * sets SSL_VERIFY_NONE and enforces all three by hand after the
 * handshake.
 *
 * That is deliberate and worth being explicit about, because
 * SSL_VERIFY_NONE reads like "no verification". It is not what it means
 * here: OpenSSL still builds and verifies the chain, it merely does not
 * abort the handshake on failure, and the outcome is available from
 * SSL_get_verify_result(). Doing the check ourselves is what makes
 * noverify('cert') able to waive the chain while still enforcing the
 * hostname - a combination that has no SSL_VERIFY_* spelling, and which
 * test/tls.rb pins precisely because getting it wrong silently accepts
 * a MITM.
 *
 * conn_verify_peer() is therefore security-critical, is called on every
 * completed client handshake, and no path may reach "handshake done"
 * without it.
 */

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/tls.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/* Ruby-visible (Tls::Protocol::*). Same bit values as the mbedTLS
 * backend and as LibreSSL's <tls.h> before it - they are part of the
 * user-facing API, not an implementation detail. */
#define MRB_TLS_PROTOCOL_TLSv1_0 (1 << 1)
#define MRB_TLS_PROTOCOL_TLSv1_1 (1 << 2)
#define MRB_TLS_PROTOCOL_TLSv1_2 (1 << 3)
#define MRB_TLS_PROTOCOL_TLSv1_3 (1 << 4)
#define MRB_TLS_PROTOCOL_TLSv1 \
  (MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3)
#define MRB_TLS_PROTOCOLS_ALL MRB_TLS_PROTOCOL_TLSv1
#define MRB_TLS_PROTOCOLS_DEFAULT \
  (MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3)

#define MRB_TLS_DEFAULT_VERIFY_DEPTH 6

/* ------------------------------------------------------------------ */
/* Data types                                                          */
/* ------------------------------------------------------------------ */

typedef struct mrb_tls_config {
  SSL_CTX *ctx;
  uint32_t protocols;
  int verify_depth;
  /* 1 = enforced. Config#verify turns all three on, Config#noverify
   * turns exactly one off. */
  int verify_cert;
  int verify_name;
  int verify_time;
} mrb_tls_config_t;

typedef struct mrb_tls_conn {
  SSL *ssl;
  /* Memory mode only (mrb_tls_accept_memory): OpenSSL reads ciphertext
   * from rbio and writes it to wbio, and the caller owns the transport.
   * NULL for a socket-backed connection, which uses SSL_set_fd. */
  BIO *rbio;
  BIO *wbio;
  int is_mem;
  int is_server;
  int handshaked;
  int close_sent;
  int own_fd; /* we created the socket in #connect and must close it */
  int fd;

  mrb_state *mrb;
  mrb_value self;
} mrb_tls_conn_t;

static void
config_free(mrb_state *mrb, void *p)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)p;
  if (!cfg) return;
  if (cfg->ctx) SSL_CTX_free(cfg->ctx);
  mrb_free(mrb, cfg);
}

static const struct mrb_data_type tls_config_type = {
  "$i_tls_config", config_free
};

static void
conn_free(mrb_state *mrb, void *p)
{
  mrb_tls_conn_t *c = (mrb_tls_conn_t *)p;
  if (!c) return;
  /* SSL_free drops the rbio/wbio references SSL_set_bio took, so the
   * BIOs must not be freed again here. */
  if (c->ssl) SSL_free(c->ssl);
  if (c->own_fd && c->fd >= 0) {
#ifdef _WIN32
    closesocket(c->fd);
#else
    close(c->fd);
#endif
  }
  mrb_free(mrb, c);
}

static const struct mrb_data_type tls_conn_type = {
  "$i_tls", conn_free
};

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

static struct RClass *
tls_module(mrb_state *mrb)
{
  return mrb_module_get_id(mrb, MRB_SYM(Tls));
}

static struct RClass *
tls_error_class(mrb_state *mrb)
{
  return mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Error));
}

static struct RClass *
tls_config_class(mrb_state *mrb)
{
  return mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Config));
}

static struct RClass *
tls_config_error_class(mrb_state *mrb)
{
  return mrb_class_get_under_id(mrb, tls_config_class(mrb), MRB_SYM(Error));
}

/* Drains OpenSSL's error queue into one message. The queue must be
 * emptied whatever we do with it: a stale entry left behind attaches
 * itself to the next unrelated failure and sends you chasing a bug in
 * the wrong place. */
static mrb_value
ossl_err_str(mrb_state *mrb, const char *prefix)
{
  mrb_value msg = mrb_str_new_cstr(mrb, prefix);
  unsigned long e;
  int first = 1;
  char buf[256];

  while ((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, buf, sizeof buf);
    mrb_str_cat_lit(mrb, msg, first ? ": " : "; ");
    mrb_str_cat_cstr(mrb, msg, buf);
    first = 0;
  }
  if (first) mrb_str_cat_lit(mrb, msg, ": unknown error");
  return msg;
}

static void
raise_ossl(mrb_state *mrb, struct RClass *cls, const char *prefix)
{
  mrb_value msg = ossl_err_str(mrb, prefix);
  mrb_exc_raise(mrb, mrb_exc_new_str(mrb, cls, msg));
}

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

static mrb_tls_config_t *
config_ptr(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)DATA_PTR(self);
  if (!cfg) mrb_raise(mrb, E_RUNTIME_ERROR, "uninitialized Tls::Config");
  return cfg;
}

/* protocols= is a bitmask of the four TLS versions. OpenSSL takes a
 * min/max range instead, so a non-contiguous request (1.0 and 1.2 but
 * not 1.1) cannot be expressed. Clamp to the span: refusing would break
 * callers passing Protocol::All, and silently widening is what libtls
 * did too. 1.0/1.1 are mapped up to 1.2 because this gem has never
 * offered them - MRB_TLS_PROTOCOL_TLSv1 is 1.2|1.3. */
static void
config_apply_protocols(mrb_state *mrb, mrb_tls_config_t *cfg)
{
  int min = TLS1_2_VERSION, max = TLS1_3_VERSION;
  uint32_t p = cfg->protocols;

  if (p == 0) p = MRB_TLS_PROTOCOLS_DEFAULT;

  if (p & (MRB_TLS_PROTOCOL_TLSv1_0 | MRB_TLS_PROTOCOL_TLSv1_1 |
           MRB_TLS_PROTOCOL_TLSv1_2)) {
    min = TLS1_2_VERSION;
  } else if (p & MRB_TLS_PROTOCOL_TLSv1_3) {
    min = TLS1_3_VERSION;
  }
  if (p & MRB_TLS_PROTOCOL_TLSv1_3) {
    max = TLS1_3_VERSION;
  } else {
    max = TLS1_2_VERSION;
  }

  if (!SSL_CTX_set_min_proto_version(cfg->ctx, min) ||
      !SSL_CTX_set_max_proto_version(cfg->ctx, max)) {
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot set protocol range");
  }
}

static mrb_value
config_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg;

  cfg = (mrb_tls_config_t *)mrb_malloc(mrb, sizeof *cfg);
  memset(cfg, 0, sizeof *cfg);
  cfg->protocols = MRB_TLS_PROTOCOLS_DEFAULT;
  cfg->verify_depth = MRB_TLS_DEFAULT_VERIFY_DEPTH;
  cfg->verify_cert = 1;
  cfg->verify_name = 1;
  cfg->verify_time = 1;

  /* Attach before anything can raise: if SSL_CTX_new fails below, the
   * struct is already owned by the GC and will not leak. */
  mrb_data_init(self, cfg, &tls_config_type);

  cfg->ctx = SSL_CTX_new(TLS_method());
  if (!cfg->ctx) raise_ossl(mrb, tls_config_error_class(mrb), "SSL_CTX_new failed");

  /* Policy is enforced by conn_verify_peer() after the handshake, not by
   * OpenSSL aborting it - see the file header. OpenSSL still verifies
   * and records the result for us to read. */
  SSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_verify_depth(cfg->ctx, cfg->verify_depth);

  /* Partial writes and moving buffers: without these SSL_write can
   * return "retry" and then insist on being handed the identical
   * pointer, which no caller of a Ruby String API can promise. */
  SSL_CTX_set_mode(cfg->ctx,
                   SSL_MODE_ENABLE_PARTIAL_WRITE |
                   SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

#ifdef SSL_OP_ENABLE_KTLS
  /* Kernel TLS where the platform has it. OpenSSL falls back silently
   * when the kernel, the ciphersuite or the build does not support it,
   * so this is safe unconditionally - and it is the whole reason the
   * Linux builds use this backend. */
  SSL_CTX_set_options(cfg->ctx, SSL_OP_ENABLE_KTLS);
#endif

  config_apply_protocols(mrb, cfg);
  return self;
}

static mrb_value
config_set_ca_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  const char *path;

  mrb_get_args(mrb, "z", &path);
  if (!SSL_CTX_load_verify_locations(cfg->ctx, path, NULL)) {
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot load CA file");
  }
  mrb_iv_set(mrb, self, MRB_IVSYM(ca_file), mrb_str_new_cstr(mrb, path));
  return self;
}

static mrb_value
config_set_ca_path(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  const char *path;

  mrb_get_args(mrb, "z", &path);
  if (!SSL_CTX_load_verify_locations(cfg->ctx, NULL, path)) {
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot load CA path");
  }
  mrb_iv_set(mrb, self, MRB_IVSYM(ca_path), mrb_str_new_cstr(mrb, path));
  return self;
}

static mrb_value
config_set_cert_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  const char *path;

  mrb_get_args(mrb, "z", &path);
  /* _chain_file, not _certificate_file: a server almost always has
   * intermediates to send, and the single-cert call silently drops
   * them, producing a chain the peer cannot build. */
  if (SSL_CTX_use_certificate_chain_file(cfg->ctx, path) != 1) {
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot load certificate file");
  }
  mrb_iv_set(mrb, self, MRB_IVSYM(cert_file), mrb_str_new_cstr(mrb, path));
  return self;
}

/* Reads a PEM chain out of memory and installs leaf + intermediates.
 * There is no SSL_CTX_use_certificate_chain_mem in OpenSSL, so this
 * walks the BIO the way the file version does internally. */
static void
config_use_cert_mem(mrb_state *mrb, mrb_tls_config_t *cfg,
                    const char *pem, size_t len)
{
  BIO *bio = BIO_new_mem_buf(pem, (int)len);
  X509 *leaf = NULL;
  int rc;

  if (!bio) raise_ossl(mrb, tls_config_error_class(mrb), "out of memory");

  leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (!leaf) {
    BIO_free(bio);
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot parse certificate");
  }
  rc = SSL_CTX_use_certificate(cfg->ctx, leaf);
  X509_free(leaf);
  if (rc != 1) {
    BIO_free(bio);
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot use certificate");
  }

  /* Everything after the leaf is a chain certificate. Clear first so a
   * second cert_mem= replaces rather than appends. */
  SSL_CTX_clear_chain_certs(cfg->ctx);
  for (;;) {
    X509 *ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!ca) break;
    if (SSL_CTX_add0_chain_cert(cfg->ctx, ca) != 1) {
      X509_free(ca);
      BIO_free(bio);
      raise_ossl(mrb, tls_config_error_class(mrb), "cannot add chain certificate");
    }
    /* add0 took ownership - no X509_free here. */
  }
  /* PEM_read_bio_X509 leaves a "no start line" error behind when it hits
   * the end of the chain; that is the loop's normal exit, not a fault. */
  ERR_clear_error();
  BIO_free(bio);
}

static mrb_value
config_set_cert_mem(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  char *pem;
  mrb_int len;

  mrb_get_args(mrb, "s", &pem, &len);
  config_use_cert_mem(mrb, cfg, pem, (size_t)len);
  return self;
}

static mrb_value
config_set_key_file(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  const char *path;

  mrb_get_args(mrb, "z", &path);
  if (SSL_CTX_use_PrivateKey_file(cfg->ctx, path, SSL_FILETYPE_PEM) != 1) {
    raise_ossl(mrb, tls_config_error_class(mrb), "cannot load private key file");
  }
  if (SSL_CTX_check_private_key(cfg->ctx) != 1) {
    raise_ossl(mrb, tls_config_error_class(mrb),
               "private key does not match certificate");
  }
  return self;
}

static mrb_value
config_set_key_mem(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  char *pem;
  mrb_int len;
  BIO *bio;
  EVP_PKEY *pkey;
  int rc;

  mrb_get_args(mrb, "s", &pem, &len);
  bio = BIO_new_mem_buf(pem, (int)len);
  if (!bio) raise_ossl(mrb, tls_config_error_class(mrb), "out of memory");

  pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) raise_ossl(mrb, tls_config_error_class(mrb), "cannot parse private key");

  rc = SSL_CTX_use_PrivateKey(cfg->ctx, pkey);
  EVP_PKEY_free(pkey);
  if (rc != 1) raise_ossl(mrb, tls_config_error_class(mrb), "cannot use private key");

  if (SSL_CTX_check_private_key(cfg->ctx) != 1) {
    raise_ossl(mrb, tls_config_error_class(mrb),
               "private key does not match certificate");
  }
  return self;
}

static mrb_value
config_set_protocols(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  mrb_int protocols;

  mrb_get_args(mrb, "i", &protocols);
  cfg->protocols = (uint32_t)protocols;
  config_apply_protocols(mrb, cfg);
  return self;
}

static mrb_value
config_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  mrb_int depth;

  mrb_get_args(mrb, "i", &depth);
  if (depth < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "verify_depth must not be negative");
  cfg->verify_depth = (int)depth;
  SSL_CTX_set_verify_depth(cfg->ctx, cfg->verify_depth);
  return self;
}

static mrb_value
config_verify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  cfg->verify_cert = 1;
  cfg->verify_name = 1;
  cfg->verify_time = 1;
  return self;
}

static mrb_value
config_noverify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  const char *mode;

  mrb_get_args(mrb, "z", &mode);
  if (strcmp(mode, "cert") == 0)      cfg->verify_cert = 0;
  else if (strcmp(mode, "name") == 0) cfg->verify_name = 0;
  else if (strcmp(mode, "time") == 0) cfg->verify_time = 0;
  else {
    mrb_raisef(mrb, E_ARGUMENT_ERROR,
               "unknown noverify mode %s (expected 'cert', 'name' or 'time')",
               mrb_str_new_cstr(mrb, mode));
  }
  return self;
}

static mrb_value
config_clear_keys(mrb_state *mrb, mrb_value self)
{
  /* OpenSSL owns the key material inside SSL_CTX and offers no "forget
   * the private key but keep everything else" call. Dropping the whole
   * SSL_CTX would invalidate every connection already made from it, so
   * this is a no-op that reports honestly rather than a security
   * guarantee it cannot keep. */
  (void)mrb;
  return self;
}

/* Ruby's Config#ciphers= hands this the split-out names and stores what
 * comes back in @ciphersuites; conn_apply_config() feeds it to OpenSSL.
 * OpenSSL takes a list as a string, so validation is the only real work,
 * and it is done here rather than at handshake time so a typo raises
 * where the user wrote it. */
static mrb_value
config_pack_ciphersuites(mrb_state *mrb, mrb_value self)
{
  mrb_value names, joined;
  SSL_CTX *probe;
  mrb_int i;

  mrb_get_args(mrb, "A", &names);
  joined = mrb_str_new_capa(mrb, 64);
  for (i = 0; i < RARRAY_LEN(names); i++) {
    mrb_value n = mrb_ary_ref(mrb, names, i);
    if (i) mrb_str_cat_lit(mrb, joined, ":");
    mrb_str_cat_str(mrb, joined, mrb_obj_as_string(mrb, n));
  }

  /* Validate against a throwaway context so a bad name cannot leave the
   * real one half-configured. TLS 1.3 suites and pre-1.3 ciphers are set
   * through different calls and either spelling should be accepted, so
   * this asks both and only complains when neither recognises it. */
  probe = SSL_CTX_new(TLS_method());
  if (probe) {
    int ok13 = SSL_CTX_set_ciphersuites(probe, RSTRING_CSTR(mrb, joined));
    int ok12 = SSL_CTX_set_cipher_list(probe, RSTRING_CSTR(mrb, joined));
    SSL_CTX_free(probe);
    ERR_clear_error();
    if (!ok13 && !ok12) {
      mrb_raisef(mrb, tls_config_error_class(mrb),
                 "no cipher suites match %v", joined);
    }
  }
  return joined;
}

static mrb_value
config_pack_groups(mrb_state *mrb, mrb_value self)
{
  mrb_value names, joined;
  SSL_CTX *probe;
  mrb_int i;

  mrb_get_args(mrb, "A", &names);
  joined = mrb_str_new_capa(mrb, 32);
  for (i = 0; i < RARRAY_LEN(names); i++) {
    mrb_value n = mrb_ary_ref(mrb, names, i);
    if (i) mrb_str_cat_lit(mrb, joined, ":");
    mrb_str_cat_str(mrb, joined, mrb_obj_as_string(mrb, n));
  }

  probe = SSL_CTX_new(TLS_method());
  if (probe) {
    int ok = SSL_CTX_set1_groups_list(probe, RSTRING_CSTR(mrb, joined));
    SSL_CTX_free(probe);
    ERR_clear_error();
    if (!ok) {
      mrb_raisef(mrb, tls_config_error_class(mrb),
                 "no ECDHE groups match %v", joined);
    }
  }
  return joined;
}

/* ------------------------------------------------------------------ */
/* Connection setup                                                    */
/* ------------------------------------------------------------------ */

static mrb_tls_conn_t *
conn_ptr(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = (mrb_tls_conn_t *)DATA_PTR(self);
  if (!c) mrb_raise(mrb, E_RUNTIME_ERROR, "uninitialized Tls::Context");
  return c;
}

/* Index for stashing the Ruby connection object on the SSL, so the SNI
 * callback can find its way back into mruby. */
static int conn_ssl_index = -1;

static mrb_value
conn_config_value(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, MRB_IVSYM(config));
}

/* Applies the per-connection half of a Config: the parts that live on
 * the SSL rather than the SSL_CTX, because they can differ between
 * connections made from the same Config. */
static void
conn_apply_config(mrb_state *mrb, mrb_value self, mrb_tls_conn_t *c)
{
  mrb_value cfgv = conn_config_value(mrb, self);
  mrb_value suites, groups;

  if (mrb_nil_p(cfgv)) return;

  suites = mrb_iv_get(mrb, cfgv, MRB_IVSYM(ciphersuites));
  if (mrb_string_p(suites)) {
    const char *s = RSTRING_CSTR(mrb, suites);
    /* Either spelling may match; _pack_ciphersuites already rejected a
     * list neither call understands. */
    int a = SSL_set_ciphersuites(c->ssl, s);
    int b = SSL_set_cipher_list(c->ssl, s);
    ERR_clear_error();
    if (!a && !b) {
      mrb_raisef(mrb, tls_config_error_class(mrb),
                 "no cipher suites match %v", suites);
    }
  }

  groups = mrb_iv_get(mrb, cfgv, MRB_IVSYM(groups));
  if (mrb_string_p(groups)) {
    if (!SSL_set1_groups_list(c->ssl, RSTRING_CSTR(mrb, groups))) {
      raise_ossl(mrb, tls_config_error_class(mrb), "cannot set ECDHE groups");
    }
  }
}

/* The SNI hook. Tls::Server.new(config) { |hostname| ... } expects the
 * block to return a Tls::Config to switch to, or nil to keep the
 * connection's default certificate.
 *
 * Runs inside OpenSSL's handshake, so it must not let an mruby exception
 * escape into C: mrb_protect_error catches it and the connection simply
 * keeps its default certificate rather than the process unwinding
 * through OpenSSL's stack frames. */
struct sni_args {
  mrb_value block;
  mrb_value host;
};

/* mrb_yield_argv, not mrb_funcall(block, :call).
 *
 * They are not interchangeable here, and the difference is a segfault.
 * `Proc#call` is an irep proc whose entire body is OP_CALL, so funcall
 * re-enters the VM to run it; vm_call_proc's cfunc branch then does
 * `cipop` and reads `ci->proc->body.irep` off the frame underneath
 * (mruby src/vm.c:2253). Reached from inside a C function - which is
 * always, since this runs inside OpenSSL's handshake - that frame is the
 * one mrb_funcall_with_block pushed, and it set `ci->proc = NULL`
 * because the method it dispatched was a plain cfunc (vm.c:869,
 * MRB_METHOD_PROC_P is false for mrb_define_method'd C functions).
 * Dereferencing NULL is the crash.
 *
 * It only bites when the block is *itself* cfunc-backed - a proc from
 * mrb_proc_new_cfunc_with_env, which is exactly what webmachine-mruby
 * hands us as its SNI hook. A Ruby block takes the irep branch and is
 * fine, which is why test/tls_sni.rb passed throughout and the crash
 * only showed up under the io_uring adapter.
 *
 * mrb_yield_argv calls the proc directly: yield_with_attr has an
 * explicit cfunc branch that invokes the function and pops, never
 * touching the caller frame's irep. */
static mrb_value
sni_call(mrb_state *mrb, void *ud)
{
  struct sni_args *a = (struct sni_args *)ud;
  return mrb_yield_argv(mrb, a->block, 1, &a->host);
}

static int
sni_cb(SSL *ssl, int *al, void *arg)
{
  mrb_tls_conn_t *c;
  mrb_state *mrb;
  const char *host;
  mrb_value block, result;
  mrb_bool raised = FALSE;
  struct sni_args args;
  int ai;

  (void)al;
  (void)arg;

  c = (mrb_tls_conn_t *)SSL_get_ex_data(ssl, conn_ssl_index);
  if (!c || !c->mrb) return SSL_TLSEXT_ERR_OK;
  mrb = c->mrb;

  block = mrb_iv_get(mrb, c->self, MRB_IVSYM(sni_block));
  if (mrb_nil_p(block)) return SSL_TLSEXT_ERR_OK;

  /* Checked here rather than left to mrb_yield_argv's own check_block,
   * because that raises - and raising is the one thing this callback
   * must not do casually while OpenSSL owns the stack. Anything that is
   * not a Proc in @sni_block cannot have got there through the public
   * constructor, so treating it as "no hook" is both the safe answer and
   * the truthful one. */
  if (!mrb_proc_p(block)) return SSL_TLSEXT_ERR_OK;

  host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!host) return SSL_TLSEXT_ERR_OK;

  /* The GC must not run out from under the callback.
   *
   * The block is reachable only through c->self's ivar table, and
   * c->self is an mrb_value living in a C struct the collector does not
   * scan - so if the last Ruby-side reference to the Tls::Server dropped
   * while a handshake was in flight, both it and the block are
   * collectable at the next allocation. The callback allocates (the host
   * String, immediately below), so that next allocation is guaranteed to
   * happen right here.
   *
   * Both go on the arena for the duration. The save/restore pair bounds
   * the growth: this is called once per handshake and the arena is a
   * fixed-size stack, so protecting without restoring would eventually
   * overflow it on a long-lived server. */
  ai = mrb_gc_arena_save(mrb);
  mrb_gc_protect(mrb, block);

  args.block = block;
  args.host = mrb_str_new_cstr(mrb, host); /* already on the arena */
  result = mrb_protect_error(mrb, sni_call, &args, &raised);

  /* Restore first, then re-protect what has to outlive it: the restore
   * drops everything the callback left on the arena, `result` included,
   * and every path below either stores it in an ivar or reads through
   * it. Protecting before the restore would be undone by the restore. */
  mrb_gc_arena_restore(mrb, ai);
  mrb_gc_protect(mrb, result);

  /* A block that blew up, or answered with something that is not a
   * certificate selection, aborts the handshake - it must not quietly
   * fall back to the default certificate, which would serve the wrong
   * site to whoever asked for the one the block failed to resolve.
   *
   * The exception is stashed rather than thrown: this runs inside
   * OpenSSL's handshake, and unwinding an mruby exception through C
   * stack frames that own locks and allocations is how you corrupt a
   * process. conn_handshake_common picks it up once SSL_do_handshake
   * has returned and re-raises it there, so the server sees the
   * original error while the client just sees the alert. */
  if (raised) {
    mrb_iv_set(mrb, c->self, MRB_IVSYM(pending_exception), result);
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  if (mrb_nil_p(result)) return SSL_TLSEXT_ERR_OK;

  if (!mrb_obj_is_kind_of(mrb, result, tls_config_class(mrb))) {
    mrb_value exc = mrb_exc_new_str(mrb, tls_error_class(mrb),
        mrb_str_new_lit(mrb, "sni block must return a Tls::Config or nil"));
    mrb_iv_set(mrb, c->self, MRB_IVSYM(pending_exception), exc);
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }

  {
    mrb_tls_config_t *other = (mrb_tls_config_t *)DATA_PTR(result);
    if (other && other->ctx) {
      /* Hold the selected Config on the connection: SSL_set_SSL_CTX does
       * not take a reference we can rely on outliving a GC pass, and the
       * SSL keeps using that SSL_CTX's certificate for the rest of the
       * handshake. */
      mrb_iv_set(mrb, c->self, MRB_IVSYM(sni_config), result);
      SSL_set_SSL_CTX(ssl, other->ctx);
      /* SSL_set_SSL_CTX resets some options from the new context; the
       * verify policy is ours and enforced after the handshake anyway. */
      SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }
  }
  return SSL_TLSEXT_ERR_OK;
}

/* Builds the SSL for a connection. `cfgv` is the Tls::Config (possibly
 * nil, in which case a default one is made). */
static void
conn_setup(mrb_state *mrb, mrb_value self, mrb_tls_conn_t *c, int is_server)
{
  mrb_value cfgv = conn_config_value(mrb, self);
  mrb_tls_config_t *cfg;

  if (mrb_nil_p(cfgv)) {
    cfgv = mrb_obj_new(mrb, tls_config_class(mrb), 0, NULL);
    mrb_iv_set(mrb, self, MRB_IVSYM(config), cfgv);
  }
  cfg = (mrb_tls_config_t *)DATA_PTR(cfgv);
  if (!cfg || !cfg->ctx) mrb_raise(mrb, tls_error_class(mrb), "invalid Tls::Config");

  c->ssl = SSL_new(cfg->ctx);
  if (!c->ssl) raise_ossl(mrb, tls_error_class(mrb), "SSL_new failed");

  c->is_server = is_server;
  c->mrb = mrb;
  c->self = self;
  SSL_set_ex_data(c->ssl, conn_ssl_index, c);

  if (is_server) {
    SSL_set_accept_state(c->ssl);
    if (!mrb_nil_p(mrb_iv_get(mrb, self, MRB_IVSYM(sni_block)))) {
      SSL_CTX_set_tlsext_servername_callback(cfg->ctx, sni_cb);
    }
  } else {
    SSL_set_connect_state(c->ssl);
  }

  /* Waiving the validity period is a verification-parameter flag rather
   * than something conn_verify_peer can undo afterwards: once OpenSSL
   * has recorded CERT_HAS_EXPIRED there is no way to ask "and what would
   * the result have been ignoring time?". */
  if (!cfg->verify_time) {
    X509_VERIFY_PARAM *param = SSL_get0_param(c->ssl);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
  }

  conn_apply_config(mrb, self, c);
}

/* ------------------------------------------------------------------ */
/* Verification - the security-critical part                           */
/* ------------------------------------------------------------------ */

/*
 * Enforces the three libtls axes after a client handshake. Called from
 * every path that can complete one; a connection that reaches
 * handshaked = 1 without passing through here is a vulnerability, not a
 * bug.
 *
 * Servers do not verify: this gem never requests a client certificate,
 * so there is nothing to check and SSL_get_verify_result() would report
 * X509_V_OK for the absence of one.
 */
static void
conn_verify_peer(mrb_state *mrb, mrb_value self, mrb_tls_conn_t *c)
{
  mrb_value cfgv = conn_config_value(mrb, self);
  mrb_tls_config_t *cfg;
  mrb_value hostv;
  X509 *peer;
  long vr;

  if (c->is_server) return;

  cfg = mrb_nil_p(cfgv) ? NULL : (mrb_tls_config_t *)DATA_PTR(cfgv);
  if (!cfg) return;

  peer = SSL_get1_peer_certificate(c->ssl);

  /* No certificate at all fails both axes that could look at one. A
   * server that sends none must never be treated as verified. */
  if (!peer) {
    if (cfg->verify_cert || cfg->verify_name) {
      mrb_raise(mrb, tls_error_class(mrb), "peer presented no certificate");
    }
    return;
  }

  if (cfg->verify_cert) {
    vr = SSL_get_verify_result(c->ssl);
    if (vr != X509_V_OK) {
      const char *reason = X509_verify_cert_error_string(vr);
      X509_free(peer);
      mrb_raisef(mrb, tls_error_class(mrb),
                 "certificate verification failed: %s",
                 mrb_str_new_cstr(mrb, reason ? reason : "unknown"));
    }
  }

  if (cfg->verify_name) {
    hostv = mrb_iv_get(mrb, self, MRB_IVSYM(hostname));
    if (mrb_string_p(hostv) && RSTRING_LEN(hostv) > 0) {
      /* X509_check_host does SAN-then-CN with the wildcard rules, which
       * is the part nobody should hand-roll. NO_PARTIAL_WILDCARDS
       * rejects "w*.example.com"; a bare "*.example.com" still matches
       * one label as it should. */
      int rc = X509_check_host(peer, RSTRING_PTR(hostv),
                               (size_t)RSTRING_LEN(hostv),
                               X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
                               NULL);
      if (rc != 1) {
        X509_free(peer);
        mrb_raisef(mrb, tls_error_class(mrb),
                   "certificate name mismatch: %v does not match the peer's certificate",
                   hostv);
      }
    }
  }

  X509_free(peer);
}

/* ------------------------------------------------------------------ */
/* Handshake / read / write                                            */
/* ------------------------------------------------------------------ */

/* Maps an OpenSSL "want more" into the Symbol the Ruby API returns, or
 * raises for a real failure. Returns 1 if the caller should retry later,
 * with *sym set. */
static int
want_symbol(mrb_state *mrb, mrb_tls_conn_t *c, int ret, mrb_value *sym,
            const char *what)
{
  int err = SSL_get_error(c->ssl, ret);

  /* :tls_want_pollin / :tls_want_pollout, not :wait_readable /
   * :wait_writable. These symbols are the return value of every
   * _nonblock method and therefore part of the public contract that
   * master established under libtls, where they were named after
   * TLS_WANT_POLLIN / TLS_WANT_POLLOUT. Renaming them to something more
   * idiomatic broke every caller *silently* - a `case r when
   * :tls_want_pollin` simply stops matching, with no exception and no
   * warning, and the connection quietly stalls. The backend changed;
   * the names callers match on must not. */
  switch (err) {
    case SSL_ERROR_WANT_READ:
      *sym = mrb_symbol_value(MRB_SYM(tls_want_pollin));
      return 1;
    case SSL_ERROR_WANT_WRITE:
      *sym = mrb_symbol_value(MRB_SYM(tls_want_pollout));
      return 1;
    case SSL_ERROR_ZERO_RETURN:
      /* Clean close_notify from the peer. */
      *sym = mrb_nil_value();
      return 2;
    case SSL_ERROR_SYSCALL:
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        *sym = mrb_symbol_value(MRB_SYM(tls_want_pollin));
        return 1;
      }
      /* ret == 0 here means the peer went away without close_notify.
       * Treat it as an error rather than a clean EOF: a truncation
       * attack looks exactly like this. */
      ERR_clear_error();
      if (errno != 0) {
        mrb_raisef(mrb, tls_error_class(mrb), "%s failed: %s",
                   mrb_str_new_cstr(mrb, what),
                   mrb_str_new_cstr(mrb, strerror(errno)));
      }
      mrb_raisef(mrb, tls_error_class(mrb), "%s failed: connection closed by peer",
                 mrb_str_new_cstr(mrb, what));
      return 0; /* not reached */
    default:
      raise_ossl(mrb, tls_error_class(mrb), what);
      return 0; /* not reached */
  }
}

static mrb_value
conn_handshake_common(mrb_state *mrb, mrb_value self, int nonblock)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  mrb_value sym;

  if (c->handshaked) return mrb_true_value();
  if (!c->ssl) mrb_raise(mrb, tls_error_class(mrb), "connection not set up");

  for (;;) {
    int ret;
    mrb_value pending;
    ERR_clear_error();
    errno = 0;
    ret = SSL_do_handshake(c->ssl);

    /* An sni block that failed aborted the handshake from inside
     * OpenSSL; its exception is the real story and outranks whatever
     * generic "handshake failure" the library would otherwise report. */
    pending = mrb_iv_get(mrb, self, MRB_IVSYM(pending_exception));
    if (!mrb_nil_p(pending)) {
      mrb_iv_set(mrb, self, MRB_IVSYM(pending_exception), mrb_nil_value());
      mrb_exc_raise(mrb, pending);
    }

    if (ret == 1) {
      /* Verified before the handshake is reported complete, never
       * after: a caller that sees "done" must never be able to send
       * anything to an unverified peer. */
      conn_verify_peer(mrb, self, c);
      c->handshaked = 1;
      return mrb_true_value();
    }
    if (want_symbol(mrb, c, ret, &sym, "handshake") == 1) {
      if (nonblock) return sym;
      /* Blocking mode on a blocking socket: SSL_do_handshake only
       * returns WANT_* on a non-blocking fd, so looping here would spin.
       * Hand the same Symbol back and let the caller poll. */
      return sym;
    }
    /* ZERO_RETURN during a handshake is a peer that closed mid-flight. */
    mrb_raise(mrb, tls_error_class(mrb), "handshake failed: connection closed by peer");
  }
}

static mrb_value
conn_handshake(mrb_state *mrb, mrb_value self)
{
  return conn_handshake_common(mrb, self, 0);
}

static mrb_value
conn_handshake_nonblock(mrb_state *mrb, mrb_value self)
{
  return conn_handshake_common(mrb, self, 1);
}

static mrb_value
conn_read_common(mrb_state *mrb, mrb_value self, int nonblock)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  mrb_int maxlen = 16384;
  mrb_value buf, sym;
  size_t nread = 0;
  int ret;

  mrb_get_args(mrb, "|i", &maxlen);
  if (maxlen <= 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "length must be positive");

  if (!c->handshaked) {
    mrb_value hs = conn_handshake_common(mrb, self, nonblock);
    if (mrb_symbol_p(hs)) return hs;
  }

  buf = mrb_str_new_capa(mrb, maxlen);
  ERR_clear_error();
  errno = 0;
  ret = SSL_read_ex(c->ssl, RSTRING_PTR(buf), (size_t)maxlen, &nread);
  if (ret == 1) {
    mrb_str_resize(mrb, buf, (mrb_int)nread);
    return buf;
  }

  switch (want_symbol(mrb, c, ret, &sym, "read")) {
    case 1: return sym;
    case 2: return mrb_nil_value(); /* clean EOF */
    default: return mrb_nil_value(); /* unreachable; want_symbol raised */
  }
}

static mrb_value
conn_read(mrb_state *mrb, mrb_value self)
{
  return conn_read_common(mrb, self, 0);
}

static mrb_value
conn_read_nonblock(mrb_state *mrb, mrb_value self)
{
  return conn_read_common(mrb, self, 1);
}

static mrb_value
conn_write_common(mrb_state *mrb, mrb_value self, int nonblock)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  char *data;
  mrb_int len;
  mrb_value sym;
  size_t written = 0;
  int ret;

  mrb_get_args(mrb, "s", &data, &len);

  if (!c->handshaked) {
    mrb_value hs = conn_handshake_common(mrb, self, nonblock);
    if (mrb_symbol_p(hs)) return hs;
  }

  if (len == 0) return mrb_fixnum_value(0);

  ERR_clear_error();
  errno = 0;
  ret = SSL_write_ex(c->ssl, data, (size_t)len, &written);
  if (ret == 1) return mrb_fixnum_value((mrb_int)written);

  switch (want_symbol(mrb, c, ret, &sym, "write")) {
    case 1: return sym;
    case 2: mrb_raise(mrb, tls_error_class(mrb), "write failed: connection closed");
    default: return mrb_nil_value(); /* unreachable */
  }
}

static mrb_value
conn_write(mrb_state *mrb, mrb_value self)
{
  return conn_write_common(mrb, self, 0);
}

static mrb_value
conn_write_nonblock(mrb_state *mrb, mrb_value self)
{
  return conn_write_common(mrb, self, 1);
}

static mrb_value
conn_close_common(mrb_state *mrb, mrb_value self, int nonblock)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  int ret;

  if (!c->ssl || c->close_sent) return mrb_nil_value();

  ERR_clear_error();
  errno = 0;
  ret = SSL_shutdown(c->ssl);
  if (ret < 0) {
    int err = SSL_get_error(c->ssl, ret);
    if (nonblock && (err == SSL_ERROR_WANT_READ)) {
      return mrb_symbol_value(MRB_SYM(tls_want_pollin));
    }
    if (nonblock && (err == SSL_ERROR_WANT_WRITE)) {
      return mrb_symbol_value(MRB_SYM(tls_want_pollout));
    }
    /* A peer that already vanished is not an error worth raising from
     * close - the connection is over either way. */
    ERR_clear_error();
  }
  c->close_sent = 1;
  return mrb_nil_value();
}

static mrb_value
conn_close(mrb_state *mrb, mrb_value self)
{
  return conn_close_common(mrb, self, 0);
}

static mrb_value
conn_close_nonblock(mrb_state *mrb, mrb_value self)
{
  return conn_close_common(mrb, self, 1);
}

static mrb_value
conn_version(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  const char *v;

  if (!c->ssl) return mrb_nil_value();
  v = SSL_get_version(c->ssl);
  return v ? mrb_str_new_cstr(mrb, v) : mrb_nil_value();
}

static mrb_value
conn_cipher(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  const SSL_CIPHER *ci;
  const char *name;

  if (!c->ssl) return mrb_nil_value();
  ci = SSL_get_current_cipher(c->ssl);
  if (!ci) return mrb_nil_value();
  name = SSL_CIPHER_get_name(ci);
  return name ? mrb_str_new_cstr(mrb, name) : mrb_nil_value();
}

static mrb_value
conn_configure(mrb_state *mrb, mrb_value self)
{
  mrb_value cfgv;

  mrb_get_args(mrb, "o", &cfgv);
  if (!mrb_obj_is_kind_of(mrb, cfgv, tls_config_class(mrb))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expected a Tls::Config");
  }
  mrb_iv_set(mrb, self, MRB_IVSYM(config), cfgv);
  return cfgv;
}

static mrb_value
conn_reset(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);

  if (c->ssl) {
    SSL_free(c->ssl);
    c->ssl = NULL;
  }
  c->rbio = c->wbio = NULL;
  c->is_mem = 0;
  c->handshaked = 0;
  c->close_sent = 0;
  c->fd = -1;
  mrb_iv_set(mrb, self, MRB_IVSYM(hostname), mrb_nil_value());
  mrb_iv_set(mrb, self, MRB_IVSYM(socket), mrb_nil_value());
  return self;
}

/* ------------------------------------------------------------------ */
/* Context / Client / Server                                           */
/* ------------------------------------------------------------------ */

static mrb_tls_conn_t *
conn_alloc(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = (mrb_tls_conn_t *)mrb_malloc(mrb, sizeof *c);
  memset(c, 0, sizeof *c);
  c->fd = -1;
  mrb_data_init(self, c, &tls_conn_type);
  return c;
}

static mrb_value
context_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_value cfgv = mrb_nil_value();

  mrb_get_args(mrb, "|o", &cfgv);
  conn_alloc(mrb, self);
  if (!mrb_nil_p(cfgv)) {
    if (!mrb_obj_is_kind_of(mrb, cfgv, tls_config_class(mrb))) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "expected a Tls::Config");
    }
    mrb_iv_set(mrb, self, MRB_IVSYM(config), cfgv);
  }
  return self;
}

static mrb_value
client_initialize(mrb_state *mrb, mrb_value self)
{
  return context_initialize(mrb, self);
}

static mrb_value
server_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_value cfgv = mrb_nil_value(), block = mrb_nil_value();

  mrb_get_args(mrb, "o&", &cfgv, &block);
  conn_alloc(mrb, self);
  if (!mrb_obj_is_kind_of(mrb, cfgv, tls_config_class(mrb))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "expected a Tls::Config");
  }
  mrb_iv_set(mrb, self, MRB_IVSYM(config), cfgv);
  if (!mrb_nil_p(block)) mrb_iv_set(mrb, self, MRB_IVSYM(sni_block), block);
  return self;
}

/* Pulls a descriptor out of whatever Ruby object was handed in. The
 * socket object itself is retained on the connection: OpenSSL only gets
 * an int, so nothing else would stop the GC closing the socket out from
 * under a live TLS session. */
static int
socket_fileno(mrb_state *mrb, mrb_value sock)
{
  mrb_value f = mrb_funcall_id(mrb, sock, MRB_SYM(fileno), 0);
  if (!mrb_fixnum_p(f)) mrb_raise(mrb, E_TYPE_ERROR, "socket#fileno did not return an Integer");
  return (int)mrb_fixnum(f);
}

static void
conn_attach_fd(mrb_state *mrb, mrb_value self, mrb_tls_conn_t *c,
               mrb_value sock, int fd)
{
  mrb_iv_set(mrb, self, MRB_IVSYM(socket), sock);
  c->fd = fd;
  if (!SSL_set_fd(c->ssl, fd)) {
    raise_ossl(mrb, tls_error_class(mrb), "cannot attach socket");
  }
}

static mrb_value
client_connect_socket(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  mrb_value sock, host;

  mrb_get_args(mrb, "oo", &sock, &host);
  if (c->ssl) mrb_raise(mrb, tls_error_class(mrb), "already connected");

  if (!mrb_nil_p(host)) {
    mrb_iv_set(mrb, self, MRB_IVSYM(hostname), mrb_obj_as_string(mrb, host));
  }
  conn_setup(mrb, self, c, 0);

  /* SNI, and the name X509_check_host will be given. Sent even when
   * verify_name is off: it selects the peer's certificate, which is a
   * different question from whether we check it. */
  if (mrb_string_p(mrb_iv_get(mrb, self, MRB_IVSYM(hostname)))) {
    mrb_value h = mrb_iv_get(mrb, self, MRB_IVSYM(hostname));
    SSL_set_tlsext_host_name(c->ssl, RSTRING_CSTR(mrb, h));
  }

  conn_attach_fd(mrb, self, c, sock, socket_fileno(mrb, sock));
  return self;
}

static mrb_value
client_connect_fds(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  mrb_int rfd, wfd;
  mrb_value host;

  mrb_get_args(mrb, "iio", &rfd, &wfd, &host);
  if (c->ssl) mrb_raise(mrb, tls_error_class(mrb), "already connected");

  if (!mrb_nil_p(host)) {
    mrb_iv_set(mrb, self, MRB_IVSYM(hostname), mrb_obj_as_string(mrb, host));
  }
  conn_setup(mrb, self, c, 0);
  if (mrb_string_p(mrb_iv_get(mrb, self, MRB_IVSYM(hostname)))) {
    mrb_value h = mrb_iv_get(mrb, self, MRB_IVSYM(hostname));
    SSL_set_tlsext_host_name(c->ssl, RSTRING_CSTR(mrb, h));
  }

  if (rfd == wfd) {
    c->fd = (int)rfd;
    if (!SSL_set_fd(c->ssl, (int)rfd)) {
      raise_ossl(mrb, tls_error_class(mrb), "cannot attach descriptor");
    }
  } else {
    if (!SSL_set_rfd(c->ssl, (int)rfd) || !SSL_set_wfd(c->ssl, (int)wfd)) {
      raise_ossl(mrb, tls_error_class(mrb), "cannot attach descriptors");
    }
    c->fd = (int)rfd;
  }
  return self;
}

/* Client#_connect(host, port) - mrblib's Client#connect splits a combined
 * "host:port" and calls this. Owns the socket it creates, so the GC
 * finaliser closes it. */
static mrb_value
client_connect(mrb_state *mrb, mrb_value self)
{
  mrb_tls_conn_t *c = conn_ptr(mrb, self);
  const char *host, *port;
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1, rc;

  mrb_get_args(mrb, "zz", &host, &port);
  if (c->ssl) mrb_raise(mrb, tls_error_class(mrb), "already connected");

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rc = getaddrinfo(host, port, &hints, &res);
  if (rc != 0) {
    mrb_raisef(mrb, tls_error_class(mrb), "cannot resolve %s:%s: %s",
               mrb_str_new_cstr(mrb, host), mrb_str_new_cstr(mrb, port),
               mrb_str_new_cstr(mrb, gai_strerror(rc)));
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    mrb_raisef(mrb, tls_error_class(mrb), "cannot connect to %s:%s: %s",
               mrb_str_new_cstr(mrb, host), mrb_str_new_cstr(mrb, port),
               mrb_str_new_cstr(mrb, strerror(errno)));
  }

  /* Take ownership before anything below can raise, so a failure still
   * closes the socket rather than leaking it. */
  c->fd = fd;
  c->own_fd = 1;

  mrb_iv_set(mrb, self, MRB_IVSYM(hostname), mrb_str_new_cstr(mrb, host));
  conn_setup(mrb, self, c, 0);
  SSL_set_tlsext_host_name(c->ssl, host);
  if (!SSL_set_fd(c->ssl, fd)) {
    raise_ossl(mrb, tls_error_class(mrb), "cannot attach socket");
  }
  return self;
}

static mrb_value
server_accept_socket(mrb_state *mrb, mrb_value self)
{
  mrb_value sock, conn;
  mrb_tls_conn_t *c;
  struct RClass *ctx_class;

  mrb_get_args(mrb, "o", &sock);

  /* A Server is a factory: each accept produces its own connection
   * object, so one server can serve many at once. */
  ctx_class = mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Context));
  conn = mrb_obj_new(mrb, ctx_class, 0, NULL);
  c = conn_ptr(mrb, conn);

  mrb_iv_set(mrb, conn, MRB_IVSYM(config), conn_config_value(mrb, self));
  mrb_iv_set(mrb, conn, MRB_IVSYM(sni_block),
             mrb_iv_get(mrb, self, MRB_IVSYM(sni_block)));

  conn_setup(mrb, conn, c, 1);
  conn_attach_fd(mrb, conn, c, sock, socket_fileno(mrb, sock));
  return conn;
}

/* ------------------------------------------------------------------ */
/* Tls.load_file                                                       */
/* ------------------------------------------------------------------ */

static mrb_value
tls_load_file(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_value password = mrb_nil_value();
  FILE *fp;
  mrb_value out;
  char buf[4096];
  size_t n;

  mrb_get_args(mrb, "z|o", &path, &password);
  (void)password; /* encrypted PEM is handled by the key setters, not here */

  fp = fopen(path, "rb");
  if (!fp) {
    mrb_raisef(mrb, tls_error_class(mrb), "cannot open %s: %s",
               mrb_str_new_cstr(mrb, path),
               mrb_str_new_cstr(mrb, strerror(errno)));
  }
  out = mrb_str_new_capa(mrb, 4096);
  while ((n = fread(buf, 1, sizeof buf, fp)) > 0) {
    mrb_str_cat(mrb, out, buf, (mrb_int)n);
  }
  fclose(fp);
  return out;
}

/* ------------------------------------------------------------------ */
/* Memory-BIO C API (include/mruby/tls.h)                              */
/* ------------------------------------------------------------------ */

/*
 * The backend-neutral half of this gem: bytes in, bytes out, no
 * descriptor and no backend type in any signature. That is what lets an
 * event loop own the transport - webmachine's io_uring adapter reads
 * ciphertext into its own provided buffers and never gives this gem an
 * fd to touch.
 */

static mrb_tls_conn_t *
mem_conn(mrb_state *mrb, mrb_value conn)
{
  mrb_tls_conn_t *c;

  if (!mrb_obj_is_kind_of(mrb, conn,
                          mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Context)))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a Tls connection");
  }
  c = (mrb_tls_conn_t *)DATA_PTR(conn);
  if (!c || !c->is_mem) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "not a memory-backed TLS connection");
  }
  return c;
}

MRB_API mrb_value
mrb_tls_accept_memory(mrb_state *mrb, mrb_value server)
{
  mrb_value conn;
  mrb_tls_conn_t *c;
  struct RClass *ctx_class;

  ctx_class = mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Context));
  conn = mrb_obj_new(mrb, ctx_class, 0, NULL);
  c = conn_ptr(mrb, conn);

  mrb_iv_set(mrb, conn, MRB_IVSYM(config), conn_config_value(mrb, server));
  mrb_iv_set(mrb, conn, MRB_IVSYM(sni_block),
             mrb_iv_get(mrb, server, MRB_IVSYM(sni_block)));

  conn_setup(mrb, conn, c, 1);

  c->rbio = BIO_new(BIO_s_mem());
  c->wbio = BIO_new(BIO_s_mem());
  if (!c->rbio || !c->wbio) {
    if (c->rbio) BIO_free(c->rbio);
    if (c->wbio) BIO_free(c->wbio);
    c->rbio = c->wbio = NULL;
    raise_ossl(mrb, tls_error_class(mrb), "cannot create memory BIOs");
  }
  /* Without this a memory BIO reports EOF as soon as it runs dry, and
   * OpenSSL treats that as the peer hanging up instead of "no more
   * ciphertext has arrived yet". */
  BIO_set_mem_eof_return(c->rbio, -1);
  BIO_set_mem_eof_return(c->wbio, -1);

  SSL_set_bio(c->ssl, c->rbio, c->wbio); /* takes ownership of both */
  c->is_mem = 1;
  return conn;
}

MRB_API int
mrb_tls_feed(mrb_state *mrb, mrb_value conn, const void *buf, size_t len)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  int n;

  if (len == 0) return 0;
  n = BIO_write(c->rbio, buf, (int)len);
  return (n > 0 && (size_t)n == len) ? 0 : -1;
}

MRB_API size_t
mrb_tls_pending(mrb_state *mrb, mrb_value conn, const unsigned char **buf)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  char *p = NULL;
  long n = BIO_get_mem_data(c->wbio, &p);

  if (n <= 0) {
    if (buf) *buf = NULL;
    return 0;
  }
  if (buf) *buf = (const unsigned char *)p;
  return (size_t)n;
}

MRB_API void
mrb_tls_drain(mrb_state *mrb, mrb_value conn, size_t len)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  char scratch[4096];

  /* BIO_s_mem has no "discard n" call, so consume by reading. Reading
   * is what advances the BIO's read pointer, and the memory BIO
   * compacts itself as it goes. */
  while (len > 0) {
    int want = (int)(len > sizeof scratch ? sizeof scratch : len);
    int got = BIO_read(c->wbio, scratch, want);
    if (got <= 0) break;
    len -= (size_t)got;
  }
}

MRB_API int
mrb_tls_handshake_memory(mrb_state *mrb, mrb_value conn)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  int ret, err;

  if (c->handshaked) return 1;

  ERR_clear_error();
  ret = SSL_do_handshake(c->ssl);
  if (ret == 1) {
    c->handshaked = 1;
    return 1;
  }
  err = SSL_get_error(c->ssl, ret);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
  ERR_clear_error();
  return -1;
}

MRB_API int
mrb_tls_read_memory(mrb_state *mrb, mrb_value conn, void *buf, size_t len)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  size_t nread = 0;
  int ret, err;

  if (len == 0) return 0;
  ERR_clear_error();
  ret = SSL_read_ex(c->ssl, buf, len, &nread);
  if (ret == 1) return (int)nread;

  err = SSL_get_error(c->ssl, ret);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
  ERR_clear_error();
  return -1;
}

MRB_API int
mrb_tls_write_memory(mrb_state *mrb, mrb_value conn, const void *buf, size_t len)
{
  mrb_tls_conn_t *c = mem_conn(mrb, conn);
  size_t written = 0;
  int ret, err;

  if (len == 0) return 0;
  ERR_clear_error();
  ret = SSL_write_ex(c->ssl, buf, len, &written);
  if (ret == 1) return (int)written;

  err = SSL_get_error(c->ssl, ret);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
  ERR_clear_error();
  return -1;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

extern "C" void
mrb_mruby_tls_gem_init(mrb_state *mrb)
{
  struct RClass *tls_mod, *proto_mod, *conf_c, *ctx_c, *cli_c, *srv_c;

  conn_ssl_index = SSL_get_ex_new_index(0, (void *)"mruby-tls conn", NULL, NULL, NULL);

  tls_mod = mrb_define_module_id(mrb, MRB_SYM(Tls));
  /* Tls::Error and Tls::Config::Error are defined by mrblib/error.rb, which
   * runs after this. Defining them here too would fix their superclass to
   * whatever C picked and collide with error.rb's `< RuntimeError`. Every
   * lookup below is therefore lazy, at raise time. */

  mrb_define_module_function_id(mrb, tls_mod, MRB_SYM(load_file), tls_load_file,
                                MRB_ARGS_ARG(1, 1));

  proto_mod = mrb_define_module_under_id(mrb, tls_mod, MRB_SYM(Protocol));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(TLSv1_0), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_0));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(TLSv1_1), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_1));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(TLSv1_2), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_2));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(TLSv1_3), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1_3));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(TLSv1), mrb_int_value(mrb, MRB_TLS_PROTOCOL_TLSv1));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(All), mrb_int_value(mrb, MRB_TLS_PROTOCOLS_ALL));
  mrb_define_const_id(mrb, proto_mod, MRB_SYM(Default), mrb_int_value(mrb, MRB_TLS_PROTOCOLS_DEFAULT));

  conf_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Config), mrb->object_class);
  MRB_SET_INSTANCE_TT(conf_c, MRB_TT_CDATA);
  mrb_define_method_id(mrb, conf_c, MRB_SYM(initialize), config_initialize, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(ca_file), config_set_ca_file, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(ca_path), config_set_ca_path, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(cert_file), config_set_cert_file, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(cert_mem), config_set_cert_mem, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(key_file), config_set_key_file, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(key_mem), config_set_key_mem, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(protocols), config_set_protocols, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM_E(verify_depth), config_set_verify_depth, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM(verify), config_verify, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, conf_c, MRB_SYM(noverify), config_noverify, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM(clear_keys), config_clear_keys, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, conf_c, MRB_SYM(_pack_ciphersuites), config_pack_ciphersuites, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_c, MRB_SYM(_pack_groups), config_pack_groups, MRB_ARGS_REQ(1));

  ctx_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Context), mrb->object_class);
  MRB_SET_INSTANCE_TT(ctx_c, MRB_TT_CDATA);
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(initialize), context_initialize, MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(configure), conn_configure, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(reset), conn_reset, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(read), conn_read, MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(read_nonblock), conn_read_nonblock, MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(write), conn_write, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(write_nonblock), conn_write_nonblock, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(close), conn_close, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(close_nonblock), conn_close_nonblock, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(handshake), conn_handshake, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(handshake_nonblock), conn_handshake_nonblock, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(version), conn_version, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, ctx_c, MRB_SYM(cipher), conn_cipher, MRB_ARGS_NONE());

  cli_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Client), ctx_c);
  MRB_SET_INSTANCE_TT(cli_c, MRB_TT_CDATA);
  mrb_define_method_id(mrb, cli_c, MRB_SYM(initialize), client_initialize, MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, cli_c, MRB_SYM(_connect), client_connect, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, cli_c, MRB_SYM(connect_fds), client_connect_fds, MRB_ARGS_REQ(3));
  mrb_define_method_id(mrb, cli_c, MRB_SYM(connect_socket), client_connect_socket, MRB_ARGS_REQ(2));

  srv_c = mrb_define_class_under_id(mrb, tls_mod, MRB_SYM(Server), ctx_c);
  MRB_SET_INSTANCE_TT(srv_c, MRB_TT_CDATA);
  mrb_define_method_id(mrb, srv_c, MRB_SYM(initialize), server_initialize,
                       MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, srv_c, MRB_SYM(accept_socket), server_accept_socket, MRB_ARGS_REQ(1));
}

extern "C" void
mrb_mruby_tls_gem_final(mrb_state *mrb)
{
  (void)mrb;
}
