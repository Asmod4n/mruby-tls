// The Schannel backend, entire. Included by exactly one translation unit
// (src/mrb_tls.cpp) and never compiled on its own - see the note there
// for why each backend defines the whole gem rather than sharing a layer.
//
// The Ruby API (Tls::Config, Tls::Context, Tls::Client, Tls::Server) and
// the C API in include/mruby/tls.h are identical to the OpenSSL
// backend's. Nothing above this file knows which provider it got.
//
// ## Shape
//
// SSPI is natively a buffer API: EncryptMessage and DecryptMessage take
// SecBuffer arrays and there is no socket concept anywhere in it. So the
// memory API (mrb_tls_feed/pending/drain/...) is the *primitive* here,
// and socket mode is built on top of it - the reverse of the OpenSSL
// backend, where a BIO pair had to be constructed to fake what Schannel
// gives for free.
//
// ## SNI
//
// Server-side SNI raises. Schannel has no equivalent of
// SSL_CTX_set_tlsext_servername_callback: there is no per-connection
// hook to pick a certificate after seeing the name. Supporting it would
// mean parsing the SNI extension out of the ClientHello before handing
// bytes to AcceptSecurityContext - a second, structurally different SNI
// path that only Windows exercises, in the one place where being wrong
// means serving the wrong certificate. A configuration-time raise cannot
// silently mis-serve. Single-certificate servers are unaffected; a
// deployment needing several uses one listener per certificate.
//
// Client-side SNI is not affected and works normally: it is just the
// target name handed to InitializeSecurityContext.
// ####################################################################
// INCOMPLETE - DOES NOT COMPILE, DOES NOT LINK, NEVER HANDSHAKEN.
//
// Present so far: the data types, error formatting, the whole Config
// surface (PEM certificate and key import through CNG, extra CA roots,
// protocols, verify flags), credential acquisition via SCH_CREDENTIALS,
// and the handshake step for both directions.
//
// Still missing, all of it required before this is worth building:
//   - EncryptMessage / DecryptMessage
//   - the MRB_API functions from include/mruby/tls.h, with one
//     exception: mrb_tls_ktls_tx_params returns -1 here and always
//     will. Windows has no kernel TLS - no SOL_TLS, no TCP_ULP, nothing
//     Schannel can hand a record layer to - so "unavailable" is the
//     permanent and correct answer. Callers already read -1 as "keep
//     encrypting in userspace", which is what Windows does regardless.
//   - Tls::Context  (read/write/handshake/close, + _nonblock, version,
//                    cipher, configure, reset)
//   - Tls::Client   (_connect, connect_fds, connect_socket)
//   - Tls::Server   (accept_socket, and the SNI raise described above)
//   - Tls.load_file
//   - mrb_mruby_tls_gem_init / _gem_final
//
// src/mrb_tls.cpp includes this on _WIN32, so a Windows build fails
// here rather than on a missing header. That is not a regression - it
// did not link before this file existed either.
// ####################################################################
#ifndef MRUBY_TLS_BACKEND_SCHANNEL_HPP
#define MRUBY_TLS_BACKEND_SCHANNEL_HPP

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <sspi.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <mruby/tls.h>

#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>

/* Mirrors the OpenSSL backend's constants so behaviour matches. */
#define MRB_TLS_PROTOCOL_TLSv1_2 0x08
#define MRB_TLS_PROTOCOL_TLSv1_3 0x10
#define MRB_TLS_PROTOCOLS_DEFAULT (MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3)
#define MRB_TLS_DEFAULT_VERIFY_DEPTH 6

/* ------------------------------------------------------------------ */
/* Data types                                                          */
/* ------------------------------------------------------------------ */

typedef struct mrb_tls_config {
  /* The certificate and its private key, for a server or a client
   * presenting one. Held as a cert context with the key attached via
   * CERT_NCRYPT_KEY_HANDLE_PROP_ID, which is what Schannel wants. */
  PCCERT_CONTEXT cert;
  NCRYPT_KEY_HANDLE key;
  HCERTSTORE ca_store; /* extra roots from ca_file/ca_path, or NULL */

  uint32_t protocols;
  int verify_depth;
  int verify_cert;
  int verify_name;
  int verify_time;
} mrb_tls_config_t;

typedef struct mrb_tls_conn {
  CredHandle cred;
  CtxtHandle ctxt;
  int have_cred;
  int have_ctxt;

  SecPkgContext_StreamSizes sizes;
  int have_sizes;

  /* Ciphertext received from the peer and not yet consumed. Schannel
   * reports what it did not use as SECBUFFER_EXTRA, so this is
   * compacted rather than indexed. */
  std::vector<char> in;
  /* Ciphertext produced and not yet written to the peer. mrb_tls_pending
   * points into this; mrb_tls_drain erases from the front. */
  std::vector<char> out;
  /* Plaintext decrypted but not yet handed to the caller. */
  std::vector<char> plain;

  std::string target; /* client: the name for SNI and verification */

  /* Copied from the Config at construction: the Config is a separate
   * Ruby object and may be mutated or collected after this point. */
  int verify_cert;
  int verify_name;

  int is_mem;
  int is_server;
  int handshaked;
  int close_sent;
  int peer_closed;
  int own_fd;
  int fd;

  mrb_state *mrb;
  mrb_value self;
} mrb_tls_conn_t;

static void
config_free(mrb_state *mrb, void *p)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)p;
  if (!cfg) return;
  if (cfg->cert) CertFreeCertificateContext(cfg->cert);
  if (cfg->key) NCryptFreeObject(cfg->key);
  if (cfg->ca_store) CertCloseStore(cfg->ca_store, 0);
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
  if (c->have_ctxt) DeleteSecurityContext(&c->ctxt);
  if (c->have_cred) FreeCredentialsHandle(&c->cred);
  if (c->own_fd && c->fd >= 0) closesocket((SOCKET)c->fd);
  c->~mrb_tls_conn();  /* the std::vector/std::string members */
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
tls_config_error_class(mrb_state *mrb)
{
  return mrb_class_get_under_id(
    mrb, mrb_class_get_under_id(mrb, tls_module(mrb), MRB_SYM(Config)), MRB_SYM(Error));
}

/* SSPI and CryptoAPI both report through GetLastError-style codes rather
 * than a string queue, so the message is formatted rather than popped.
 * FormatMessage's text is localised and can be absent for SEC_E_ codes,
 * hence the hex fallback - a number that can be looked up beats an empty
 * string. */
static std::string
win_error_string(long code)
{
  char *msg = NULL;
  DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, (DWORD)code, 0, (char *)&msg, 0, NULL);
  std::string s;
  if (n && msg) {
    s.assign(msg, n);
    while (!s.empty() && (s[s.size() - 1] == '\r' || s[s.size() - 1] == '\n' ||
                          s[s.size() - 1] == ' ')) {
      s.erase(s.size() - 1);
    }
  }
  if (msg) LocalFree(msg);
  char buf[32];
  snprintf(buf, sizeof(buf), " (0x%08lx)", (unsigned long)code);
  s += buf;
  return s;
}

static void
tls_raise_win(mrb_state *mrb, struct RClass *klass, const char *what, long code)
{
  mrb_raisef(mrb, klass, "%s: %s", what, win_error_string(code).c_str());
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

/* PEM in, DER out. CRYPT_STRING_BASE64HEADER accepts the -----BEGIN-----
 * armour and rejects anything else, which is the validation we want. */
static bool
pem_to_der(const char *pem, size_t len, std::vector<BYTE> *der)
{
  DWORD n = 0;
  if (!CryptStringToBinaryA(pem, (DWORD)len, CRYPT_STRING_BASE64HEADER, NULL, &n, NULL, NULL)) {
    return false;
  }
  der->resize(n);
  if (!CryptStringToBinaryA(pem, (DWORD)len, CRYPT_STRING_BASE64HEADER, der->data(), &n, NULL,
                            NULL)) {
    return false;
  }
  der->resize(n);
  return true;
}

static std::string
read_whole_file(mrb_state *mrb, const char *path)
{
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    mrb_raisef(mrb, tls_config_error_class(mrb), "cannot open %s: %s", path,
               win_error_string((long)GetLastError()).c_str());
  }
  std::string out;
  char buf[8192];
  DWORD got = 0;
  while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) out.append(buf, got);
  CloseHandle(h);
  return out;
}

/* The private key. PKCS#8 (BEGIN PRIVATE KEY) and PKCS#1 (BEGIN RSA
 * PRIVATE KEY) are both accepted, because both are what a PEM file in
 * the wild actually contains. The key is imported into an ephemeral CNG
 * provider - it never touches the machine or user key store, so nothing
 * is left behind for the next process to find. */
static NCRYPT_KEY_HANDLE
import_private_key(mrb_state *mrb, const std::string &pem)
{
  std::vector<BYTE> der;
  if (!pem_to_der(pem.data(), pem.size(), &der)) {
    mrb_raise(mrb, tls_config_error_class(mrb), "private key is not PEM");
  }

  /* CryptDecodeObjectEx normalises both encodings into a CNG blob. */
  DWORD blob_len = 0;
  BYTE *blob = NULL;
  const char *type = PKCS_PRIVATE_KEY_INFO;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, der.data(),
                           (DWORD)der.size(), CRYPT_DECODE_ALLOC_FLAG, NULL, &blob, &blob_len)) {
    /* Not PKCS#8; try PKCS#1 RSA directly. */
    type = PKCS_RSA_PRIVATE_KEY;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, der.data(),
                             (DWORD)der.size(), CRYPT_DECODE_ALLOC_FLAG, NULL, &blob,
                             &blob_len)) {
      tls_raise_win(mrb, tls_config_error_class(mrb), "cannot decode private key",
                    (long)GetLastError());
    }
  }

  NCRYPT_PROV_HANDLE prov = 0;
  NCRYPT_KEY_HANDLE key = 0;
  SECURITY_STATUS ss = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
  if (ss != ERROR_SUCCESS) {
    LocalFree(blob);
    tls_raise_win(mrb, tls_config_error_class(mrb), "NCryptOpenStorageProvider", (long)ss);
  }

  /* NCRYPT_DO_NOT_FINALIZE is not passed: the key is complete and must
   * be usable immediately. No name is given, so it is ephemeral. */
  ss = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &key, der.data(),
                       (DWORD)der.size(), NCRYPT_SILENT_FLAG);
  if (ss != ERROR_SUCCESS) {
    /* PKCS#8 import failed; fall back to the legacy RSA blob path. */
    ss = NCryptImportKey(prov, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &key, blob, blob_len,
                         NCRYPT_SILENT_FLAG);
  }
  LocalFree(blob);
  NCryptFreeObject(prov);
  if (ss != ERROR_SUCCESS) {
    tls_raise_win(mrb, tls_config_error_class(mrb), "NCryptImportKey", (long)ss);
  }
  return key;
}

static void
config_set_cert_pem(mrb_state *mrb, mrb_tls_config_t *cfg, const std::string &pem)
{
  std::vector<BYTE> der;
  if (!pem_to_der(pem.data(), pem.size(), &der)) {
    mrb_raise(mrb, tls_config_error_class(mrb), "certificate is not PEM");
  }
  PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  der.data(), (DWORD)der.size());
  if (!c) {
    tls_raise_win(mrb, tls_config_error_class(mrb), "CertCreateCertificateContext",
                  (long)GetLastError());
  }
  if (cfg->cert) CertFreeCertificateContext(cfg->cert);
  cfg->cert = c;
}

/* Binds an imported key to the certificate. Schannel finds the key
 * through this property when the credential is acquired. */
static void
config_bind_key(mrb_state *mrb, mrb_tls_config_t *cfg)
{
  if (!cfg->cert || !cfg->key) return;
  if (!CertSetCertificateContextProperty(cfg->cert, CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                                         CERT_SET_KEY_PROV_HANDLE_PROP_ID, (void *)cfg->key)) {
    tls_raise_win(mrb, tls_config_error_class(mrb), "CertSetCertificateContextProperty",
                  (long)GetLastError());
  }
}

static mrb_value
config_initialize(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = (mrb_tls_config_t *)mrb_malloc(mrb, sizeof(mrb_tls_config_t));
  memset(cfg, 0, sizeof(*cfg));
  cfg->protocols = MRB_TLS_PROTOCOLS_DEFAULT;
  cfg->verify_depth = MRB_TLS_DEFAULT_VERIFY_DEPTH;
  cfg->verify_cert = cfg->verify_name = cfg->verify_time = 1;
  mrb_data_init(self, cfg, &tls_config_type);
  return self;
}

static mrb_value
config_set_cert_file(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_get_args(mrb, "z", &path);
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  config_set_cert_pem(mrb, cfg, read_whole_file(mrb, path));
  config_bind_key(mrb, cfg);
  return self;
}

static mrb_value
config_set_cert_mem(mrb_state *mrb, mrb_value self)
{
  const char *p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  config_set_cert_pem(mrb, cfg, std::string(p, (size_t)n));
  config_bind_key(mrb, cfg);
  return self;
}

static mrb_value
config_set_key_file(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_get_args(mrb, "z", &path);
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  if (cfg->key) NCryptFreeObject(cfg->key);
  cfg->key = import_private_key(mrb, read_whole_file(mrb, path));
  config_bind_key(mrb, cfg);
  return self;
}

static mrb_value
config_set_key_mem(mrb_state *mrb, mrb_value self)
{
  const char *p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  if (cfg->key) NCryptFreeObject(cfg->key);
  cfg->key = import_private_key(mrb, std::string(p, (size_t)n));
  config_bind_key(mrb, cfg);
  return self;
}

/* Extra roots. Schannel verifies against the system store by default;
 * these are added to a memory store consulted alongside it. */
static void
config_add_ca_pem(mrb_state *mrb, mrb_tls_config_t *cfg, const std::string &pem)
{
  if (!cfg->ca_store) {
    cfg->ca_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!cfg->ca_store) {
      tls_raise_win(mrb, tls_config_error_class(mrb), "CertOpenStore", (long)GetLastError());
    }
  }
  /* A ca_file may hold several concatenated certificates. */
  size_t pos = 0;
  const char *begin = "-----BEGIN";
  while (true) {
    size_t s = pem.find(begin, pos);
    if (s == std::string::npos) break;
    size_t e = pem.find("-----END", s);
    if (e == std::string::npos) break;
    e = pem.find('\n', e);
    if (e == std::string::npos) e = pem.size(); else e++;
    std::vector<BYTE> der;
    if (pem_to_der(pem.data() + s, e - s, &der)) {
      CertAddEncodedCertificateToStore(cfg->ca_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                       der.data(), (DWORD)der.size(), CERT_STORE_ADD_USE_EXISTING,
                                       NULL);
    }
    pos = e;
  }
}

static mrb_value
config_set_ca_file(mrb_state *mrb, mrb_value self)
{
  const char *path;
  mrb_get_args(mrb, "z", &path);
  config_add_ca_pem(mrb, config_ptr(mrb, self), read_whole_file(mrb, path));
  return self;
}

/* Directory of PEM roots. Enumerated here rather than lazily, so a bad
 * path is a configuration error at startup like every other one. */
static mrb_value
config_set_ca_path(mrb_state *mrb, mrb_value self)
{
  const char *dir;
  mrb_get_args(mrb, "z", &dir);
  mrb_tls_config_t *cfg = config_ptr(mrb, self);

  std::string pat = std::string(dir) + "\\*";
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pat.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) {
    mrb_raisef(mrb, tls_config_error_class(mrb), "cannot read ca_path %s: %s", dir,
               win_error_string((long)GetLastError()).c_str());
  }
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    std::string p = std::string(dir) + "\\" + fd.cFileName;
    config_add_ca_pem(mrb, cfg, read_whole_file(mrb, p.c_str()));
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  return self;
}

static mrb_value
config_set_protocols(mrb_state *mrb, mrb_value self)
{
  mrb_int v;
  mrb_get_args(mrb, "i", &v);
  config_ptr(mrb, self)->protocols = (uint32_t)v;
  return self;
}

static mrb_value
config_set_verify_depth(mrb_state *mrb, mrb_value self)
{
  mrb_int d;
  mrb_get_args(mrb, "i", &d);
  if (d < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "verify_depth must not be negative");
  config_ptr(mrb, self)->verify_depth = (int)d;
  return self;
}

static mrb_value
config_verify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  cfg->verify_cert = cfg->verify_name = cfg->verify_time = 1;
  return self;
}

static mrb_value
config_noverify(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  cfg->verify_cert = cfg->verify_name = cfg->verify_time = 0;
  return self;
}

static mrb_value
config_clear_keys(mrb_state *mrb, mrb_value self)
{
  mrb_tls_config_t *cfg = config_ptr(mrb, self);
  if (cfg->key) {
    NCryptFreeObject(cfg->key);
    cfg->key = 0;
  }
  return self;
}

/* Schannel does not take a cipher list or a group list: the selection is
 * the system's TLS policy, set by administrators through group policy or
 * the registry, and deliberately not per-process. Accepting a spec and
 * ignoring it would be worse than refusing, because a caller pinning a
 * cipher suite for a reason would never learn it had no effect. */
static mrb_value
config_pack_ciphersuites(mrb_state *mrb, mrb_value self)
{
  (void)self;
  mrb_raise(mrb, tls_config_error_class(mrb),
            "Schannel takes no cipher list; suite selection is the system TLS policy");
  return mrb_nil_value();
}

static mrb_value
config_pack_groups(mrb_state *mrb, mrb_value self)
{
  (void)self;
  mrb_raise(mrb, tls_config_error_class(mrb),
            "Schannel takes no group list; group selection is the system TLS policy");
  return mrb_nil_value();
}

/* ------------------------------------------------------------------ */
/* Credentials                                                         */
/* ------------------------------------------------------------------ */

static void
acquire_credentials(mrb_state *mrb, mrb_tls_conn_t *c, mrb_tls_config_t *cfg, bool server)
{
  TLS_PARAMETERS params;
  memset(&params, 0, sizeof(params));
  DWORD disabled = 0;
  if (!(cfg->protocols & MRB_TLS_PROTOCOL_TLSv1_2)) {
    disabled |= server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT;
  }
  if (!(cfg->protocols & MRB_TLS_PROTOCOL_TLSv1_3)) {
    disabled |= server ? SP_PROT_TLS1_3_SERVER : SP_PROT_TLS1_3_CLIENT;
  }
  /* Everything older is off unconditionally, matching the OpenSSL
   * backend's floor. */
  disabled |= server ? (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_SSL3_SERVER |
                        SP_PROT_SSL2_SERVER)
                     : (SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_SSL3_CLIENT |
                        SP_PROT_SSL2_CLIENT);
  params.grbitDisabledProtocols = disabled;

  SCH_CREDENTIALS creds;
  memset(&creds, 0, sizeof(creds));
  creds.dwVersion = SCH_CREDENTIALS_VERSION;
  creds.cTlsParameters = 1;
  creds.pTlsParameters = &params;
  if (cfg->cert) {
    creds.cCreds = 1;
    creds.paCred = (PCCERT_CONTEXT *)&cfg->cert;
  }
  if (!server) {
    /* Verification is driven here rather than by the handshake result,
     * so a noverify config really does not check. */
    creds.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    creds.dwFlags |= cfg->verify_cert ? SCH_CRED_AUTO_CRED_VALIDATION
                                      : SCH_CRED_MANUAL_CRED_VALIDATION;
  }

  TimeStamp expiry;
  SECURITY_STATUS ss = AcquireCredentialsHandleA(
    NULL, (SEC_CHAR *)UNISP_NAME_A, server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL,
    &creds, NULL, NULL, &c->cred, &expiry);
  if (ss != SEC_E_OK) {
    tls_raise_win(mrb, tls_error_class(mrb), "AcquireCredentialsHandle", (long)ss);
  }
  c->have_cred = 1;
}

/* ------------------------------------------------------------------ */
/* Handshake                                                           */
/* ------------------------------------------------------------------ */

/* Returns 1 done, 0 needs more ciphertext, -1 failed. Any token Schannel
 * produced is appended to c->out either way, because a failure often
 * carries the alert that tells the peer why. */
static int
handshake_step(mrb_tls_conn_t *c)
{
  SecBuffer inbuf[2];
  inbuf[0].BufferType = SECBUFFER_TOKEN;
  inbuf[0].pvBuffer = c->in.empty() ? NULL : c->in.data();
  inbuf[0].cbBuffer = (unsigned long)c->in.size();
  inbuf[1].BufferType = SECBUFFER_EMPTY;
  inbuf[1].pvBuffer = NULL;
  inbuf[1].cbBuffer = 0;
  SecBufferDesc in_desc = {SECBUFFER_VERSION, 2, inbuf};

  SecBuffer outbuf[3];
  memset(outbuf, 0, sizeof(outbuf));
  outbuf[0].BufferType = SECBUFFER_TOKEN;
  outbuf[1].BufferType = SECBUFFER_ALERT;
  outbuf[2].BufferType = SECBUFFER_EMPTY;
  SecBufferDesc out_desc = {SECBUFFER_VERSION, 3, outbuf};

  DWORD req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
              ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
  DWORD got = 0;
  TimeStamp expiry;
  SECURITY_STATUS ss;

  if (c->is_server) {
    ss = AcceptSecurityContext(&c->cred, c->have_ctxt ? &c->ctxt : NULL, &in_desc, req,
                               SECURITY_NATIVE_DREP, &c->ctxt, &out_desc, &got, &expiry);
  } else {
    DWORD creq = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                 ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    if (!c->verify_cert) creq |= ISC_REQ_MANUAL_CRED_VALIDATION;
    ss = InitializeSecurityContextA(
      &c->cred, c->have_ctxt ? &c->ctxt : NULL,
      c->target.empty() ? NULL : (SEC_CHAR *)c->target.c_str(), creq, 0, SECURITY_NATIVE_DREP,
      c->have_ctxt ? &in_desc : NULL, 0, &c->ctxt, &out_desc, &got, &expiry);
  }

  if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE ||
      FAILED(ss)) {
    /* Emit whatever was produced, including an alert on failure. */
    for (int i = 0; i < 3; i++) {
      if (outbuf[i].cbBuffer && outbuf[i].pvBuffer) {
        const char *p = (const char *)outbuf[i].pvBuffer;
        c->out.insert(c->out.end(), p, p + outbuf[i].cbBuffer);
        FreeContextBuffer(outbuf[i].pvBuffer);
        outbuf[i].pvBuffer = NULL;
      }
    }
  }

  if (ss == SEC_E_INCOMPLETE_MESSAGE) return 0; /* keep c->in intact */

  if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
    c->have_ctxt = 1;
    /* Anything Schannel did not consume is the start of the next record
     * (or of application data) and must survive. */
    if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer) {
      const size_t keep = inbuf[1].cbBuffer;
      c->in.erase(c->in.begin(), c->in.end() - (ptrdiff_t)keep);
    } else {
      c->in.clear();
    }
    if (ss == SEC_E_OK) {
      c->handshaked = 1;
      if (QueryContextAttributes(&c->ctxt, SECPKG_ATTR_STREAM_SIZES, &c->sizes) == SEC_E_OK) {
        c->have_sizes = 1;
      }
      return 1;
    }
    return 0;
  }

  return -1;
}

#endif  // MRUBY_TLS_BACKEND_SCHANNEL_HPP
