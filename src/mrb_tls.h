#ifndef MRB_TLS_H
#define MRB_TLS_H

/* Targets real MSVC only -- MinGW/Cygwin already have working POSIX
 * headers and fall through the non-Windows branches below. */
#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <mruby.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>

/* MSVC's CRT has no POSIX ssize_t/S_ISDIR/S_ISREG; both used throughout
 * mrb_tls.cpp. */
#ifdef _MSC_VER
#include <BaseTsd.h>
#ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#endif

/* ecp.h is gone from mbedTLS 4.x's public include path; mrb_tls_parse_groups()
 * looks curve names up in its own static table instead. */
#include <mbedtls/build_info.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/secure_wipe_memory.h>
#include <mruby/string.h>
#include <mruby/variable.h>

/* Ruby-visible (Tls::Protocol::*), reproduced bit for bit from LibreSSL
 * 4.0.0's <tls.h>. See mrb_tls_protocols_to_versions() for the 1.0/1.1
 * clamping this implies. */
#define MRB_TLS_PROTOCOL_TLSv1_0 (1 << 1)
#define MRB_TLS_PROTOCOL_TLSv1_1 (1 << 2)
#define MRB_TLS_PROTOCOL_TLSv1_2 (1 << 3)
#define MRB_TLS_PROTOCOL_TLSv1_3 (1 << 4)

#define MRB_TLS_PROTOCOL_TLSv1 \
  (MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3)

#define MRB_TLS_PROTOCOLS_ALL MRB_TLS_PROTOCOL_TLSv1
#define MRB_TLS_PROTOCOLS_DEFAULT \
  (MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3)

/* libtls's default; passed on to the certificate chain length check. */
#define MRB_TLS_DEFAULT_VERIFY_DEPTH 6

/* Tls::Config backing store: a pure settings bag, materialised into an
 * mbedtls_ssl_config only at connect/accept time (matching libtls). String/
 * blob settings live as mrb_value String ivars on the Ruby object instead
 * of here -- see mrb_tls_ivar_str_set()/mrb_tls_ivar_buf_set(). */
typedef struct mrb_tls_config {
  uint32_t protocols;
  int verify_depth;
  /*
   * The three independent verification axes libtls exposes.  1 = enforced.
   * Config#verify re-enables all three, Config#noverify(mode) turns exactly
   * one of them off.
   */
  int verify_cert;
  int verify_name;
  int verify_time;

  /*
   * Lazily parsed from this Config's own cert_file/cert_mem + key_file/
   * key_mem ivars the first time it is selected as an SNI certificate (see
   * mrb_tls_config_ensure_cert() in mrb_tls.cpp) -- reused by every
   * connection that resolves to this same Config afterward instead of
   * re-parsing the same PEM text on every single handshake. Left unused
   * (cert_loaded stays 0) by the ordinary, non-SNI path: a Context's own
   * default certificate is still parsed straight into the Context's own
   * ctx->cert/ctx->pk in mrb_tls_ctx_setup(), exactly as before.
   */
  mbedtls_x509_crt cert;
  mbedtls_pk_context pk;
  int cert_loaded;
} mrb_tls_config_t;

/* Tls::Context (and Tls::Client/Tls::Server) backing store. Owns everything
 * the mbedtls_ssl_config points at. ciphersuites/groups/hostname live as
 * ivars on the Ruby Context object instead (must outlive ctx->conf/ctx->ssl,
 * which an ivar does for free). */
typedef struct mrb_tls_ctx {
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;   /* trust anchors                       */
  mbedtls_x509_crt cert; /* our own certificate chain           */
  mbedtls_pk_context pk; /* our own private key                 */

  int fd_read;
  int fd_write;
  int own_fd;   /* we created the socket ourselves in #connect */
  int endpoint; /* MBEDTLS_SSL_IS_CLIENT / MBEDTLS_SSL_IS_SERVER */

  int setup;       /* mbedtls_ssl_setup() has run          */
  int handshaked;  /* handshake completed and verified     */
  int close_sent;  /* close_notify already emitted         */

  /* verification policy snapshot, read by mrb_tls_verify_cb() */
  int authmode;
  int verify_cert;
  int verify_name;
  int verify_time;
  int verify_depth;

  mrb_tls_config_t *cfg; /* borrowed from whichever Tls::Config is in
                           * play (explicit or implicit); kept alive by
                           * an ivar on the Context -- see mrb_tls.cpp. */

  /* Set once per mrb_tls_ctx_setup() call so the BIO callbacks (which only
   * get the raw `void *p_bio` mbedTLS hands them) can reach back into
   * mruby -- self is safe to store by value here: ctx is self's own DATA_PTR,
   * so ctx is only ever alive/consulted while self is already reachable
   * (either on the call stack directly, or via the resume Procs' own REnv,
   * which is a real GC root -- see mrb_tls_bio_send/recv). */
  mrb_state *mrb;
  mrb_value self;
} mrb_tls_ctx_t;

void mrb_tls_config_destroy(mrb_state *mrb, mrb_tls_config_t *cfg);

static void
mrb_tls_config_free(mrb_state *mrb, void *p)
{
  if (p) {
    mrb_tls_config_destroy(mrb, (mrb_tls_config_t *)p);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type tls_config_type = {
  "$i_tls_config", mrb_tls_config_free
};

void mrb_tls_ctx_destroy(mrb_state *mrb, mrb_tls_ctx_t *ctx);

static void
mrb_tls_free(mrb_state *mrb, void *p)
{
  if (p) {
    mrb_tls_ctx_destroy(mrb, (mrb_tls_ctx_t *)p);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type tls_type = {
  "$i_tls", mrb_tls_free
};

#endif
