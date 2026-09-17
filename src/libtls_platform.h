#ifndef MRUBY_LIBTLS_PLATFORM_H
#define MRUBY_LIBTLS_PLATFORM_H

/* Which TLS library libtls is built against, and what it does not have.
 *
 * libtls is OpenBSD's, and OpenBSD builds it against LibreSSL. Three
 * other libraries offer the same headers and answer to most of the same
 * names. This file says which one is in the build and fills the gaps
 * that library leaves. The build forces this header into every libtls
 * source, so the imported files under deps/libtls stay as close to the
 * release as the port allows.
 *
 * What each library lacks was measured, not assumed: every libtls source
 * was compiled against each library's headers and the missing names
 * counted. The numbers are in the README.
 */

/* libtls gates its own error codes on this: it means "the build is the
 * library, not a caller of it". That is what this build is, whichever
 * TLS library sits underneath. */
#ifndef LIBRESSL_INTERNAL
#define LIBRESSL_INTERNAL 1
#endif

/* opensslv.h names the vendor at compile time. */
#include <openssl/opensslv.h>

#if defined(LIBRESSL_VERSION_NUMBER)
#define TLS_LIBRARY_LIBRESSL 1
#define TLS_LIBRARY_NAME "LibreSSL"
#elif defined(OPENSSL_IS_AWSLC)
#define TLS_LIBRARY_AWSLC 1
#define TLS_LIBRARY_NAME "AWS-LC"
#elif defined(OPENSSL_IS_BORINGSSL)
#define TLS_LIBRARY_BORINGSSL 1
#define TLS_LIBRARY_NAME "BoringSSL"
#else
#define TLS_LIBRARY_OPENSSL 1
#define TLS_LIBRARY_NAME "OpenSSL"
#endif

/* OCSP. BoringSSL has no ocsp.h at all - the API was removed, not
 * renamed - and sixteen of libtls's own functions rest on it. So on
 * BoringSSL those sixteen are not built and not declared. A caller that
 * wants one gets a compile error naming it, which is the earliest and
 * loudest way to say that this library does not do that. */
#ifndef TLS_LIBRARY_BORINGSSL
#define TLS_HAS_OCSP 1
#endif

/* OpenBSD marks a library's own declarations hidden. Outside its tree
 * the marker has nothing to do. */
#ifndef __BEGIN_HIDDEN_DECLS
#define __BEGIN_HIDDEN_DECLS
#define __END_HIDDEN_DECLS
#endif

#include <openssl/ssl.h>

/* LibreSSL refuses the renegotiation a client asks for; OpenSSL and its
 * forks refuse every renegotiation. TLS 1.3 has none at all, and for
 * 1.2 the wider refusal is the safer one, so the wider name answers
 * where the narrow one is absent. */
#ifndef SSL_OP_NO_CLIENT_RENEGOTIATION
#define SSL_OP_NO_CLIENT_RENEGOTIATION SSL_OP_NO_RENEGOTIATION
#endif

#include <time.h>

/* What libtls asks of LibreSSL and no other library answers.
 *
 * Every one of these is a name, so a macro can send the call somewhere
 * else and the imported sources under deps/libtls need no edit. That is
 * the whole point: the port is additive, and a later LibreSSL release
 * merges without a conflict.
 *
 * The macros come after <openssl/ssl.h> above, so they rewrite libtls's
 * calls and never that header's own declarations. */
#ifndef TLS_LIBRARY_LIBRESSL

/* A leaf and its chain, read from PEM in memory. Answers 1, or 0 with
 * the reason on the library's error queue. */
int tls_compat_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len);

/* Trusted certificates, read from PEM in memory into the context's
 * verify store. Answers 1, or 0 with the reason on the queue. */
int tls_compat_load_verify_mem(SSL_CTX *ctx, void *buf, int len);

/* libtls asks for the trust store with both names NULL when a config
 * named neither a CA file nor a CA path. LibreSSL reads that as "the
 * usual place for this system"; OpenSSL refuses the call. So the usual
 * place is asked for by its own name. */
int tls_compat_load_verify_locations(SSL_CTX *ctx, const char *file, const char *path);

/* libtls asks for its own default suites in LibreSSL's cipher grammar,
 * which no other library parses. The one string that uses it is mapped;
 * anything else a caller wrote goes through untouched. */
int tls_compat_set_cipher_list(SSL_CTX *ctx, const char *list);

#define SSL_CTX_set_cipher_list tls_compat_set_cipher_list
#define SSL_CTX_use_certificate_chain_mem tls_compat_use_certificate_chain_mem
#define SSL_CTX_load_verify_mem tls_compat_load_verify_mem
#define SSL_CTX_load_verify_locations tls_compat_load_verify_locations

#endif /* !TLS_LIBRARY_LIBRESSL */

#endif /* MRUBY_LIBTLS_PLATFORM_H */
