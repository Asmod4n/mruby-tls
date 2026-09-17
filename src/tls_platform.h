#ifndef MRUBY_TLS_PLATFORM_H
#define MRUBY_TLS_PLATFORM_H

/* What this build sits on, read once and named once.
 *
 * Two questions are answered here and nowhere else: which TLS library
 * this is, and whether this system has a kernel record layer. Every
 * other file asks these names rather than testing macros of its own, so
 * a third library or a fourth system is one edit here.
 */

#ifdef _WIN32
#define TLS_LIBRARY_SCHANNEL 1
#define TLS_LIBRARY_NAME "Schannel"
#else

#include <openssl/opensslv.h>

/* opensslv.h names the vendor at compile time, and each of them defines
 * exactly one of these. The order matters: LibreSSL and BoringSSL both
 * claim an OPENSSL_VERSION_NUMBER, so they are asked about first. */
#if defined(LIBRESSL_VERSION_NUMBER)
#define TLS_LIBRARY_LIBRESSL 1
#define TLS_LIBRARY_NAME "LibreSSL"
#elif defined(OPENSSL_IS_BORINGSSL)
#define TLS_LIBRARY_BORINGSSL 1
#define TLS_LIBRARY_NAME "BoringSSL"
#elif defined(OPENSSL_IS_AWSLC)
#define TLS_LIBRARY_AWSLC 1
#define TLS_LIBRARY_NAME "AWS-LC"
#else
#define TLS_LIBRARY_OPENSSL 1
#define TLS_LIBRARY_NAME "OpenSSL"
#endif

#endif /* _WIN32 */

/* The kernel record layer, and the three conditions it takes. Linux is
 * the system, OpenSSL is the library whose key schedule this tree
 * derives from, and 3.0 is the version whose keylog callback carries the
 * traffic secrets. Anything else compiles the handover out: the plan is
 * never offered, the reason names the library or the system, and
 * mrb_tls_session_mode answers userspace. */
#if defined(__linux__) && defined(TLS_LIBRARY_OPENSSL) && defined(OPENSSL_VERSION_MAJOR) && \
    OPENSSL_VERSION_MAJOR >= 3
#define TLS_KERNEL_RECORDS 1
#endif

/* Nothing else is defined here.
 *
 * A fallback for a system constant belongs beside the header that
 * declares it and never before one: glibc spells the MSG_* family as an
 * enum, so a define of MSG_NOSIGNAL ahead of <sys/socket.h> turns an
 * enumerator into a numeral and the include stops compiling. The two
 * numbers the handover needs sit in tls_keys.hpp, after <linux/tls.h>
 * has had its say.
 */

#endif /* MRUBY_TLS_PLATFORM_H */
