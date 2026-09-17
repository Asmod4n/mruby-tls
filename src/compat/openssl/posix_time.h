#ifndef MRUBY_TLS_COMPAT_POSIX_TIME_H
#define MRUBY_TLS_COMPAT_POSIX_TIME_H

/* LibreSSL's <openssl/posix_time.h>, for the libraries that have none.
 *
 * libtls includes this header and calls the two functions in it. The
 * header exists only in LibreSSL, so this stands in its place on the
 * include path of every other library, and src/libtls_compat.c defines
 * the two. That way the imported sources under deps/libtls need no edit
 * at all, and a later LibreSSL release merges without a conflict.
 */

#include <stdint.h>
#include <time.h>

/* A broken down time as a time_t. Answers 1 and writes it, or 0 where
 * this system's time_t cannot name that instant. */
int OPENSSL_timegm(const struct tm *tm, time_t *out);

/* The same instant as a count of seconds since the epoch, with the
 * range of the C library's time_t taken out of the question. Answers 1
 * and writes it, or 0 where the fields do not name a day. */
int OPENSSL_tm_to_posix(const struct tm *tm, int64_t *out);

#endif /* MRUBY_TLS_COMPAT_POSIX_TIME_H */
