/* What libtls asks of LibreSSL and no other library answers.
 *
 * Three functions, written here against the public API of OpenSSL 3 and
 * its forks. LibreSSL has all three of its own, so none of this is
 * built there.
 *
 * Copyright (c) 2026 the mruby-tls authors
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "libtls_platform.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* The header above sends libtls's calls here. This file needs the
 * library's own, so the name is given back before it is used. */
#undef SSL_CTX_load_verify_locations
#undef SSL_CTX_set_cipher_list

#ifndef TLS_LIBRARY_LIBRESSL

int
tls_compat_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len)
{
	BIO *bio = NULL;
	X509 *leaf = NULL, *next = NULL;
	int ok = 0;

	if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
		goto done;

	/* The first certificate is the leaf. PEM_read_bio_X509_AUX reads
	 * the trust settings openssl writes beside it, where there are
	 * any, and a plain certificate where there are none. */
	if ((leaf = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)) == NULL)
		goto done;
	if (SSL_CTX_use_certificate(ctx, leaf) != 1)
		goto done;

	/* Everything after the leaf is the chain, in the order it was
	 * written. The context takes each one. */
	if (SSL_CTX_clear_chain_certs(ctx) != 1)
		goto done;
	while ((next = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		if (SSL_CTX_add0_chain_cert(ctx, next) != 1)
			goto done;
		next = NULL; /* the context owns it now */
	}

	/* The loop ends on a read error, and the end of the buffer is
	 * one. Anything else is a certificate this could not read, and
	 * the queue says which. */
	if (ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE)
		goto done;
	ERR_clear_error();
	ok = 1;

 done:
	X509_free(next);
	X509_free(leaf);
	BIO_free(bio);
	return ok;
}

int
tls_compat_load_verify_mem(SSL_CTX *ctx, void *buf, int len)
{
	STACK_OF(X509_INFO) *infos = NULL;
	X509_STORE *store;
	BIO *bio = NULL;
	int i, count = 0, ok = 0;

	if ((store = SSL_CTX_get_cert_store(ctx)) == NULL)
		goto done;
	if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
		goto done;
	if ((infos = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL)) == NULL)
		goto done;

	for (i = 0; i < sk_X509_INFO_num(infos); i++) {
		X509_INFO *info = sk_X509_INFO_value(infos, i);

		if (info->x509 == NULL)
			continue;
		if (X509_STORE_add_cert(store, info->x509) != 1)
			goto done;
		count++;
	}

	/* A buffer that held no certificate is a caller's mistake, and
	 * answering 1 would leave an empty trust store looking
	 * configured. */
	if (count == 0)
		goto done;
	ok = 1;

 done:
	sk_X509_INFO_pop_free(infos, X509_INFO_free);
	BIO_free(bio);
	return ok;
}

/* What libtls asks for, and what this library has to be told instead.
 *
 * A table and not a chain of tests, because a claim that two spellings
 * name the same thing is a claim a test must be able to walk. test/
 * walks these rows and asks the library what each one actually offers.
 *
 * "exact" says the two name the same set of suites. Nothing here is
 * approximate; a row that were would say so and name what it loses.
 */
struct cipher_row {
	const char *asked;   /* what libtls passes, in LibreSSL's grammar */
	const char *given;   /* what this library is told instead */
	const char *why;
};

static const struct cipher_row cipher_rows[] = {
	{
		"TLSv1.3:TLSv1.2+AEAD+ECDHE:TLSv1.2+AEAD+DHE",
		"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20",
		/* exact. "TLSv1.3" and "AEAD" are words only LibreSSL
		 * parses. Here the TLS 1.3 suites are a list of their
		 * own that this call does not touch, and its default is
		 * those three suites, so naming the TLS 1.2 half leaves
		 * the same set offered. */
		"TLSv1.3 and AEAD are LibreSSL words; the 1.3 suites are a separate list here"
	},
};

/* The other three sets libtls names - compat, legacy and all - are
 * already plain grammar every library parses, so they have no row. */

const struct cipher_row *tls_compat_cipher_rows(size_t *count);

const struct cipher_row *
tls_compat_cipher_rows(size_t *count)
{
	*count = sizeof(cipher_rows) / sizeof(cipher_rows[0]);
	return cipher_rows;
}

int
tls_compat_set_cipher_list(SSL_CTX *ctx, const char *list)
{
	size_t i;

	if (list != NULL) {
		for (i = 0; i < sizeof(cipher_rows) / sizeof(cipher_rows[0]); i++) {
			if (strcmp(list, cipher_rows[i].asked) == 0) {
				list = cipher_rows[i].given;
				break;
			}
		}
	}
	/* Anything a caller wrote goes through untouched, and the
	 * library judges it. */
	return (SSL_CTX_set_cipher_list)(ctx, list);
}

int
tls_compat_load_verify_locations(SSL_CTX *ctx, const char *file, const char *path)
{
	if (file == NULL && path == NULL)
		return SSL_CTX_set_default_verify_paths(ctx);
	return (SSL_CTX_load_verify_locations)(ctx, file, path);
}

#endif /* !TLS_LIBRARY_LIBRESSL */

#ifndef TLS_LIBRARY_LIBRESSL

/* The two functions of LibreSSL's <openssl/posix_time.h>.
 *
 * libtls calls them to turn a certificate's notBefore and notAfter into
 * seconds. src/compat/openssl/posix_time.h stands in for the header on
 * every other library, and these stand in for the functions.
 */

/* Days from 1970-01-01 to the given civil date, for any year the
 * arithmetic can hold. This is the shift-the-era method: move the start
 * of the year to March, so a leap day is the last day of a year and
 * never a day in the middle of one, and the leap rule becomes
 * arithmetic with no branches. */
static int64_t
days_from_civil(int64_t year, unsigned month, unsigned day)
{
	int64_t era, year_of_era;
	unsigned day_of_year, day_of_era;

	year -= month <= 2;
	era = (year >= 0 ? year : year - 399) / 400;
	year_of_era = year - era * 400;                       /* 0 .. 399 */
	day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	return era * 146097 + (int64_t)day_of_era - 719468;
}

int
OPENSSL_tm_to_posix(const struct tm *tm, int64_t *out)
{
	int64_t days;

	/* The fields a certificate's time carries. A month or a day
	 * outside its range is a time this cannot name, and it says so
	 * rather than answering a day that is not the one asked for. */
	if (tm->tm_mon < 0 || tm->tm_mon > 11)
		return 0;
	if (tm->tm_mday < 1 || tm->tm_mday > 31)
		return 0;
	if (tm->tm_hour < 0 || tm->tm_hour > 23)
		return 0;
	if (tm->tm_min < 0 || tm->tm_min > 59)
		return 0;
	if (tm->tm_sec < 0 || tm->tm_sec > 60)   /* a leap second is legal */
		return 0;

	days = days_from_civil((int64_t)tm->tm_year + 1900,
	    (unsigned)tm->tm_mon + 1, (unsigned)tm->tm_mday);
	*out = days * 86400 + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
	return 1;
}

int
OPENSSL_timegm(const struct tm *tm, time_t *out)
{
	int64_t seconds;
	time_t t;

	if (!OPENSSL_tm_to_posix(tm, &seconds))
		return 0;

	/* Whether this system's time_t can name that instant. The test
	 * is a round trip through the type, so the type answers it and
	 * no number of ours does. */
	t = (time_t)seconds;
	if ((int64_t)t != seconds)
		return 0;
	*out = t;
	return 1;
}

#endif /* !TLS_LIBRARY_LIBRESSL */

/* freezero and timingsafe_memcmp come from the same LibreSSL release,
 * under deps/libtls/compat. They are OpenBSD's C library, and
 * timingsafe_memcmp compares a MAC in constant time, so it is taken
 * from a reviewed source rather than written here. */
