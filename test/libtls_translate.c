/* The translation table, walked.
 *
 * src/libtls_compat.c claims that where libtls asks for suites in
 * LibreSSL's grammar, this library is told a spelling that names the
 * same set. A comment cannot carry that claim, so this asks the library
 * what each row actually offers.
 *
 * It does not compare against LibreSSL, which would need LibreSSL here.
 * It checks the property the LibreSSL string names, which is the
 * stronger question and the same on every library.
 */

#include "libtls_platform.h"

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

/* The platform header sends this name at the shim. These macros are
 * object-like, so parentheses do not suppress them and the real
 * function has to be named back. This test exists to compare the two,
 * so it needs both. */
#undef SSL_CTX_set_cipher_list

struct cipher_row {
	const char *asked;
	const char *given;
	const char *why;
};
const struct cipher_row *tls_compat_cipher_rows(size_t *count);

static int failures;

static void
fail(const char *what, const char *detail)
{
	printf("  NOT ok: %s: %s\n", what, detail);
	failures++;
}

/* Every suite this context offers, judged against what the row's
 * LibreSSL spelling promises: the TLS 1.3 suites, and of the older ones
 * only those that are AEAD and agree their key with ECDHE or DHE. */
static void
check_offered(SSL_CTX *ctx, const char *label)
{
	STACK_OF(SSL_CIPHER) *suites = SSL_CTX_get_ciphers(ctx);
	int i, tls13 = 0, older = 0;

	if (suites == NULL || sk_SSL_CIPHER_num(suites) == 0) {
		fail(label, "the library offers no suite at all");
		return;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(suites); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(suites, i);
		const char *version = SSL_CIPHER_get_version(c);
		int kx;

		if (strcmp(version, "TLSv1.3") == 0) {
			tls13++;
			continue;
		}
		older++;

		if (!SSL_CIPHER_is_aead(c)) {
			fail(label, SSL_CIPHER_get_name(c));
			printf("    that suite is not AEAD, and the row promises only AEAD\n");
			continue;
		}
		kx = SSL_CIPHER_get_kx_nid(c);
		if (kx != NID_kx_ecdhe && kx != NID_kx_dhe) {
			fail(label, SSL_CIPHER_get_name(c));
			printf("    that suite agrees its key another way than ECDHE or DHE\n");
		}
	}

	if (tls13 == 0)
		fail(label, "no TLS 1.3 suite is offered, and the row promises them");
	if (older == 0)
		fail(label, "no TLS 1.2 suite is offered, and the row promises them");
	printf("  ok: %s offers %d TLS 1.3 suites and %d older ones, all AEAD with ECDHE or DHE\n",
	    label, tls13, older);
}

int
main(void)
{
	const struct cipher_row *rows;
	size_t count, i;

	printf("library: %s\n", TLS_LIBRARY_NAME);
	rows = tls_compat_cipher_rows(&count);
	printf("rows: %zu\n", count);

	for (i = 0; i < count; i++) {
		SSL_CTX *plain, *through;

		/* Why the row exists: this library refuses the spelling
		 * libtls asks for. On LibreSSL it is accepted, and the
		 * row would then be dead weight, so the same test says
		 * the opposite there. */
		if ((plain = SSL_CTX_new(TLS_method())) == NULL)
			return 1;
		{
			int took = (SSL_CTX_set_cipher_list)(plain, rows[i].asked);
#ifdef TLS_LIBRARY_LIBRESSL
			if (took != 1)
				fail("the row's own library", "LibreSSL refused its own spelling");
			else
				printf("  ok: LibreSSL takes its own spelling, as it must\n");
#else
			if (took == 1)
				fail("the row is not needed",
				    "this library takes LibreSSL's spelling, so the row is dead");
			else
				printf("  ok: this library refuses LibreSSL's spelling, so the row earns its place\n");
#endif
		}
		SSL_CTX_free(plain);

		/* And what the translation offers. */
		if ((through = SSL_CTX_new(TLS_method())) == NULL)
			return 1;
		if (tls_compat_set_cipher_list(through, rows[i].asked) != 1) {
			fail("the translated spelling", "the library refused it");
			SSL_CTX_free(through);
			continue;
		}
		check_offered(through, "the translated spelling");
		SSL_CTX_free(through);
	}

	printf(failures == 0 ? "ok\n" : "NOT ok: %d\n", failures);
	return failures == 0 ? 0 : 1;
}
