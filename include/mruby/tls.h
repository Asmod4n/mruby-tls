#ifndef MRUBY_TLS_H
#define MRUBY_TLS_H

#include <mruby.h>

MRB_BEGIN_DECL

#define E_TLS_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Error"))
#define E_TLS_CONFIG_ERROR (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Config"), "Error"))

/*
 * TLS for a caller that owns its own I/O.
 *
 * Everything else in this gem drives TLS through a socket. These
 * functions remove the transport instead: the caller feeds ciphertext in
 * as it arrives, takes whatever ciphertext the library produced back out
 * and writes it however it likes, and drives the handshake with plain
 * want-more semantics. Nothing here touches a descriptor, which is what
 * makes it usable from an event loop whose "socket" may not be a
 * process-level fd at all (an io_uring adapter reading into kernel
 * buffers against registered descriptors, say).
 *
 * No provider type appears in any signature below, on purpose: this is
 * the contract a second implementation (Schannel) has to satisfy, not a
 * view of OpenSSL.
 *
 * `conn` is always a Tls connection returned by mrb_tls_accept_memory() -
 * an ordinary Ruby object, so its lifetime is the GC's problem as usual;
 * keep it reachable for as long as the connection lives. Passing any
 * other TLS object raises.
 *
 * Typical loop, per connection:
 *
 *   conn = mrb_tls_accept_memory(mrb, server);
 *   ... on ciphertext arriving:
 *         mrb_tls_feed(mrb, conn, buf, len);
 *         if (mrb_tls_handshake_memory(mrb, conn) < 0) drop;
 *         ... then mrb_tls_read_memory() for plaintext,
 *             mrb_tls_write_memory() for the response
 *   ... after any of the above, flush what it produced:
 *         n = mrb_tls_pending(mrb, conn, &out);
 *         if (n) { write(out, n); mrb_tls_drain(mrb, conn, n); }
 */

/* A server-side connection with no socket behind it. `server` is a
 * Tls::Server; the connection borrows its Config and SNI handler exactly
 * as Tls::Server#accept_socket's does. */
MRB_API mrb_value mrb_tls_accept_memory(mrb_state *mrb, mrb_value server);

/* Hand over ciphertext that arrived from the peer. 0 on success, -1 if
 * the buffer could not grow. */
MRB_API int mrb_tls_feed(mrb_state *mrb, mrb_value conn, const void *buf, size_t len);

/* Ciphertext waiting to go to the peer. Returns its length and, unless
 * `buf` is NULL, points it at the bytes. Valid until the next call that
 * can produce more output. */
MRB_API size_t mrb_tls_pending(mrb_state *mrb, mrb_value conn, const unsigned char **buf);

/* Discards the first `len` bytes of the pending output, after writing
 * them. */
MRB_API void mrb_tls_drain(mrb_state *mrb, mrb_value conn, size_t len);

/* 1 = handshake complete, 0 = needs more ciphertext, -1 = failed. */
MRB_API int mrb_tls_handshake_memory(mrb_state *mrb, mrb_value conn);

/* >0 = plaintext bytes written to `buf`, 0 = needs more ciphertext,
 * -1 = peer closed cleanly or the connection failed. */
MRB_API int mrb_tls_read_memory(mrb_state *mrb, mrb_value conn, void *buf, size_t len);

/* Encrypts `len` bytes; the ciphertext lands in the pending-output buffer
 * above. Returns bytes accepted, or -1 on failure. */
MRB_API int mrb_tls_write_memory(mrb_state *mrb, mrb_value conn, const void *buf, size_t len);

MRB_END_DECL

#endif
