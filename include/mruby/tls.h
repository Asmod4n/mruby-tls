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

/* Queues a close_notify alert into the outgoing BIO. Flush it with
 * mrb_tls_pending/mrb_tls_drain before closing the socket: OpenSSL 3.x
 * treats a connection that ends without one as a hard error
 * (SSL_R_UNEXPECTED_EOF_WHILE_READING), not a clean EOF. */
MRB_API int mrb_tls_shutdown_memory(mrb_state *mrb, mrb_value conn);

/* ------------------------------------------------------------------ */
/* Kernel TLS TX handover                                              */
/* ------------------------------------------------------------------ */

/* Hand the record layer for the SEND direction to the kernel, so bulk
 * bytes can be write(2)'d or splice(2)'d as plaintext and encrypted on
 * the way out.
 *
 * This deliberately does NOT touch a socket, and does not use OpenSSL's
 * own SSL_OP_ENABLE_KTLS: that path only works when OpenSSL owns a
 * socket BIO and performs the setsockopt itself, and a caller in
 * io_uring direct-descriptor mode has no process fd to give it - the
 * connection lives in the ring's file table and never gets one. So this
 * hands out the key material instead and the caller installs it however
 * it reaches its socket.
 *
 * The kernel's own tls12_crypto_info_* structs are Linux headers, so
 * they are not used here. The caller builds them from these fields:
 * for TLS 1.3 the derived 12-byte nonce splits into salt (first 4) and
 * iv (last 8), and rec_seq is what the kernel starts counting from.
 *
 * Requires Config#ktls_tx = true BEFORE the handshake: the key material
 * is captured during it, and enabling it also disables session tickets
 * so that nothing is written under the application keys before handover
 * and rec_seq is exactly 0.
 *
 * RULES AFTER A SUCCESSFUL CALL, both of which corrupt the stream if
 * broken, because the kernel now owns the sequence number:
 *   - OpenSSL must never write on this connection again. No
 *     mrb_tls_write_memory, and no mrb_tls_shutdown_memory - the
 *     close_notify would carry a stale sequence.
 *   - RX is unaffected and stays with OpenSSL for the connection's
 *     life; keep feeding it as before.
 *
 * A TLS 1.3 KeyUpdate from the peer asks for a server key the kernel
 * does not have. Until TX rekey is wired, a caller that sees one must
 * close the connection. */

#define MRB_TLS_KTLS_AES_GCM_128       1
#define MRB_TLS_KTLS_AES_GCM_256       2
#define MRB_TLS_KTLS_CHACHA20_POLY1305 3

typedef struct mrb_tls_ktls_tx {
  int cipher;                 /* MRB_TLS_KTLS_* */
  int version;                /* 0x0304 = TLS 1.3 */
  unsigned char key[32];
  size_t key_len;             /* 16 or 32 */
  unsigned char iv[12];       /* full derived nonce; split 4 + 8 */
  size_t iv_len;              /* always 12 */
  unsigned char rec_seq[8];   /* 0 for a TLS 1.3 handover */
} mrb_tls_ktls_tx_t;

/* 0 on success, -1 if unavailable - not enabled before the handshake,
 * handshake not finished, not TLS 1.3, or an unsupported cipher. Never
 * raises: a caller that cannot get this simply keeps using
 * mrb_tls_write_memory. */
MRB_API int mrb_tls_ktls_tx_params(mrb_state *mrb, mrb_value conn, mrb_tls_ktls_tx_t *out);

MRB_END_DECL

#endif
