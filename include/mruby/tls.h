#ifndef MRUBY_TLS_H
#define MRUBY_TLS_H

/* TLS over the caller's own I/O.
 *
 * A session here never owns a socket and never reads or writes one. The
 * caller hands in a table of callbacks and the session asks them for
 * every byte it needs. That is what lets a session sit on a ZMQ socket,
 * a libuv handle, a memory pipe between two threads, or a descriptor
 * that only exists inside an io_uring file table and has no number a
 * process could pass to anyone.
 *
 * Two record layers answer the same calls:
 *
 *   userspace  the TLS library holds the records. Every byte goes
 *              through the read and write callbacks as ciphertext.
 *   kernel     the kernel holds them, after the caller's own socket
 *              option hook attached them. read and write then carry
 *              plaintext and the library does setup and rekeying only.
 *
 * The session decides which one it is in, once, at the end of the
 * handshake, and mrb_tls_session_mode says what it decided. Both are
 * success. A caller that cannot offer a socket option hook, or whose
 * kernel refuses the handover, gets the userspace layer and a reason it
 * can print.
 *
 * No provider type appears in any signature below. OpenSSL implements
 * this on the systems that have it and Schannel implements it on
 * Windows, and a caller cannot tell from the API which one answered.
 *
 * Nothing here includes mruby. The macros at the end appear only when
 * mruby.h was included first, so a plain C program links against this
 * header alone.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* What a call answers                                                 */
/* ------------------------------------------------------------------ */

/* Every fallible call answers one of these.
 *
 * MRB_TLS_AGAIN_READ and MRB_TLS_AGAIN_WRITE name what the transport
 * has to do before the same call is made again: the peer's bytes have
 * to arrive, or the bytes already handed to the write callback have to
 * leave. The session keeps its place, so the call is repeated and not
 * restarted.
 *
 * MRB_TLS_CLOSED is the peer's own close_notify, read on a session that
 * is still sound. A stream that simply stops without one is a failure
 * of kind MRB_TLS_ERR_IO, because a truncation and a close are not the
 * same event.
 *
 * MRB_TLS_FAILED leaves the reason in mrb_tls_session_error or
 * mrb_tls_config_error. */
typedef enum {
  MRB_TLS_OK = 0,
  MRB_TLS_AGAIN_READ,
  MRB_TLS_AGAIN_WRITE,
  MRB_TLS_CLOSED,
  MRB_TLS_FAILED
} mrb_tls_status;

/* What kind of failure it was. The kind decides what a caller can do
 * about it, which is why it is a kind and not a string.
 *
 * ARGUMENT and STATE are the caller's own mistake: a wrong value, or a
 * call in the wrong order. Everything else happened on the wire or
 * underneath. */
typedef enum {
  MRB_TLS_ERR_NONE = 0,
  MRB_TLS_ERR_ARGUMENT, /* a value this call cannot take */
  MRB_TLS_ERR_STATE,    /* right call, wrong moment */
  MRB_TLS_ERR_IO,       /* the transport said so; errno carries its word */
  MRB_TLS_ERR_LIBRARY,  /* the TLS library itself; code carries its word */
  MRB_TLS_ERR_VERIFY,   /* the peer's certificate was refused */
  MRB_TLS_ERR_PROTOCOL, /* the peer broke the protocol */
  MRB_TLS_ERR_ALERT,    /* the peer sent an alert; errno is its description */
  MRB_TLS_ERR_KERNEL,   /* the kernel refused a handover it had begun */
  MRB_TLS_ERR_MEMORY
} mrb_tls_error_kind;

/* Which record layer holds this session's records. */
typedef enum {
  MRB_TLS_MODE_UNDECIDED = 0, /* the handshake has not finished */
  MRB_TLS_MODE_USERSPACE,
  MRB_TLS_MODE_KERNEL
} mrb_tls_mode;

typedef enum { MRB_TLS_CLIENT = 0, MRB_TLS_SERVER } mrb_tls_role;

/* The protocol bits, unchanged from the versions of this gem that came
 * before, so a caller that carries them across an upgrade keeps its
 * meaning. TLS 1.0 and 1.1 have names here and are refused: a mask that
 * asks only for them is an argument error rather than a silent
 * widening. */
#define MRB_TLS_PROTOCOL_TLSv1_0 (1u << 1)
#define MRB_TLS_PROTOCOL_TLSv1_1 (1u << 2)
#define MRB_TLS_PROTOCOL_TLSv1_2 (1u << 3)
#define MRB_TLS_PROTOCOL_TLSv1_3 (1u << 4)
#define MRB_TLS_PROTOCOLS_DEFAULT MRB_TLS_PROTOCOL_TLSv1_3

/* ------------------------------------------------------------------ */
/* The error value                                                     */
/* ------------------------------------------------------------------ */

/* Opaque, and owned by the session or the config that answered it. It
 * is valid until the next call on that object, so a caller that wants
 * to keep it copies what it needs first.
 *
 * There is no last-error function and no thread-local. An error belongs
 * to the object it happened to, which is the only way two sessions on
 * two threads can fail at once and both be readable. */
typedef struct mrb_tls_error mrb_tls_error;

mrb_tls_error_kind mrb_tls_error_kind_of(const mrb_tls_error *error);

/* The number behind the kind, and it is a different number per kind:
 * an errno for IO and KERNEL, the alert description for ALERT, an
 * X509_V_ERR_* for VERIFY. Zero where the kind carries no number. */
int mrb_tls_error_number(const mrb_tls_error *error);

/* The TLS library's own code, for a caller that wants to look it up:
 * the first entry of OpenSSL's error queue, or the SECURITY_STATUS on
 * Windows. Zero when the library said nothing. */
unsigned long mrb_tls_error_code(const mrb_tls_error *error);

/* One sentence, "what: why", never NULL. The whole of OpenSSL's error
 * queue is drained into it, so a failure with three entries reads as
 * three clauses rather than as the last one. */
const char *mrb_tls_error_text(const mrb_tls_error *error);

/* ------------------------------------------------------------------ */
/* The caller's I/O                                                    */
/* ------------------------------------------------------------------ */

typedef enum {
  MRB_TLS_IO_DONE = 0,
  MRB_TLS_IO_AGAIN,
  MRB_TLS_IO_CLOSED,
  MRB_TLS_IO_FAILED
} mrb_tls_io_status;

/* What MRB_TLS_IO_AGAIN promises, and it is the one contract every
 * adapter has to keep: the callback may already have started the
 * operation. The session calls the same callback again with the same
 * length, and for a write with the same bytes, and the callback then
 * answers what the operation did. An adapter that queues an operation
 * and answers AGAIN is therefore correct; one that drops the request
 * and answers AGAIN is not.
 *
 * The write callback may see its buffer move between two calls. The
 * bytes do not change.
 *
 * Every callback reports an errno through err. A callback that has no
 * errno to give writes 0 there. */
typedef struct mrb_tls_io {
  void *ctx;

  /* Ciphertext from the peer, in userspace mode; plaintext the kernel
   * decrypted, in kernel mode. */
  mrb_tls_io_status (*read)(void *ctx, void *buf, size_t cap, size_t *got, int *err);

  /* The same, outward. */
  mrb_tls_io_status (*write)(void *ctx, const void *buf, size_t len, size_t *put, int *err);

  /* Optional. Sets one socket option on whatever the transport is.
   * NULL means the kernel handover is never offered and the session
   * stays in userspace mode, with that as its reason.
   *
   * The session computes the payloads and asks for them one at a time.
   * The bytes stay valid until the callback answers something other
   * than AGAIN, so an adapter may point an asynchronous call at them. */
  mrb_tls_io_status (*set_socket_option)(void *ctx, int level, int name, const void *value,
                                         size_t len, int *err);

  /* Optional, and both or neither. A kernel record layer delivers
   * alerts, KeyUpdate and NewSessionTicket as records of their own
   * type, and a read that cannot carry a type meets EIO on the first
   * one and again on every later one, because the record stays queued.
   * So kernel mode needs this pair. Without it the session stays in
   * userspace mode and says so.
   *
   * type is the RFC 8446 ContentType: 21 alert, 22 handshake, 23
   * application data. */
  mrb_tls_io_status (*read_record)(void *ctx, void *buf, size_t cap, size_t *got,
                                   unsigned char *type, int *err);
  mrb_tls_io_status (*write_record)(void *ctx, unsigned char type, const void *buf, size_t len,
                                    size_t *put, int *err);

  /* Optional. How many bytes the transport has already taken from the
   * peer and not yet delivered. It reports and never refuses: the
   * session drains them before it decides its mode, because bytes held
   * outside the kernel cannot be decrypted by it. */
  size_t (*read_ahead_held)(void *ctx);
} mrb_tls_io;

/* ------------------------------------------------------------------ */
/* The configuration                                                   */
/* ------------------------------------------------------------------ */

/* One configuration serves many sessions. A session holds a reference,
 * so a config may be freed while its sessions live on. */
typedef struct mrb_tls_config mrb_tls_config;

/* TLS 1.3 only, the peer's certificate verified on every completed
 * client handshake, renegotiation refused, partial writes allowed.
 * NULL only when there was no memory. */
mrb_tls_config *mrb_tls_config_new(void);
void mrb_tls_config_free(mrb_tls_config *config);

/* The last failure on this config, valid until the next call on it. */
const mrb_tls_error *mrb_tls_config_error(const mrb_tls_config *config);

/* The leaf and whatever chain follows it, as PEM. */
mrb_tls_status mrb_tls_config_set_certificate(mrb_tls_config *config, const char *pem, size_t len);
mrb_tls_status mrb_tls_config_set_certificate_file(mrb_tls_config *config, const char *path);
mrb_tls_status mrb_tls_config_set_private_key(mrb_tls_config *config, const char *pem, size_t len);
mrb_tls_status mrb_tls_config_set_private_key_file(mrb_tls_config *config, const char *path);

/* One more certificate, for one more name. A leading "*." matches one
 * label and no more. A client that asks for a name with no entry gets
 * the certificate set above. */
mrb_tls_status mrb_tls_config_add_named_certificate(mrb_tls_config *config, const char *host,
                                                    const char *cert_pem, size_t cert_len,
                                                    const char *key_pem, size_t key_len);

/* Whom to believe about a peer. Without either, the system's own store
 * answers. */
mrb_tls_status mrb_tls_config_set_trust_file(mrb_tls_config *config, const char *path);
mrb_tls_status mrb_tls_config_set_trust_path(mrb_tls_config *config, const char *path);

/* The three axes, each on or off: the chain to a trusted root, the name
 * against the one the client asked for, and the validity dates. All
 * three are on. */
void mrb_tls_config_set_verify(mrb_tls_config *config, bool chain, bool name, bool time);
void mrb_tls_config_set_verify_depth(mrb_tls_config *config, int depth);

/* Widen the range below TLS 1.3. The new APIs pin their own sessions to
 * 1.3 whatever this says; it exists for a caller that has to speak to
 * something older. A session under 1.3 never reaches the kernel record
 * layer and records that as its reason. */
mrb_tls_status mrb_tls_config_set_protocols(mrb_tls_config *config, uint32_t mask);

/* A cipher list and a group list, in the TLS library's own spelling. A
 * name the library does not know is an argument error naming it. */
mrb_tls_status mrb_tls_config_set_ciphers(mrb_tls_config *config, const char *list);
mrb_tls_status mrb_tls_config_set_groups(mrb_tls_config *config, const char *list);

/* The protocols this side offers, in order of preference. A server
 * picks the first of its own list that the client also offered. */
mrb_tls_status mrb_tls_config_set_alpn(mrb_tls_config *config, const char *const *names,
                                       size_t count);

/* How many session tickets a server issues per handshake. Zero turns
 * them off, and a client then cannot resume. */
mrb_tls_status mrb_tls_config_set_tickets(mrb_tls_config *config, size_t count);

/* One ticket key for every process behind one address. Without it each
 * process invents its own, and a client that resumes against a
 * different process than it handshook with does a full handshake
 * instead. */
mrb_tls_status mrb_tls_config_set_ticket_key(mrb_tls_config *config, const void *key, size_t len);

/* Answer a config for a name this one has no certificate for, or NULL
 * to use this one's. Setting abort ends the session before any byte
 * goes back, which a client sees as a closed connection.
 *
 * The hook runs inside the TLS library's own call. It may not raise,
 * throw, or free the config it is attached to. */
void mrb_tls_config_set_server_name_hook(mrb_tls_config *config,
                                         mrb_tls_config *(*hook)(void *ctx, const char *host,
                                                                 bool *abort),
                                         void *ctx);

/* ------------------------------------------------------------------ */
/* The session                                                         */
/* ------------------------------------------------------------------ */

typedef struct mrb_tls_session mrb_tls_session;

/* The I/O table is copied, so the caller may keep its own on the stack.
 * What ctx points at has to outlive the session. NULL only when there
 * was no memory. */
mrb_tls_session *mrb_tls_session_new(mrb_tls_config *config, mrb_tls_role role,
                                     const mrb_tls_io *io);
void mrb_tls_session_free(mrb_tls_session *session);

/* The last failure on this session, valid until the next call on it. */
const mrb_tls_error *mrb_tls_session_error(const mrb_tls_session *session);

/* A client's server name: sent to the peer, and the name the
 * certificate is checked against. Before the handshake. */
mrb_tls_status mrb_tls_session_set_server_name(mrb_tls_session *session, const char *host);

/* This session's own protocol range, whatever the config allows. */
mrb_tls_status mrb_tls_session_set_protocols(mrb_tls_session *session, uint32_t mask);

/* Resumption. A client exports a finished session and offers it back
 * later; the bytes are opaque and belong to this library's own format.
 * mrb_tls_session_resume is called before the handshake, export after
 * it. */
mrb_tls_status mrb_tls_session_resume(mrb_tls_session *session, const void *der, size_t len);
const void *mrb_tls_session_export(const mrb_tls_session *session, size_t *len);
bool mrb_tls_session_resumed(const mrb_tls_session *session);

/* Drives the handshake, the verification, the drain of whatever the
 * transport read ahead, and the handover attempt. It answers
 * MRB_TLS_OK only once the record layer is decided, so a caller that
 * sees OK may read mrb_tls_session_mode and trust it. */
mrb_tls_status mrb_tls_session_handshake(mrb_tls_session *session);

mrb_tls_mode mrb_tls_session_mode(const mrb_tls_session *session);

/* Why the records stayed in userspace. Kind MRB_TLS_ERR_NONE in kernel
 * mode, and before the handshake finished. It is not a failure: it is
 * the sentence a caller prints when it wants to know why. */
const mrb_tls_error *mrb_tls_session_fallback_reason(const mrb_tls_session *session);

/* Read plaintext, and write plaintext. Both answer how much they moved
 * through the size_t the caller points at, and both may move less than
 * was asked for.
 *
 * What a caller owes after MRB_TLS_AGAIN_READ or MRB_TLS_AGAIN_WRITE:
 * wait for the transport, then call again with the SAME bytes it was
 * given before, from the same offset. A write that answers AGAIN_WRITE
 * with *put at 0 took nothing; one that answers OK with *put below len
 * took that much, and the rest is the caller's to offer again. Handing
 * a retry other bytes, or fewer, breaks the record the library is in
 * the middle of writing.
 *
 * A write may answer MRB_TLS_AGAIN_READ, and a read may answer
 * MRB_TLS_AGAIN_WRITE: the library is in the middle of a key update,
 * and it is the transport that decides, never the direction of the
 * call. */
mrb_tls_status mrb_tls_session_read(mrb_tls_session *session, void *buf, size_t cap, size_t *got);
mrb_tls_status mrb_tls_session_write(mrb_tls_session *session, const void *buf, size_t len,
                                     size_t *put);

/* Plaintext the session holds and a read would answer at once, without
 * asking the transport for anything. */
size_t mrb_tls_session_pending(const mrb_tls_session *session);

/* Sends close_notify. A peer that never gets one cannot tell a close
 * from a truncation, so this is not optional politeness. */
mrb_tls_status mrb_tls_session_close(mrb_tls_session *session);

/* Take new traffic keys in both directions. A session does this by
 * itself when a cipher's record limit comes near; this is for a caller
 * with a rule of its own. */
mrb_tls_status mrb_tls_session_rekey(mrb_tls_session *session);

/* How many records this cipher may protect before a rekey is owed. Zero
 * when the cipher sets no limit worth counting. */
uint64_t mrb_tls_session_record_limit(const mrb_tls_session *session);

/* A record the caller read itself, of a type that is not application
 * data. A reactor that owns its own recvmsg hands them here: alerts,
 * KeyUpdate, and the tickets that arrive after a handover. */
mrb_tls_status mrb_tls_session_control_record(mrb_tls_session *session, unsigned char type,
                                              const void *payload, size_t len);

/* What the kernel's record layer can be asked for once it holds this
 * session. Both are refused with kind MRB_TLS_ERR_STATE in userspace
 * mode. */
typedef enum {
  MRB_TLS_KERNEL_SEND_PAGES_READ_ONLY = 0, /* the sender will not touch the pages again */
  MRB_TLS_KERNEL_RECEIVE_NO_PADDING        /* the peer pads no record */
} mrb_tls_kernel_option;

mrb_tls_status mrb_tls_session_set_kernel_option(mrb_tls_session *session,
                                                 mrb_tls_kernel_option option, bool on);

/* Give back what only the handshake needed. In kernel mode the TLS
 * library holds nothing the data path uses, so a server with many idle
 * connections may drop it. The names below stay readable afterwards,
 * and so do the secrets a rekey needs. */
mrb_tls_status mrb_tls_session_shrink(mrb_tls_session *session);

/* What was negotiated. Never NULL; an empty string before the handshake
 * finished, or where the peer offered nothing. */
const char *mrb_tls_session_cipher(const mrb_tls_session *session);
const char *mrb_tls_session_version(const mrb_tls_session *session);
const char *mrb_tls_session_alpn(const mrb_tls_session *session, size_t *len);

/* ------------------------------------------------------------------ */
/* For a caller that reads its own records                             */
/* ------------------------------------------------------------------ */

/* The control message a kernel record layer uses to carry a record's
 * type, for a reactor that builds its own recvmsg and sendmsg. Every
 * one of these is defined on every system: on a system with no kernel
 * record layer they answer 0 and mrb_tls_record_type_of answers 23, so
 * nothing links short and nothing has to be guarded by the caller. */
int mrb_tls_record_type_level(void);
int mrb_tls_record_type_cmsg(void);
int mrb_tls_record_type_set_cmsg(void);
unsigned char mrb_tls_record_type_of(const void *cmsg_data, size_t len);

/* Whether this processor carries AES instructions. A server that orders
 * its cipher list by what the machine does well asks this. */
bool mrb_tls_aes_is_fast(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* The exception classes, for a caller that is inside mruby already. */
#ifdef MRUBY_H
#define E_TLS_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Error"))
#define E_TLS_CONFIG_ERROR \
  (mrb_class_get_under(mrb, mrb_class_get_under(mrb, mrb_module_get(mrb, "Tls"), "Config"), \
                       "Error"))
#endif

#endif /* MRUBY_TLS_H */
