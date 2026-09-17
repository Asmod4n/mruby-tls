/* OpenSSL reads and writes through here, and here asks the caller.
 *
 * A BIO is the one seam OpenSSL offers for a transport it does not own.
 * Every byte of ciphertext in userspace mode, and every byte of the
 * handshake in either mode, crosses this file.
 *
 * What it must never do is lose the reason. OpenSSL asks a BIO to
 * retry by way of one bit, and a caller needs more than a bit: whether
 * to wait for the peer, to wait for the transport, or to stop. So the
 * want is kept on the BIO beside the retry flag, and the core reads it
 * back with tls_bio_want.
 */

#include "tls_private.hpp"

#ifndef _WIN32

#include <algorithm>
#include <atomic>
#include <cstring>

#include <openssl/bio.h>
#include <openssl/err.h>

namespace
{

/* What a BIO of ours carries: the session whose callbacks it asks, and
 * what the last call could not finish. */
struct bio_state {
    mrb_tls_session *session;
    bio_want want;
    /* A read callback may deliver bytes and see the end of the stream
     * in one call - a recv that returns data and then zero is the
     * ordinary shape of it. The bytes go out first and the end is
     * remembered for the next call, because throwing them away loses
     * the peer's close_notify and turns a clean close into a
     * truncation. */
    bool closed_seen;
};

bio_state *state_of(BIO *bio)
{
    return static_cast<bio_state *>(BIO_get_data(bio));
}

/* One answer from a callback, turned into the two things OpenSSL and
 * the core each need: a return value, and a want. */
int settle(BIO *bio, mrb_tls_io_status status, std::size_t moved, bio_want on_again)
{
    bio_state *state = state_of(bio);
    BIO_clear_retry_flags(bio);
    switch (status) {
    case MRB_TLS_IO_DONE:
        state->want = bio_want::none;
        /* Nothing moved, and the callback did not say to wait. There is
         * no way to tell OpenSSL that: a zero with no retry flag is a
         * failure it will not retry. A callback that moved nothing has
         * to wait, so it is answered as such. */
        if (moved == 0) {
            state->want = on_again;
            if (on_again == bio_want::read)
                BIO_set_retry_read(bio);
            else
                BIO_set_retry_write(bio);
            return -1;
        }
        return static_cast<int>(moved);
    case MRB_TLS_IO_AGAIN:
        state->want = on_again;
        /* The retry flag OpenSSL reads, and the direction with it: a
         * write that has to wait for the transport is a want-write, and
         * OpenSSL will not ask again until the caller says so. */
        if (on_again == bio_want::read)
            BIO_set_retry_read(bio);
        else
            BIO_set_retry_write(bio);
        return -1;
    case MRB_TLS_IO_CLOSED:
        /* The end of the transport, and possibly bytes with it. The
         * bytes go first: they are usually the peer's close_notify, and
         * discarding them would report a truncation where the peer
         * closed properly. */
        if (moved > 0) {
            state->closed_seen = true;
            state->want = bio_want::none;
            return static_cast<int>(moved);
        }
        state->want = bio_want::closed;
        /* Zero is an orderly end of the transport. OpenSSL turns it
         * into SSL_ERROR_ZERO_RETURN or into an unexpected EOF,
         * depending on whether close_notify came first, and that
         * distinction is one this file must not make for it. */
        return 0;
    case MRB_TLS_IO_FAILED:
    default:
        state->want = bio_want::failed;
        return -1;
    }
}

/* A callback that reports more bytes than the buffer it was given is
 * a defect in the adapter, and a silent clamp would hide it. Worse, the
 * number reaches OpenSSL, which parses records out of memory nobody
 * wrote - a heap over-read that leaves this process as decrypted
 * content. So it is refused, loudly, and the session says who did it. */
bool moved_too_much(mrb_tls_session *session, std::size_t moved, int len, const char *which)
{
    if (moved <= static_cast<std::size_t>(len))
        return false;
    session->last.kind = MRB_TLS_ERR_ARGUMENT;
    session->last.number = 0;
    session->last.text = std::string("the ") + which + " callback reported more bytes than the "
                                                       "buffer it was given holds";
    return true;
}

int bio_read(BIO *bio, char *buf, int len)
{
    bio_state *state = state_of(bio);
    if (state == nullptr || state->session == nullptr || len <= 0)
        return 0;
    if (state->closed_seen) {
        /* The end was seen on an earlier call, after its bytes went
         * out. Nothing more will arrive. */
        state->want = bio_want::closed;
        BIO_clear_retry_flags(bio);
        return 0;
    }
    mrb_tls_io &io = state->session->io;
    std::size_t got = 0;
    int err = 0;
    const mrb_tls_io_status status =
        io.read(io.ctx, buf, static_cast<std::size_t>(len), &got, &err);
    if ((status == MRB_TLS_IO_DONE || status == MRB_TLS_IO_CLOSED) &&
        moved_too_much(state->session, got, len, "read")) {
        state->want = bio_want::failed;
        BIO_clear_retry_flags(bio);
        return -1;
    }
    if (status == MRB_TLS_IO_FAILED) {
        state->session->last.kind = MRB_TLS_ERR_IO;
        state->session->last.number = err;
        state->session->last.text = "the transport could not be read";
    }
    if ((status == MRB_TLS_IO_DONE || status == MRB_TLS_IO_CLOSED) && got > 0) {
        state->session->rx_walk.feed(
            {reinterpret_cast<const unsigned char *>(buf), got});
        /* Every record written before this read was written under an
         * earlier key. What the kernel counts from is what follows. */
        state->session->tx_at_last_read = state->session->tx_walk.records;
    }
    return settle(bio, status, got, bio_want::read);
}

int bio_write(BIO *bio, const char *buf, int len)
{
    bio_state *state = state_of(bio);
    if (state == nullptr || state->session == nullptr || len <= 0)
        return 0;
    mrb_tls_io &io = state->session->io;
    std::size_t put = 0;
    int err = 0;
    const mrb_tls_io_status status =
        io.write(io.ctx, buf, static_cast<std::size_t>(len), &put, &err);
    if ((status == MRB_TLS_IO_DONE || status == MRB_TLS_IO_CLOSED) &&
        moved_too_much(state->session, put, len, "write")) {
        state->want = bio_want::failed;
        BIO_clear_retry_flags(bio);
        return -1;
    }
    if (status == MRB_TLS_IO_FAILED) {
        state->session->last.kind = MRB_TLS_ERR_IO;
        state->session->last.number = err;
        state->session->last.text = "the transport could not be written";
    }
    if ((status == MRB_TLS_IO_DONE || status == MRB_TLS_IO_CLOSED) && put > 0)
        state->session->tx_walk.feed({reinterpret_cast<const unsigned char *>(buf), put});
    return settle(bio, status, put, bio_want::write);
}

long bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
    (void)larg;
    (void)parg;
    switch (cmd) {
    /* OpenSSL flushes before it waits. There is nothing held here: a
     * write callback either took the bytes or said again, and the core
     * repeats the call. */
    case BIO_CTRL_FLUSH:
        return 1;
    case BIO_CTRL_EOF:
        return state_of(bio) != nullptr && state_of(bio)->want == bio_want::closed ? 1 : 0;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        return 0;
    }
}

int bio_create(BIO *bio)
{
    bio_state *state = new (std::nothrow) bio_state{nullptr, bio_want::none, false};
    if (state == nullptr)
        return 0;
    BIO_set_data(bio, state);
    BIO_set_init(bio, 1);
    return 1;
}

int bio_destroy(BIO *bio)
{
    if (bio == nullptr)
        return 0;
    delete state_of(bio);
    BIO_set_data(bio, nullptr);
    return 1;
}

/* One method for the whole process. BIO_get_new_index hands out the
 * type number; asking for it once is what keeps two gems in one
 * process from colliding. */
/* One method for the whole process, built on first use.
 *
 * A failure is not remembered. BIO_get_new_index hands out a limited
 * number of type values, and a process that ran out of them a moment
 * ago may have them back later; caching the null would make every
 * session of this gem fail for the rest of the process's life over a
 * condition that had passed. */
BIO_METHOD *method_once()
{
    static std::atomic<BIO_METHOD *> method{nullptr};
    BIO_METHOD *made = method.load(std::memory_order_acquire);
    if (made != nullptr)
        return made;

    const int index = BIO_get_new_index();
    if (index < 0)
        return nullptr;
    made = BIO_meth_new(index | BIO_TYPE_SOURCE_SINK, "mruby-tls caller io");
    if (made == nullptr)
        return nullptr;
    BIO_meth_set_read(made, bio_read);
    BIO_meth_set_write(made, bio_write);
    BIO_meth_set_ctrl(made, bio_ctrl);
    BIO_meth_set_create(made, bio_create);
    BIO_meth_set_destroy(made, bio_destroy);

    BIO_METHOD *none = nullptr;
    if (method.compare_exchange_strong(none, made, std::memory_order_acq_rel)) {
        return made;
    }
    /* Another thread got there first. Its method is the one every BIO
     * will carry, and this one is dropped. */
    BIO_meth_free(made);
    return method.load(std::memory_order_acquire);
}

} // namespace

BIO *tls_bio_new(mrb_tls_session *session)
{
    BIO_METHOD *method = method_once();
    if (method == nullptr)
        return nullptr;
    BIO *bio = BIO_new(method);
    if (bio == nullptr)
        return nullptr;
    state_of(bio)->session = session;
    return bio;
}

bio_want tls_bio_want(const BIO *bio)
{
    /* BIO_get_data takes a non-const BIO and reads nothing, so the cast
     * is the library's spelling and not a change of ownership. */
    const bio_state *state = static_cast<const bio_state *>(BIO_get_data(const_cast<BIO *>(bio)));
    return state == nullptr ? bio_want::none : state->want;
}

/* The session is going away, and the BIO may outlive it: OpenSSL frees
 * the BIO from SSL_free, and the SSL is freed from the session's own
 * destructor. Nothing calls read or write in between today - SSL_free
 * sends no close_notify - but that is a property of OpenSSL rather than
 * of this file, so the pointer is cleared rather than trusted. */
void tls_bio_forget_session(BIO *bio)
{
    bio_state *state = state_of(bio);
    if (state != nullptr)
        state->session = nullptr;
}

void tls_bio_clear_want(BIO *bio)
{
    bio_state *state = state_of(bio);
    if (state != nullptr)
        state->want = bio_want::none;
}

std::string tls_library_error(std::string_view what)
{
    std::string text(what);
    bool first = true;
    unsigned long code = 0;
    char line[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, line, sizeof line);
        text += first ? ": " : "; ";
        text += line;
        first = false;
    }
    if (first)
        text += ": the library said nothing";
    return text;
}

#endif /* _WIN32 */
