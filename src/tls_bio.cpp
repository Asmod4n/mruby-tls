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

int bio_read(BIO *bio, char *buf, int len)
{
    bio_state *state = state_of(bio);
    if (state == nullptr || len <= 0)
        return 0;
    mrb_tls_io &io = state->session->io;
    std::size_t got = 0;
    int err = 0;
    const mrb_tls_io_status status =
        io.read(io.ctx, buf, static_cast<std::size_t>(len), &got, &err);
    if (status == MRB_TLS_IO_FAILED) {
        state->session->last.kind = MRB_TLS_ERR_IO;
        state->session->last.number = err;
        state->session->last.text = "the transport could not be read";
    }
    return settle(bio, status, got, bio_want::read);
}

int bio_write(BIO *bio, const char *buf, int len)
{
    bio_state *state = state_of(bio);
    if (state == nullptr || len <= 0)
        return 0;
    mrb_tls_io &io = state->session->io;
    std::size_t put = 0;
    int err = 0;
    const mrb_tls_io_status status =
        io.write(io.ctx, buf, static_cast<std::size_t>(len), &put, &err);
    if (status == MRB_TLS_IO_FAILED) {
        state->session->last.kind = MRB_TLS_ERR_IO;
        state->session->last.number = err;
        state->session->last.text = "the transport could not be written";
    }
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
    bio_state *state = new (std::nothrow) bio_state{nullptr, bio_want::none};
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
BIO_METHOD *method_once()
{
    static BIO_METHOD *method = [] {
        const int index = BIO_get_new_index();
        BIO_METHOD *made = index < 0 ? nullptr : BIO_meth_new(index | BIO_TYPE_SOURCE_SINK,
                                                              "mruby-tls caller io");
        if (made == nullptr)
            return static_cast<BIO_METHOD *>(nullptr);
        BIO_meth_set_read(made, bio_read);
        BIO_meth_set_write(made, bio_write);
        BIO_meth_set_ctrl(made, bio_ctrl);
        BIO_meth_set_create(made, bio_create);
        BIO_meth_set_destroy(made, bio_destroy);
        return made;
    }();
    return method;
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
