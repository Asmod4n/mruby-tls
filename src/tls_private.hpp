#ifndef MRUBY_TLS_PRIVATE_HPP
#define MRUBY_TLS_PRIVATE_HPP

/* What the sources of this gem share, and nothing a caller ever sees.
 *
 * The three types the C API names as opaque are defined here, so every
 * file that touches one agrees on its shape. Their tags carry the
 * mrb_tls_ prefix because the header shows those tags to a C caller;
 * everything else in this file carries none, because nothing outside
 * these sources can name it.
 */

#include "tls_platform.h"
#include "tls_keys.hpp"

#include <mruby/tls.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <openssl/ssl.h>
#endif

namespace {
/* The largest record a peer may send, so a buffer that must hold one
 * has a size from the library rather than from us. */
constexpr std::size_t kRecordMax = SSL3_RT_MAX_ENCRYPTED_LENGTH;
} // namespace

/* A failure, carried rather than reported. Kind decides what a caller
 * can do; the rest is for the person reading the message.
 *
 * This is the C++ side of mrb_tls_error. The C type is the same object,
 * which is why the struct below inherits nothing and adds nothing. */
struct error_value {
    mrb_tls_error_kind kind = MRB_TLS_ERR_NONE;
    /* An errno for IO and KERNEL, the alert description for ALERT, an
     * X509_V_ERR_* for VERIFY. */
    int number = 0;
    /* The library's own code: OpenSSL's first queue entry, or a
     * SECURITY_STATUS. */
    unsigned long code = 0;
    std::string text;

    bool failed() const { return kind != MRB_TLS_ERR_NONE; }
    void clear()
    {
        kind = MRB_TLS_ERR_NONE;
        number = 0;
        code = 0;
        text.clear();
    }
};

/* The C API hands out a pointer to one of these. It is the same object
 * as error_value; the struct exists so the header can name a type
 * without showing what is in it. */
struct mrb_tls_error : error_value {};

#ifndef _WIN32

struct ssl_ctx_deleter {
    void operator()(SSL_CTX *ctx) const
    {
        if (ctx != nullptr)
            SSL_CTX_free(ctx);
    }
};
struct ssl_deleter {
    void operator()(SSL *ssl) const
    {
        if (ssl != nullptr)
            SSL_free(ssl);
    }
};

using ctx_ptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;
using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

/* One certificate for one name, for a server that answers several. A
 * leading "*." matches one label. */
struct named_certificate {
    std::string host;
    ctx_ptr ctx;
};

struct mrb_tls_config {
    ctx_ptr ctx;
    std::vector<named_certificate> named;
    /* The wire form of the ALPN list: one length byte per name. */
    std::vector<unsigned char> alpn;
    bool verify_chain = true;
    bool verify_name = true;
    bool verify_time = true;
    mrb_tls_config *(*name_hook)(void *ctx, const char *host, bool *abort) = nullptr;
    void *name_hook_ctx = nullptr;
    mrb_tls_error last;
};

/* How far a session has come. The mode is decided once, at ready. */
enum class phase { handshake, verified, ready, closed };

/* Records that crossed, counted as they cross.
 *
 * The kernel counts records, not bytes: a handover hands it the
 * sequence number to continue from, and a number that is wrong by one
 * makes every later record undecryptable to the peer. Nothing else in
 * this gem knows that number, so it is taken where the bytes are - at
 * the BIO, in both directions.
 *
 * A record is five bytes of header and the length those five declare.
 * The stream arrives in pieces that do not respect that, so the walker
 * carries what it has of a header and how much of a body it still
 * owes. */
struct record_walk {
    std::uint64_t records = 0;
    /* How many of the five header bytes are still wanted. Five means a
     * record is about to start. */
    std::size_t header_left = 5;
    std::array<unsigned char, 5> header{};
    /* How many body bytes this record still owes. */
    std::size_t body_left = 0;

    void feed(std::span<const unsigned char> bytes)
    {
        while (!bytes.empty()) {
            if (body_left == 0 && header_left > 0) {
                const std::size_t take = std::min(header_left, bytes.size());
                std::copy_n(bytes.begin(), take,
                            std::next(header.begin(),
                                      static_cast<std::ptrdiff_t>(header.size() - header_left)));
                header_left -= take;
                bytes = bytes.subspan(take);
                if (header_left == 0) {
                    /* RFC 8446 5.1: the length is the last two bytes of
                     * the header, big endian. */
                    body_left = (static_cast<std::size_t>(header[3]) << 8) | header[4];
                    if (body_left == 0) {
                        records++;
                        header_left = header.size();
                    }
                }
                continue;
            }
            const std::size_t take = std::min(body_left, bytes.size());
            body_left -= take;
            bytes = bytes.subspan(take);
            if (body_left == 0) {
                records++;
                header_left = header.size();
            }
        }
    }
};

/* One socket option the kernel takes, computed whole before any of it
 * is applied. The bytes live on the session, so a hook that answers
 * again may point an asynchronous call at them and they are still
 * there when it finishes. */
struct handover_step {
    int level;
    int name;
    std::vector<std::byte> bytes;
};

struct mrb_tls_session {
    ssl_ptr ssl;
    /* The config keeps its SSL_CTX alive through a reference of its
     * own, so a caller may free the config first. */
    ctx_ptr ctx;
    mrb_tls_io io{};
    mrb_tls_role role = MRB_TLS_CLIENT;
    enum phase phase = phase::handshake;
    mrb_tls_mode mode = MRB_TLS_MODE_UNDECIDED;
    /* Why the records stayed in userspace. Kind NONE in kernel mode. */
    mrb_tls_error fallback;
    /* What a write callback was handed and has not yet taken. The
     * contract says the same bytes come back, so they are held. */
    std::vector<std::byte> out;
    std::size_t out_sent = 0;
    std::string server_name;
    std::string cipher_name;
    std::string version_name;
    std::string alpn_name;
    std::vector<std::byte> session_der;

    /* The three axes, copied from the config so a session answers for
     * itself after the config is gone. */
    bool verify_chain = true;
    bool verify_name = true;

    /* The kernel handover. The plan is a value; performing it walks the
     * steps and may stop between two of them. */
    std::vector<handover_step> plan;
    std::size_t step = 0;

    /* What the keylog handed over: the client's application traffic
     * secret at 0 and the server's at 1, whichever end this is. */
    std::array<std::vector<std::byte>, 2> secret;
    const cipher_row *row = nullptr;
    const EVP_MD *digest = nullptr;

    /* Where each direction's record count stands when the kernel takes
     * over. The kernel counts on from these.
     *
     * TLS 1.3 changes keys during the handshake and the kernel is given
     * the application traffic key, so what it must count from is the
     * number of records written under THAT key and no other. Which
     * records those are depends on the role, because the two ends stop
     * writing handshake records at different moments.
     *
     * A server writes its Finished under the handshake key, reads the
     * client's Finished, and only then writes the tickets. So every
     * record it writes after the last record it read is an application
     * key record, and the tickets are exactly what the kernel must
     * count past.
     *
     * A client writes its Finished under the handshake key AFTER it has
     * read the server's last flight. Counting from its last read would
     * therefore count that Finished, which is wrong by one. Its
     * application key records are the ones it writes after the
     * handshake is done, and at the handover there are none.
     *
     * Inbound is the same for both: nothing arrives under the
     * application key before the handshake is done, so the count is
     * whatever the transport had read ahead of it. */
    record_walk tx_walk;
    record_walk rx_walk;
    std::uint64_t tx_at_last_read = 0;
    std::uint64_t tx_at_done = 0;
    std::uint64_t rx_at_done = 0;

    std::uint64_t tx_records() const
    {
        const std::uint64_t from = role == MRB_TLS_SERVER ? tx_at_last_read : tx_at_done;
        return tx_walk.records - from;
    }
    std::uint64_t rx_records() const { return rx_walk.records - rx_at_done; }

    mrb_tls_error last;
};

/* tls_bio.cpp: one BIO_METHOD for every session, reading and writing
 * through the session's own io table. The BIO is owned by the SSL. */
BIO *tls_bio_new(mrb_tls_session *session);

/* What the BIO could not finish, so the core can turn it into a status
 * without the BIO knowing what a status is. */
enum class bio_want { none, read, write, closed, failed };
bio_want tls_bio_want(const BIO *bio);
void tls_bio_clear_want(BIO *bio);

/* The library's own words for what just failed, drained whole. */
std::string tls_library_error(std::string_view what);

/* For the Ruby binding's introspection methods, and for nothing else. */
SSL *tls_session_ssl(mrb_tls_session *session);

/* What the kernel would be told to count from, in each direction. The
 * handover is the only caller that matters; an example and a test read
 * it to check the number on a box where no kernel will take it. */
std::uint64_t tls_session_record_count(const mrb_tls_session *session, bool sending);

#endif /* _WIN32 */

#endif /* MRUBY_TLS_PRIVATE_HPP */
