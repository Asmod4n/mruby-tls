/* The session, and the configuration behind it.
 *
 * ONE RULE ABOVE THE OTHERS: this file performs no system call. Not a
 * read, not a write, not a setsockopt. Every byte and every socket
 * option goes out through the caller's own io table, because the
 * transport underneath may not be a descriptor at all - in a reactor it
 * is an entry in a ring's file table, and the option is a submission
 * like any other. A syscall here would work on a socket and quietly
 * fail on everything else this gem exists for.
 *
 * The record layer is decided once. After the handshake, after the peer
 * is verified, after whatever the transport read ahead has been drained
 * through the library: if the caller offered a socket option hook and a
 * record-typed read and write, the kernel is asked to take the records.
 * If it takes them, the library keeps only setup and rekeying. If it
 * refuses, or the caller offered no hook, the library keeps the records
 * and the session says why in one sentence.
 */

#include "tls_private.hpp"

#ifndef _WIN32

#include "tls_keys.hpp"

#include <algorithm>
#include <cstring>
#include <new>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef TLS_KERNEL_RECORDS
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace
{

/* Where a caller's mistake is told apart from the wire's. */
void fail(mrb_tls_error &slot, mrb_tls_error_kind kind, std::string text, int number = 0,
          unsigned long code = 0)
{
    slot.kind = kind;
    slot.number = number;
    slot.code = code;
    slot.text = std::move(text);
}

void fail_library(mrb_tls_error &slot, std::string_view what)
{
    const unsigned long first = ERR_peek_error();
    fail(slot, MRB_TLS_ERR_LIBRARY, tls_library_error(what), 0, first);
}

/* The protocol mask is a set; OpenSSL takes a range. A request for 1.0
 * or 1.1 alone is refused rather than widened: those versions have
 * never been offered here, and answering a wider range than was asked
 * for is how a caller ends up with a protocol it rejected. */
bool apply_protocols(SSL_CTX *ctx, std::uint32_t mask, mrb_tls_error &slot)
{
    const std::uint32_t known = MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3;
    if ((mask & known) == 0) {
        fail(slot, MRB_TLS_ERR_ARGUMENT,
             "the protocol mask names no version this library offers; TLS 1.2 and TLS 1.3 are "
             "the two it has");
        return false;
    }
    const int low = (mask & MRB_TLS_PROTOCOL_TLSv1_2) != 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
    const int high = (mask & MRB_TLS_PROTOCOL_TLSv1_3) != 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
    if (SSL_CTX_set_min_proto_version(ctx, low) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, high) != 1) {
        fail_library(slot, "the protocol range was refused");
        return false;
    }
    return true;
}

/* The ALPN list on the wire: one length byte before each name. */
bool pack_alpn(const char *const *names, std::size_t count, std::vector<unsigned char> &out,
               mrb_tls_error &slot)
{
    out.clear();
    for (std::size_t i = 0; i < count; i++) {
        const std::string_view name(names[i]);
        if (name.empty() || name.size() > 255) {
            fail(slot, MRB_TLS_ERR_ARGUMENT,
                 "an ALPN name is empty or longer than 255 bytes, which the wire cannot carry");
            return false;
        }
        out.push_back(static_cast<unsigned char>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
    }
    return true;
}

/* The server's choice: the first of ITS list the client also offered,
 * so the server's order is the one that decides. */
int alpn_pick(SSL *ssl, const unsigned char **out, unsigned char *out_len,
              const unsigned char *client, unsigned int client_len, void *arg)
{
    (void)ssl;
    const auto *ours = static_cast<const std::vector<unsigned char> *>(arg);
    if (ours == nullptr || ours->empty())
        return SSL_TLSEXT_ERR_NOACK;
    for (std::size_t i = 0; i + 1 <= ours->size();) {
        const unsigned char len = (*ours)[i];
        if (len == 0 || i + 1 + len > ours->size())
            break;
        const unsigned char *name = std::next(ours->data(), static_cast<std::ptrdiff_t>(i + 1));
        for (unsigned int j = 0; j + 1 <= client_len;) {
            const unsigned char their_len = client[j];
            if (their_len == 0 || j + 1 + their_len > client_len)
                break;
            if (their_len == len &&
                std::memcmp(name, std::next(client, static_cast<std::ptrdiff_t>(j + 1)), len) == 0) {
                *out = name;
                *out_len = len;
                return SSL_TLSEXT_ERR_OK;
            }
            j += 1 + their_len;
        }
        i += 1 + len;
    }
    /* No overlap is not a handshake failure. The peer learns that
     * nothing was agreed and may still speak whatever it defaults to. */
    return SSL_TLSEXT_ERR_NOACK;
}

/* A name with a leading "*." matches one label and no more, which is
 * what a certificate's wildcard means and all it means. */
bool host_matches(std::string_view pattern, std::string_view host)
{
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
        const std::size_t dot = host.find('.');
        if (dot == std::string_view::npos)
            return false;
        return host.substr(dot + 1) == pattern.substr(2);
    }
    return pattern == host;
}

int servername_pick(SSL *ssl, int *alert, void *arg)
{
    (void)alert;
    auto *config = static_cast<mrb_tls_config *>(arg);
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (host == nullptr)
        return SSL_TLSEXT_ERR_OK;

    for (named_certificate &one : config->named) {
        if (host_matches(one.host, host)) {
            SSL_set_SSL_CTX(ssl, one.ctx.get());
            return SSL_TLSEXT_ERR_OK;
        }
    }
    if (config->name_hook != nullptr) {
        bool abort = false;
        mrb_tls_config *answer = config->name_hook(config->name_hook_ctx, host, &abort);
        if (abort)
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (answer != nullptr)
            SSL_set_SSL_CTX(ssl, answer->ctx.get());
    }
    /* A name nobody claimed keeps the default certificate. The client
     * decides whether that is acceptable, which is its job and not
     * ours. */
    return SSL_TLSEXT_ERR_OK;
}

} // namespace

/* ------------------------------------------------------------------ */
/* The error value                                                     */
/* ------------------------------------------------------------------ */

extern "C" {

mrb_tls_error_kind mrb_tls_error_kind_of(const mrb_tls_error *error)
{
    return error == nullptr ? MRB_TLS_ERR_NONE : error->kind;
}

int mrb_tls_error_number(const mrb_tls_error *error)
{
    return error == nullptr ? 0 : error->number;
}

unsigned long mrb_tls_error_code(const mrb_tls_error *error)
{
    return error == nullptr ? 0ul : error->code;
}

const char *mrb_tls_error_text(const mrb_tls_error *error)
{
    return error == nullptr ? "" : error->text.c_str();
}

/* ------------------------------------------------------------------ */
/* The configuration                                                   */
/* ------------------------------------------------------------------ */

mrb_tls_config *mrb_tls_config_new(void)
{
    auto *config = new (std::nothrow) mrb_tls_config();
    if (config == nullptr)
        return nullptr;

    config->ctx.reset(SSL_CTX_new(TLS_method()));
    if (!config->ctx) {
        delete config;
        return nullptr;
    }
    SSL_CTX *ctx = config->ctx.get();

    /* TLS 1.3 by default. A caller that needs 1.2 asks for it, and a
     * session that speaks 1.2 never reaches the kernel record layer. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Verification is ours, after the handshake, on three axes this
     * library cannot express as one flag. So OpenSSL is told to collect
     * the result and not to act on it. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    /* A write that took some of the bytes says so, rather than
     * pretending it took none; and the buffer a retry points at may
     * move, because a caller's buffer is the caller's to move. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
    return config;
}

void mrb_tls_config_free(mrb_tls_config *config)
{
    delete config;
}

const mrb_tls_error *mrb_tls_config_error(const mrb_tls_config *config)
{
    return config == nullptr ? nullptr : &config->last;
}

mrb_tls_status mrb_tls_config_set_certificate(mrb_tls_config *config, const char *pem, size_t len)
{
    if (config == nullptr || pem == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    BIO *bio = BIO_new_mem_buf(pem, static_cast<int>(len));
    if (bio == nullptr) {
        fail(config->last, MRB_TLS_ERR_MEMORY, "no memory for the certificate");
        return MRB_TLS_FAILED;
    }
    X509 *leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (leaf == nullptr) {
        BIO_free(bio);
        fail_library(config->last, "the certificate could not be read");
        return MRB_TLS_FAILED;
    }
    const int ok = SSL_CTX_use_certificate(config->ctx.get(), leaf);
    X509_free(leaf);
    if (ok != 1) {
        BIO_free(bio);
        fail_library(config->last, "the certificate was refused");
        return MRB_TLS_FAILED;
    }
    /* Whatever follows the leaf is the chain, in the order it was
     * written. SSL_CTX_add0_chain_cert takes ownership of each. */
    SSL_CTX_clear_chain_certs(config->ctx.get());
    X509 *next = nullptr;
    while ((next = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
        if (SSL_CTX_add0_chain_cert(config->ctx.get(), next) != 1) {
            X509_free(next);
            BIO_free(bio);
            fail_library(config->last, "a chain certificate was refused");
            return MRB_TLS_FAILED;
        }
    }
    ERR_clear_error(); /* the loop ends on a read error, which is the end of the file */
    BIO_free(bio);
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_certificate_file(mrb_tls_config *config, const char *path)
{
    if (config == nullptr || path == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    if (SSL_CTX_use_certificate_chain_file(config->ctx.get(), path) != 1) {
        fail_library(config->last, "the certificate file was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_private_key(mrb_tls_config *config, const char *pem, size_t len)
{
    if (config == nullptr || pem == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    BIO *bio = BIO_new_mem_buf(pem, static_cast<int>(len));
    if (bio == nullptr) {
        fail(config->last, MRB_TLS_ERR_MEMORY, "no memory for the private key");
        return MRB_TLS_FAILED;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        fail_library(config->last, "the private key could not be read");
        return MRB_TLS_FAILED;
    }
    const int ok = SSL_CTX_use_PrivateKey(config->ctx.get(), key);
    EVP_PKEY_free(key);
    if (ok != 1) {
        fail_library(config->last, "the private key was refused");
        return MRB_TLS_FAILED;
    }
    if (SSL_CTX_check_private_key(config->ctx.get()) != 1) {
        fail_library(config->last, "the private key does not match the certificate");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_private_key_file(mrb_tls_config *config, const char *path)
{
    if (config == nullptr || path == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    if (SSL_CTX_use_PrivateKey_file(config->ctx.get(), path, SSL_FILETYPE_PEM) != 1) {
        fail_library(config->last, "the private key file was refused");
        return MRB_TLS_FAILED;
    }
    if (SSL_CTX_check_private_key(config->ctx.get()) != 1) {
        fail_library(config->last, "the private key does not match the certificate");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_add_named_certificate(mrb_tls_config *config, const char *host,
                                                    const char *cert_pem, size_t cert_len,
                                                    const char *key_pem, size_t key_len)
{
    if (config == nullptr || host == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();

    /* A named certificate is a context of its own, because that is what
     * SSL_set_SSL_CTX swaps. It inherits nothing, so it is given the
     * same defaults the config was given. */
    named_certificate one;
    one.host = host;
    one.ctx.reset(SSL_CTX_new(TLS_method()));
    if (!one.ctx) {
        fail(config->last, MRB_TLS_ERR_MEMORY, "no memory for a named certificate");
        return MRB_TLS_FAILED;
    }
    SSL_CTX_set_min_proto_version(one.ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(one.ctx.get(), TLS1_3_VERSION);
    SSL_CTX_set_verify(one.ctx.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_mode(one.ctx.get(),
                     SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(one.ctx.get(), SSL_OP_NO_RENEGOTIATION);

    mrb_tls_config holder;
    holder.ctx = std::move(one.ctx);
    const mrb_tls_status cert = mrb_tls_config_set_certificate(&holder, cert_pem, cert_len);
    const mrb_tls_status key =
        cert == MRB_TLS_OK ? mrb_tls_config_set_private_key(&holder, key_pem, key_len) : cert;
    if (key != MRB_TLS_OK) {
        config->last = holder.last;
        return MRB_TLS_FAILED;
    }
    one.ctx = std::move(holder.ctx);
    config->named.push_back(std::move(one));

    /* The callback is installed on the first named certificate and not
     * before: a config with one certificate has nothing to choose. */
    SSL_CTX_set_tlsext_servername_callback(config->ctx.get(), servername_pick);
    SSL_CTX_set_tlsext_servername_arg(config->ctx.get(), config);
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_trust_file(mrb_tls_config *config, const char *path)
{
    if (config == nullptr || path == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    if (SSL_CTX_load_verify_locations(config->ctx.get(), path, nullptr) != 1) {
        fail_library(config->last, "the trust file was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_trust_path(mrb_tls_config *config, const char *path)
{
    if (config == nullptr || path == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    if (SSL_CTX_load_verify_locations(config->ctx.get(), nullptr, path) != 1) {
        fail_library(config->last, "the trust directory was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

void mrb_tls_config_set_verify(mrb_tls_config *config, bool chain, bool name, bool time)
{
    if (config == nullptr)
        return;
    config->verify_chain = chain;
    config->verify_name = name;
    config->verify_time = time;
}

void mrb_tls_config_set_verify_depth(mrb_tls_config *config, int depth)
{
    if (config != nullptr)
        SSL_CTX_set_verify_depth(config->ctx.get(), depth);
}

mrb_tls_status mrb_tls_config_set_protocols(mrb_tls_config *config, uint32_t mask)
{
    if (config == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    return apply_protocols(config->ctx.get(), mask, config->last) ? MRB_TLS_OK : MRB_TLS_FAILED;
}

mrb_tls_status mrb_tls_config_set_ciphers(mrb_tls_config *config, const char *list)
{
    if (config == nullptr || list == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    /* Two lists, because TLS 1.3 names its suites in one and everything
     * older in the other. A name the library does not know fails here
     * rather than at the handshake. */
    if (SSL_CTX_set_ciphersuites(config->ctx.get(), list) != 1 &&
        SSL_CTX_set_cipher_list(config->ctx.get(), list) != 1) {
        fail_library(config->last, "the cipher list was refused");
        return MRB_TLS_FAILED;
    }
    ERR_clear_error();
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_groups(mrb_tls_config *config, const char *list)
{
    if (config == nullptr || list == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    if (SSL_CTX_set1_groups_list(config->ctx.get(), list) != 1) {
        fail_library(config->last, "the group list was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_alpn(mrb_tls_config *config, const char *const *names,
                                       size_t count)
{
    if (config == nullptr || (names == nullptr && count > 0))
        return MRB_TLS_FAILED;
    config->last.clear();
    if (!pack_alpn(names, count, config->alpn, config->last))
        return MRB_TLS_FAILED;

    /* A client sends its list; a server answers with one of its own. A
     * config serves both roles, so both are installed. */
    if (!config->alpn.empty()) {
        SSL_CTX_set_alpn_protos(config->ctx.get(), config->alpn.data(),
                                static_cast<unsigned int>(config->alpn.size()));
        SSL_CTX_set_alpn_select_cb(config->ctx.get(), alpn_pick, &config->alpn);
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_config_set_tickets(mrb_tls_config *config, size_t count)
{
    if (config == nullptr)
        return MRB_TLS_FAILED;
    config->last.clear();
    SSL_CTX_set_num_tickets(config->ctx.get(), count);
    return MRB_TLS_OK;
}

void mrb_tls_config_set_server_name_hook(mrb_tls_config *config,
                                         mrb_tls_config *(*hook)(void *ctx, const char *host,
                                                                 bool *abort),
                                         void *ctx)
{
    if (config == nullptr)
        return;
    config->name_hook = hook;
    config->name_hook_ctx = ctx;
    SSL_CTX_set_tlsext_servername_callback(config->ctx.get(), servername_pick);
    SSL_CTX_set_tlsext_servername_arg(config->ctx.get(), config);
}

} /* extern "C" */

#endif /* _WIN32 */

#ifndef _WIN32

/* ------------------------------------------------------------------ */
/* The session                                                         */
/* ------------------------------------------------------------------ */

namespace
{

/* The three axes, asked after the handshake rather than during it.
 *
 * OpenSSL can answer the chain by itself, but not "and what would the
 * result have been ignoring the dates" once it has recorded an expiry,
 * and not the name against a host it was never told. So the chain comes
 * from the library, the name from X509_check_host, and the dates are
 * waived before the handshake when they are not wanted. */
bool verify_peer(mrb_tls_session *session)
{
    mrb_tls_config *config = nullptr;
    (void)config;
    if (!session->verify_chain && !session->verify_name)
        return true;

    X509 *peer = SSL_get1_peer_certificate(session->ssl.get());
    if (peer == nullptr) {
        fail(session->last, MRB_TLS_ERR_VERIFY, "the peer presented no certificate");
        return false;
    }
    bool ok = true;
    if (session->verify_chain) {
        const long result = SSL_get_verify_result(session->ssl.get());
        if (result != X509_V_OK) {
            fail(session->last, MRB_TLS_ERR_VERIFY,
                 std::string("the peer's certificate chain was refused: ") +
                     X509_verify_cert_error_string(result),
                 static_cast<int>(result));
            ok = false;
        }
    }
    if (ok && session->verify_name) {
        if (session->server_name.empty()) {
            fail(session->last, MRB_TLS_ERR_VERIFY,
                 "the name was to be checked and no server name was set");
            ok = false;
        } else if (X509_check_host(peer, session->server_name.data(), session->server_name.size(),
                                   0, nullptr) != 1) {
            fail(session->last, MRB_TLS_ERR_VERIFY,
                 "the peer's certificate is for another name than " + session->server_name);
            ok = false;
        }
    }
    X509_free(peer);
    return ok;
}

/* What the library says it wants, turned into what the caller has to
 * do. The BIO's own want is preferred where it has one: it knows
 * whether the transport could not be read or could not be written, and
 * SSL_get_error flattens both into want-read on a renegotiating
 * handshake. */
mrb_tls_status want_of(mrb_tls_session *session, int result)
{
    const int why = SSL_get_error(session->ssl.get(), result);
    BIO *bio = SSL_get_rbio(session->ssl.get());
    const bio_want bw = bio == nullptr ? bio_want::none : tls_bio_want(bio);

    if (bw == bio_want::failed) {
        /* The io callback already wrote the reason, kind IO. */
        return MRB_TLS_FAILED;
    }
    if (bw == bio_want::closed && why != SSL_ERROR_ZERO_RETURN) {
        fail(session->last, MRB_TLS_ERR_IO,
             "the transport ended before the peer said close_notify");
        return MRB_TLS_FAILED;
    }
    switch (why) {
    case SSL_ERROR_WANT_READ:
        return MRB_TLS_AGAIN_READ;
    case SSL_ERROR_WANT_WRITE:
        return MRB_TLS_AGAIN_WRITE;
    case SSL_ERROR_ZERO_RETURN:
        return MRB_TLS_CLOSED;
    case SSL_ERROR_SYSCALL:
        if (session->last.kind == MRB_TLS_ERR_NONE)
            fail(session->last, MRB_TLS_ERR_IO, "the transport failed and said nothing");
        return MRB_TLS_FAILED;
    default:
        fail_library(session->last, "the library refused the session");
        return MRB_TLS_FAILED;
    }
}

/* Why this session will not hand its records to a kernel. Recorded
 * once, read by whoever wants to print it, and never a failure. */
void stay_in_userspace(mrb_tls_session *session, std::string why)
{
    session->mode = MRB_TLS_MODE_USERSPACE;
    session->fallback.kind = MRB_TLS_ERR_KERNEL;
    session->fallback.text = std::move(why);
}

#ifdef TLS_KERNEL_RECORDS

/* The kernel takes three options in this order, and each answer means
 * something different.
 *
 * TCP_ULP may say EEXIST, which is not a failure: something attached
 * the module already, and that is exactly what a reactor does at accept
 * time so the cost lands off the handshake. ENOENT is the module not
 * being there at all, EPERM the caller not being allowed to load it -
 * both of them ordinary, and both of them userspace.
 *
 * TLS_TX taking and TLS_RX refusing is the one answer that is a
 * failure: the kernel holds the send key and the session can no longer
 * write through the library. Kernel cipher support is symmetric, so it
 * should not happen; if it does, the session says so rather than
 * carrying on with half a socket. */
mrb_tls_status perform_handover(mrb_tls_session *session)
{
    mrb_tls_io &io = session->io;
    while (session->step < session->plan.size()) {
        handover_step &step = session->plan[session->step];
        int err = 0;
        const mrb_tls_io_status status = io.set_socket_option(
            io.ctx, step.level, step.name, step.bytes.data(), step.bytes.size(), &err);
        if (status == MRB_TLS_IO_AGAIN)
            return MRB_TLS_AGAIN_WRITE;
        if (status == MRB_TLS_IO_DONE) {
            session->step++;
            continue;
        }

        const bool first = session->step == 0;
        if (first && err == EEXIST) {
            /* Attached earlier, by the caller, on purpose. */
            session->step++;
            continue;
        }
        if (first && (err == ENOENT || err == EPERM || err == EOPNOTSUPP || err == ENOTCONN)) {
            stay_in_userspace(session, err == ENOENT
                                           ? "this kernel has no tls module to attach"
                                           : "this process may not attach the tls module");
            return MRB_TLS_OK;
        }
        if (session->step == 1 && (err == EINVAL || err == ENOPROTOOPT || err == EOPNOTSUPP)) {
            /* An older kernel with the module but without this cipher.
             * The ULP alone forwards bytes unchanged, so nothing is
             * broken; the records stay here. */
            stay_in_userspace(session, "this kernel does not take the negotiated cipher");
            return MRB_TLS_OK;
        }
        fail(session->last, MRB_TLS_ERR_KERNEL,
             session->step == 2
                 ? "the kernel took the send key and refused the receive key"
                 : "the kernel refused the record layer it had begun to take",
             err);
        return MRB_TLS_FAILED;
    }
    session->mode = MRB_TLS_MODE_KERNEL;
    session->fallback.clear();
    return MRB_TLS_OK;
}

/* Everything the kernel needs, computed as one value before any of it
 * is applied. A plan that cannot be built is a session that stays where
 * it is, with the reason. */
bool plan_handover(mrb_tls_session *session)
{
    const SSL_CIPHER *cipher = SSL_get_current_cipher(session->ssl.get());
    if (cipher == nullptr) {
        stay_in_userspace(session, "no cipher was negotiated");
        return false;
    }
    const cipher_row *row = cipher_row_of(SSL_CIPHER_get_cipher_nid(cipher));
    if (row == nullptr) {
        stay_in_userspace(session, std::string("the kernel has no shape for ") +
                                       SSL_CIPHER_get_name(cipher));
        return false;
    }
    session->row = row;
    session->digest = SSL_CIPHER_get_handshake_digest(cipher);
    if (session->digest == nullptr) {
        stay_in_userspace(session, "the suite named no digest");
        return false;
    }
    if (session->secret[0].empty() || session->secret[1].empty()) {
        stay_in_userspace(session, "the traffic secrets did not reach the keylog");
        return false;
    }

    /* Which secret is ours to send under depends on which end we are. */
    const int send_at = session->role == MRB_TLS_SERVER ? 1 : 0;
    const int receive_at = 1 - send_at;

    std::vector<std::byte> tx;
    std::vector<std::byte> rx;
    if (!write_handover_payload(*row, session->secret[send_at], session->digest,
                                session->tx_records(), tx) ||
        !write_handover_payload(*row, session->secret[receive_at], session->digest,
                                session->rx_records(), rx)) {
        stay_in_userspace(session, "the traffic keys could not be derived");
        return false;
    }

    session->plan.clear();
    /* "tls" with its terminator, which is what TCP_ULP takes. */
    const char ulp[] = "tls";
    std::vector<std::byte> ulp_bytes(sizeof ulp);
    std::memcpy(ulp_bytes.data(), ulp, sizeof ulp);
    session->plan.push_back({IPPROTO_TCP, TCP_ULP, std::move(ulp_bytes)});
    session->plan.push_back({SOL_TLS, TLS_TX, std::move(tx)});
    session->plan.push_back({SOL_TLS, TLS_RX, std::move(rx)});
    session->step = 0;
    return true;
}

#endif /* TLS_KERNEL_RECORDS */

/* The one place the mode is decided. Everything before it has to be
 * finished: the handshake, the peer, and whatever the transport read
 * past the handshake and is holding. */
mrb_tls_status decide_mode(mrb_tls_session *session)
{
    if (session->mode != MRB_TLS_MODE_UNDECIDED)
        return MRB_TLS_OK;

    mrb_tls_io &io = session->io;
    if (io.set_socket_option == nullptr) {
        stay_in_userspace(session, "the caller offered no way to set a socket option");
        return MRB_TLS_OK;
    }
    if (io.read_record == nullptr || io.write_record == nullptr) {
        stay_in_userspace(session,
                          "the caller offered no record-typed read and write, which a kernel "
                          "record layer needs for alerts and key updates");
        return MRB_TLS_OK;
    }
    if (SSL_version(session->ssl.get()) != TLS1_3_VERSION) {
        stay_in_userspace(session, "kernel records need TLS 1.3");
        return MRB_TLS_OK;
    }
    if (io.read_ahead_held != nullptr && io.read_ahead_held(io.ctx) > 0) {
        stay_in_userspace(session,
                          "the transport is holding bytes the kernel would never see");
        return MRB_TLS_OK;
    }

#ifdef TLS_KERNEL_RECORDS
    if (!plan_handover(session))
        return MRB_TLS_OK; /* the reason is recorded */
    return perform_handover(session);
#else
    stay_in_userspace(session, "this build has no kernel record layer: " TLS_LIBRARY_NAME
                               " on this system");
    return MRB_TLS_OK;
#endif
}

} // namespace

extern "C" {

mrb_tls_session *mrb_tls_session_new(mrb_tls_config *config, mrb_tls_role role,
                                     const mrb_tls_io *io)
{
    if (config == nullptr || io == nullptr || io->read == nullptr || io->write == nullptr)
        return nullptr;

    auto *session = new (std::nothrow) mrb_tls_session();
    if (session == nullptr)
        return nullptr;

    session->io = *io;
    session->role = role;
    session->verify_chain = config->verify_chain;
    session->verify_name = config->verify_name;

    /* A reference of our own, so the caller may free the config while
     * this session lives. */
    SSL_CTX_up_ref(config->ctx.get());
    session->ctx.reset(config->ctx.get());

    session->ssl.reset(SSL_new(session->ctx.get()));
    if (!session->ssl) {
        delete session;
        return nullptr;
    }
    if (!config->verify_time) {
        X509_VERIFY_PARAM *param = SSL_get0_param(session->ssl.get());
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
    }

    BIO *bio = tls_bio_new(session);
    if (bio == nullptr) {
        delete session;
        return nullptr;
    }
    /* One BIO for both directions, and the SSL owns it from here. */
    BIO_up_ref(bio);
    SSL_set_bio(session->ssl.get(), bio, bio);

    if (role == MRB_TLS_SERVER)
        SSL_set_accept_state(session->ssl.get());
    else
        SSL_set_connect_state(session->ssl.get());
    return session;
}

void mrb_tls_session_free(mrb_tls_session *session)
{
    delete session;
}

const mrb_tls_error *mrb_tls_session_error(const mrb_tls_session *session)
{
    return session == nullptr ? nullptr : &session->last;
}

const mrb_tls_error *mrb_tls_session_fallback_reason(const mrb_tls_session *session)
{
    return session == nullptr ? nullptr : &session->fallback;
}

mrb_tls_mode mrb_tls_session_mode(const mrb_tls_session *session)
{
    return session == nullptr ? MRB_TLS_MODE_UNDECIDED : session->mode;
}

mrb_tls_status mrb_tls_session_set_server_name(mrb_tls_session *session, const char *host)
{
    if (session == nullptr || host == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->phase != phase::handshake) {
        fail(session->last, MRB_TLS_ERR_STATE, "the server name is set before the handshake");
        return MRB_TLS_FAILED;
    }
    session->server_name = host;
    if (session->role == MRB_TLS_CLIENT &&
        SSL_set_tlsext_host_name(session->ssl.get(), session->server_name.c_str()) != 1) {
        fail_library(session->last, "the server name was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_session_set_protocols(mrb_tls_session *session, uint32_t mask)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    const std::uint32_t known = MRB_TLS_PROTOCOL_TLSv1_2 | MRB_TLS_PROTOCOL_TLSv1_3;
    if ((mask & known) == 0) {
        fail(session->last, MRB_TLS_ERR_ARGUMENT, "the protocol mask names no version this "
                                                  "library offers");
        return MRB_TLS_FAILED;
    }
    const int low = (mask & MRB_TLS_PROTOCOL_TLSv1_2) != 0 ? TLS1_2_VERSION : TLS1_3_VERSION;
    const int high = (mask & MRB_TLS_PROTOCOL_TLSv1_3) != 0 ? TLS1_3_VERSION : TLS1_2_VERSION;
    if (SSL_set_min_proto_version(session->ssl.get(), low) != 1 ||
        SSL_set_max_proto_version(session->ssl.get(), high) != 1) {
        fail_library(session->last, "the protocol range was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_session_handshake(mrb_tls_session *session)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();

    if (session->phase == phase::handshake) {
        const int result = SSL_do_handshake(session->ssl.get());
        if (result != 1)
            return want_of(session, result);

        /* What was agreed, read once and kept: after a shrink the SSL
         * may be gone and these still answer. */
        const SSL_CIPHER *cipher = SSL_get_current_cipher(session->ssl.get());
        if (cipher != nullptr)
            session->cipher_name = SSL_CIPHER_get_name(cipher);
        session->version_name = SSL_get_version(session->ssl.get());
        const unsigned char *alpn = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(session->ssl.get(), &alpn, &alpn_len);
        session->alpn_name.assign(reinterpret_cast<const char *>(alpn), alpn_len);

        if (session->role == MRB_TLS_CLIENT && !verify_peer(session))
            return MRB_TLS_FAILED;
        /* Nothing arrives under the application key before this point,
         * and a client writes nothing under it either, so both counts
         * start here. A server's outbound count does not: its tickets
         * go out inside this very call, and they are application key
         * records the kernel has to count past. */
        session->rx_at_done = session->rx_walk.records;
        session->tx_at_done = session->tx_walk.records;
        session->phase = phase::verified;
    }

    if (session->phase == phase::verified) {
        const mrb_tls_status decided = decide_mode(session);
        if (decided != MRB_TLS_OK)
            return decided;
        session->phase = phase::ready;
    }
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_session_read(mrb_tls_session *session, void *buf, size_t cap, size_t *got)
{
    if (session == nullptr || buf == nullptr || got == nullptr)
        return MRB_TLS_FAILED;
    *got = 0;
    session->last.clear();
    if (session->phase != phase::ready) {
        fail(session->last, MRB_TLS_ERR_STATE, "the handshake has not finished");
        return MRB_TLS_FAILED;
    }

    if (session->mode == MRB_TLS_MODE_KERNEL) {
        /* The kernel decrypted it. What arrives is plaintext, and the
         * type says whether it is the application's. */
        mrb_tls_io &io = session->io;
        unsigned char type = 23;
        int err = 0;
        const mrb_tls_io_status status = io.read_record(io.ctx, buf, cap, got, &type, &err);
        switch (status) {
        case MRB_TLS_IO_DONE:
            if (type == 23)
                return MRB_TLS_OK;
            return mrb_tls_session_control_record(session, type, buf, *got);
        case MRB_TLS_IO_AGAIN:
            return MRB_TLS_AGAIN_READ;
        case MRB_TLS_IO_CLOSED:
            return MRB_TLS_CLOSED;
        default:
            fail(session->last, MRB_TLS_ERR_IO, "the transport could not be read", err);
            return MRB_TLS_FAILED;
        }
    }

    const int result = SSL_read_ex(session->ssl.get(), buf, cap, got);
    if (result == 1)
        return MRB_TLS_OK;
    return want_of(session, 0);
}

mrb_tls_status mrb_tls_session_write(mrb_tls_session *session, const void *buf, size_t len,
                                     size_t *put)
{
    if (session == nullptr || buf == nullptr || put == nullptr)
        return MRB_TLS_FAILED;
    *put = 0;
    session->last.clear();
    if (session->phase != phase::ready) {
        fail(session->last, MRB_TLS_ERR_STATE, "the handshake has not finished");
        return MRB_TLS_FAILED;
    }

    if (session->mode == MRB_TLS_MODE_KERNEL) {
        mrb_tls_io &io = session->io;
        int err = 0;
        const mrb_tls_io_status status = io.write(io.ctx, buf, len, put, &err);
        switch (status) {
        case MRB_TLS_IO_DONE:
            return MRB_TLS_OK;
        case MRB_TLS_IO_AGAIN:
            return MRB_TLS_AGAIN_WRITE;
        case MRB_TLS_IO_CLOSED:
            return MRB_TLS_CLOSED;
        default:
            fail(session->last, MRB_TLS_ERR_IO, "the transport could not be written", err);
            return MRB_TLS_FAILED;
        }
    }

    const int result = SSL_write_ex(session->ssl.get(), buf, len, put);
    if (result == 1)
        return MRB_TLS_OK;
    return want_of(session, 0);
}

size_t mrb_tls_session_pending(const mrb_tls_session *session)
{
    if (session == nullptr || !session->ssl)
        return 0;
    return static_cast<size_t>(SSL_pending(session->ssl.get()));
}

mrb_tls_status mrb_tls_session_close(mrb_tls_session *session)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->phase == phase::closed)
        return MRB_TLS_OK;

    if (session->mode == MRB_TLS_MODE_KERNEL) {
        /* close_notify as a record of its own type: the kernel is
         * holding the send key, so the library must not write it. */
        mrb_tls_io &io = session->io;
        const unsigned char bye[] = {1, 0}; /* warning, close_notify */
        std::size_t put = 0;
        int err = 0;
        const mrb_tls_io_status status = io.write_record(io.ctx, 21, bye, sizeof bye, &put, &err);
        if (status == MRB_TLS_IO_AGAIN)
            return MRB_TLS_AGAIN_WRITE;
        session->phase = phase::closed;
        return status == MRB_TLS_IO_FAILED ? MRB_TLS_FAILED : MRB_TLS_OK;
    }

    const int result = SSL_shutdown(session->ssl.get());
    if (result < 0) {
        const mrb_tls_status status = want_of(session, result);
        if (status == MRB_TLS_AGAIN_READ || status == MRB_TLS_AGAIN_WRITE)
            return status;
    }
    session->phase = phase::closed;
    return MRB_TLS_OK;
}

/* A record the caller read itself, of a type that is not application
 * data. In kernel mode this is the only way an alert or a KeyUpdate
 * reaches the session, because the kernel decrypted it and the library
 * never saw the bytes.
 *
 * RFC 8446 6.1: a close_notify is an alert of level warning with
 * description 0. Anything else at level fatal ends the session, and the
 * description is the number a caller wants. */
mrb_tls_status mrb_tls_session_control_record(mrb_tls_session *session, unsigned char type,
                                              const void *payload, size_t len)
{
    if (session == nullptr || (payload == nullptr && len > 0))
        return MRB_TLS_FAILED;
    const auto *bytes = static_cast<const unsigned char *>(payload);

    if (type == 21) { /* alert */
        if (len < 2) {
            fail(session->last, MRB_TLS_ERR_PROTOCOL, "an alert record carried fewer than two "
                                                      "bytes");
            return MRB_TLS_FAILED;
        }
        if (bytes[1] == 0) { /* close_notify */
            session->phase = phase::closed;
            return MRB_TLS_CLOSED;
        }
        fail(session->last, MRB_TLS_ERR_ALERT, "the peer sent an alert", bytes[1]);
        return MRB_TLS_FAILED;
    }

    if (type == 22) { /* handshake */
        if (len < 1) {
            fail(session->last, MRB_TLS_ERR_PROTOCOL, "a handshake record carried no type");
            return MRB_TLS_FAILED;
        }
        /* A NewSessionTicket that arrives after the handover cannot be
         * given to the library: there is no way to hand it a plaintext
         * handshake message. The connection is sound and one ticket is
         * lost, so this is not a failure and not a reason to change
         * the record layer. */
        if (bytes[0] == 4)
            return MRB_TLS_OK;
        if (bytes[0] == 24) /* KeyUpdate */
            return mrb_tls_session_rekey(session);
        fail(session->last, MRB_TLS_ERR_PROTOCOL,
             "the peer sent a handshake message this session cannot take after the handover");
        return MRB_TLS_FAILED;
    }

    fail(session->last, MRB_TLS_ERR_PROTOCOL, "the peer sent a record of an unknown type",
         type);
    return MRB_TLS_FAILED;
}

/* New traffic keys in both directions.
 *
 * In userspace mode the library owns this and does it properly, wire
 * message and all. In kernel mode the keys are ours to derive and the
 * kernel's to install, and the sequence starts over at zero under each
 * new secret. */
mrb_tls_status mrb_tls_session_rekey(mrb_tls_session *session)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->phase != phase::ready) {
        fail(session->last, MRB_TLS_ERR_STATE, "a rekey needs a finished handshake");
        return MRB_TLS_FAILED;
    }
    if (session->mode == MRB_TLS_MODE_USERSPACE) {
        if (SSL_key_update(session->ssl.get(), SSL_KEY_UPDATE_NOT_REQUESTED) != 1) {
            fail_library(session->last, "the library refused a key update");
            return MRB_TLS_FAILED;
        }
        return MRB_TLS_OK;
    }

#ifdef TLS_KERNEL_RECORDS
    if (session->row == nullptr || session->digest == nullptr) {
        fail(session->last, MRB_TLS_ERR_STATE, "this session has no kernel keys to update");
        return MRB_TLS_FAILED;
    }
    const int send_at = session->role == MRB_TLS_SERVER ? 1 : 0;
    for (int which = 0; which < 2; which++) {
        std::vector<std::byte> next(session->secret[which].size());
        if (!next_traffic_secret(session->digest, session->secret[which], next)) {
            fail(session->last, MRB_TLS_ERR_LIBRARY, "the next traffic secret could not be "
                                                     "derived");
            return MRB_TLS_FAILED;
        }
        session->secret[which] = std::move(next);
    }
    /* A new key starts its own count, so every walker is read as being
     * at zero from here, whichever rule the role uses. */
    session->tx_at_last_read = session->tx_walk.records;
    session->tx_at_done = session->tx_walk.records;
    session->rx_at_done = session->rx_walk.records;
    std::vector<std::byte> tx;
    std::vector<std::byte> rx;
    if (!write_handover_payload(*session->row, session->secret[send_at], session->digest, 0, tx) ||
        !write_handover_payload(*session->row, session->secret[1 - send_at], session->digest, 0,
                                rx)) {
        fail(session->last, MRB_TLS_ERR_LIBRARY, "the new traffic keys could not be written");
        return MRB_TLS_FAILED;
    }
    session->plan.clear();
    session->plan.push_back({SOL_TLS, TLS_TX, std::move(tx)});
    session->plan.push_back({SOL_TLS, TLS_RX, std::move(rx)});
    session->step = 0;
    return perform_handover(session);
#else
    fail(session->last, MRB_TLS_ERR_STATE, "this build has no kernel record layer");
    return MRB_TLS_FAILED;
#endif
}

uint64_t mrb_tls_session_record_limit(const mrb_tls_session *session)
{
#ifdef TLS_KERNEL_RECORDS
    return session != nullptr && session->row != nullptr ? session->row->record_limit : 0;
#else
    (void)session;
    return 0;
#endif
}

mrb_tls_status mrb_tls_session_set_kernel_option(mrb_tls_session *session,
                                                 mrb_tls_kernel_option option, bool on)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->mode != MRB_TLS_MODE_KERNEL) {
        fail(session->last, MRB_TLS_ERR_STATE,
             "this option belongs to a kernel record layer, and this session keeps its own");
        return MRB_TLS_FAILED;
    }
#ifdef TLS_KERNEL_RECORDS
    const int name = option == MRB_TLS_KERNEL_SEND_PAGES_READ_ONLY ? TLS_TX_ZEROCOPY_RO
                                                                  : TLS_RX_EXPECT_NO_PAD;
    const int value = on ? 1 : 0;
    int err = 0;
    mrb_tls_io &io = session->io;
    const mrb_tls_io_status status =
        io.set_socket_option(io.ctx, SOL_TLS, name, &value, sizeof value, &err);
    if (status == MRB_TLS_IO_AGAIN)
        return MRB_TLS_AGAIN_WRITE;
    if (status != MRB_TLS_IO_DONE) {
        fail(session->last, MRB_TLS_ERR_KERNEL, "the kernel refused the option", err);
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
#else
    (void)option;
    (void)on;
    fail(session->last, MRB_TLS_ERR_STATE, "this build has no kernel record layer");
    return MRB_TLS_FAILED;
#endif
}

/* Once the kernel holds the records the library is needed for rekeying
 * and nothing else, and a rekey needs the secrets rather than the SSL.
 * A server with many idle connections may therefore drop it. */
mrb_tls_status mrb_tls_session_shrink(mrb_tls_session *session)
{
    if (session == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->mode != MRB_TLS_MODE_KERNEL) {
        fail(session->last, MRB_TLS_ERR_STATE,
             "a session that keeps its own records needs the library it would drop");
        return MRB_TLS_FAILED;
    }
    session->ssl.reset();
    session->ctx.reset();
    return MRB_TLS_OK;
}

mrb_tls_status mrb_tls_session_resume(mrb_tls_session *session, const void *der, size_t len)
{
    if (session == nullptr || der == nullptr)
        return MRB_TLS_FAILED;
    session->last.clear();
    if (session->phase != phase::handshake) {
        fail(session->last, MRB_TLS_ERR_STATE, "a session is offered before the handshake");
        return MRB_TLS_FAILED;
    }
    const auto *bytes = static_cast<const unsigned char *>(der);
    SSL_SESSION *earlier = d2i_SSL_SESSION(nullptr, &bytes, static_cast<long>(len));
    if (earlier == nullptr) {
        fail_library(session->last, "the session could not be read");
        return MRB_TLS_FAILED;
    }
    const int ok = SSL_set_session(session->ssl.get(), earlier);
    SSL_SESSION_free(earlier);
    if (ok != 1) {
        fail_library(session->last, "the session was refused");
        return MRB_TLS_FAILED;
    }
    return MRB_TLS_OK;
}

const void *mrb_tls_session_export(const mrb_tls_session *session, size_t *len)
{
    if (len != nullptr)
        *len = 0;
    if (session == nullptr || !session->ssl)
        return nullptr;
    SSL_SESSION *now = SSL_get1_session(session->ssl.get());
    if (now == nullptr)
        return nullptr;
    auto *mutable_session = const_cast<mrb_tls_session *>(session);
    unsigned char *out = nullptr;
    const int size = i2d_SSL_SESSION(now, &out);
    SSL_SESSION_free(now);
    if (size <= 0 || out == nullptr)
        return nullptr;
    mutable_session->session_der.assign(reinterpret_cast<std::byte *>(out),
                                        reinterpret_cast<std::byte *>(std::next(out, size)));
    OPENSSL_free(out);
    if (len != nullptr)
        *len = mutable_session->session_der.size();
    return mutable_session->session_der.data();
}

bool mrb_tls_session_resumed(const mrb_tls_session *session)
{
    return session != nullptr && session->ssl && SSL_session_reused(session->ssl.get()) == 1;
}

/* The control message a kernel record layer carries a record's type in.
 * Defined on every system, so a reactor that builds its own recvmsg
 * needs no guard of its own: where there is no kernel record layer they
 * answer zero, and the type of a record nobody labelled is application
 * data. */
int mrb_tls_record_type_level(void)
{
#ifdef TLS_KERNEL_RECORDS
    return SOL_TLS;
#else
    return 0;
#endif
}

int mrb_tls_record_type_cmsg(void)
{
#ifdef TLS_KERNEL_RECORDS
    return TLS_GET_RECORD_TYPE;
#else
    return 0;
#endif
}

int mrb_tls_record_type_set_cmsg(void)
{
#ifdef TLS_KERNEL_RECORDS
    return TLS_SET_RECORD_TYPE;
#else
    return 0;
#endif
}

unsigned char mrb_tls_record_type_of(const void *cmsg_data, size_t len)
{
    if (cmsg_data == nullptr || len == 0)
        return 23;
    return *static_cast<const unsigned char *>(cmsg_data);
}

const char *mrb_tls_session_cipher(const mrb_tls_session *session)
{
    return session == nullptr ? "" : session->cipher_name.c_str();
}

const char *mrb_tls_session_version(const mrb_tls_session *session)
{
    return session == nullptr ? "" : session->version_name.c_str();
}

const char *mrb_tls_session_alpn(const mrb_tls_session *session, size_t *len)
{
    if (session == nullptr) {
        if (len != nullptr)
            *len = 0;
        return "";
    }
    if (len != nullptr)
        *len = session->alpn_name.size();
    return session->alpn_name.c_str();
}

bool mrb_tls_aes_is_fast(void)
{
    /* Whether the processor carries AES instructions. OpenSSL knows,
     * and keeps the answer to itself: EVP_has_aes_hardware is internal.
     * So the compiler's own probe answers, which is what the kTLS line
     * of this gem used and what every arch here can be asked.
     *
     * A server that gets false orders ChaCha20 ahead of AES, because a
     * processor without the instructions runs ChaCha faster. */
#if defined(__x86_64__) || defined(__i386__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("aes") != 0;
#elif defined(__aarch64__) && defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return false;
#endif
}

} /* extern "C" */

SSL *tls_session_ssl(mrb_tls_session *session)
{
    return session == nullptr ? nullptr : session->ssl.get();
}

std::uint64_t tls_session_record_count(const mrb_tls_session *session, bool sending)
{
    if (session == nullptr)
        return 0;
    return sending ? session->tx_records() : session->rx_records();
}

#endif /* _WIN32 */

#ifndef _WIN32
/* The example's window onto the record count, with C linkage so a C
 * program can declare it. Not in the public header: a caller does not
 * need this number, and a test does. */
extern "C" unsigned long long tls_session_record_count_of(mrb_tls_session *session, int sending)
{
    return tls_session_record_count(session, sending != 0);
}
#endif
