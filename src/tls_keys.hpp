#ifndef MRUBY_TLS_KEYS_HPP
#define MRUBY_TLS_KEYS_HPP

/* The kernel's record layer, in the terms it takes.
 *
 * Declared apart from the core because it is the one part with no state
 * of its own: give it a secret and a cipher and it answers bytes. That
 * makes it testable without a session, and it keeps the kernel's
 * headers out of every other file.
 */

#include "tls_platform.h"

#ifdef TLS_KERNEL_RECORDS

#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* The kernel's own numbers, for a distribution whose headers are older
 * than its kernel. Defined after the headers that may already carry
 * them, so a system that has them keeps its own. */
#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>

/* TLS 1.3 derives twelve iv bytes, always, whatever the cipher. The
 * kernel splits them into a salt it keeps and an iv it counts from, and
 * the two lengths add up to this. */
constexpr std::size_t kTrafficIvSize = 12;

/* The record sequence the kernel counts from, eight bytes big endian,
 * as every tls12_crypto_info_* declares it. */
constexpr std::size_t kRecordSequenceSize = 8;

/* One cipher the kernel can hold. Every size is the header's own. */
struct cipher_row {
    int nid;                   /* what SSL_CIPHER_get_cipher_nid answers */
    std::uint16_t kernel_type; /* TLS_CIPHER_* */
    std::size_t key_size;
    std::size_t salt_size;
    std::size_t iv_size;
    std::size_t payload_size; /* sizeof the kernel's struct for this cipher */
    /* How many records this cipher may protect before a rekey is owed.
     * Zero where the RFC sets no limit worth counting. These four are
     * ours to state, because they are a rule and not a size. */
    std::uint64_t record_limit;
    std::string_view name;
};

/* Key material wiped when it goes out of scope.
 *
 * A vector that held a traffic key calls operator delete with the key
 * still in the block, and the next allocation of that size - an mruby
 * String, a receive buffer, an error message - is handed those bytes.
 * So every run that held key material is wiped before it is released,
 * and the guard does it wherever the scope ends, including on a throw.
 *
 * It holds a REFERENCE to the container and reads its bytes at
 * destruction, not at construction. A guard built over a span of an
 * empty vector that is filled afterwards would wipe nothing, which is
 * a guard that lies.
 *
 * It cannot save a buffer a vector abandoned while growing. That one is
 * the caller's to avoid, by reserving what it will need before it
 * fills anything.
 *
 * OPENSSL_cleanse and not std::fill: a compiler may drop a write to
 * memory nothing reads again, and OPENSSL_cleanse is written so it
 * cannot. */
template <class Bytes>
class scoped_wipe
{
public:
    explicit scoped_wipe(Bytes &held) : held_(held) {}
    scoped_wipe(const scoped_wipe &) = delete;
    scoped_wipe &operator=(const scoped_wipe &) = delete;
    ~scoped_wipe()
    {
        if (!held_.empty())
            OPENSSL_cleanse(held_.data(), held_.size() * sizeof(typename Bytes::value_type));
    }

private:
    Bytes &held_;
};

template <class Bytes> scoped_wipe(Bytes &) -> scoped_wipe<Bytes>;

/* The same, for a run of bytes a caller owns and will keep using. */
void wipe_bytes(std::span<std::byte> bytes);

/* The row for a cipher, or nullptr where the kernel has no shape for
 * it. A suite with no row is not a failure: it is a session that keeps
 * its records in userspace, and the reason names the suite. */
const cipher_row *cipher_row_of(int nid);

/* HKDF-Expand-Label for "key" and "iv", RFC 8446 7.3. */
bool derive_traffic_key(const EVP_MD *digest, std::span<const std::byte> secret,
                        std::span<std::byte> key, std::span<std::byte> iv);

/* The next secret in the same direction, RFC 8446 7.2. The sequence
 * starts over at zero under it. */
bool next_traffic_secret(const EVP_MD *digest, std::span<const std::byte> secret,
                         std::span<std::byte> out);

/* The bytes a TLS_TX or TLS_RX socket option takes, for this cipher and
 * this secret, counting from this record. */
bool write_handover_payload(const cipher_row &row, std::span<const std::byte> secret,
                            const EVP_MD *digest, std::uint64_t record_sequence,
                            std::vector<std::byte> &out);

#endif /* TLS_KERNEL_RECORDS */

#endif /* MRUBY_TLS_KEYS_HPP */
