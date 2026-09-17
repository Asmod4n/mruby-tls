/* What the kernel needs to hold a record layer, derived and written.
 *
 * Every size in this file comes from <linux/tls.h>. Not one is ours: a
 * key length, a salt length, a payload length are the kernel's own
 * constants, and a number invented here would be a wrong guess that
 * compiles.
 *
 * The schedule is TLS 1.3's, RFC 8446 7.3. The keylog callback hands us
 * the two application traffic secrets, and a key and an iv follow from
 * each by HKDF-Expand-Label. A rekey expands the secret again under
 * "traffic upd" and starts the sequence over.
 *
 * This file calls no syscall and touches no socket. It produces bytes.
 * Who applies them, and how, is the caller's business - in a reactor
 * they go through a ring, and nothing here would know the difference.
 */

#include "tls_keys.hpp"

#ifdef TLS_KERNEL_RECORDS

#include <algorithm>
#include <cstring>
#include <string>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>

namespace
{

/* One row per cipher the kernel can hold. The sizes are the header's,
 * and the payload size is sizeof the kernel's own struct, so a row can
 * never disagree with the bytes it describes. */
constexpr cipher_row kRows[] = {
    {NID_aes_128_gcm, TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_128_KEY_SIZE,
     TLS_CIPHER_AES_GCM_128_SALT_SIZE, TLS_CIPHER_AES_GCM_128_IV_SIZE,
     sizeof(struct tls12_crypto_info_aes_gcm_128), 1ull << 23, "TLS_AES_128_GCM_SHA256"},
    {NID_aes_256_gcm, TLS_CIPHER_AES_GCM_256, TLS_CIPHER_AES_GCM_256_KEY_SIZE,
     TLS_CIPHER_AES_GCM_256_SALT_SIZE, TLS_CIPHER_AES_GCM_256_IV_SIZE,
     sizeof(struct tls12_crypto_info_aes_gcm_256), 1ull << 23, "TLS_AES_256_GCM_SHA384"},
    {NID_chacha20_poly1305, TLS_CIPHER_CHACHA20_POLY1305,
     TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE, TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE,
     TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE, sizeof(struct tls12_crypto_info_chacha20_poly1305), 0,
     "TLS_CHACHA20_POLY1305_SHA256"},
#ifdef TLS_CIPHER_AES_CCM_128
    {NID_aes_128_ccm, TLS_CIPHER_AES_CCM_128, TLS_CIPHER_AES_CCM_128_KEY_SIZE,
     TLS_CIPHER_AES_CCM_128_SALT_SIZE, TLS_CIPHER_AES_CCM_128_IV_SIZE,
     sizeof(struct tls12_crypto_info_aes_ccm_128), 1ull << 22, "TLS_AES_128_CCM_SHA256"},
#endif
};

/* HKDF-Expand-Label, RFC 8446 7.1, written out rather than taken from
 * EVP_KDF.
 *
 * Two reasons. The KDF form pins its digest at fetch time, and this
 * needs the suite's own - SHA-384 for AES-256-GCM. And "TLS13-KDF" is
 * an OpenSSL 3 name that LibreSSL does not carry, so the KDF form would
 * make this file refuse to build where plain HMAC builds everywhere. */
bool expand_label(const EVP_MD *digest, std::span<const std::byte> secret, std::string_view label,
                  std::span<std::byte> out)
{
    const std::size_t hash_len = static_cast<std::size_t>(EVP_MD_get_size(digest));
    if (hash_len == 0 || out.size() > 255 || secret.size() != hash_len)
        return false;

    /* The info structure the RFC spells: length, then "tls13 " and the
     * label, then an empty context. */
    std::vector<unsigned char> info;
    info.push_back(static_cast<unsigned char>(out.size() >> 8));
    info.push_back(static_cast<unsigned char>(out.size() & 0xff));
    const std::string full = std::string("tls13 ") + std::string(label);
    info.push_back(static_cast<unsigned char>(full.size()));
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);

    /* HKDF-Expand with one block or two, which is what a key and an iv
     * need: no output here is longer than two digests. */
    std::vector<unsigned char> block;
    std::size_t done = 0;
    unsigned char counter = 1;
    while (done < out.size()) {
        std::vector<unsigned char> input;
        input.insert(input.end(), block.begin(), block.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        unsigned int made = 0;
        block.assign(EVP_MAX_MD_SIZE, 0);
        if (HMAC(digest, secret.data(), static_cast<int>(secret.size()), input.data(), input.size(),
                 block.data(), &made) == nullptr)
            return false;
        block.resize(made);

        const std::size_t take = std::min(out.size() - done, block.size());
        std::memcpy(std::next(out.data(), static_cast<std::ptrdiff_t>(done)), block.data(), take);
        done += take;
        counter++;
    }
    return true;
}

} // namespace

const cipher_row *cipher_row_of(int nid)
{
    for (const cipher_row &row : kRows) {
        if (row.nid == nid)
            return &row;
    }
    return nullptr;
}

bool derive_traffic_key(const EVP_MD *digest, std::span<const std::byte> secret,
                        std::span<std::byte> key, std::span<std::byte> iv)
{
    return expand_label(digest, secret, "key", key) && expand_label(digest, secret, "iv", iv);
}

bool next_traffic_secret(const EVP_MD *digest, std::span<const std::byte> secret,
                         std::span<std::byte> out)
{
    return expand_label(digest, secret, "traffic upd", out);
}

/* The kernel's struct, filled. One writer for every row: the layout is
 * the same shape in each - info, then iv, then key, then salt, then the
 * record sequence - and only the lengths differ, which the row carries.
 *
 * The iv the kernel wants is the last iv_size bytes of the twelve the
 * schedule produced, and the salt is the first salt_size. The two
 * always add up to twelve, which is the one thing worth asserting about
 * a header we did not write. */
bool write_handover_payload(const cipher_row &row, std::span<const std::byte> secret,
                            const EVP_MD *digest, std::uint64_t record_sequence,
                            std::vector<std::byte> &out)
{
    if (row.salt_size + row.iv_size != kTrafficIvSize)
        return false;

    std::array<std::byte, kTrafficIvSize> iv{};
    std::vector<std::byte> key(row.key_size);
    if (!derive_traffic_key(digest, secret, key, iv))
        return false;

    out.assign(row.payload_size, std::byte{0});

    /* Every tls12_crypto_info_* begins with the same header, so it is
     * written through the common type rather than through each. */
    struct tls_crypto_info info{};
    info.version = TLS_1_3_VERSION;
    info.cipher_type = row.kernel_type;
    std::memcpy(out.data(), &info, sizeof info);

    std::size_t at = sizeof info;
    /* iv, then key, then salt, then rec_seq: the order every one of the
     * kernel's structs declares them in. */
    std::memcpy(std::next(out.data(), static_cast<std::ptrdiff_t>(at)),
                std::next(iv.data(), static_cast<std::ptrdiff_t>(row.salt_size)), row.iv_size);
    at += row.iv_size;
    std::memcpy(std::next(out.data(), static_cast<std::ptrdiff_t>(at)), key.data(), row.key_size);
    at += row.key_size;
    std::memcpy(std::next(out.data(), static_cast<std::ptrdiff_t>(at)), iv.data(), row.salt_size);
    at += row.salt_size;

    /* The sequence the kernel starts counting from, big endian, which
     * is how it sits on the wire. */
    std::array<std::byte, 8> sequence{};
    for (std::size_t i = 0; i < sequence.size(); i++) {
        sequence[sequence.size() - 1 - i] =
            static_cast<std::byte>((record_sequence >> (8 * i)) & 0xff);
    }
    if (at + sequence.size() > out.size())
        return false;
    std::memcpy(std::next(out.data(), static_cast<std::ptrdiff_t>(at)), sequence.data(),
                sequence.size());
    return true;
}

#endif /* TLS_KERNEL_RECORDS */
