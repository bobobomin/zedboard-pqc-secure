#include "software_crypto_benchmark.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "xil_printf.h"
#include "xtime_l.h"

#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
#include "../../golden_reference/third_party/mlkem-native/mlkem/mlkem_native.h"
#include "../../golden_reference/third_party/monocypher/monocypher.h"
#include "zed_pqc_kat_vectors.h"

#define SW_MLKEM_ROUNDS 10u
#define SW_AEAD_ROUNDS  1000u
#define AAD_BYTES       16u
#define PACKET_BYTES    64u
#define TAG_BYTES       16u

static volatile uint32_t benchmark_sink;

static const uint8_t expected_shared_secret[32] = {
    0xee,0x5f,0x8f,0x90,0xfb,0x6f,0x15,0xa5,
    0x93,0x45,0x04,0xe1,0xf6,0x5c,0x23,0xad,
    0x2d,0x60,0x96,0x41,0x04,0xbf,0x42,0x46,
    0x38,0x76,0x36,0x3a,0x79,0x9d,0xee,0x4f
};

static const uint8_t pc_to_zb_key[32] = {
    0x71,0x73,0x2b,0xda,0xfb,0x22,0xb7,0xdc,
    0xc9,0x49,0xf0,0x90,0x2c,0x5e,0xf4,0x20,
    0xc1,0x6a,0x94,0x56,0x33,0xdc,0x87,0xe5,
    0x79,0xfe,0x9e,0x5b,0x77,0x55,0x11,0x4a
};

static const uint8_t pc_to_zb_prefix[4] = {0x7d,0x3f,0xe8,0x4c};

static void store32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void store64_be(uint8_t out[8], uint64_t value)
{
    unsigned int i;
    for (i = 0u; i < 8u; ++i)
        out[7u - i] = (uint8_t)(value >> (8u * i));
}

static void store64_le(uint8_t out[8], uint64_t value)
{
    unsigned int i;
    for (i = 0u; i < 8u; ++i)
        out[i] = (uint8_t)(value >> (8u * i));
}

static void build_packet_fields(uint8_t aad[AAD_BYTES], uint8_t nonce[12],
                                uint64_t counter)
{
    memset(aad, 0, AAD_BYTES);
    store32_be(aad, 0x01020304u);
    store64_be(aad + 4u, counter);
    aad[12] = PACKET_BYTES;
    memcpy(nonce, pc_to_zb_prefix, sizeof(pc_to_zb_prefix));
    store64_be(nonce + 4u, counter);
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    uint8_t difference = 0u;
    size_t i;
    for (i = 0u; i < length; ++i)
        difference |= (uint8_t)(a[i] ^ b[i]);
    return difference == 0u;
}

static void encrypt_fixed64(uint8_t ciphertext[PACKET_BYTES],
                            uint8_t tag[TAG_BYTES], const uint8_t nonce[12],
                            const uint8_t aad[AAD_BYTES],
                            const uint8_t plaintext[PACKET_BYTES])
{
    uint8_t zero[PACKET_BYTES] = {0};
    uint8_t block0[PACKET_BYTES];
    uint8_t mac_input[AAD_BYTES + PACKET_BYTES + 16u];

    crypto_chacha20_ietf(block0, zero, sizeof(zero), pc_to_zb_key, nonce, 0);
    crypto_chacha20_ietf(ciphertext, plaintext, PACKET_BYTES,
                         pc_to_zb_key, nonce, 1);
    memcpy(mac_input, aad, AAD_BYTES);
    memcpy(mac_input + AAD_BYTES, ciphertext, PACKET_BYTES);
    store64_le(mac_input + AAD_BYTES + PACKET_BYTES, AAD_BYTES);
    store64_le(mac_input + AAD_BYTES + PACKET_BYTES + 8u, PACKET_BYTES);
    crypto_poly1305(tag, mac_input, sizeof(mac_input), block0);
    crypto_wipe(block0, sizeof(block0));
    crypto_wipe(mac_input, sizeof(mac_input));
}

static int decrypt_fixed64(uint8_t plaintext[PACKET_BYTES],
                           const uint8_t ciphertext[PACKET_BYTES],
                           const uint8_t tag[TAG_BYTES],
                           const uint8_t nonce[12],
                           const uint8_t aad[AAD_BYTES])
{
    uint8_t zero[PACKET_BYTES] = {0};
    uint8_t block0[PACKET_BYTES];
    uint8_t expected_tag[TAG_BYTES];
    uint8_t mac_input[AAD_BYTES + PACKET_BYTES + 16u];
    int valid;

    crypto_chacha20_ietf(block0, zero, sizeof(zero), pc_to_zb_key, nonce, 0);
    memcpy(mac_input, aad, AAD_BYTES);
    memcpy(mac_input + AAD_BYTES, ciphertext, PACKET_BYTES);
    store64_le(mac_input + AAD_BYTES + PACKET_BYTES, AAD_BYTES);
    store64_le(mac_input + AAD_BYTES + PACKET_BYTES + 8u, PACKET_BYTES);
    crypto_poly1305(expected_tag, mac_input, sizeof(mac_input), block0);
    valid = bytes_equal(expected_tag, tag, TAG_BYTES);
    if (valid)
        crypto_chacha20_ietf(plaintext, ciphertext, PACKET_BYTES,
                             pc_to_zb_key, nonce, 1);
    else
        memset(plaintext, 0, PACKET_BYTES);
    crypto_wipe(block0, sizeof(block0));
    crypto_wipe(expected_tag, sizeof(expected_tag));
    crypto_wipe(mac_input, sizeof(mac_input));
    return valid ? 0 : -1;
}

static uint64_t average_ns(XTime begin, XTime end, uint32_t rounds)
{
    uint64_t ticks = (uint64_t)(end - begin);
    return (ticks * 1000000000ull) /
           ((uint64_t)COUNTS_PER_SECOND * (uint64_t)rounds);
}

static void print_average(const char *label, uint64_t ns, uint32_t rounds)
{
    xil_printf("%-34s %lu.%03lu us  (%lu rounds)\r\n",
               label,
               (unsigned long)(ns / 1000ull),
               (unsigned long)(ns % 1000ull),
               (unsigned long)rounds);
}

int software_crypto_benchmark_run(void)
{
    static uint8_t plaintext[PACKET_BYTES];
    static uint8_t decrypted[PACKET_BYTES];
    static uint8_t ciphertext[PACKET_BYTES];
    static uint8_t tag[TAG_BYTES];
    static uint8_t shared_secret[MLKEM_BYTES];
    uint8_t aad[AAD_BYTES];
    uint8_t nonce[12];
    XTime begin, end;
    uint64_t mlkem_ns, encrypt_ns, decrypt_ns;
    uint32_t round;
    int result = 0;

    for (round = 0u; round < PACKET_BYTES; ++round)
        plaintext[round] = (uint8_t)(round ^ 0x5au);

    xil_printf("\r\n========================================\r\n");
    xil_printf(" Cortex-A9 software-only benchmark\r\n");
    xil_printf("========================================\r\n");

    XTime_GetTime(&begin);
    for (round = 0u; round < SW_MLKEM_ROUNDS; ++round) {
        result |= mlkem_dec(shared_secret, zed_kat_kem_ciphertext,
                            zed_kat_secret_key);
        benchmark_sink ^= shared_secret[round & 31u];
    }
    XTime_GetTime(&end);
    mlkem_ns = average_ns(begin, end, SW_MLKEM_ROUNDS);

    build_packet_fields(aad, nonce, 0u);
    encrypt_fixed64(ciphertext, tag, nonce, aad, plaintext);
    if (!bytes_equal(shared_secret, expected_shared_secret, 32u) ||
        decrypt_fixed64(decrypted, ciphertext, tag, nonce, aad) != 0 ||
        !bytes_equal(plaintext, decrypted, PACKET_BYTES)) {
        xil_printf("[FAIL] software correctness check\r\n");
        return -1;
    }
    xil_printf("[PASS] ML-KEM secret and AEAD round trip\r\n");

    build_packet_fields(aad, nonce, 0u);
    XTime_GetTime(&begin);
    for (round = 0u; round < SW_AEAD_ROUNDS; ++round) {
        encrypt_fixed64(ciphertext, tag, nonce, aad, plaintext);
        benchmark_sink ^= ciphertext[round & 63u] ^ tag[round & 15u];
    }
    XTime_GetTime(&end);
    encrypt_ns = average_ns(begin, end, SW_AEAD_ROUNDS);

    /* Keep one valid packet fixed so only authenticated decryption is timed. */
    encrypt_fixed64(ciphertext, tag, nonce, aad, plaintext);
    XTime_GetTime(&begin);
    for (round = 0u; round < SW_AEAD_ROUNDS; ++round) {
        if (decrypt_fixed64(decrypted, ciphertext, tag, nonce, aad) != 0)
            result = -1;
        benchmark_sink ^= decrypted[round & 63u];
    }
    XTime_GetTime(&end);
    decrypt_ns = average_ns(begin, end, SW_AEAD_ROUNDS);

    print_average("SW ML-KEM-512 decapsulation", mlkem_ns, SW_MLKEM_ROUNDS);
    print_average("SW ChaCha20-Poly1305 encrypt 64B", encrypt_ns,
                  SW_AEAD_ROUNDS);
    print_average("SW ChaCha20-Poly1305 decrypt 64B", decrypt_ns,
                  SW_AEAD_ROUNDS);
    xil_printf("Reference HW service: ML-KEM ~2832 us, RX ~25 us, TX ~24 us\r\n");
    xil_printf("sink=%08lx (ignore; prevents optimization)\r\n",
               (unsigned long)benchmark_sink);
    xil_printf("========================================\r\n");
    return result;
}
