/*
 * Golden reference for the ZedBoard ML-KEM-512 + ChaCha20-Poly1305 demo.
 *
 * ML-KEM implementation: mlkem-native (FIPS 203)
 * ChaCha20 / Poly1305 primitives: Monocypher
 *
 * This program deliberately uses deterministic ML-KEM randomness so every
 * execution produces byte-for-byte identical vectors for RTL testbenches.
 * Production code must use a cryptographically secure random generator.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem_native.h"
#include "src/fips202/fips202.h"
#include "monocypher.h"

#define SESSION_ID 0x01020304u
#define PACKET_COUNTER UINT64_C(0)

#define AAD_BYTES 16u
#define PLAINTEXT_BYTES 64u
#define TAG_BYTES 16u
#define PACKET_BYTES (AAD_BYTES + PLAINTEXT_BYTES + TAG_BYTES)
#define KDF_OUTPUT_BYTES 72u

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
    for (i = 0; i < 8; i++) {
        out[7u - i] = (uint8_t)(value >> (8u * i));
    }
}

static void store64_le(uint8_t out[8], uint64_t value)
{
    unsigned int i;
    for (i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value >> (8u * i));
    }
}

static int secure_equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < length; i++) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }
    return difference == 0;
}

static void write_hex(FILE *stream, const char *name,
                      const uint8_t *data, size_t length)
{
    size_t i;
    fprintf(stream, "%s[%zu] = ", name, length);
    for (i = 0; i < length; i++) {
        fprintf(stream, "%02x", data[i]);
    }
    fputc('\n', stream);
}

static int write_binary(const char *name, const uint8_t *data, size_t length)
{
    FILE *stream = fopen(name, "wb");
    if (stream == NULL) {
        fprintf(stderr, "cannot open %s\n", name);
        return -1;
    }
    if (fwrite(data, 1, length, stream) != length) {
        fprintf(stderr, "cannot write %s\n", name);
        fclose(stream);
        return -1;
    }
    fclose(stream);
    return 0;
}

static void build_aad(uint8_t aad[AAD_BYTES], uint8_t data_length)
{
    memset(aad, 0, AAD_BYTES);
    store32_be(aad, SESSION_ID);
    store64_be(aad + 4, PACKET_COUNTER);
    aad[12] = data_length;
    /* aad[13..15] are reserved and remain zero. */
}

static void derive_session_material(
    uint8_t output[KDF_OUTPUT_BYTES],
    uint8_t transcript_hash[32],
    const uint8_t shared_secret[MLKEM_BYTES],
    const uint8_t public_key[MLKEM_PUBLICKEYBYTES(512)],
    const uint8_t ciphertext[MLKEM_CIPHERTEXTBYTES(512)])
{
    static const uint8_t domain[] = "ZYNQ-PQC-v1";
    uint8_t transcript[MLKEM_PUBLICKEYBYTES(512) +
                       MLKEM_CIPHERTEXTBYTES(512) + 4u];
    uint8_t input[(sizeof(domain) - 1u) + MLKEM_BYTES + 32u];

    memcpy(transcript, public_key, MLKEM_PUBLICKEYBYTES(512));
    memcpy(transcript + MLKEM_PUBLICKEYBYTES(512), ciphertext,
           MLKEM_CIPHERTEXTBYTES(512));
    store32_be(transcript + MLKEM_PUBLICKEYBYTES(512) +
               MLKEM_CIPHERTEXTBYTES(512), SESSION_ID);
    mlk_sha3_256(transcript_hash, transcript, sizeof(transcript));

    memcpy(input, domain, sizeof(domain) - 1u);
    memcpy(input + sizeof(domain) - 1u, shared_secret, MLKEM_BYTES);
    memcpy(input + sizeof(domain) - 1u + MLKEM_BYTES,
           transcript_hash, 32u);
    mlk_shake256(output, KDF_OUTPUT_BYTES, input, sizeof(input));

    crypto_wipe(transcript, sizeof(transcript));
    crypto_wipe(input, sizeof(input));
}

static void build_nonce(uint8_t nonce[12], const uint8_t prefix[4],
                        uint64_t packet_counter)
{
    memcpy(nonce, prefix, 4);
    store64_be(nonce + 4, packet_counter);
}

static void aead_encrypt_fixed64(
    uint8_t ciphertext[PLAINTEXT_BYTES], uint8_t tag[TAG_BYTES],
    uint8_t one_time_key[32], uint8_t keystream[PLAINTEXT_BYTES],
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t aad[AAD_BYTES],
    const uint8_t plaintext[PLAINTEXT_BYTES])
{
    uint8_t zero_block[PLAINTEXT_BYTES] = {0};
    uint8_t mac_input[AAD_BYTES + PLAINTEXT_BYTES + 16u];

    /* RFC 8439: counter 0 derives the one-time Poly1305 key. */
    crypto_chacha20_ietf(keystream, zero_block, sizeof(zero_block),
                         key, nonce, 0);
    memcpy(one_time_key, keystream, 32);

    /* RFC 8439: payload encryption starts at block counter 1. */
    crypto_chacha20_ietf(keystream, zero_block, sizeof(zero_block),
                         key, nonce, 1);
    crypto_chacha20_ietf(ciphertext, plaintext, PLAINTEXT_BYTES,
                         key, nonce, 1);

    /* AAD and ciphertext are both multiples of 16, so no pad16 bytes. */
    memcpy(mac_input, aad, AAD_BYTES);
    memcpy(mac_input + AAD_BYTES, ciphertext, PLAINTEXT_BYTES);
    store64_le(mac_input + AAD_BYTES + PLAINTEXT_BYTES,
               (uint64_t)AAD_BYTES);
    store64_le(mac_input + AAD_BYTES + PLAINTEXT_BYTES + 8u,
               (uint64_t)PLAINTEXT_BYTES);
    crypto_poly1305(tag, mac_input, sizeof(mac_input), one_time_key);

    crypto_wipe(zero_block, sizeof(zero_block));
    crypto_wipe(mac_input, sizeof(mac_input));
}

static int aead_decrypt_fixed64(
    uint8_t plaintext[PLAINTEXT_BYTES], const uint8_t key[32],
    const uint8_t nonce[12], const uint8_t aad[AAD_BYTES],
    const uint8_t ciphertext[PLAINTEXT_BYTES],
    const uint8_t received_tag[TAG_BYTES])
{
    uint8_t zero_block[PLAINTEXT_BYTES] = {0};
    uint8_t block0[PLAINTEXT_BYTES];
    uint8_t expected_tag[TAG_BYTES];
    uint8_t mac_input[AAD_BYTES + PLAINTEXT_BYTES + 16u];

    crypto_chacha20_ietf(block0, zero_block, sizeof(zero_block),
                         key, nonce, 0);
    memcpy(mac_input, aad, AAD_BYTES);
    memcpy(mac_input + AAD_BYTES, ciphertext, PLAINTEXT_BYTES);
    store64_le(mac_input + AAD_BYTES + PLAINTEXT_BYTES,
               (uint64_t)AAD_BYTES);
    store64_le(mac_input + AAD_BYTES + PLAINTEXT_BYTES + 8u,
               (uint64_t)PLAINTEXT_BYTES);
    crypto_poly1305(expected_tag, mac_input, sizeof(mac_input), block0);

    if (!secure_equal(expected_tag, received_tag, TAG_BYTES)) {
        memset(plaintext, 0, PLAINTEXT_BYTES);
        crypto_wipe(block0, sizeof(block0));
        crypto_wipe(expected_tag, sizeof(expected_tag));
        crypto_wipe(mac_input, sizeof(mac_input));
        return -1;
    }

    crypto_chacha20_ietf(plaintext, ciphertext, PLAINTEXT_BYTES,
                         key, nonce, 1);
    crypto_wipe(block0, sizeof(block0));
    crypto_wipe(expected_tag, sizeof(expected_tag));
    crypto_wipe(mac_input, sizeof(mac_input));
    return 0;
}

int main(void)
{
    static const uint8_t message[] =
        "ZedBoard ML-KEM + ChaCha20-Poly1305 demo";
    uint8_t keygen_coins[2u * MLKEM_SYMBYTES];
    uint8_t encaps_coins[MLKEM_SYMBYTES];
    uint8_t public_key[MLKEM_PUBLICKEYBYTES(512)];
    uint8_t secret_key[MLKEM_SECRETKEYBYTES(512)];
    uint8_t kem_ciphertext[MLKEM_CIPHERTEXTBYTES(512)];
    uint8_t client_secret[MLKEM_BYTES];
    uint8_t server_secret[MLKEM_BYTES];
    uint8_t fingerprint[32];
    uint8_t transcript_hash[32];
    uint8_t key_material[KDF_OUTPUT_BYTES];
    uint8_t nonce[12];
    uint8_t aad[AAD_BYTES];
    uint8_t padded_plaintext[PLAINTEXT_BYTES] = {0};
    uint8_t decrypted[PLAINTEXT_BYTES];
    uint8_t ciphertext[PLAINTEXT_BYTES];
    uint8_t tag[TAG_BYTES];
    uint8_t one_time_key[32];
    uint8_t keystream[PLAINTEXT_BYTES];
    uint8_t packet[PACKET_BYTES];
    uint8_t tampered_ciphertext[PLAINTEXT_BYTES];
    FILE *vectors;
    size_t i;
    const uint8_t *pc_to_zb_key = key_material;
    const uint8_t *pc_to_zb_nonce_prefix = key_material + 32;
    const uint8_t *zb_to_pc_key = key_material + 36;
    const uint8_t *zb_to_pc_nonce_prefix = key_material + 68;

    if (sizeof(message) - 1u > PLAINTEXT_BYTES) {
        fprintf(stderr, "test message is too long\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < sizeof(keygen_coins); i++) {
        keygen_coins[i] = (uint8_t)i;
    }
    for (i = 0; i < sizeof(encaps_coins); i++) {
        encaps_coins[i] = (uint8_t)(0xa0u + i);
    }

    if (mlkem_keypair_derand(public_key, secret_key, keygen_coins) != 0) {
        fprintf(stderr, "ML-KEM key generation failed\n");
        return EXIT_FAILURE;
    }
    if (mlkem_enc_derand(kem_ciphertext, client_secret,
                         public_key, encaps_coins) != 0) {
        fprintf(stderr, "ML-KEM encapsulation failed\n");
        return EXIT_FAILURE;
    }
    if (mlkem_dec(server_secret, kem_ciphertext, secret_key) != 0) {
        fprintf(stderr, "ML-KEM decapsulation failed\n");
        return EXIT_FAILURE;
    }
    if (!secure_equal(client_secret, server_secret, MLKEM_BYTES)) {
        fprintf(stderr, "ML-KEM shared secrets do not match\n");
        return EXIT_FAILURE;
    }

    mlk_sha3_256(fingerprint, public_key, sizeof(public_key));
    derive_session_material(key_material, transcript_hash, client_secret,
                            public_key, kem_ciphertext);
    build_nonce(nonce, pc_to_zb_nonce_prefix, PACKET_COUNTER);
    build_aad(aad, (uint8_t)(sizeof(message) - 1u));
    memcpy(padded_plaintext, message, sizeof(message) - 1u);

    aead_encrypt_fixed64(ciphertext, tag, one_time_key, keystream,
                         pc_to_zb_key, nonce, aad, padded_plaintext);
    memcpy(packet, aad, AAD_BYTES);
    memcpy(packet + AAD_BYTES, ciphertext, PLAINTEXT_BYTES);
    memcpy(packet + AAD_BYTES + PLAINTEXT_BYTES, tag, TAG_BYTES);

    if (aead_decrypt_fixed64(decrypted, pc_to_zb_key, nonce, aad,
                             ciphertext, tag) != 0 ||
        !secure_equal(decrypted, padded_plaintext, PLAINTEXT_BYTES)) {
        fprintf(stderr, "AEAD round trip failed\n");
        return EXIT_FAILURE;
    }

    memcpy(tampered_ciphertext, ciphertext, sizeof(tampered_ciphertext));
    tampered_ciphertext[0] ^= 1u;
    if (aead_decrypt_fixed64(decrypted, pc_to_zb_key, nonce, aad,
                             tampered_ciphertext, tag) == 0) {
        fprintf(stderr, "tamper test unexpectedly succeeded\n");
        return EXIT_FAILURE;
    }

    vectors = fopen("golden_vectors.txt", "w");
    if (vectors == NULL) {
        fprintf(stderr, "cannot open golden_vectors.txt\n");
        return EXIT_FAILURE;
    }
    fprintf(vectors, "ML-KEM parameter set = 512\n");
    fprintf(vectors, "Packet format = AAD[16] || ciphertext[64] || tag[16]\n");
    fprintf(vectors, "Header integers = big-endian\n");
    fprintf(vectors, "Poly1305 length integers = little-endian\n");
    write_hex(vectors, "keygen_coins", keygen_coins, sizeof(keygen_coins));
    write_hex(vectors, "encaps_coins", encaps_coins, sizeof(encaps_coins));
    write_hex(vectors, "public_key", public_key, sizeof(public_key));
    write_hex(vectors, "secret_key", secret_key, sizeof(secret_key));
    write_hex(vectors, "fingerprint_sha3_256", fingerprint, sizeof(fingerprint));
    write_hex(vectors, "kem_ciphertext", kem_ciphertext, sizeof(kem_ciphertext));
    write_hex(vectors, "shared_secret", client_secret, sizeof(client_secret));
    write_hex(vectors, "transcript_hash", transcript_hash, sizeof(transcript_hash));
    write_hex(vectors, "kdf_output", key_material, sizeof(key_material));
    write_hex(vectors, "pc_to_zb_key", pc_to_zb_key, 32);
    write_hex(vectors, "pc_to_zb_nonce_prefix", pc_to_zb_nonce_prefix, 4);
    write_hex(vectors, "zb_to_pc_key", zb_to_pc_key, 32);
    write_hex(vectors, "zb_to_pc_nonce_prefix", zb_to_pc_nonce_prefix, 4);
    write_hex(vectors, "nonce", nonce, sizeof(nonce));
    write_hex(vectors, "aad", aad, sizeof(aad));
    write_hex(vectors, "padded_plaintext", padded_plaintext,
              sizeof(padded_plaintext));
    write_hex(vectors, "chacha20_counter1_keystream", keystream,
              sizeof(keystream));
    write_hex(vectors, "poly1305_one_time_key", one_time_key,
              sizeof(one_time_key));
    write_hex(vectors, "ciphertext", ciphertext, sizeof(ciphertext));
    write_hex(vectors, "tag", tag, sizeof(tag));
    write_hex(vectors, "packet", packet, sizeof(packet));
    fclose(vectors);

    if (write_binary("public_key.bin", public_key, sizeof(public_key)) != 0 ||
        write_binary("secret_key.bin", secret_key, sizeof(secret_key)) != 0 ||
        write_binary("kem_ciphertext.bin", kem_ciphertext,
                     sizeof(kem_ciphertext)) != 0 ||
        write_binary("packet.bin", packet, sizeof(packet)) != 0) {
        return EXIT_FAILURE;
    }

    puts("PASS: ML-KEM-512 shared secrets match");
    puts("PASS: ChaCha20-Poly1305 fixed-64 round trip");
    puts("PASS: one-bit ciphertext tampering rejected");
    write_hex(stdout, "fingerprint_sha3_256", fingerprint, sizeof(fingerprint));
    write_hex(stdout, "shared_secret", client_secret, sizeof(client_secret));
    write_hex(stdout, "nonce", nonce, sizeof(nonce));
    write_hex(stdout, "aad", aad, sizeof(aad));
    write_hex(stdout, "ciphertext", ciphertext, sizeof(ciphertext));
    write_hex(stdout, "tag", tag, sizeof(tag));
    puts("Wrote golden_vectors.txt and binary vectors.");

    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(client_secret, sizeof(client_secret));
    crypto_wipe(server_secret, sizeof(server_secret));
    crypto_wipe(key_material, sizeof(key_material));
    crypto_wipe(one_time_key, sizeof(one_time_key));
    return EXIT_SUCCESS;
}
