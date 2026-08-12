#ifndef AEAD_HW_H
#define AEAD_HW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEAD_HW_PACKET_BYTES 64u
#define AEAD_HW_TAG_BYTES    16u
#define AEAD_HW_KEY_BYTES    32u
#define AEAD_HW_PREFIX_BYTES  4u

typedef struct {
    uintptr_t base_address;
    uint32_t poll_limit;
} aead_hw_t;

enum {
    AEAD_HW_OK = 0,
    AEAD_HW_ERR_TIMEOUT = -1,
    AEAD_HW_ERR_AUTH = -2,
    AEAD_HW_ERR_ARGUMENT = -3
};

void aead_hw_init(aead_hw_t *device, uintptr_t base_address,
                  uint32_t poll_limit);

int aead_hw_configure_session(aead_hw_t *device, uint8_t slot,
                              uint32_t session_id,
                              const uint8_t tx_key[AEAD_HW_KEY_BYTES],
                              const uint8_t rx_key[AEAD_HW_KEY_BYTES],
                              const uint8_t tx_prefix[AEAD_HW_PREFIX_BYTES],
                              const uint8_t rx_prefix[AEAD_HW_PREFIX_BYTES]);

int aead_hw_clear_session(aead_hw_t *device, uint8_t slot);

/* Derives direction-separated keys in PL from an ML-KEM result and installs
 * the ZedBoard-side session (TX=ZB->PC, RX=PC->ZB). */
int aead_hw_install_mlkem_session(aead_hw_t *device, uint8_t slot,
                                 uint32_t session_id,
                                 const uint8_t shared_secret[32],
                                 const uint8_t transcript_hash[32]);

int aead_hw_encrypt(aead_hw_t *device, uint8_t slot,
                    const uint8_t *message, uint8_t message_length,
                    uint8_t ciphertext[AEAD_HW_PACKET_BYTES],
                    uint8_t tag[AEAD_HW_TAG_BYTES],
                    uint64_t *packet_counter);

int aead_hw_decrypt(aead_hw_t *device, uint8_t slot,
                    uint64_t packet_counter, uint8_t message_length,
                    const uint8_t ciphertext[AEAD_HW_PACKET_BYTES],
                    const uint8_t tag[AEAD_HW_TAG_BYTES],
                    uint8_t plaintext[AEAD_HW_PACKET_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
