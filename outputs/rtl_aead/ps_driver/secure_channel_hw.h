#ifndef SECURE_CHANNEL_HW_H
#define SECURE_CHANNEL_HW_H

#include "aead_hw.h"
#include "mlkem_decaps_hw.h"

typedef struct {
    mlkem_decaps_hw_t mlkem;
    aead_hw_t traffic;
} secure_channel_hw_t;

void secure_channel_hw_init(secure_channel_hw_t *device,
                            uintptr_t mlkem_base, uintptr_t traffic_base,
                            uint32_t poll_limit);
int secure_channel_hw_load_secret_key(secure_channel_hw_t *device,
                                      const uint8_t secret_key[1632]);
int secure_channel_hw_establish_session(secure_channel_hw_t *device,
                                        const uint8_t ciphertext[768],
                                        uint8_t slot, uint32_t session_id);
int secure_channel_hw_encrypt(secure_channel_hw_t *device, uint8_t slot,
                              const uint8_t *message, uint8_t message_length,
                              uint8_t ciphertext[64], uint8_t tag[16],
                              uint64_t *packet_counter);
int secure_channel_hw_decrypt(secure_channel_hw_t *device, uint8_t slot,
                              uint64_t packet_counter,uint8_t message_length,
                              const uint8_t ciphertext[64],const uint8_t tag[16],
                              uint8_t plaintext[64]);

#endif
