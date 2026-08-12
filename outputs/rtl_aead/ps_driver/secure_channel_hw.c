#include "secure_channel_hw.h"

void secure_channel_hw_init(secure_channel_hw_t *device,
                            uintptr_t mlkem_base, uintptr_t traffic_base,
                            uint32_t poll_limit)
{
    if (device == NULL)
        return;
    mlkem_decaps_hw_init(&device->mlkem, mlkem_base, poll_limit);
    aead_hw_init(&device->traffic, traffic_base, poll_limit);
}

int secure_channel_hw_load_secret_key(secure_channel_hw_t *device,
                                      const uint8_t secret_key[1632])
{
    if (device == NULL)
        return MLKEM_HW_ARGUMENT;
    return mlkem_decaps_hw_load_secret_key(&device->mlkem, secret_key);
}

int secure_channel_hw_establish_session(secure_channel_hw_t *device,
                                        const uint8_t ciphertext[768],
                                        uint8_t slot, uint32_t session_id)
{
    int result;
    if (device == NULL)
        return MLKEM_HW_ARGUMENT;
    result = mlkem_decaps_hw_start(&device->mlkem, ciphertext, slot, session_id);
    if (result != MLKEM_HW_OK)
        return result;
    return mlkem_decaps_hw_wait(&device->mlkem);
}

int secure_channel_hw_encrypt(secure_channel_hw_t *device, uint8_t slot,
                              const uint8_t *message, uint8_t message_length,
                              uint8_t ciphertext[64], uint8_t tag[16],
                              uint64_t *packet_counter)
{
    if (device == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    return aead_hw_encrypt(&device->traffic,slot,message,message_length,
                           ciphertext,tag,packet_counter);
}

int secure_channel_hw_decrypt(secure_channel_hw_t *device, uint8_t slot,
                              uint64_t packet_counter,uint8_t message_length,
                              const uint8_t ciphertext[64],const uint8_t tag[16],
                              uint8_t plaintext[64])
{
    if (device == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    return aead_hw_decrypt(&device->traffic,slot,packet_counter,message_length,
                           ciphertext,tag,plaintext);
}
