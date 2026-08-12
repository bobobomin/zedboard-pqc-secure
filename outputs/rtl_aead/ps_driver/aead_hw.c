#include "aead_hw.h"

#define REG_CONTROL          0x004u
#define REG_STATUS           0x008u
#define REG_REQUEST_SLOT     0x00cu
#define REG_DATA_LEN         0x010u
#define REG_COUNTER_LO       0x014u
#define REG_COUNTER_HI       0x018u
#define REG_RSP_COUNTER_LO   0x01cu
#define REG_RSP_COUNTER_HI   0x020u
#define REG_CFG_SESSION_ID   0x028u
#define REG_CFG_CONTROL      0x02cu
#define REG_TX_KEY_BASE      0x040u
#define REG_RX_KEY_BASE      0x060u
#define REG_TX_PREFIX        0x080u
#define REG_RX_PREFIX        0x084u
#define REG_INPUT_DATA_BASE  0x100u
#define REG_INPUT_TAG_BASE   0x140u
#define REG_OUTPUT_DATA_BASE 0x180u
#define REG_OUTPUT_TAG_BASE  0x1c0u
#define REG_KDF_CONTROL      0x200u
#define REG_SHARED_SECRET    0x204u
#define REG_TRANSCRIPT_HASH  0x224u

#define CONTROL_START        (1u << 0)
#define CONTROL_DECRYPT      (1u << 1)
#define CONTROL_CLEAR_DONE   (1u << 8)

#define STATUS_BUSY          (1u << 0)
#define STATUS_DONE          (1u << 1)
#define STATUS_AUTH_OK       (1u << 2)
#define STATUS_ERROR         (1u << 3)
#define STATUS_CFG_PENDING   (1u << 4)
#define STATUS_REQ_PENDING   (1u << 5)
#define STATUS_KDF_BUSY      (1u << 6)

static void mmio_write(const aead_hw_t *device, uint32_t offset,
                       uint32_t value)
{
    volatile uint32_t *address =
        (volatile uint32_t *)(device->base_address + (uintptr_t)offset);
    *address = value;
}

static uint32_t mmio_read(const aead_hw_t *device, uint32_t offset)
{
    volatile const uint32_t *address =
        (volatile const uint32_t *)(device->base_address + (uintptr_t)offset);
    return *address;
}

static uint32_t load32_le(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0])
         | ((uint32_t)bytes[1] << 8)
         | ((uint32_t)bytes[2] << 16)
         | ((uint32_t)bytes[3] << 24);
}

static void store32_le(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int wait_status(const aead_hw_t *device, uint32_t set_mask,
                       uint32_t clear_mask, uint32_t *final_status)
{
    uint32_t count;
    uint32_t status = 0u;

    for (count = 0u; count < device->poll_limit; ++count) {
        status = mmio_read(device, REG_STATUS);
        if ((status & set_mask) == set_mask && (status & clear_mask) == 0u) {
            if (final_status != NULL)
                *final_status = status;
            return AEAD_HW_OK;
        }
    }
    if (final_status != NULL)
        *final_status = status;
    return AEAD_HW_ERR_TIMEOUT;
}

static int wait_request_idle(const aead_hw_t *device)
{
    return wait_status(device, 0u,
                       STATUS_BUSY | STATUS_REQ_PENDING | STATUS_CFG_PENDING,
                       NULL);
}

static void write_key(const aead_hw_t *device, uint32_t base,
                      const uint8_t key[AEAD_HW_KEY_BYTES])
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i)
        mmio_write(device, base + 4u*i, load32_le(key + 4u*i));
}

static void write_packet(const aead_hw_t *device, const uint8_t *message,
                         uint8_t message_length)
{
    uint32_t i;
    uint8_t word_bytes[4];

    for (i = 0u; i < 16u; ++i) {
        uint32_t j;
        for (j = 0u; j < 4u; ++j) {
            uint32_t index = 4u*i + j;
            word_bytes[j] = index < message_length ? message[index] : 0u;
        }
        mmio_write(device, REG_INPUT_DATA_BASE + 4u*i,
                   load32_le(word_bytes));
    }
}

static void read_packet(const aead_hw_t *device, uint8_t output[64])
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i)
        store32_le(output + 4u*i,
                   mmio_read(device, REG_OUTPUT_DATA_BASE + 4u*i));
}

void aead_hw_init(aead_hw_t *device, uintptr_t base_address,
                  uint32_t poll_limit)
{
    if (device == NULL)
        return;
    device->base_address = base_address;
    device->poll_limit = poll_limit == 0u ? 1000000u : poll_limit;
}

int aead_hw_configure_session(aead_hw_t *device, uint8_t slot,
                              uint32_t session_id,
                              const uint8_t tx_key[32],
                              const uint8_t rx_key[32],
                              const uint8_t tx_prefix[4],
                              const uint8_t rx_prefix[4])
{
    if (device == NULL || slot >= 4u || tx_key == NULL || rx_key == NULL
        || tx_prefix == NULL || rx_prefix == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    if (wait_request_idle(device) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;

    mmio_write(device, REG_CFG_SESSION_ID, session_id);
    write_key(device, REG_TX_KEY_BASE, tx_key);
    write_key(device, REG_RX_KEY_BASE, rx_key);
    mmio_write(device, REG_TX_PREFIX, load32_le(tx_prefix));
    mmio_write(device, REG_RX_PREFIX, load32_le(rx_prefix));
    mmio_write(device, REG_CFG_CONTROL,
               (1u << 31) | (1u << 8) | (uint32_t)slot);
    return wait_status(device, 0u, STATUS_CFG_PENDING, NULL);
}

int aead_hw_clear_session(aead_hw_t *device, uint8_t slot)
{
    if (device == NULL || slot >= 4u)
        return AEAD_HW_ERR_ARGUMENT;
    if (wait_request_idle(device) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;
    mmio_write(device, REG_CFG_CONTROL, (1u << 31) | (uint32_t)slot);
    return wait_status(device, 0u, STATUS_CFG_PENDING, NULL);
}

int aead_hw_install_mlkem_session(aead_hw_t *device, uint8_t slot,
                                 uint32_t session_id,
                                 const uint8_t shared_secret[32],
                                 const uint8_t transcript_hash[32])
{
    uint32_t i;
    if (device == NULL || slot >= 4u || shared_secret == NULL
        || transcript_hash == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    if (wait_request_idle(device) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;
    mmio_write(device, REG_REQUEST_SLOT, slot);
    mmio_write(device, REG_CFG_SESSION_ID, session_id);
    for (i = 0u; i < 8u; ++i) {
        mmio_write(device, REG_SHARED_SECRET + 4u*i,
                   load32_le(shared_secret + 4u*i));
        mmio_write(device, REG_TRANSCRIPT_HASH + 4u*i,
                   load32_le(transcript_hash + 4u*i));
    }
    mmio_write(device, REG_KDF_CONTROL, 1u);
    return wait_status(device, 0u, STATUS_KDF_BUSY | STATUS_CFG_PENDING, NULL);
}

int aead_hw_encrypt(aead_hw_t *device, uint8_t slot,
                    const uint8_t *message, uint8_t message_length,
                    uint8_t ciphertext[64], uint8_t tag[16],
                    uint64_t *packet_counter)
{
    uint32_t i;
    uint32_t status;
    uint64_t counter;

    if (device == NULL || slot >= 4u || message == NULL
        || message_length > 64u || ciphertext == NULL || tag == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    if (wait_request_idle(device) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;

    mmio_write(device, REG_CONTROL, CONTROL_CLEAR_DONE);
    mmio_write(device, REG_REQUEST_SLOT, slot);
    mmio_write(device, REG_DATA_LEN, message_length);
    write_packet(device, message, message_length);
    mmio_write(device, REG_CONTROL, CONTROL_START);

    if (wait_status(device, STATUS_DONE, 0u, &status) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;
    if ((status & STATUS_AUTH_OK) == 0u || (status & STATUS_ERROR) != 0u)
        return AEAD_HW_ERR_AUTH;

    read_packet(device, ciphertext);
    for (i = 0u; i < 4u; ++i)
        store32_le(tag + 4u*i,
                   mmio_read(device, REG_OUTPUT_TAG_BASE + 4u*i));
    counter = (uint64_t)mmio_read(device, REG_RSP_COUNTER_LO)
            | ((uint64_t)mmio_read(device, REG_RSP_COUNTER_HI) << 32);
    if (packet_counter != NULL)
        *packet_counter = counter;
    return AEAD_HW_OK;
}

int aead_hw_decrypt(aead_hw_t *device, uint8_t slot,
                    uint64_t packet_counter, uint8_t message_length,
                    const uint8_t ciphertext[64], const uint8_t tag[16],
                    uint8_t plaintext[64])
{
    uint32_t i;
    uint32_t status;

    if (device == NULL || slot >= 4u || message_length > 64u
        || ciphertext == NULL || tag == NULL || plaintext == NULL)
        return AEAD_HW_ERR_ARGUMENT;
    if (wait_request_idle(device) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;

    mmio_write(device, REG_CONTROL, CONTROL_CLEAR_DONE);
    mmio_write(device, REG_REQUEST_SLOT, slot);
    mmio_write(device, REG_DATA_LEN, message_length);
    mmio_write(device, REG_COUNTER_LO, (uint32_t)packet_counter);
    mmio_write(device, REG_COUNTER_HI, (uint32_t)(packet_counter >> 32));
    write_packet(device, ciphertext, 64u);
    for (i = 0u; i < 4u; ++i)
        mmio_write(device, REG_INPUT_TAG_BASE + 4u*i,
                   load32_le(tag + 4u*i));
    mmio_write(device, REG_CONTROL, CONTROL_START | CONTROL_DECRYPT);

    if (wait_status(device, STATUS_DONE, 0u, &status) != AEAD_HW_OK)
        return AEAD_HW_ERR_TIMEOUT;
    if ((status & STATUS_AUTH_OK) == 0u || (status & STATUS_ERROR) != 0u)
        return AEAD_HW_ERR_AUTH;
    read_packet(device, plaintext);
    return AEAD_HW_OK;
}
