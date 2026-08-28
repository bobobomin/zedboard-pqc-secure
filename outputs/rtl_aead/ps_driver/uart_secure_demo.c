#include "uart_secure_demo.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "xil_printf.h"
#include "xtime_l.h"

#include "aead_hw.h"
#include "secure_channel_hw.h"
#include "zed_pqc_kat_vectors.h"

#define UART_DEMO_SESSIONS   AEAD_HW_MAX_SESSIONS
#define UART_DEMO_LINE_BYTES 256u

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_hex_exact(const char *text, uint8_t *output, size_t bytes)
{
    size_t index;
    if (text == NULL || output == NULL || strlen(text) != 2u * bytes)
        return 0;
    for (index = 0u; index < bytes; ++index) {
        int high = hex_nibble(text[2u * index]);
        int low = hex_nibble(text[2u * index + 1u]);
        if (high < 0 || low < 0) return 0;
        output[index] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static int parse_u64_hex(const char *text, uint64_t *value)
{
    uint64_t result = 0u;
    size_t index;
    if (text == NULL || value == NULL || strlen(text) != 16u) return 0;
    for (index = 0u; index < 16u; ++index) {
        int nibble = hex_nibble(text[index]);
        if (nibble < 0) return 0;
        result = (result << 4) | (uint64_t)nibble;
    }
    *value = result;
    return 1;
}

static int parse_decimal(const char *text, unsigned int maximum,
                         unsigned int *value)
{
    unsigned int result = 0u;
    if (text == NULL || value == NULL || *text == '\0') return 0;
    while (*text != '\0') {
        if (*text < '0' || *text > '9') return 0;
        result = 10u * result + (unsigned int)(*text - '0');
        if (result > maximum) return 0;
        ++text;
    }
    *value = result;
    return 1;
}

static int parse_length(const char *text, uint8_t *length)
{
    unsigned int value;
    if (!parse_decimal(text, AEAD_HW_PACKET_BYTES, &value)) return 0;
    *length = (uint8_t)value;
    return 1;
}

static int parse_slot(const char *text, uint8_t *slot)
{
    unsigned int value;
    if (!parse_decimal(text, UART_DEMO_SESSIONS - 1u, &value)) return 0;
    *slot = (uint8_t)value;
    return 1;
}

static uint32_t ticks_to_us(XTime begin, XTime end)
{
    uint64_t ticks = (uint64_t)(end - begin);
    return (uint32_t)((ticks * 1000000ull) / COUNTS_PER_SECOND);
}

static void write_hex(const uint8_t *data, size_t bytes)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    for (index = 0u; index < bytes; ++index) {
        outbyte(digits[data[index] >> 4]);
        outbyte(digits[data[index] & 0x0fu]);
    }
}

static void write_u32_hex(uint32_t value)
{
    uint8_t bytes[4];
    int index;
    for (index = 0; index < 4; ++index)
        bytes[index] = (uint8_t)(value >> (24 - 8 * index));
    write_hex(bytes, sizeof(bytes));
}

static void write_u64_hex(uint64_t value)
{
    uint8_t bytes[8];
    int index;
    for (index = 0; index < 8; ++index)
        bytes[index] = (uint8_t)(value >> (56 - 8 * index));
    write_hex(bytes, sizeof(bytes));
}

static int read_line(char *line, size_t capacity)
{
    size_t length = 0u;
    int overflow = 0;
    for (;;) {
        char value = (char)inbyte();
        if (value == '\r' || value == '\n') {
            if (length == 0u && !overflow) continue;
            line[length] = '\0';
            return overflow ? 0 : 1;
        }
        if (length + 1u < capacity) line[length++] = value;
        else overflow = 1;
    }
}

static uint32_t make_session_id(uint8_t slot, uint32_t generation)
{
    return 0x60000000u | ((generation & 0x003fffffu) << 6) | slot;
}

static int establish_demo_session(secure_channel_hw_t *device, uint8_t slot,
                                  uint32_t session_id)
{
    XTime begin, end;
    uint32_t elapsed_us;
    int result;

    XTime_GetTime(&begin);
    result = secure_channel_hw_establish_session(
        device, zed_kat_kem_ciphertext, slot, session_id);
    XTime_GetTime(&end);
    elapsed_us = ticks_to_us(begin, end);

    if (result != MLKEM_HW_OK) {
        xil_printf("ERR KEM %d %d\r\n", (int)slot, result);
        return 0;
    }

    xil_printf("READY %d ", (int)slot);
    write_u32_hex(session_id);
    xil_printf(" %lu\r\n", (unsigned long)elapsed_us);
    return 1;
}

static void write_status(const uint8_t active[UART_DEMO_SESSIONS])
{
    uint32_t bitmap_lo = 0u;
    uint32_t bitmap_hi = 0u;
    uint32_t count = 0u;
    uint32_t slot;

    for (slot = 0u; slot < UART_DEMO_SESSIONS; ++slot) {
        if (!active[slot]) continue;
        ++count;
        if (slot < 32u) bitmap_lo |= (uint32_t)1u << slot;
        else bitmap_hi |= (uint32_t)1u << (slot - 32u);
    }

    xil_printf("STATUS %lu ", (unsigned long)count);
    write_u32_hex(bitmap_hi);
    outbyte(' ');
    write_u32_hex(bitmap_lo);
    xil_printf("\r\n");
}

int uart_secure_demo_run(uintptr_t mlkem_base, uintptr_t aead_base,
                         uint32_t poll_limit)
{
    secure_channel_hw_t device;
    char line[UART_DEMO_LINE_BYTES];
    uint8_t session_active[UART_DEMO_SESSIONS];
    uint32_t session_generation[UART_DEMO_SESSIONS];
    uint32_t session_id[UART_DEMO_SESSIONS];
    uint8_t ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t tag[AEAD_HW_TAG_BYTES];
    uint8_t plaintext[AEAD_HW_PACKET_BYTES];
    uint8_t response_ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t response_tag[AEAD_HW_TAG_BYTES];
    int result;

    memset(session_active, 0, sizeof(session_active));
    memset(session_generation, 0, sizeof(session_generation));
    memset(session_id, 0, sizeof(session_id));

    secure_channel_hw_init(&device, mlkem_base, aead_base, poll_limit);
    result = secure_channel_hw_load_secret_key(&device, zed_kat_secret_key);
    if (result != MLKEM_HW_OK) {
        xil_printf("ERR KEY %d\r\n", result);
        return result;
    }

    xil_printf("\r\nUART-SECURE-DEMO 3 64-SESSIONS\r\n");
    xil_printf("COMMANDS OPEN/LEAVE/DATA <0..63>, STATUS, QUIT\r\n");
    xil_printf("NOTE LEAVE is PS-logical; OPEN securely overwrites the slot\r\n");

    for (;;) {
        char *command;
        char *slot_text;
        uint8_t slot;

        if (!read_line(line, sizeof(line))) {
            xil_printf("ERR LINE\r\n");
            continue;
        }

        command = strtok(line, " ");
        if (command == NULL) continue;

        if (strcmp(command, "QUIT") == 0) {
            xil_printf("BYE\r\n");
            return 0;
        }
        if (strcmp(command, "STATUS") == 0) {
            write_status(session_active);
            continue;
        }

        slot_text = strtok(NULL, " ");
        if (!parse_slot(slot_text, &slot)) {
            xil_printf("ERR SLOT\r\n");
            continue;
        }

        if (strcmp(command, "OPEN") == 0) {
            uint32_t new_id = make_session_id(slot, session_generation[slot]);
            if (establish_demo_session(&device, slot, new_id)) {
                session_active[slot] = 1u;
                session_id[slot] = new_id;
                ++session_generation[slot];
            }
            continue;
        }

        if (strcmp(command, "LEAVE") == 0) {
            if (!session_active[slot]) {
                xil_printf("ERR NOSESSION %d\r\n", (int)slot);
                continue;
            }
            session_active[slot] = 0u;
            xil_printf("LEFT %d ", (int)slot);
            write_u32_hex(session_id[slot]);
            xil_printf("\r\n");
            session_id[slot] = 0u;
            continue;
        }

        if (strcmp(command, "DATA") == 0) {
            char *counter_text = strtok(NULL, " ");
            char *length_text = strtok(NULL, " ");
            char *ciphertext_text = strtok(NULL, " ");
            char *tag_text = strtok(NULL, " ");
            uint64_t request_counter, response_counter;
            uint8_t message_length;
            XTime rx_begin, rx_end, tx_begin, tx_end;
            uint32_t rx_us, tx_us;

            if (!session_active[slot]) {
                xil_printf("ERR NOSESSION %d\r\n", (int)slot);
                continue;
            }
            if (!parse_u64_hex(counter_text, &request_counter)
                || !parse_length(length_text, &message_length)
                || !decode_hex_exact(ciphertext_text, ciphertext,
                                     sizeof(ciphertext))
                || !decode_hex_exact(tag_text, tag, sizeof(tag))) {
                xil_printf("ERR FORMAT\r\n");
                continue;
            }

            memset(plaintext, 0, sizeof(plaintext));
            XTime_GetTime(&rx_begin);
            result = secure_channel_hw_decrypt(
                &device, slot, request_counter, message_length,
                ciphertext, tag, plaintext);
            XTime_GetTime(&rx_end);
            rx_us = ticks_to_us(rx_begin, rx_end);

            if (result == AEAD_HW_ERR_AUTH) {
                xil_printf("ERR AUTH %d %lu\r\n",
                           (int)slot, (unsigned long)rx_us);
                continue;
            }
            if (result != AEAD_HW_OK) {
                xil_printf("ERR RX %d %d\r\n", (int)slot, result);
                continue;
            }

            XTime_GetTime(&tx_begin);
            result = secure_channel_hw_encrypt(
                &device, slot, plaintext, message_length,
                response_ciphertext, response_tag, &response_counter);
            XTime_GetTime(&tx_end);
            tx_us = ticks_to_us(tx_begin, tx_end);

            if (result != AEAD_HW_OK) {
                xil_printf("ERR TX %d %d\r\n", (int)slot, result);
                continue;
            }

            xil_printf("RESP %d ", (int)slot);
            write_u64_hex(response_counter);
            xil_printf(" %d %lu %lu ", (int)message_length,
                       (unsigned long)rx_us, (unsigned long)tx_us);
            write_hex(response_ciphertext, sizeof(response_ciphertext));
            outbyte(' ');
            write_hex(response_tag, sizeof(response_tag));
            xil_printf("\r\n");
            continue;
        }

        xil_printf("ERR CMD\r\n");
    }
}
