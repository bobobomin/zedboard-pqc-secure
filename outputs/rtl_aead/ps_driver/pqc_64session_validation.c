#include "pqc_64session_validation.h"

#include <stdint.h>
#include <string.h>

#include "xil_printf.h"
#include "xtime_l.h"

#include "aead_hw.h"
#include "mlkem_decaps_hw.h"
#include "secure_channel_hw.h"
#include "zed_pqc_kat_vectors.h"

#define SESSION_ID_BASE 0x64000000u

static int bytes_differ(const uint8_t *left, const uint8_t *right,
                        uint32_t length)
{
    return memcmp(left, right, (size_t)length) != 0;
}

static uint32_t elapsed_us(XTime begin, XTime end)
{
    uint64_t ticks = (uint64_t)(end - begin);
    return (uint32_t)((ticks * 1000000ull) / COUNTS_PER_SECOND);
}

static void report(const char *name, int passed, int *failures)
{
    xil_printf("[%s] %s\r\n", passed ? "PASS" : "FAIL", name);
    if (!passed)
        ++(*failures);
}

int pqc_64session_validation_run(uintptr_t mlkem_base,
                                 uintptr_t aead_base,
                                 uint32_t poll_limit)
{
    secure_channel_hw_t device;
    static const uint8_t probe[] = "64-session ML-KEM probe";
    uint8_t ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t tag[AEAD_HW_TAG_BYTES];
    uint8_t previous_ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t previous_tag[AEAD_HW_TAG_BYTES];
    uint8_t old_slot63_ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t old_slot63_tag[AEAD_HW_TAG_BYTES];
    uint64_t counter;
    XTime begin, end;
    uint32_t total_us;
    uint32_t installed = 0u;
    int counters_ok = 1;
    int distinct_ok = 1;
    int failures = 0;
    int result;
    uint32_t slot;

    xil_printf("\r\n-- 64-session BRAM validation --\r\n");
    secure_channel_hw_init(&device, mlkem_base, aead_base, poll_limit);

    result = secure_channel_hw_load_secret_key(&device, zed_kat_secret_key);
    report("load ML-KEM key for 64-session validation",
           result == MLKEM_HW_OK, &failures);
    if (result != MLKEM_HW_OK)
        return failures;

    memset(previous_ciphertext, 0, sizeof(previous_ciphertext));
    memset(previous_tag, 0, sizeof(previous_tag));
    XTime_GetTime(&begin);

    for (slot = 0u; slot < AEAD_HW_MAX_SESSIONS; ++slot) {
        result = secure_channel_hw_establish_session(
            &device, zed_kat_kem_ciphertext, (uint8_t)slot,
            SESSION_ID_BASE + slot);
        if (result != MLKEM_HW_OK)
            break;

        counter = UINT64_MAX;
        result = secure_channel_hw_encrypt(
            &device, (uint8_t)slot, probe,
            (uint8_t)(sizeof(probe) - 1u), ciphertext, tag, &counter);
        if (result != AEAD_HW_OK)
            break;

        ++installed;
        if (counter != 0u)
            counters_ok = 0;
        if (slot != 0u
            && !bytes_differ(ciphertext, previous_ciphertext,
                             AEAD_HW_PACKET_BYTES)
            && !bytes_differ(tag, previous_tag, AEAD_HW_TAG_BYTES))
            distinct_ok = 0;

        memcpy(previous_ciphertext, ciphertext, sizeof(ciphertext));
        memcpy(previous_tag, tag, sizeof(tag));
        if (slot == 63u) {
            memcpy(old_slot63_ciphertext, ciphertext, sizeof(ciphertext));
            memcpy(old_slot63_tag, tag, sizeof(tag));
        }
    }

    XTime_GetTime(&end);
    total_us = elapsed_us(begin, end);
    report("install and use every slot 0..63",
           installed == AEAD_HW_MAX_SESSIONS, &failures);
    report("all 64 first TX counters start at zero",
           installed == AEAD_HW_MAX_SESSIONS && counters_ok, &failures);
    report("session IDs produce separated traffic material",
           installed == AEAD_HW_MAX_SESSIONS && distinct_ok, &failures);

    xil_printf("[METRIC] 64 ML-KEM sessions: %lu us total, %lu us average\r\n",
               (unsigned long)total_us,
               (unsigned long)(installed == 0u ? 0u : total_us / installed));

    if (installed == AEAD_HW_MAX_SESSIONS) {
        counter = UINT64_MAX;
        result = secure_channel_hw_encrypt(
            &device, 0u, probe, (uint8_t)(sizeof(probe) - 1u),
            ciphertext, tag, &counter);
        report("slot 0 retains its independent TX counter",
               result == AEAD_HW_OK && counter == 1u, &failures);

        result = secure_channel_hw_establish_session(
            &device, zed_kat_kem_ciphertext, 63u, 0x6500003fu);
        counter = UINT64_MAX;
        if (result == MLKEM_HW_OK)
            result = secure_channel_hw_encrypt(
                &device, 63u, probe, (uint8_t)(sizeof(probe) - 1u),
                ciphertext, tag, &counter);
        report("new user overwrites reused slot and resets its counter",
               result == AEAD_HW_OK && counter == 0u
               && (bytes_differ(ciphertext, old_slot63_ciphertext,
                                AEAD_HW_PACKET_BYTES)
                   || bytes_differ(tag, old_slot63_tag, AEAD_HW_TAG_BYTES)),
               &failures);
    } else {
        report("slot 0 retains its independent TX counter", 0, &failures);
        report("new user overwrites reused slot and resets its counter",
               0, &failures);
    }

    result = secure_channel_hw_encrypt(
        &device, 64u, probe, (uint8_t)(sizeof(probe) - 1u),
        ciphertext, tag, &counter);
    report("driver rejects out-of-range slot 64",
           result == AEAD_HW_ERR_ARGUMENT, &failures);

    return failures;
}
