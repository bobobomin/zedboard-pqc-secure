/*
 * SWKEM command for the two-board UART demo firmware (uart_two_board_demo.c).
 *
 * The PC GUI sends "SWKEM\n" to each board every 2 s.  The board runs ONE
 * software ML-KEM-512 decapsulation on the Cortex-A9 (mlkem-native, the same
 * library used by software_crypto_benchmark.c), times it with the global
 * timer, and answers:
 *
 *     SWKEM <microseconds> <1|0>
 *
 * The last field is 1 when the recovered shared secret matches the KAT value.
 * Firmware without this command answers "ERR CMD"; the GUI then falls back to
 * the fixed --ps-kem-us reference, so old ELFs keep working.
 *
 * Integration
 *   1. Add this file to the Vitis application sources, together with the
 *      mlkem-native sources already used by software_crypto_benchmark.c
 *      (golden_reference/third_party/mlkem-native).  Adjust the include path
 *      below if the project layout differs.
 *   2. In the UART command dispatcher, next to HELLO / STATUS / OPEN, add:
 *
 *          } else if (strcmp(command, "SWKEM") == 0) {
 *              two_board_handle_swkem();
 *
 *   3. Rebuild both ELFs (A and B).  Nothing else in the protocol changes.
 *
 * Note: ML-KEM decapsulation is constant-time, so timing it on the fixed KAT
 * ciphertext gives the same cost as timing it on a live session ciphertext.
 * When Board B gets its own long-term key, replace zed_kat_secret_key with
 * that key and drop the KAT shared-secret comparison.
 */

#include <stdint.h>
#include <string.h>

#include "xil_printf.h"
#include "xtime_l.h"

#define MLK_CONFIG_PARAMETER_SET 512
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
#include "../../golden_reference/third_party/mlkem-native/mlkem/mlkem_native.h"
#include "zed_pqc_kat_vectors.h"

void two_board_handle_swkem(void);

static const uint8_t swkem_expected_ss[32] = {
    0xee,0x5f,0x8f,0x90,0xfb,0x6f,0x15,0xa5,
    0x93,0x45,0x04,0xe1,0xf6,0x5c,0x23,0xad,
    0x2d,0x60,0x96,0x41,0x04,0xbf,0x42,0x46,
    0x38,0x76,0x36,0x3a,0x79,0x9d,0xee,0x4f
};

void two_board_handle_swkem(void)
{
    static uint8_t shared_secret[MLKEM_BYTES];
    XTime begin, end;
    uint64_t elapsed_us;
    int rc;
    int match;

    XTime_GetTime(&begin);
    rc = mlkem_dec(shared_secret, zed_kat_kem_ciphertext, zed_kat_secret_key);
    XTime_GetTime(&end);

    /* Global timer runs at COUNTS_PER_SECOND (CPU clock / 2). */
    elapsed_us = ((uint64_t)(end - begin) * 1000000ULL) / COUNTS_PER_SECOND;
    match = (rc == 0) && (memcmp(shared_secret, swkem_expected_ss, 32u) == 0);

    xil_printf("SWKEM %lu %d\r\n", (unsigned long)elapsed_us, match);
}
