#include <stdint.h>
#include <string.h>

#include "platform.h"
#include "xil_printf.h"
#include "xparameters.h"

#include "aead_hw.h"
#include "mlkem_decaps_hw.h"
#include "secure_channel_hw.h"
#include "zed_pqc_kat_vectors.h"

/* The packaged IP has two AXI-Lite slaves. Vitis 2020.2 emits only the
 * representative custom-IP base address in xparameters.h, so keep both
 * Address Editor assignments explicit here. */
#define ZED_PQC_AEAD_BASEADDR  0x43C00000u
#define ZED_PQC_MLKEM_BASEADDR 0x43C10000u
#define ZED_PQC_POLL_LIMIT     10000000u

#if XPAR_MLKEM_SECURE_CHANNEL_0_BASEADDR != ZED_PQC_MLKEM_BASEADDR
#error "The Vitis ML-KEM base address no longer matches the Vivado Address Editor"
#endif

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       uint32_t length)
{
    return memcmp(left, right, (size_t)length) == 0;
}

static void report_result(const char *name, int passed, int *failures)
{
    xil_printf("[%s] %s\r\n", passed ? "PASS" : "FAIL", name);
    if (!passed)
        ++(*failures);
}

static int run_mlkem_secure_channel_test(void)
{
    secure_channel_hw_t device;
    uint8_t plaintext[AEAD_HW_PACKET_BYTES];
    uint8_t response_ciphertext[AEAD_HW_PACKET_BYTES];
    uint8_t response_tag[AEAD_HW_TAG_BYTES];
    uint8_t tampered_kem_ciphertext[MLKEM512_CIPHERTEXT_BYTES];
    uint64_t response_counter = UINT64_MAX;
    static const uint8_t response[] = "ZedBoard secure reply";
    int failures = 0;
    int result;

    xil_printf("\r\n-- Full ML-KEM to AEAD test --\r\n");
    secure_channel_hw_init(&device, ZED_PQC_MLKEM_BASEADDR,
                           ZED_PQC_AEAD_BASEADDR, ZED_PQC_POLL_LIMIT);

    result = secure_channel_hw_load_secret_key(&device, zed_kat_secret_key);
    report_result("load ML-KEM-512 decapsulation key",
                  result == MLKEM_HW_OK, &failures);
    if (result != MLKEM_HW_OK)
        return failures;

    result = secure_channel_hw_establish_session(
        &device, zed_kat_kem_ciphertext, 1u, ZED_KAT_SESSION_ID);
    report_result("decapsulate and install session slot 1",
                  result == MLKEM_HW_OK, &failures);
    if (result != MLKEM_HW_OK)
        return failures;

    result = secure_channel_hw_decrypt(
        &device, 1u, 0u, ZED_KAT_MESSAGE_BYTES,
        zed_kat_ciphertext, zed_kat_tag, plaintext);
    report_result("decrypt PC packet with ML-KEM-derived RX key",
                  result == AEAD_HW_OK, &failures);
    if (result == AEAD_HW_OK)
        report_result("ML-KEM session plaintext matches reference",
                      bytes_equal(plaintext, zed_kat_plaintext,
                                  ZED_KAT_MESSAGE_BYTES), &failures);

    result = secure_channel_hw_encrypt(
        &device, 1u, response, (uint8_t)(sizeof(response) - 1u),
        response_ciphertext, response_tag, &response_counter);
    report_result("encrypt ZedBoard response with derived TX key",
                  result == AEAD_HW_OK && response_counter == 0u, &failures);

    memcpy(tampered_kem_ciphertext, zed_kat_kem_ciphertext,
           sizeof(tampered_kem_ciphertext));
    tampered_kem_ciphertext[0] ^= 1u;
    result = secure_channel_hw_establish_session(
        &device, tampered_kem_ciphertext, 2u, 0x02030405u);
    report_result("tampered ML-KEM ciphertext is rejected",
                  result == MLKEM_HW_REJECTED, &failures);
    return failures;
}

int main(void)
{
    int failures = 0;

    init_platform();
    xil_printf("\r\n========================================\r\n");
    xil_printf(" ZedBoard PQC secure-channel bring-up\r\n");
    xil_printf("========================================\r\n");
    xil_printf("AEAD AXI  : 0x%08lx\r\n",
               (unsigned long)ZED_PQC_AEAD_BASEADDR);
    xil_printf("ML-KEM AXI: 0x%08lx\r\n",
               (unsigned long)ZED_PQC_MLKEM_BASEADDR);

    failures += run_mlkem_secure_channel_test();

    xil_printf("\r\n========================================\r\n");
    if (failures == 0)
        xil_printf("ALL PS-PL HARDWARE TESTS PASSED\r\n");
    else
        xil_printf("BRING-UP FAILED: %d check(s) failed\r\n", failures);
    xil_printf("========================================\r\n");

    cleanup_platform();
    return failures == 0 ? 0 : 1;
}
