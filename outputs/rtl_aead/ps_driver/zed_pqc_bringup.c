#include <stdint.h>
#include <string.h>

#include "platform.h"
#include "xil_printf.h"
#include "xparameters.h"

#include "aead_hw.h"
#include "mlkem_decaps_hw.h"
#include "pqc_64session_validation.h"
#include "secure_channel_hw.h"
#include "uart_secure_demo.h"
#include "zed_pqc_kat_vectors.h"

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
    uint8_t tampered_tag[AEAD_HW_TAG_BYTES];
    uint8_t tampered_kem_ciphertext[MLKEM512_CIPHERTEXT_BYTES];
    uint64_t response_counter = UINT64_MAX;
    static const uint8_t response[] = "ZedBoard secure reply";
    static const uint8_t expected_response_ciphertext[AEAD_HW_PACKET_BYTES] = {
        0xb7,0xb2,0x35,0xda,0x3d,0xbb,0xb9,0xec,
        0xd9,0x10,0xe3,0xde,0x27,0xde,0x0a,0x3a,
        0x6f,0xc9,0x93,0xae,0xcd,0xbe,0x7e,0x1e,
        0xae,0xb6,0x74,0x0d,0x1d,0x1f,0xf8,0xfa,
        0x3d,0xff,0xad,0xe4,0x99,0x4d,0x01,0xf9,
        0x3f,0xfe,0x34,0x6c,0x86,0x44,0xbd,0x72,
        0x38,0x60,0x83,0xca,0x10,0x5e,0x9f,0x23,
        0xcd,0xbc,0x26,0x97,0x87,0x7d,0x85,0xfa
    };
    static const uint8_t expected_response_tag[AEAD_HW_TAG_BYTES] = {
        0x9c,0x2c,0x69,0x58,0x27,0x50,0xaf,0x21,
        0x29,0xb2,0x20,0xb9,0x9a,0x08,0xe6,0x51
    };
    int failures = 0;
    int result;

    xil_printf("\r\n-- Full ML-KEM to AEAD known-answer test --\r\n");
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

    memcpy(tampered_tag, zed_kat_tag, sizeof(tampered_tag));
    tampered_tag[0] ^= 1u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    result = secure_channel_hw_decrypt(
        &device, 1u, 0u, ZED_KAT_MESSAGE_BYTES,
        zed_kat_ciphertext, tampered_tag, plaintext);
    report_result("tampered AEAD tag is rejected",
                  result == AEAD_HW_ERR_AUTH, &failures);

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
                  result == AEAD_HW_OK, &failures);
    if (result == AEAD_HW_OK) {
        report_result("first TX packet counter is zero",
                      response_counter == 0u, &failures);
        report_result("ChaCha20 response ciphertext matches PC golden",
                      bytes_equal(response_ciphertext,
                                  expected_response_ciphertext,
                                  AEAD_HW_PACKET_BYTES), &failures);
        report_result("Poly1305 response tag matches PC golden",
                      bytes_equal(response_tag, expected_response_tag,
                                  AEAD_HW_TAG_BYTES), &failures);
    }

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
    xil_printf(" ZedBoard PQC 64-session bring-up\r\n");
    xil_printf("========================================\r\n");
    xil_printf("AEAD AXI  : 0x%08lx\r\n",
               (unsigned long)ZED_PQC_AEAD_BASEADDR);
    xil_printf("ML-KEM AXI: 0x%08lx\r\n",
               (unsigned long)ZED_PQC_MLKEM_BASEADDR);

    failures += run_mlkem_secure_channel_test();
    if (failures == 0)
        failures += pqc_64session_validation_run(
            ZED_PQC_MLKEM_BASEADDR,
            ZED_PQC_AEAD_BASEADDR,
            ZED_PQC_POLL_LIMIT);

    xil_printf("\r\n========================================\r\n");
    if (failures == 0)
        xil_printf("ALL 64-SESSION PS-PL TESTS PASSED\r\n");
    else
        xil_printf("BRING-UP FAILED: %d check(s) failed\r\n", failures);
    xil_printf("========================================\r\n");

    if (failures == 0)
        failures += uart_secure_demo_run(
            ZED_PQC_MLKEM_BASEADDR,
            ZED_PQC_AEAD_BASEADDR,
            ZED_PQC_POLL_LIMIT);

    cleanup_platform();
    return failures == 0 ? 0 : 1;
}
