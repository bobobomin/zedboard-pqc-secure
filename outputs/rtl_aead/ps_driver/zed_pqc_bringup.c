#include <stdint.h>
#include <string.h>

//#include "platform.h"
#include "xil_printf.h"
#include "xparameters.h"

#include "aead_hw.h"
#include "mlkem_decaps_hw.h"
#include "secure_channel_hw.h"
#include "zed_pqc_kat_vectors.h"

#include "uart_secure_demo.h"
#include "software_crypto_benchmark.h"

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

    memcpy(tampered_tag, zed_kat_tag, sizeof(tampered_tag));
    tampered_tag[0] ^= 1u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    result = secure_channel_hw_decrypt(
        &device, 1u, 0u, ZED_KAT_MESSAGE_BYTES,
        zed_kat_ciphertext, tampered_tag, plaintext);
    report_result("tampered AEAD tag is rejected",
                  result == AEAD_HW_ERR_AUTH, &failures);

    /* Authentication failure must not advance the slot's RX counter, so the
     * valid reference packet still uses counter zero here. */
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

static int run_four_session_independence_test(void)
{
    secure_channel_hw_t device;
    uint8_t plaintext[AEAD_HW_PACKET_BYTES];
    uint8_t ciphertext[4][AEAD_HW_PACKET_BYTES];
    uint8_t tag[4][AEAD_HW_TAG_BYTES];
    uint64_t counter[4] = {
        UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX
    };

    static const uint8_t response[] = "ZedBoard secure reply";

    static const char *install_name[4] = {
        "install session slot 0",
        "install session slot 1",
        "install session slot 2",
        "install session slot 3"
    };

    static const char *decrypt_name[4] = {
        "slot 0 decrypts independently",
        "slot 1 decrypts independently",
        "slot 2 decrypts independently",
        "slot 3 decrypts independently"
    };

    static const char *encrypt_name[4] = {
        "slot 0 encrypts independently",
        "slot 1 encrypts independently",
        "slot 2 encrypts independently",
        "slot 3 encrypts independently"
    };

    static const char *counter_name[4] = {
        "slot 0 first TX counter is zero",
        "slot 1 first TX counter is zero",
        "slot 2 first TX counter is zero",
        "slot 3 first TX counter is zero"
    };

    int installed[4] = {0, 0, 0, 0};
    int encrypted[4] = {0, 0, 0, 0};
    int failures = 0;
    int outputs_match = 1;
    int result;
    int slot;

    xil_printf("\r\n-- Four-session independence test --\r\n");

    secure_channel_hw_init(
        &device,
        ZED_PQC_MLKEM_BASEADDR,
        ZED_PQC_AEAD_BASEADDR,
        ZED_PQC_POLL_LIMIT
    );

    result = secure_channel_hw_load_secret_key(
        &device, zed_kat_secret_key
    );

    report_result(
        "load key for four-session test",
        result == MLKEM_HW_OK,
        &failures
    );

    if (result != MLKEM_HW_OK)
        return failures;

    /*
     * 동일한 정상 세션을 네 슬롯에 각각 설치한다.
     * 세션 설치는 순차적으로 수행하지만 네 슬롯의 context는
     * PL session table에 독립적으로 보관되어야 한다.
     */
    for (slot = 0; slot < 4; ++slot) {
        result = secure_channel_hw_establish_session(
            &device,
            zed_kat_kem_ciphertext,
            (uint8_t)slot,
            ZED_KAT_SESSION_ID
        );

        installed[slot] = (result == MLKEM_HW_OK);
        report_result(
            install_name[slot],
            installed[slot],
            &failures
        );
    }

    /*
     * 모든 슬롯에 동일한 counter 0 패킷을 넣는다.
     * RX counter가 슬롯 사이에서 공유된다면 slot 0 이후의
     * 복호화가 counter 오류로 실패한다.
     */
    for (slot = 0; slot < 4; ++slot) {
        int passed = 0;

        memset(plaintext, 0xa5, sizeof(plaintext));

        if (installed[slot]) {
            result = secure_channel_hw_decrypt(
                &device,
                (uint8_t)slot,
                0u,
                ZED_KAT_MESSAGE_BYTES,
                zed_kat_ciphertext,
                zed_kat_tag,
                plaintext
            );

            passed =
                result == AEAD_HW_OK &&
                bytes_equal(
                    plaintext,
                    zed_kat_plaintext,
                    ZED_KAT_MESSAGE_BYTES
                );
        }

        report_result(
            decrypt_name[slot],
            passed,
            &failures
        );
    }

    /*
     * 네 슬롯에서 각각 첫 TX 패킷을 만든다.
     * TX counter가 독립적이면 모든 슬롯이 counter 0을 반환한다.
     */
    for (slot = 0; slot < 4; ++slot) {
        if (installed[slot]) {
            result = secure_channel_hw_encrypt(
                &device,
                (uint8_t)slot,
                response,
                (uint8_t)(sizeof(response) - 1u),
                ciphertext[slot],
                tag[slot],
                &counter[slot]
            );

            encrypted[slot] = (result == AEAD_HW_OK);
        }

        report_result(
            encrypt_name[slot],
            encrypted[slot],
            &failures
        );

        report_result(
            counter_name[slot],
            encrypted[slot] && counter[slot] == 0u,
            &failures
        );
    }

    /*
     * 네 슬롯은 같은 session ID, key, nonce 및 counter 0을
     * 사용했으므로 암호문과 tag도 동일해야 한다.
     */
    if (!encrypted[0]) {
        outputs_match = 0;
    } else {
        for (slot = 1; slot < 4; ++slot) {
            if (!encrypted[slot] ||
                !bytes_equal(
                    ciphertext[0],
                    ciphertext[slot],
                    AEAD_HW_PACKET_BYTES
                ) ||
                !bytes_equal(
                    tag[0],
                    tag[slot],
                    AEAD_HW_TAG_BYTES
                )) {
                outputs_match = 0;
            }
        }
    }

    report_result(
        "identical session produces identical output in all slots",
        outputs_match,
        &failures
    );

    return failures;
}

static int run_counter_replay_test(void)
{
    secure_channel_hw_t device;
    uint8_t plaintext[AEAD_HW_PACKET_BYTES];
    uint8_t tx_ciphertext[3][AEAD_HW_PACKET_BYTES];
    uint8_t tx_tag[3][AEAD_HW_TAG_BYTES];
    uint64_t tx_counter[3] = {
        UINT64_MAX, UINT64_MAX, UINT64_MAX
    };
    static const uint8_t response[] = "ZedBoard secure reply";

    /*
     * PC -> ZedBoard, session 0x01020304, counter 1.
     * AAD = session ID || counter || message length || reserved.
     */
    static const uint8_t rx_counter1_ciphertext[64] = {
        0x45,0x42,0x80,0x30,0x21,0x44,0x64,0xe8,
        0x56,0xd8,0xcd,0x21,0x87,0x4e,0x29,0x57,
        0x37,0xdf,0x46,0x7c,0x73,0x08,0xb9,0x0f,
        0x50,0xce,0xcc,0x76,0xad,0xc7,0x68,0x37,
        0x55,0xc8,0x21,0xba,0x14,0x0a,0x8e,0xbd,
        0x60,0x91,0x95,0xb6,0xb0,0xa2,0xbf,0xd1,
        0xe0,0x93,0x68,0x87,0xe9,0x46,0x4b,0x20,
        0x1f,0x76,0xe9,0xee,0x8a,0xad,0xd5,0x1d
    };

    static const uint8_t rx_counter1_tag[16] = {
        0xe7,0xa8,0x24,0xaa,0xa4,0x32,0x48,0xa2,
        0xb4,0xc4,0x82,0x9d,0x3d,0x05,0x3d,0x56
    };

    /* PC -> ZedBoard, same session, counter 2. */
    static const uint8_t rx_counter2_ciphertext[64] = {
        0xee,0xa0,0x83,0x0b,0x4d,0x80,0x77,0x20,
        0x49,0x99,0x50,0x2c,0xac,0xc4,0xed,0x0b,
        0xc5,0x20,0xa3,0x22,0xd5,0x65,0x6c,0x03,
        0xaa,0x21,0x6f,0x01,0xff,0x6c,0xdb,0xf0,
        0xfd,0xb4,0xc4,0xf1,0xfc,0x13,0x6f,0xd4,
        0x4f,0xc1,0x29,0xba,0x05,0xbc,0x7b,0x5d,
        0x53,0x6e,0x70,0x59,0x0e,0xfd,0x50,0x75,
        0x7b,0xb6,0xb9,0x85,0xe1,0xba,0x96,0x10
    };

    static const uint8_t rx_counter2_tag[16] = {
        0x40,0x5d,0x9a,0xae,0xa4,0x24,0x36,0x32,
        0x92,0xec,0x03,0x50,0xef,0x54,0xcc,0xdd
    };

    int failures = 0;
    int result;
    int tx_ok[3] = {0, 0, 0};
    int tx_outputs_unique;
    int i;

    xil_printf("\r\n-- Counter and replay test --\r\n");

    secure_channel_hw_init(
        &device,
        ZED_PQC_MLKEM_BASEADDR,
        ZED_PQC_AEAD_BASEADDR,
        ZED_PQC_POLL_LIMIT
    );

    result = secure_channel_hw_load_secret_key(
        &device, zed_kat_secret_key
    );
    report_result(
        "load key for counter test",
        result == MLKEM_HW_OK,
        &failures
    );

    if (result != MLKEM_HW_OK)
        return failures;

    /*
     * 세션을 다시 설치하면 해당 슬롯의 TX/RX counter가
     * 모두 0으로 초기화되어야 한다.
     */
    result = secure_channel_hw_establish_session(
        &device,
        zed_kat_kem_ciphertext,
        0u,
        ZED_KAT_SESSION_ID
    );
    report_result(
        "reinstall slot 0 and reset counters",
        result == MLKEM_HW_OK,
        &failures
    );

    if (result != MLKEM_HW_OK)
        return failures;

    /* 정상 counter 0. */
    memset(plaintext, 0xa5, sizeof(plaintext));
    result = secure_channel_hw_decrypt(
        &device,
        0u,
        0u,
        ZED_KAT_MESSAGE_BYTES,
        zed_kat_ciphertext,
        zed_kat_tag,
        plaintext
    );
    report_result(
        "accept expected RX counter 0",
        result == AEAD_HW_OK &&
        bytes_equal(
            plaintext,
            zed_kat_plaintext,
            ZED_KAT_MESSAGE_BYTES
        ),
        &failures
    );

    /* 이미 사용한 counter 0을 다시 보내면 거부해야 한다. */
    result = secure_channel_hw_decrypt(
        &device,
        0u,
        0u,
        ZED_KAT_MESSAGE_BYTES,
        zed_kat_ciphertext,
        zed_kat_tag,
        plaintext
    );
    report_result(
        "reject replayed RX counter 0",
        result == AEAD_HW_ERR_AUTH,
        &failures
    );

    /*
     * 현재 예상 counter는 1이다.
     * counter 2를 먼저 보내면 거부해야 한다.
     */
    result = secure_channel_hw_decrypt(
        &device,
        0u,
        2u,
        ZED_KAT_MESSAGE_BYTES,
        rx_counter2_ciphertext,
        rx_counter2_tag,
        plaintext
    );
    report_result(
        "reject skipped RX counter 2",
        result == AEAD_HW_ERR_AUTH,
        &failures
    );

    /*
     * 앞의 잘못된 요청들이 RX counter를 증가시키지 않았다면
     * 정상 counter 1을 여전히 받을 수 있어야 한다.
     */
    memset(plaintext, 0xa5, sizeof(plaintext));
    result = secure_channel_hw_decrypt(
        &device,
        0u,
        1u,
        ZED_KAT_MESSAGE_BYTES,
        rx_counter1_ciphertext,
        rx_counter1_tag,
        plaintext
    );
    report_result(
        "accept expected RX counter 1 after rejects",
        result == AEAD_HW_OK &&
        bytes_equal(
            plaintext,
            zed_kat_plaintext,
            ZED_KAT_MESSAGE_BYTES
        ),
        &failures
    );

    result = secure_channel_hw_decrypt(
        &device,
        0u,
        1u,
        ZED_KAT_MESSAGE_BYTES,
        rx_counter1_ciphertext,
        rx_counter1_tag,
        plaintext
    );
    report_result(
        "reject replayed RX counter 1",
        result == AEAD_HW_ERR_AUTH,
        &failures
    );

    memset(plaintext, 0xa5, sizeof(plaintext));
    result = secure_channel_hw_decrypt(
        &device,
        0u,
        2u,
        ZED_KAT_MESSAGE_BYTES,
        rx_counter2_ciphertext,
        rx_counter2_tag,
        plaintext
    );
    report_result(
        "accept expected RX counter 2",
        result == AEAD_HW_OK &&
        bytes_equal(
            plaintext,
            zed_kat_plaintext,
            ZED_KAT_MESSAGE_BYTES
        ),
        &failures
    );

    /*
     * RX와 TX counter는 방향별로 독립적이므로 앞에서 RX를
     * 세 번 처리했더라도 첫 TX counter는 0이어야 한다.
     */
    for (i = 0; i < 3; ++i) {
        result = secure_channel_hw_encrypt(
            &device,
            0u,
            response,
            (uint8_t)(sizeof(response) - 1u),
            tx_ciphertext[i],
            tx_tag[i],
            &tx_counter[i]
        );

        tx_ok[i] =
            result == AEAD_HW_OK &&
            tx_counter[i] == (uint64_t)i;
    }

    report_result(
        "TX counter sequence is 0, 1, 2",
        tx_ok[0] && tx_ok[1] && tx_ok[2],
        &failures
    );

    tx_outputs_unique =
        tx_ok[0] && tx_ok[1] && tx_ok[2] &&
        (!bytes_equal(
            tx_ciphertext[0],
            tx_ciphertext[1],
            AEAD_HW_PACKET_BYTES
        ) ||
         !bytes_equal(
            tx_tag[0],
            tx_tag[1],
            AEAD_HW_TAG_BYTES
        )) &&
        (!bytes_equal(
            tx_ciphertext[1],
            tx_ciphertext[2],
            AEAD_HW_PACKET_BYTES
        ) ||
         !bytes_equal(
            tx_tag[1],
            tx_tag[2],
            AEAD_HW_TAG_BYTES
        ));

    report_result(
        "TX output changes when packet counter changes",
        tx_outputs_unique,
        &failures
    );

    return failures;
}

static int run_packet_boundary_test(void)
{
    secure_channel_hw_t device;
    uint8_t message_a[AEAD_HW_PACKET_BYTES];
    uint8_t message_b[AEAD_HW_PACKET_BYTES];
    uint8_t ciphertext_a[AEAD_HW_PACKET_BYTES];
    uint8_t ciphertext_b[AEAD_HW_PACKET_BYTES];
    uint8_t tag_a[AEAD_HW_TAG_BYTES];
    uint8_t tag_b[AEAD_HW_TAG_BYTES];
    uint64_t counter_a;
    uint64_t counter_b;
    static const uint8_t lengths[4] = {0u, 1u, 63u, 64u};
    static const char *length_names[4] = {
        "accept zero-byte packet",
        "accept one-byte packet",
        "accept 63-byte packet",
        "accept 64-byte packet"
    };
    int failures = 0;
    int result;
    int result_a;
    int result_b;
    int passed;
    int i;

    xil_printf("\r\n-- Packet boundary test --\r\n");

    secure_channel_hw_init(
        &device,
        ZED_PQC_MLKEM_BASEADDR,
        ZED_PQC_AEAD_BASEADDR,
        ZED_PQC_POLL_LIMIT
    );

    result = secure_channel_hw_load_secret_key(
        &device, zed_kat_secret_key
    );
    report_result(
        "load key for packet boundary test",
        result == MLKEM_HW_OK,
        &failures
    );

    if (result != MLKEM_HW_OK)
        return failures;

    result = secure_channel_hw_establish_session(
        &device,
        zed_kat_kem_ciphertext,
        0u,
        ZED_KAT_SESSION_ID
    );
    report_result(
        "install slot 0 for boundary lengths",
        result == MLKEM_HW_OK,
        &failures
    );

    if (result != MLKEM_HW_OK)
        return failures;

    for (i = 0; i < AEAD_HW_PACKET_BYTES; ++i)
        message_a[i] = (uint8_t)(i + 1);

    /*
     * 지원하는 네 경계 길이를 연속 처리한다.
     * 성공한 요청만 TX counter를 증가시켜야 한다.
     */
    for (i = 0; i < 4; ++i) {
        counter_a = UINT64_MAX;

        result = secure_channel_hw_encrypt(
            &device,
            0u,
            message_a,
            lengths[i],
            ciphertext_a,
            tag_a,
            &counter_a
        );

        report_result(
            length_names[i],
            result == AEAD_HW_OK &&
            counter_a == (uint64_t)i,
            &failures
        );
    }

    /*
     * 공개 드라이버 API는 64-byte를 초과하는 요청을
     * PL에 보내기 전에 거부해야 한다.
     */
    result = secure_channel_hw_encrypt(
        &device,
        0u,
        message_a,
        65u,
        ciphertext_a,
        tag_a,
        &counter_a
    );
    report_result(
        "reject 65-byte packet",
        result == AEAD_HW_ERR_ARGUMENT,
        &failures
    );

    result = secure_channel_hw_encrypt(
        &device,
        4u,
        message_a,
        1u,
        ciphertext_a,
        tag_a,
        &counter_a
    );
    report_result(
        "reject invalid session slot 4",
        result == AEAD_HW_ERR_ARGUMENT,
        &failures
    );

    /*
     * 앞의 잘못된 요청이 counter를 증가시키지 않았다면
     * 다음 정상 요청은 counter 4를 사용해야 한다.
     */
    counter_a = UINT64_MAX;
    result = secure_channel_hw_encrypt(
        &device,
        0u,
        message_a,
        1u,
        ciphertext_a,
        tag_a,
        &counter_a
    );
    report_result(
        "invalid requests do not advance TX counter",
        result == AEAD_HW_OK && counter_a == 4u,
        &failures
    );

    /*
     * slot 1과 2에 같은 세션을 설치한다.
     * 두 슬롯의 counter가 같으므로 입력 길이 처리 결과를
     * 암호문과 tag로 직접 비교할 수 있다.
     */
    result_a = secure_channel_hw_establish_session(
        &device,
        zed_kat_kem_ciphertext,
        1u,
        ZED_KAT_SESSION_ID
    );

    result_b = secure_channel_hw_establish_session(
        &device,
        zed_kat_kem_ciphertext,
        2u,
        ZED_KAT_SESSION_ID
    );

    report_result(
        "install comparison sessions in slots 1 and 2",
        result_a == MLKEM_HW_OK &&
        result_b == MLKEM_HW_OK,
        &failures
    );

    if (result_a != MLKEM_HW_OK || result_b != MLKEM_HW_OK)
        return failures;

    /*
     * 길이 0이면 입력 buffer 내용 전체가 무시되고
     * 64-byte zero block으로 처리되어야 한다.
     */
    memset(message_a, 0x11, sizeof(message_a));
    memset(message_b, 0xee, sizeof(message_b));

    result_a = secure_channel_hw_encrypt(
        &device, 1u, message_a, 0u,
        ciphertext_a, tag_a, &counter_a
    );

    result_b = secure_channel_hw_encrypt(
        &device, 2u, message_b, 0u,
        ciphertext_b, tag_b, &counter_b
    );

    passed =
        result_a == AEAD_HW_OK &&
        result_b == AEAD_HW_OK &&
        counter_a == 0u &&
        counter_b == 0u &&
        bytes_equal(
            ciphertext_a,
            ciphertext_b,
            AEAD_HW_PACKET_BYTES
        ) &&
        bytes_equal(tag_a, tag_b, AEAD_HW_TAG_BYTES);

    report_result(
        "zero-byte packet ignores entire input buffer",
        passed,
        &failures
    );

    /*
     * 길이 1이면 첫 바이트만 사용하고 나머지 63바이트는
     * zero padding해야 한다.
     */
    memset(message_a, 0x11, sizeof(message_a));
    memset(message_b, 0xee, sizeof(message_b));
    message_a[0] = 0xa5u;
    message_b[0] = 0xa5u;

    result_a = secure_channel_hw_encrypt(
        &device, 1u, message_a, 1u,
        ciphertext_a, tag_a, &counter_a
    );

    result_b = secure_channel_hw_encrypt(
        &device, 2u, message_b, 1u,
        ciphertext_b, tag_b, &counter_b
    );

    passed =
        result_a == AEAD_HW_OK &&
        result_b == AEAD_HW_OK &&
        counter_a == 1u &&
        counter_b == 1u &&
        bytes_equal(
            ciphertext_a,
            ciphertext_b,
            AEAD_HW_PACKET_BYTES
        ) &&
        bytes_equal(tag_a, tag_b, AEAD_HW_TAG_BYTES);

    report_result(
        "one-byte packet ignores and clears trailing bytes",
        passed,
        &failures
    );

    /*
     * 첫 63바이트는 같고 마지막 바이트만 다르게 한다.
     * 길이 63에서는 마지막 바이트가 무시되어야 한다.
     */
    for (i = 0; i < 63; ++i) {
        message_a[i] = (uint8_t)(i + 1);
        message_b[i] = (uint8_t)(i + 1);
    }
    message_a[63] = 0x11u;
    message_b[63] = 0xeeu;

    result_a = secure_channel_hw_encrypt(
        &device, 1u, message_a, 63u,
        ciphertext_a, tag_a, &counter_a
    );

    result_b = secure_channel_hw_encrypt(
        &device, 2u, message_b, 63u,
        ciphertext_b, tag_b, &counter_b
    );

    passed =
        result_a == AEAD_HW_OK &&
        result_b == AEAD_HW_OK &&
        counter_a == 2u &&
        counter_b == 2u &&
        bytes_equal(
            ciphertext_a,
            ciphertext_b,
            AEAD_HW_PACKET_BYTES
        ) &&
        bytes_equal(tag_a, tag_b, AEAD_HW_TAG_BYTES);

    report_result(
        "63-byte packet ignores byte index 63",
        passed,
        &failures
    );

    /*
     * 길이 64에서는 마지막 바이트도 암호화 및 인증에
     * 포함되므로 서로 다른 결과가 나와야 한다.
     */
    result_a = secure_channel_hw_encrypt(
        &device, 1u, message_a, 64u,
        ciphertext_a, tag_a, &counter_a
    );

    result_b = secure_channel_hw_encrypt(
        &device, 2u, message_b, 64u,
        ciphertext_b, tag_b, &counter_b
    );

    passed =
        result_a == AEAD_HW_OK &&
        result_b == AEAD_HW_OK &&
        counter_a == 3u &&
        counter_b == 3u &&
        (!bytes_equal(
            ciphertext_a,
            ciphertext_b,
            AEAD_HW_PACKET_BYTES
        ) ||
         !bytes_equal(tag_a, tag_b, AEAD_HW_TAG_BYTES));

    report_result(
        "64-byte packet includes byte index 63",
        passed,
        &failures
    );

    return failures;
}

int main(void)
{
    int failures = 0;

    //init_platform();
    xil_printf("\r\n========================================\r\n");
    xil_printf(" ZedBoard PQC secure-channel bring-up\r\n");
    xil_printf("========================================\r\n");
    xil_printf("AEAD AXI  : 0x%08lx\r\n",
               (unsigned long)ZED_PQC_AEAD_BASEADDR);
    xil_printf("ML-KEM AXI: 0x%08lx\r\n",
               (unsigned long)ZED_PQC_MLKEM_BASEADDR);

    failures += run_mlkem_secure_channel_test();
    failures += run_four_session_independence_test();
    failures += run_counter_replay_test();
    failures += run_packet_boundary_test();

    xil_printf("\r\n========================================\r\n");
    if (failures == 0)
        xil_printf("ALL PS-PL HARDWARE TESTS PASSED\r\n");
    else
        xil_printf("BRING-UP FAILED: %d check(s) failed\r\n", failures);
    xil_printf("========================================\r\n");

    if (failures == 0)
        failures += software_crypto_benchmark_run();

    if (failures == 0)
        uart_secure_demo_run(
            ZED_PQC_MLKEM_BASEADDR,
            ZED_PQC_AEAD_BASEADDR,
            ZED_PQC_POLL_LIMIT
        );

    //cleanup_platform();
    return failures == 0 ? 0 : 1;
}

