# ZedBoard PS bring-up

The Vivado Address Editor assigns the two AXI-Lite windows as follows:

- AEAD traffic frontend: `0x43C00000`
- ML-KEM decapsulation frontend: `0x43C10000`

Vitis 2020.2 emits only one representative `XPAR_*_BASEADDR` macro for this
multi-interface packaged IP. `zed_pqc_bringup.c` therefore names both address
windows explicitly and compile-time checks the generated ML-KEM address.

Add these sources to a standalone Cortex-A9 application:

- `zed_pqc_bringup.c` (use as the application's `main`)
- `zed_pqc_kat_vectors.h`
- `aead_hw.c/.h`
- `mlkem_decaps_hw.c/.h`
- `secure_channel_hw.c/.h`

The application performs the following board tests in order:

1. Configure a deterministic AEAD session through AXI-Lite.
2. Compare hardware ciphertext and Poly1305 tag with the PC golden reference.
3. Authenticate/decrypt the golden packet and reject a modified tag.
4. Load the ML-KEM-512 decapsulation key and ciphertext.
5. Run complete PL decapsulation and atomically install session slot 1.
6. Decrypt the PC golden packet with the ML-KEM-derived RX key.
7. Encrypt a ZedBoard response with the direction-separated TX key.
8. Reject a modified ML-KEM ciphertext.

UART is configured by the generated BSP for PS UART 1 at 115200 baud. A
successful run ends with `ALL PS-PL HARDWARE TESTS PASSED`.

The KAT header contains public test vectors only. It must not be used as a
production key store.
