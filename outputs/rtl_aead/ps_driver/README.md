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

1. Load the ML-KEM-512 decapsulation key and ciphertext.
2. Run complete PL decapsulation and atomically install session slot 1.
3. Reject a modified Poly1305 tag without advancing the RX counter.
4. Authenticate/decrypt the PC golden packet and compare its plaintext.
5. Encrypt a ZedBoard response with the direction-separated TX key.
6. Compare its packet counter, ChaCha20 ciphertext, and Poly1305 tag with the
   independently generated PC golden reference.
7. Reject a modified ML-KEM ciphertext.

The integrated AEAD traffic window intentionally does not expose direct key or
session-configuration registers to the PS. Session material is installed only
through the successful ML-KEM path, so standalone direct-session tests for
`aead_axi_lite_wrapper` do not apply to this packaged secure-channel top.

UART is configured by the generated BSP for PS UART 1 at 115200 baud. A
successful run ends with `ALL PS-PL HARDWARE TESTS PASSED`.

The KAT header contains public test vectors only. It must not be used as a
production key store.
