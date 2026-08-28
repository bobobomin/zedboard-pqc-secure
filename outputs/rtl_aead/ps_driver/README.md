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
- `uart_secure_demo.c/.h`
- `software_crypto_benchmark.c/.h`
- `mlkem512_portable_wrapper.c`
- `monocypher_portable_wrapper.c`

The application performs the following board tests in order:

1. Load the ML-KEM-512 decapsulation key and ciphertext.
2. Run complete PL decapsulation and atomically install session slot 1.
3. Reject a modified Poly1305 tag without advancing the RX counter.
4. Authenticate/decrypt the PC golden packet and compare its plaintext.
5. Encrypt a ZedBoard response with the direction-separated TX key.
6. Compare its packet counter, ChaCha20 ciphertext, and Poly1305 tag with the
   independently generated PC golden reference.
7. Reject a modified ML-KEM ciphertext.
8. Verify four independent session slots.
9. Verify independent counters, replay rejection, and skipped-counter rejection.
10. Verify 0/1/63/64-byte packet boundaries and reject oversized/invalid-slot requests.

The integrated AEAD traffic window intentionally does not expose direct key or
session-configuration registers to the PS. Session material is installed only
through the successful ML-KEM path, so standalone direct-session tests for
`aead_axi_lite_wrapper` do not apply to this packaged secure-channel top.

UART is configured by the generated BSP for PS UART 1 at 115200 baud. A
successful run ends with `ALL PS-PL HARDWARE TESTS PASSED`.

After the hardware tests, the application measures portable-C ML-KEM-512 and ChaCha20-Poly1305 on the Cortex-A9. Build as Release (`-O2`) and raise the linker stack to at least `0x10000`. The wrappers reuse libraries already vendored under `outputs/golden_reference/third_party`.

If every test passes, `uart_secure_demo_run()` starts a four-logical-session secure echo protocol:

```powershell
py outputs/rtl_aead/pc_tools/uart_secure_client.py --port COM3
```

The client requires `pyserial` and `cryptography` and supports `/user 0..3`, `/round N`, `/stats`, `/reopen N`, and `/quit`. UART serializes requests, so true simultaneous arbitration remains an RTL simulation property.

The KAT header contains public test vectors only. It must not be used as a
production key store.
