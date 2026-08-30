# ZedBoard PS bring-up

The Vivado Address Editor assigns the two AXI-Lite windows as follows:

- AEAD traffic frontend: `0x43C00000`
- ML-KEM decapsulation frontend: `0x43C10000`

Use the bitstream-bearing `system_wrapper_64session.xsa` to create or update
the Vitis 2020.2 standalone platform.

Add these sources to the Cortex-A9 application:

- `zed_pqc_bringup.c` (application `main`)
- `zed_pqc_kat_vectors.h`
- `aead_hw.c/.h`
- `mlkem_decaps_hw.c/.h`
- `secure_channel_hw.c/.h`
- `pqc_64session_validation.c/.h`
- `uart_secure_demo.c/.h`
- `pqc_session_scheduler.c/.h` (future Ethernet request queue)

The application performs these tests before starting the UART demo:

1. ML-KEM-512 decapsulation and atomic session installation.
2. Valid AEAD decrypt/encrypt golden vectors.
3. Modified Poly1305 tag and modified ML-KEM ciphertext rejection.
4. Sequential installation and first use of every slot from 0 through 63.
5. Independent counter-zero state in all 64 slots.
6. Directional traffic-material separation for distinct session IDs.
7. Counter preservation in an untouched slot.
8. Slot reuse by a new session, including key overwrite and counter reset.
9. Driver rejection of out-of-range slot 64.

Success ends with:

```text
ALL 64-SESSION PS-PL TESTS PASSED
```

The UART protocol then accepts:

```text
OPEN <0..63>
LEAVE <0..63>
DATA <slot> <counter_hex> <length> <ciphertext_hex> <tag_hex>
STATUS
QUIT
```

Run the PC client from the repository so it can load
`outputs/golden_reference/public_key.bin` and `kem_ciphertext.bin`:

```powershell
py outputs/rtl_aead/pc_tools/uart_secure_client.py --port COM3
```

Useful interactive commands are `/join [slot]`, `/leave <slot>`,
`/fill <count>`, `/churn <count>`, `/round <count>`, `/status`, and
`/stats`.

The current XSA exposes session installation only through successful ML-KEM
decapsulation. `LEAVE` therefore removes PS authorization immediately but
does not physically zero the BRAM entry. A later `OPEN` on the same slot runs
ML-KEM again, overwrites all key material and resets both counters. A future
hardware revision should expose an authenticated invalidate/zeroize command
if immediate physical erasure on disconnect is required.

The deterministic KAT ciphertext is reused to make the demonstration
repeatable. Distinct session IDs are included in the transcript hash, so each
join still derives separated traffic keys. This is a validation/demo setup,
not a production key-exchange implementation.
