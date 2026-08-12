# Boardless completion record

## Completed on 2026-08-11

- Rebuilt the deterministic ML-KEM-512 and ChaCha20-Poly1305 C vectors.
- Independently verified the C output with Python SHA3, SHAKE and AEAD.
- Ran the complete Vivado XSim regression suite.
- Verified the protected Decaps path against valid and modified KAT inputs.
- Verified replay, bad-tag, oversized-payload and unconfigured-session rejection.
- Verified hash-sequence, NTT-count, compare-rail, protected-storage, watchdog
  and spurious-valid fault injection.
- Added a second AXI-Lite frontend for PS-visible AEAD packet traffic.
- Added `mlkem_secure_channel_complete_axi_top`, joining both AXI ports to one
  protected ML-KEM/AEAD session table.
- Verified AXI ML-KEM load -> Decaps -> atomic session installation -> AXI
  encryption/decryption -> replay rejection in one self-checking testbench.
- Compiled all PS driver sources as C99 with `-Wall -Wextra -Werror`.
- Synthesized the final top for `xc7z020clg484-1` with zero synthesis logic
  errors. The local Vivado installation reports a temporary-directory cleanup
  error after synthesis, so the cell summary is preserved in
  `SYNTHESIS_NOTES.md` and the Vivado log.

## Board-facing top

Use `rtl/mlkem_secure_channel_complete_axi_top.sv`.

- ML-KEM AXI-Lite port: secret-key/ciphertext load and handshake control.
- AEAD AXI-Lite port: fixed 64-byte traffic encryption/decryption.
- `fault_inject_i`: tie permanently to zero in the production block design.

## Work that genuinely requires the board/project

1. Create the Zynq PS block design and assign the two AXI address ranges.
2. Add a 100 MHz clock constraint, place, route and close timing with the real
   AXI interconnect and PS configuration.
3. Generate the bitstream/XSA and run the Vitis bare-metal driver on ZedBoard.
4. Integrate lwIP Ethernet and test PC-to-board packets.
5. Measure latency, throughput, power and physical fault/side-channel leakage.

No RTL functional stage, software golden-vector stage or simulation-only fault
test remains unfinished.
