# XC7Z020 synthesis checkpoint

Vivado 2020.2 successfully elaborated and synthesized the encryption wrapper
and its ChaCha20/Poly1305 cores for `xc7z020clg484-1` with no RTL synthesis
warnings. The tool reported the following cell counts before a local Vivado
temporary-directory cleanup issue stopped report-file generation:

```text
DSP48E1     4
FDCE        5000
LUT1..LUT6  4360 total primitive LUT cells
CARRY4      660
```

These figures are an early out-of-context estimate. The top currently exposes
995 input and 642 output bits directly, so final utilization and timing must be
measured after replacing the wide test ports with the project AXI/BRAM wrapper
and adding clock constraints.

The important architectural result is that the serialized radix-2^26
Poly1305 datapath reduced inferred DSP48E1 use from 64 in the initial direct
wide-multiply baseline to 4 while preserving the C golden tag.

The four-session arbiter plus shared AEAD engine was also synthesized through
Vivado RTL synthesis. The pre-report cell summary showed 4 DSP48E1, 12,441
flip-flops, and 11,207 primitive LUT cells. These numbers include very large
multiplexers and 3,474 input/2,833 output buffers caused by the deliberately
wide simulation top. They are not the expected AXI-integrated result.

The Poly1305 "unconnected input bits" warnings correspond to bits removed by
the standard `r` clamp mask. Constant-output warnings come from reserved AAD
bytes and fixed packet lengths; neither indicates a functional mismatch.

The AXI4-Lite top including the SHAKE256 session KDF was synthesized for
`xc7z020clg484-1`. Vivado's pre-report cell summary reported 4 DSP48E1,
32,470 primitive LUT cells, and 24,680 flip-flops. This is substantially larger
than the AEAD-only baseline because one full Keccak round is evaluated per
cycle, but remains inside the XC7Z020 raw LUT/FF capacity.
Only 63 input and 41 output buffers remained at the AXI top, confirming that
the earlier thousands of I/O buffers were caused by the simulation-only wide
ports. The result has no timing constraint yet and the session table is still
implemented in registers, so these are integration-baseline figures rather
than final place-and-route utilization.

In this local Vivado 2020.2 installation, synthesis reports completion and the
cell summary before a tool-side `.Xil/realtime/tmp` cleanup error terminates the
batch command. RTL synthesis itself reports zero errors and zero critical
warnings; final reports should be regenerated inside the normal Vivado project.

The first polynomial-kernel memory style dissolved the three coefficient banks
into registers and exceeded the board LUT budget. The corrected design uses
explicit true dual-port synchronous memories. Vivado recognizes three 256x16
RAM templates and reports this compact standalone ML-KEM kernel summary:

```text
RAMB18E1       3
DSP48E1       26
LUT1..LUT6   754 total primitive LUT cells
flip-flops    184
```

The additional read/write phase doubles butterfly latency but makes the NTT,
inverse NTT and BaseMul accelerator practical on the ZedBoard.

## Full ML-KEM Decaps plus AEAD top

`mlkem_secure_channel_axi_top` passes functional simulation and Vivado RTL
synthesis reports zero synthesis logic errors. Its current functional form is
too large for XC7Z020 because every sequential hash user owns a separate
Keccak datapath:

```text
DSP48E1                 71 / 220
RAMB18E1                 6
RAMB36E1                 4
flip-flops          ~64,036 / 106,400
primitive LUT cells 123,731 / 53,200
```

The seven Keccak instances account for most of the LUT total. Matrix sampling,
noise sampling, Hash-G, Hash-J, public-key validation, transcript hashing and
the traffic KDF never need to run concurrently. The board implementation must
therefore replace them with one `sha3_shake_stream` instance plus a command and
byte-source multiplexer. The two polynomial accelerators can also be shared,
but they are small compared with Keccak and are a secondary optimization.

The thousands of I/O buffers in the standalone top report come from exposing
the flattened four-session request buses as top-level pins. In the Vivado block
design those signals are internal to the Ethernet/packet path and must be
synthesized out-of-context or behind AXI/BRAM interfaces.

## Shared-Keccak optimized top

`mlkem_secure_channel_shared_axi_top` uses one `sha3_shake_stream` for public-
key hashing, Hash-G, Hash-J, matrix sampling, noise sampling, transcript hashing
and the traffic KDF. Valid/tampered Decaps KATs and the complete AXI-to-AEAD
integration test pass. Vivado 2020.2 synthesis reports:

```text
DSP48E1                 71 / 220
RAMB18E1                 6
RAMB36E1                 4
flip-flops          25,220 / 106,400
primitive LUT cells 34,338 / 53,200
```

The LUT reduction is 72.2% versus the seven-Keccak top. The shared design is
inside the XC7Z020 synthesis resource budget. The local Vivado temporary-file
cleanup fault still prevents the scripted report/checkpoint write after a
successful synthesis, so final timing and routed utilization must be generated
inside the board project.

## Fault-protected shared top

After adding hash/NTT operation counters, value/complement storage checks,
dual-rail ciphertext comparison, a watchdog and response-valid tracking,
`mlkem_secure_channel_fault_protected_axi_top` synthesizes to:

```text
DSP48E1                 71 / 220
RAMB18E1                 6
RAMB36E1                 4
flip-flops          26,615 / 106,400
primitive LUT cells 38,194 / 53,200
```

This is about 71.8% of the XC7Z020 LUT capacity and remains within the device
budget. Synthesis completed with zero logic errors; the same local Vivado
temporary-directory cleanup problem prevented the post-synthesis report file.

## Complete dual-AXI production top

`mlkem_secure_channel_complete_axi_top` adds a PS-facing AEAD packet port while
retaining protected ML-KEM Decaps and its internally installed session table.
Vivado synthesis completed with zero synthesis logic errors and reported:

```text
DSP48E1                 71 / 220
RAMB18E1                 6
RAMB36E1                 4
flip-flops          28,971 / 106,400
primitive LUT cells 42,456 / 53,200
```

The design remains inside the raw XC7Z020 budget at about 79.8% LUT use. Final
block-design placement and timing closure must be checked before adding more
optional PL features.
