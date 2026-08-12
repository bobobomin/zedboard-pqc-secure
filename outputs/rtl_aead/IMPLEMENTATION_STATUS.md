# Implementation status

## Functionally complete and regression-tested

- ChaCha20-Poly1305 AEAD with authenticate-before-release decryption;
- four session slots, direction-separated keys/nonces/counters, replay checks
  and round-robin arbitration;
- SHA3-256/512 and SHAKE128/256;
- ML-KEM-512 codec, CBD sampling, matrix generation, noise generation,
  NTT, inverse NTT and BaseMul;
- complete K-PKE.Decrypt and deterministic K-PKE re-encryption;
- regenerated-ciphertext compression and constant-time 768-byte comparison;
- `G(m || H(ek))`, public-key hash check and `J(z || ciphertext)`;
- implicit-rejection selection of the final 32-byte shared secret;
- SHA3-256 transcript hash over `ek || ciphertext || session_id_be`;
- DMA-free AXI4-Lite loading of the 1,632-byte SK and 768-byte ciphertext;
- automatic session KDF and atomic installation into the selected AEAD slot.
- a single shared Keccak/SHA3/SHAKE engine for every sequential ML-KEM,
  transcript and traffic-KDF operation.

The full valid-vector Decaps test returns
`ee5f8f90...99dee4f`. A one-bit-modified ciphertext is rejected and returns
the independently calculated rejection secret. The AXI integration test loads
the complete SK and ciphertext, performs Decaps in PL, installs slot 0 and
then reproduces the golden ChaCha20-Poly1305 packet. The complete regression
suite passes in Vivado XSim.

## Stage status

- Stage 6, ML-KEM RTL: functionally complete and KAT-verified.
- Stage 7, PS-PL AXI-Lite connection: functionally complete and integration-
  verified without DMA. Separate ML-KEM and AEAD traffic slave ports connect
  to the same protected session table.
- Stage 8, Ethernet/lwIP: not started.
- Stage 9, fault protection: RTL implementation and attack/fault-injection
  regression complete; physical fault and side-channel validation requires
  the board/lab setup.

## ZedBoard shared-resource synthesis

`mlkem_secure_channel_shared_axi_top` replaces seven independent Keccak
datapaths with one command-driven engine. Vivado RTL synthesis completes with
zero synthesis logic errors. The final primitive summary is 34,338 LUTs,
25,220 flip-flops, 71 DSP48E1, six RAMB18E1 and four RAMB36E1. This is about
64.5% of the XC7Z020 LUT capacity, down 72.2% from the 123,731-LUT reference
top, so the shared version fits the device at synthesis level. Place-and-route
and timing closure remain to be performed in the final Vivado block design.

The final fault-protected top also fits: 38,194 primitive LUTs (71.8%), 26,615
flip-flops, 71 DSP48E1, six RAMB18E1 and four RAMB36E1. The protection overhead
is therefore about 3,856 LUTs over the unprotected shared top.

The final dual-AXI top synthesizes with zero synthesis logic errors: 42,456
primitive LUTs (79.8%), 28,971 flip-flops, 71 DSP48E1, six RAMB18E1 and four
RAMB36E1. Final routed timing remains a block-design task because the PS,
interconnect and clock constraints are not yet present.
