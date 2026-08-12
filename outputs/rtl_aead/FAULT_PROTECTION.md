# Fault protection and attack regression

The preferred protected top is
`rtl/mlkem_secure_channel_fault_protected_axi_top.sv`. It retains the single
shared Keccak architecture and adds fail-closed control/data checks.

## Implemented checks

- Exact 14-command hash schedule check:
  `H, G, Noise x5, Matrix x4, J, Transcript, KDF`.
- Per-stage watchdog. A missing completion pulse terminates the handshake and
  prevents session installation.
- K-PKE operation counters: two forward NTTs, two BaseMul operations and one
  inverse NTT are required.
- Dual-rail ciphertext comparison. The sticky mismatch bit and its complement
  must remain mutually consistent throughout all 768 ciphertext bytes.
- Shared secret, transcript hash and 72-byte traffic-key material are stored as
  value/complement pairs and checked before the next security boundary.
- AEAD session installation is enabled only after every check succeeds.
- Request/response outstanding tracking suppresses an unexpected response
  `valid` pulse.
- Existing AEAD checks reject invalid tags, replayed/out-of-order counters,
  unconfigured slots and payload lengths above 64 bytes.

`fault_inject_i` is a verification/debug interface and must be tied to zero in
the production block design. Its bits inject a hash-command fault, bit faults
in the three protected intermediate values, a stalled hash completion, and a
spurious response-valid pulse.

## Verified attacks

`tb/tb_full_attack_fault_protection.sv` checks:

1. normal ML-KEM handshake and authenticated packet;
2. replayed counter;
3. invalid Poly1305 tag with zero plaintext release;
4. oversized payload;
5. one-bit ML-KEM ciphertext modification;
6. embedded public-key modification;
7. missing NTT operation;
8. ciphertext-comparison rail fault;
9. shared-hash command corruption;
10. shared-secret, transcript and traffic-key storage faults;
11. stalled hash completion;
12. spurious output-valid assertion.

Every attack is rejected, and no failed/faulted handshake installs a session.

## Scope

These checks target control-flow faults, single-bit storage faults and common
network attacks. They are not a substitute for physical side-channel
countermeasures such as masking, hiding, power balancing or electromagnetic
shielding. Multi-bit/common-mode faults require stronger redundancy if they
are included in the final threat model.
