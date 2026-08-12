# ML-KEM integration

The PC performs ML-KEM-512 Encaps. The Zynq PS receives the ciphertext and
selects a session slot, while the PL performs the complete Decaps and AEAD
session installation.

```text
PC Encaps
  -> ciphertext
  -> PS writes SK/CT/slot/session ID through AXI-Lite
  -> PL K-PKE.Decrypt
  -> G(m || H(ek))
  -> deterministic K-PKE re-encryption
  -> compare all 768 ciphertext bytes
  -> J(z || ciphertext)
  -> candidate/rejection secret selection
  -> SHA3-256(ek || ciphertext || session_id_be)
  -> session SHAKE256 KDF
  -> selected four-session AEAD slot
```

`mlkem512_decaps_shared_engine.sv` implements the preferred full Decaps
sequence, and `mlkem_secure_channel_shared_axi_top.sv` connects it to the
AXI-Lite loader and AEAD session table. One `mlkem_shared_hash_engine.sv` is
time-shared by Decaps, transcript hashing and the session KDF. No intermediate
polynomial or ML-KEM shared secret is sent back through the PS.

The invalid-ciphertext path executes decryption, re-encryption, comparison and
rejection hashing before selecting the result. It does not expose a candidate
secret on authentication failure, and a failed Decaps does not install an
AEAD session.

The earlier non-shared modules remain as regression references. The preferred
shared top passes the same KATs and reduces synthesized LUTs by 72.2%; see
`SYNTHESIS_NOTES.md`.
