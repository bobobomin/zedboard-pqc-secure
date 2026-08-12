# ZedBoard PQC golden reference

This program generates deterministic RTL test vectors for the project protocol:

1. ML-KEM-512 key generation, encapsulation, and decapsulation.
2. SHA3-256 public-key fingerprint.
3. SHAKE256 session-key derivation.
4. A fixed 96-byte ChaCha20-Poly1305 application packet.
5. Successful decrypt/verify and one-bit tamper rejection.

The application packet is:

```text
AAD/header 16 bytes
  session_id       4 bytes, big-endian
  packet_counter   8 bytes, big-endian
  data_len         1 byte
  reserved         3 bytes, all zero
ciphertext         64 bytes
Poly1305 tag       16 bytes
```

The plaintext area is always 64 bytes. The first `data_len` bytes contain the
message and the remainder is zero padding. The entire 64-byte area is encrypted.

## Dependencies

- `mlkem-native`, pinned to commit
  `c4f993c3f1d20b77a7c3f0144c7ffaadc9943b0d`.
- Monocypher, pinned to commit
  `1830c06d5910fba451cec329c8f30f348fc607db`.
- A C99 compiler. The included Windows build script uses a local Zig compiler.

The pinned cryptographic C sources and their licenses are included under
`third_party`. The build script uses the Zig C compiler prepared under the
workspace's `work/toolchain` directory.

## Build and run

From PowerShell:

```powershell
.\build_and_run.ps1
```

If PowerShell script execution is disabled, use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build_and_run.ps1
```

The result can be independently checked with the bundled Python runtime:

```powershell
python verify_with_python.py
```

The executable writes the following files in this directory:

- `golden_vectors.txt`: all intermediate values in hexadecimal.
- `public_key.bin`: 800-byte ML-KEM-512 public key.
- `secret_key.bin`: 1632-byte ML-KEM-512 secret key.
- `kem_ciphertext.bin`: 768-byte ML-KEM-512 ciphertext.
- `packet.bin`: final 96-byte encrypted application packet.

The ML-KEM randomness is deterministic only to make simulations reproducible.
Do not reuse this deterministic setup in a real deployment.
