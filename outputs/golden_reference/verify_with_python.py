"""Independent verification of the C-generated SHA3/SHAKE/AEAD vectors."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


HERE = Path(__file__).resolve().parent
VECTOR_PATTERN = re.compile(r"^(\w+)\[(\d+)] = ([0-9a-f]+)$")


def load_vectors() -> dict[str, bytes]:
    vectors: dict[str, bytes] = {}
    for line in (HERE / "golden_vectors.txt").read_text(encoding="ascii").splitlines():
        match = VECTOR_PATTERN.match(line)
        if not match:
            continue
        name, length_text, hex_text = match.groups()
        value = bytes.fromhex(hex_text)
        assert len(value) == int(length_text), name
        vectors[name] = value
    return vectors


def main() -> None:
    vectors = load_vectors()

    assert hashlib.sha3_256(vectors["public_key"]).digest() == vectors[
        "fingerprint_sha3_256"
    ]

    session_id = vectors["aad"][:4]
    transcript = vectors["public_key"] + vectors["kem_ciphertext"] + session_id
    transcript_hash = hashlib.sha3_256(transcript).digest()
    assert transcript_hash == vectors["transcript_hash"]

    kdf_input = b"ZYNQ-PQC-v1" + vectors["shared_secret"] + transcript_hash
    assert hashlib.shake_256(kdf_input).digest(72) == vectors["kdf_output"]

    aead = ChaCha20Poly1305(vectors["pc_to_zb_key"])
    encrypted = aead.encrypt(
        vectors["nonce"], vectors["padded_plaintext"], vectors["aad"]
    )
    assert encrypted == vectors["ciphertext"] + vectors["tag"]
    assert (
        aead.decrypt(vectors["nonce"], encrypted, vectors["aad"])
        == vectors["padded_plaintext"]
    )

    tampered = bytearray(encrypted)
    tampered[0] ^= 1
    try:
        aead.decrypt(vectors["nonce"], bytes(tampered), vectors["aad"])
    except InvalidTag:
        pass
    else:
        raise AssertionError("tampered ciphertext was accepted")

    assert (HERE / "packet.bin").read_bytes() == vectors["packet"]
    print("PASS: Python SHA3-256 fingerprint matches C")
    print("PASS: Python SHAKE256 KDF matches C")
    print("PASS: Python ChaCha20-Poly1305 ciphertext and tag match C")
    print("PASS: Python rejects the one-bit ciphertext tampering")


if __name__ == "__main__":
    main()
