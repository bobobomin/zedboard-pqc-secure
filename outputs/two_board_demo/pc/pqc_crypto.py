"""PC-side ML-KEM and ChaCha20-Poly1305 helpers for the two-board demo.

The wire-format constants mirror the existing ZedBoard secure-channel IP.
Nothing secret is written to the UART; the PC sends only an ML-KEM ciphertext
and authenticated traffic packets.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PACKET_BYTES = 64
PUBLIC_KEY_BYTES = 800
CIPHERTEXT_BYTES = 768
SHARED_SECRET_BYTES = 32
KDF_DOMAIN = b"ZYNQ-PQC-v1"


@dataclass
class SessionKeys:
    """Direction is always relative to the PC (vehicle) side."""

    sid: int
    pc_to_board_key: bytes
    pc_to_board_prefix: bytes
    board_to_pc_key: bytes
    board_to_pc_prefix: bytes
    tx_counter: int = 0
    rx_counter: int = 0


def encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(shared_secret, ciphertext)`` using FIPS 203 ML-KEM-512."""

    if len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError(f"ML-KEM-512 public key must be {PUBLIC_KEY_BYTES} bytes")
    try:
        from kyber_py.ml_kem import ML_KEM_512
    except ImportError as exc:
        raise RuntimeError("Install PC dependencies: py -m pip install -r requirements.txt") from exc
    shared_secret, ciphertext = ML_KEM_512.encaps(public_key)
    if len(shared_secret) != SHARED_SECRET_BYTES or len(ciphertext) != CIPHERTEXT_BYTES:
        raise RuntimeError("Unexpected ML-KEM-512 result size")
    return shared_secret, ciphertext


def derive_session(public_key: bytes, kem_ciphertext: bytes, shared_secret: bytes,
                   sid: int) -> SessionKeys:
    """Derive the exact 72 bytes consumed by the PL KDF implementation."""

    if not (0 <= sid <= 0xFFFFFFFF):
        raise ValueError("sid must be uint32")
    if len(public_key) != PUBLIC_KEY_BYTES or len(kem_ciphertext) != CIPHERTEXT_BYTES:
        raise ValueError("Invalid ML-KEM public key or ciphertext length")
    if len(shared_secret) != SHARED_SECRET_BYTES:
        raise ValueError("ML-KEM-512 shared secret must be 32 bytes")
    transcript = hashlib.sha3_256(
        public_key + kem_ciphertext + sid.to_bytes(4, "big")
    ).digest()
    material = hashlib.shake_256(KDF_DOMAIN + shared_secret + transcript).digest(72)
    return SessionKeys(
        sid=sid,
        pc_to_board_key=material[:32],
        pc_to_board_prefix=material[32:36],
        board_to_pc_key=material[36:68],
        board_to_pc_prefix=material[68:72],
    )


def _nonce(prefix: bytes, counter: int) -> bytes:
    if len(prefix) != 4 or not (0 <= counter <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("Invalid nonce prefix/counter")
    return prefix + counter.to_bytes(8, "big")


def _aad(sid: int, counter: int, length: int) -> bytes:
    return sid.to_bytes(4, "big") + counter.to_bytes(8, "big") + bytes((length, 0, 0, 0))


def seal(keys: SessionKeys, plaintext: bytes) -> tuple[int, bytes, bytes]:
    """Encrypt one PC→board 64-byte-wire packet without advancing counters."""

    if len(plaintext) > PACKET_BYTES:
        raise ValueError("Demo payload may be at most 64 bytes")
    length = len(plaintext)
    padded = plaintext + bytes(PACKET_BYTES - length)
    frame = ChaCha20Poly1305(keys.pc_to_board_key).encrypt(
        _nonce(keys.pc_to_board_prefix, keys.tx_counter), padded,
        _aad(keys.sid, keys.tx_counter, length),
    )
    return length, frame[:-16], frame[-16:]


def open_response(keys: SessionKeys, counter: int, length: int,
                  ciphertext: bytes, tag: bytes) -> bytes:
    """Verify/decrypt a board→PC response; counter increment is caller-owned."""

    if not (0 <= length <= PACKET_BYTES):
        raise ValueError("Invalid response length")
    if len(ciphertext) != PACKET_BYTES or len(tag) != 16:
        raise ValueError("Invalid response ciphertext/tag length")
    plain = ChaCha20Poly1305(keys.board_to_pc_key).decrypt(
        _nonce(keys.board_to_pc_prefix, counter), ciphertext + tag,
        _aad(keys.sid, counter, length),
    )
    return plain[:length]
