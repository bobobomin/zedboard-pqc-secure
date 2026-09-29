"""Verify kyber-py FIPS 203 byte compatibility before using unique Board B keys."""

from __future__ import annotations

import argparse
from pathlib import Path

EXPECTED_SHARED_SECRET = bytes.fromhex(
    "ee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector_dir", type=Path,
                        help="directory containing secret_key.bin and kem_ciphertext.bin")
    args = parser.parse_args()
    try:
        from kyber_py.ml_kem import ML_KEM_512
    except ImportError as exc:
        raise SystemExit("Install dependencies first: py -m pip install -r requirements.txt") from exc
    secret_key = (args.vector_dir / "secret_key.bin").read_bytes()
    ciphertext = (args.vector_dir / "kem_ciphertext.bin").read_bytes()
    recovered = ML_KEM_512.decaps(secret_key, ciphertext)
    if recovered != EXPECTED_SHARED_SECRET:
        print("FAIL: PC ML-KEM implementation is not byte-compatible with the board KAT")
        return 1
    print("PASS: kyber-py ML-KEM-512 matches the ZedBoard KAT shared secret")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
