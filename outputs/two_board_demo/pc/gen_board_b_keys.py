"""Generate the non-versioned board_b_keys.h file for physical Board B.

Run this only after ``verify_kat.py`` confirms kyber-py matches the existing
hardware's ML-KEM-512 KAT.  The generated secret-key header must never be
committed to Git or uploaded with exhibition material.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def c_array(name: str, value: bytes) -> str:
    rows = []
    for start in range(0, len(value), 12):
        rows.append("    " + ", ".join(f"0x{x:02x}" for x in value[start:start + 12]))
    return f"static const uint8_t {name}[{len(value)}] = {{\n" + ",\n".join(rows) + "\n};\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path, help="e.g. .../src/board_b_keys.h")
    args = parser.parse_args()
    try:
        from kyber_py.ml_kem import ML_KEM_512
    except ImportError as exc:
        raise SystemExit("Install dependencies first: py -m pip install -r requirements.txt") from exc
    public_key, secret_key = ML_KEM_512.keygen()
    if len(public_key) != 800 or len(secret_key) != 1632:
        raise SystemExit("Unexpected ML-KEM-512 key length")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "#ifndef BOARD_B_KEYS_H\n#define BOARD_B_KEYS_H\n\n#include <stdint.h>\n\n"
        + c_array("board_b_public_key", public_key)
        + "\n" + c_array("board_b_secret_key", secret_key)
        + "\n#endif\n",
        encoding="ascii",
    )
    print(f"Created {args.output}; keep this secret-key file out of Git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
