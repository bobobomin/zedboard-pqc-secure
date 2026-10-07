"""Drop-in real-board backend for the supplied Pygame demo.

Keep the supplied ``board_link.py`` unchanged: it continues to provide
``Session``, ``BoardWorker`` and the mock backend.  In ``demo_pr5.py`` this
class replaces only its old fixed-vector ``SerialBoardLink``.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from board_link import PACKET_BYTES, Session  # Existing demo data model.
from pqc_crypto import SessionKeys, derive_session, encaps, open_response, seal


class SerialBoardLink:
    RESPONSE_PREFIXES = (
        "HELLO ", "RESET ", "READY ", "RESP ", "ERR ", "BYE", "LEFT ", "STATUS ",
        "SWKEM ",
    )

    def __init__(self, name: str, port_name: str, baud: int, _unused_vector_dir: Path,
                 timeout: float = 3.0):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("Real mode needs pyserial; install requirements.txt") from exc
        self.name = name
        self._timeout = timeout
        self._serial = serial.Serial(port_name, baud, timeout=0.20)
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self._keys: dict[int, SessionKeys] = {}
        self._sessions: dict[int, Session] = {}
        self._public_key = b""
        self.hello()
        self.reset()

    def close(self) -> None:
        self._serial.close()

    def _read_protocol_line(self) -> str:
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            raw = self._serial.readline()
            if not raw:
                continue
            line = raw.decode("ascii", errors="replace").strip()
            if line.startswith(self.RESPONSE_PREFIXES):
                return line
        raise TimeoutError(f"Board {self.name} response timeout")

    def _send(self, text: str) -> str:
        self._serial.write((text + "\n").encode("ascii"))
        self._serial.flush()
        return self._read_protocol_line()

    @staticmethod
    def _reject_error(line: str) -> None:
        if line.startswith("ERR "):
            raise RuntimeError(line)

    def hello(self) -> bytes:
        fields = self._send("HELLO").split()
        if len(fields) != 3 or fields[0] != "HELLO" or fields[1] != self.name:
            raise RuntimeError(f"Wrong board or malformed HELLO: {' '.join(fields)}")
        self._public_key = bytes.fromhex(fields[2])
        if len(self._public_key) != 800:
            raise RuntimeError("Board returned a malformed ML-KEM-512 public key")
        return self._public_key

    def reset(self) -> None:
        line = self._send("RESET")
        if line != "RESET OK":
            self._reject_error(line)
            raise RuntimeError(f"Malformed RESET: {line}")
        self._keys.clear()
        self._sessions.clear()

    def status(self) -> tuple[int, int]:
        fields = self._send("STATUS").split()
        if len(fields) != 4 or fields[0] != "STATUS":
            raise RuntimeError(f"Malformed STATUS: {' '.join(fields)}")
        return int(fields[1]), (int(fields[2], 16) << 32) | int(fields[3], 16)

    def sw_kem(self) -> Optional[tuple[int, bool]]:
        """Time one software ML-KEM-512 decaps on the board's Cortex-A9.

        Reply format: ``SWKEM <us> <1|0>`` (1 = shared secret matched the KAT).
        Returns None when the firmware does not implement the command.
        """
        try:
            line = self._send("SWKEM")
        except TimeoutError:
            return None
        fields = line.split()
        if len(fields) == 3 and fields[0] == "SWKEM":
            return int(fields[1]), fields[2] == "1"
        return None

    def open_session(self, vehicle_id: int, slot: int) -> Session:
        if slot in self._sessions:
            raise RuntimeError(f"slot {slot} is already open")
        shared_secret, kem_ciphertext = encaps(self._public_key)
        line = self._send(f"OPEN {slot} {vehicle_id} {kem_ciphertext.hex()}")
        self._reject_error(line)
        fields = line.split()
        if (len(fields) != 5 or fields[0] != "READY" or int(fields[1]) != slot
                or int(fields[4]) != vehicle_id):
            raise RuntimeError(f"Malformed READY: {line}")
        sid, kem_us = int(fields[2], 16), int(fields[3])
        session = Session(vehicle_id=vehicle_id, slot=slot, sid=sid, kem_us=kem_us)
        self._sessions[slot] = session
        self._keys[slot] = derive_session(self._public_key, kem_ciphertext,
                                          shared_secret, sid)
        return session

    def leave_session(self, slot: int) -> Session:
        old = self._sessions.get(slot)
        if old is None:
            raise RuntimeError(f"no local session for slot {slot}")
        line = self._send(f"LEAVE {slot}")
        self._reject_error(line)
        fields = line.split()
        if (len(fields) != 3 or fields[0] != "LEFT" or int(fields[1]) != slot
                or int(fields[2], 16) != old.sid):
            raise RuntimeError(f"Malformed LEFT: {line}")
        del self._sessions[slot]
        del self._keys[slot]
        return old

    def send_data(self, slot: int, payload: bytes, tamper: bool = False) -> dict:
        if len(payload) > PACKET_BYTES:
            raise ValueError("payload exceeds 64 bytes")
        keys = self._keys.get(slot)
        if keys is None:
            raise RuntimeError(f"no local session for slot {slot}")
        length, ciphertext, tag = seal(keys, payload)
        if tamper:
            corrupt = bytearray(ciphertext)
            corrupt[0] ^= 0x01
            ciphertext = bytes(corrupt)
        started = time.perf_counter()
        line = self._send(
            f"DATA {slot} {keys.tx_counter:016x} {length} "
            f"{ciphertext.hex()} {tag.hex()}"
        )
        rtt_ms = (time.perf_counter() - started) * 1000.0
        if tamper:
            fields = line.split()
            blocked = len(fields) == 4 and fields[:2] == ["ERR", "AUTH"]
            return {
                "ok": False, "blocked": blocked, "detail": line,
                "rx_us": int(fields[3]) if blocked else 0, "tx_us": 0,
                "rtt_ms": rtt_ms,
            }
        self._reject_error(line)
        fields = line.split()
        if len(fields) != 8 or fields[0] != "RESP" or int(fields[1]) != slot:
            raise RuntimeError(f"Malformed RESP: {line}")
        response_counter = int(fields[2], 16)
        if response_counter != keys.rx_counter:
            raise RuntimeError("Board response counter mismatch")
        response = open_response(keys, response_counter, int(fields[3]),
                                 bytes.fromhex(fields[6]), bytes.fromhex(fields[7]))
        if response != payload:
            raise RuntimeError("authenticated echo plaintext mismatch")
        keys.tx_counter += 1
        keys.rx_counter += 1
        return {
            "ok": True, "blocked": False, "detail": "secure echo verified",
            "rx_us": int(fields[4]), "tx_us": int(fields[5]), "rtt_ms": rtt_ms,
        }
