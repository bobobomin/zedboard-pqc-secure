"""Real UART link for the two-board exhibition protocol.

This intentionally uses PC-assigned slots.  There is a single PC producer in
the exhibit, so reserving the lowest free slot locally avoids an allocation
race and keeps the firmware simple.  Each physical board owns slots 0..63.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from pqc_crypto import (
    CIPHERTEXT_BYTES,
    PACKET_BYTES,
    PUBLIC_KEY_BYTES,
    SessionKeys,
    derive_session,
    encaps,
    open_response,
    seal,
)


class BoardError(RuntimeError):
    pass


@dataclass
class OpenSession:
    vehicle_id: int
    slot: int
    kem_us: int
    keys: SessionKeys


class TwoBoardSerialLink:
    """One synchronous UART connection.  Put this behind the existing worker."""

    prefixes = ("HELLO ", "RESET ", "READY ", "LEFT ", "RESP ", "STATUS ", "ERR ", "BYE")

    def __init__(self, expected_name: str, port_name: str, baud: int = 115200,
                 timeout: float = 3.0):
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("Install pyserial: py -m pip install -r requirements.txt") from exc
        self.name = expected_name
        self._timeout = timeout
        self._serial = serial.Serial(port_name, baud, timeout=0.20)
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self.public_key = b""
        self.sessions: dict[int, OpenSession] = {}
        self.hello()

    def close(self) -> None:
        self._serial.close()

    def _read(self) -> str:
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            raw = self._serial.readline()
            if not raw:
                continue
            line = raw.decode("ascii", errors="replace").strip()
            if line.startswith(self.prefixes):
                return line
        raise TimeoutError(f"Board {self.name} response timeout")

    def _send(self, command: str) -> str:
        self._serial.write((command + "\n").encode("ascii"))
        self._serial.flush()
        return self._read()

    @staticmethod
    def _err(line: str) -> None:
        if line.startswith("ERR "):
            raise BoardError(line)

    def hello(self) -> bytes:
        fields = self._send("HELLO").split()
        if len(fields) != 3 or fields[0] != "HELLO" or fields[1] != self.name:
            raise BoardError("Malformed HELLO or wrong UART port")
        self.public_key = bytes.fromhex(fields[2])
        if len(self.public_key) != PUBLIC_KEY_BYTES:
            raise BoardError("Board returned malformed ML-KEM public key")
        return self.public_key

    def reset(self) -> None:
        line = self._send("RESET")
        if line != "RESET OK":
            self._err(line)
            raise BoardError(f"Malformed RESET response: {line}")
        self.sessions.clear()

    def status(self) -> tuple[int, int]:
        fields = self._send("STATUS").split()
        if len(fields) != 4 or fields[0] != "STATUS":
            raise BoardError("Malformed STATUS")
        return int(fields[1]), (int(fields[2], 16) << 32) | int(fields[3], 16)

    def open_session(self, vehicle_id: int, slot: int) -> OpenSession:
        if not 0 <= slot < 64 or not 0 <= vehicle_id < 64:
            raise ValueError("vehicle and slot must be 0..63")
        if slot in self.sessions:
            raise BoardError(f"Local slot {slot} is already in use")
        shared_secret, kem_ciphertext = encaps(self.public_key)
        assert len(kem_ciphertext) == CIPHERTEXT_BYTES
        line = self._send(f"OPEN {slot} {vehicle_id} {kem_ciphertext.hex()}")
        self._err(line)
        fields = line.split()
        if (len(fields) != 5 or fields[0] != "READY" or int(fields[1]) != slot
                or int(fields[4]) != vehicle_id):
            raise BoardError(f"Malformed READY: {line}")
        keys = derive_session(self.public_key, kem_ciphertext, shared_secret,
                              int(fields[2], 16))
        session = OpenSession(vehicle_id, slot, int(fields[3]), keys)
        self.sessions[slot] = session
        return session

    def leave_session(self, slot: int) -> None:
        old = self.sessions.get(slot)
        if old is None:
            raise BoardError(f"No local session at slot {slot}")
        line = self._send(f"LEAVE {slot}")
        self._err(line)
        fields = line.split()
        if (len(fields) != 3 or fields[0] != "LEFT" or int(fields[1]) != slot
                or int(fields[2], 16) != old.keys.sid):
            raise BoardError(f"Malformed LEFT: {line}")
        del self.sessions[slot]

    def data(self, slot: int, plaintext: bytes, tamper: bool = False) -> tuple[int, int, int]:
        """Run one PC→board→PC echo. Returns ``(rx_us, tx_us, rtt_us)``."""
        session = self.sessions.get(slot)
        if session is None:
            raise BoardError(f"No local session at slot {slot}")
        length, ciphertext, tag = seal(session.keys, plaintext)
        if tamper:
            altered = bytearray(ciphertext)
            altered[0] ^= 0x01
            ciphertext = bytes(altered)
        started = time.perf_counter_ns()
        line = self._send(
            f"DATA {slot} {session.keys.tx_counter:016x} {length} "
            f"{ciphertext.hex()} {tag.hex()}"
        )
        rtt_us = (time.perf_counter_ns() - started) // 1000
        if tamper:
            fields = line.split()
            if len(fields) == 4 and fields[:2] == ["ERR", "AUTH"]:
                return int(fields[3]), 0, int(rtt_us)
            raise BoardError(f"Tampered packet was not rejected: {line}")
        self._err(line)
        fields = line.split()
        if len(fields) != 8 or fields[0] != "RESP" or int(fields[1]) != slot:
            raise BoardError(f"Malformed RESP: {line}")
        response_counter = int(fields[2], 16)
        if response_counter != session.keys.rx_counter:
            raise BoardError("Unexpected board response counter")
        response = open_response(session.keys, response_counter, int(fields[3]),
                                 bytes.fromhex(fields[6]), bytes.fromhex(fields[7]))
        if response != plaintext:
            raise BoardError("Authenticated echo plaintext mismatch")
        session.keys.tx_counter += 1
        session.keys.rx_counter += 1
        return int(fields[4]), int(fields[5]), int(rtt_us)
