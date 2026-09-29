"""Board backends and asynchronous workers for the handover demo.

The public API deliberately hides whether a command is handled by a mock board
or by a ZedBoard connected over UART.  Pygame therefore never waits for serial
I/O on its render thread.
"""

from __future__ import annotations

import hashlib
import queue
import random
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

PACKET_BYTES = 64
MAX_SESSIONS = 64
KDF_DOMAIN = b"ZYNQ-PQC-v1"
SHARED_SECRET = bytes.fromhex(
    "ee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f"
)


@dataclass
class Session:
    vehicle_id: int
    slot: int
    sid: int
    kem_us: int
    tx_key: bytes = b""
    tx_prefix: bytes = b""
    rx_key: bytes = b""
    rx_prefix: bytes = b""
    tx_counter: int = 0
    rx_counter: int = 0


@dataclass
class BoardStats:
    name: str
    connected: bool = True
    slots: list[Optional[int]] = field(
        default_factory=lambda: [None] * MAX_SESSIONS
    )
    last_kem_us: int = 0
    kem_total_us: int = 0
    kem_samples: int = 0
    kem_min_us: int = 0
    kem_max_us: int = 0
    sw_supported: Optional[bool] = None   # None = not probed yet
    sw_total_us: int = 0
    sw_samples: int = 0
    last_sw_us: int = 0
    sw_mismatch: int = 0
    opens: int = 0
    leaves: int = 0
    data_ok: int = 0
    data_fail: int = 0
    attacks_blocked: int = 0
    last_rx_us: int = 0
    last_tx_us: int = 0
    last_rtt_ms: float = 0.0
    error: str = ""

    @property
    def active_count(self) -> int:
        return sum(vehicle is not None for vehicle in self.slots)

    @property
    def average_kem_us(self) -> float:
        return self.kem_total_us / self.kem_samples if self.kem_samples else 0.0

    @property
    def average_sw_us(self) -> float:
        return self.sw_total_us / self.sw_samples if self.sw_samples else 0.0

    def record_sw(self, sw_us: int, match: bool) -> None:
        self.last_sw_us = sw_us
        self.sw_total_us += sw_us
        self.sw_samples += 1
        if not match:
            self.sw_mismatch += 1

    def record_kem(self, kem_us: int) -> None:
        self.last_kem_us = kem_us
        self.kem_total_us += kem_us
        self.kem_samples += 1
        self.kem_min_us = kem_us if self.kem_samples == 1 else min(self.kem_min_us, kem_us)
        self.kem_max_us = max(self.kem_max_us, kem_us)


@dataclass(frozen=True)
class BoardCommand:
    command_id: int
    kind: str
    vehicle_id: int
    slot: Optional[int] = None
    payload: bytes = b""
    tamper: bool = False


@dataclass
class BoardResult:
    command_id: int
    board: str
    kind: str
    vehicle_id: int
    ok: bool
    slot: Optional[int] = None
    session: Optional[Session] = None
    detail: str = ""
    blocked: bool = False
    rx_us: int = 0
    tx_us: int = 0
    rtt_ms: float = 0.0
    sw_us: int = 0


class MockBoardLink:
    """Small behavioural model of the existing A-protocol firmware."""

    def __init__(self, name: str, seed: int = 0):
        self.name = name
        self._rng = random.Random(seed)
        self._sessions: dict[int, Session] = {}
        self._generation = [0] * MAX_SESSIONS

    def close(self) -> None:
        return

    def open_session(self, vehicle_id: int, slot: int) -> Session:
        if slot not in range(MAX_SESSIONS):
            raise ValueError("slot must be 0..63")
        time.sleep(self._rng.uniform(0.035, 0.095))
        generation = self._generation[slot]
        sid = 0x60000000 | ((generation & 0x003FFFFF) << 6) | slot
        self._generation[slot] += 1
        session = Session(
            vehicle_id=vehicle_id,
            slot=slot,
            sid=sid,
            kem_us=self._rng.randint(530, 578),
        )
        self._sessions[slot] = session
        return session

    def sw_kem(self) -> Optional[tuple[int, bool]]:
        """Model of the SWKEM command: one PS software ML-KEM decaps."""
        time.sleep(self._rng.uniform(0.012, 0.020))
        return self._rng.randint(1238, 1279), True

    def leave_session(self, slot: int) -> Session:
        if slot not in self._sessions:
            raise RuntimeError(f"ERR NOSESSION {slot}")
        time.sleep(self._rng.uniform(0.008, 0.025))
        return self._sessions.pop(slot)

    def send_data(self, slot: int, payload: bytes, tamper: bool = False) -> dict:
        if slot not in self._sessions:
            raise RuntimeError(f"ERR NOSESSION {slot}")
        if len(payload) > PACKET_BYTES:
            raise ValueError("payload exceeds 64 bytes")
        time.sleep(self._rng.uniform(0.012, 0.035))
        if tamper:
            return {
                "ok": False,
                "blocked": True,
                "detail": "ERR AUTH",
                "rx_us": self._rng.randint(8, 20),
                "tx_us": 0,
                "rtt_ms": self._rng.uniform(13.0, 25.0),
            }
        session = self._sessions[slot]
        session.tx_counter += 1
        session.rx_counter += 1
        return {
            "ok": True,
            "blocked": False,
            "detail": "secure echo verified",
            "rx_us": self._rng.randint(8, 20),
            "tx_us": self._rng.randint(8, 20),
            "rtt_ms": self._rng.uniform(13.0, 25.0),
        }


class SerialBoardLink:
    """Adapter for the existing ``OPEN <slot>`` UART demo protocol."""

    RESPONSE_PREFIXES = ("READY ", "RESP ", "ERR ", "BYE", "LEFT ", "STATUS ")

    def __init__(
        self,
        name: str,
        port_name: str,
        baud: int,
        vector_dir: Path,
        timeout: float = 60.0,
    ):
        try:
            import serial
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except ImportError as exc:
            raise RuntimeError(
                "Real mode needs pyserial and cryptography. "
                "Run: pip install -r requirements.txt"
            ) from exc

        self.name = name
        self._aead_class = ChaCha20Poly1305
        self._timeout = timeout
        self._serial = serial.Serial(port_name, baud, timeout=0.25)
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()
        self._sessions: dict[int, Session] = {}
        self._public_key = (vector_dir / "public_key.bin").read_bytes()
        self._kem_ciphertext = (vector_dir / "kem_ciphertext.bin").read_bytes()
        if len(self._public_key) != 800 or len(self._kem_ciphertext) != 768:
            raise ValueError("expected ML-KEM-512 public_key.bin and kem_ciphertext.bin")
        self.status()

    def close(self) -> None:
        self._serial.close()

    @staticmethod
    def _nonce(prefix: bytes, counter: int) -> bytes:
        return prefix + counter.to_bytes(8, "big")

    @staticmethod
    def _aad(sid: int, counter: int, length: int) -> bytes:
        return (
            sid.to_bytes(4, "big")
            + counter.to_bytes(8, "big")
            + bytes((length, 0, 0, 0))
        )

    def _derive(self, vehicle_id: int, slot: int, sid: int, kem_us: int) -> Session:
        transcript = hashlib.sha3_256(
            self._public_key + self._kem_ciphertext + sid.to_bytes(4, "big")
        ).digest()
        material = hashlib.shake_256(
            KDF_DOMAIN + SHARED_SECRET + transcript
        ).digest(72)
        return Session(
            vehicle_id=vehicle_id,
            slot=slot,
            sid=sid,
            kem_us=kem_us,
            tx_key=material[0:32],
            tx_prefix=material[32:36],
            rx_key=material[36:68],
            rx_prefix=material[68:72],
        )

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

    def status(self) -> tuple[int, int]:
        line = self._send("STATUS")
        fields = line.split()
        if len(fields) != 4 or fields[0] != "STATUS":
            raise RuntimeError(line)
        return int(fields[1]), (int(fields[2], 16) << 32) | int(fields[3], 16)

    def open_session(self, vehicle_id: int, slot: int) -> Session:
        line = self._send(f"OPEN {slot}")
        if line.startswith("ERR "):
            raise RuntimeError(line)
        fields = line.split()
        if len(fields) != 4 or fields[0] != "READY" or int(fields[1]) != slot:
            raise RuntimeError(f"malformed READY: {line}")
        session = self._derive(vehicle_id, slot, int(fields[2], 16), int(fields[3]))
        self._sessions[slot] = session
        return session

    def leave_session(self, slot: int) -> Session:
        old = self._sessions.get(slot)
        if old is None:
            raise RuntimeError(f"no local session for slot {slot}")
        line = self._send(f"LEAVE {slot}")
        fields = line.split()
        if (
            len(fields) != 3
            or fields[0] != "LEFT"
            or int(fields[1]) != slot
            or int(fields[2], 16) != old.sid
        ):
            raise RuntimeError(line)
        del self._sessions[slot]
        return old

    def send_data(self, slot: int, payload: bytes, tamper: bool = False) -> dict:
        if len(payload) > PACKET_BYTES:
            raise ValueError("payload exceeds 64 bytes")
        session = self._sessions.get(slot)
        if session is None:
            raise RuntimeError(f"no local session for slot {slot}")

        padded = payload + bytes(PACKET_BYTES - len(payload))
        request = self._aead_class(session.tx_key).encrypt(
            self._nonce(session.tx_prefix, session.tx_counter),
            padded,
            self._aad(session.sid, session.tx_counter, len(payload)),
        )
        ciphertext, tag = bytearray(request[:-16]), request[-16:]
        if tamper:
            ciphertext[0] ^= 0x01
        command = (
            f"DATA {slot} {session.tx_counter:016x} {len(payload)} "
            f"{bytes(ciphertext).hex()} {tag.hex()}"
        )
        started = time.perf_counter()
        line = self._send(command)
        rtt_ms = (time.perf_counter() - started) * 1000.0

        if tamper:
            fields = line.split()
            blocked = len(fields) >= 2 and fields[0:2] == ["ERR", "AUTH"]
            return {
                "ok": False,
                "blocked": blocked,
                "detail": line,
                "rx_us": int(fields[3]) if blocked and len(fields) >= 4 else 0,
                "tx_us": 0,
                "rtt_ms": rtt_ms,
            }
        if line.startswith("ERR "):
            raise RuntimeError(line)

        fields = line.split()
        if len(fields) != 8 or fields[0] != "RESP":
            raise RuntimeError(f"malformed RESP: {line}")
        response_slot = int(fields[1])
        response_counter = int(fields[2], 16)
        response_length = int(fields[3])
        if response_slot != slot or response_counter != session.rx_counter:
            raise RuntimeError("response slot/counter mismatch")
        response = self._aead_class(session.rx_key).decrypt(
            self._nonce(session.rx_prefix, response_counter),
            bytes.fromhex(fields[6]) + bytes.fromhex(fields[7]),
            self._aad(session.sid, response_counter, response_length),
        )[:response_length]
        if response != payload:
            raise RuntimeError("secure echo plaintext mismatch")
        session.tx_counter += 1
        session.rx_counter += 1
        return {
            "ok": True,
            "blocked": False,
            "detail": "secure echo verified",
            "rx_us": int(fields[4]),
            "tx_us": int(fields[5]),
            "rtt_ms": rtt_ms,
        }


class BoardWorker:
    """Serializes board operations and reports results to the main thread."""

    def __init__(self, board: Any):
        self.board = board
        self.name = board.name
        self.commands: queue.Queue[Optional[BoardCommand]] = queue.Queue()
        self.results: queue.Queue[BoardResult] = queue.Queue()
        self.stats = BoardStats(self.name)
        self._thread = threading.Thread(
            target=self._run,
            name=f"board-{self.name}",
            daemon=True,
        )
        self._thread.start()

    @property
    def pending_count(self) -> int:
        return self.commands.qsize()

    def submit(self, command: BoardCommand) -> None:
        self.commands.put(command)

    def poll(self) -> list[BoardResult]:
        items: list[BoardResult] = []
        while True:
            try:
                items.append(self.results.get_nowait())
            except queue.Empty:
                return items

    def stop(self) -> None:
        self.commands.put(None)
        self._thread.join(timeout=2.0)
        self.board.close()

    def _run(self) -> None:
        while True:
            command = self.commands.get()
            if command is None:
                return
            try:
                if command.kind == "open":
                    assert command.slot is not None
                    session = self.board.open_session(command.vehicle_id, command.slot)
                    self.stats.slots[session.slot] = command.vehicle_id
                    self.stats.record_kem(session.kem_us)
                    self.stats.opens += 1
                    result = BoardResult(
                        command.command_id, self.name, command.kind,
                        command.vehicle_id, True, session.slot, session,
                        f"READY sid={session.sid:08x} kem={session.kem_us}us",
                    )
                elif command.kind == "leave":
                    assert command.slot is not None
                    self.board.leave_session(command.slot)
                    self.stats.slots[command.slot] = None
                    self.stats.leaves += 1
                    result = BoardResult(
                        command.command_id, self.name, command.kind,
                        command.vehicle_id, True, command.slot,
                        detail="LEFT",
                    )
                elif command.kind == "swkem":
                    result = self._run_swkem(command)
                    self.commands.task_done()
                    self.results.put(result)
                    continue
                elif command.kind == "data":
                    assert command.slot is not None
                    info = self.board.send_data(
                        command.slot, command.payload, command.tamper
                    )
                    self.stats.last_rx_us = info["rx_us"]
                    self.stats.last_tx_us = info["tx_us"]
                    self.stats.last_rtt_ms = info["rtt_ms"]
                    if info["ok"]:
                        self.stats.data_ok += 1
                    else:
                        self.stats.data_fail += 1
                    if info["blocked"]:
                        self.stats.attacks_blocked += 1
                    result = BoardResult(
                        command.command_id, self.name, command.kind,
                        command.vehicle_id, info["ok"], command.slot,
                        detail=info["detail"], blocked=info["blocked"],
                        rx_us=info["rx_us"], tx_us=info["tx_us"],
                        rtt_ms=info["rtt_ms"],
                    )
                else:
                    raise ValueError(f"unknown command: {command.kind}")
                self.stats.error = ""
            except Exception as exc:  # Worker must stay alive after one UART error.
                self.stats.error = str(exc)
                result = BoardResult(
                    command.command_id, self.name, command.kind,
                    command.vehicle_id, False, command.slot,
                    detail=str(exc),
                )
            self.commands.task_done()
            self.results.put(result)

    def _run_swkem(self, command: BoardCommand) -> BoardResult:
        """Ask the board to time one software ML-KEM decaps on the Cortex-A9.

        Firmware without the SWKEM command answers ERR (or nothing); the board is
        then marked unsupported and the GUI falls back to the fixed baseline.
        """
        probe = getattr(self.board, "sw_kem", None)
        info = None
        if probe is not None:
            try:
                info = probe()
            except Exception:
                info = None
        if info is None:
            self.stats.sw_supported = False
            return BoardResult(command.command_id, self.name, command.kind,
                               command.vehicle_id, False, detail="SWKEM unsupported")
        sw_us, match = info
        self.stats.sw_supported = True
        self.stats.record_sw(sw_us, match)
        return BoardResult(command.command_id, self.name, command.kind,
                           command.vehicle_id, match, sw_us=sw_us,
                           detail="SWKEM ok" if match else "SWKEM secret mismatch")
