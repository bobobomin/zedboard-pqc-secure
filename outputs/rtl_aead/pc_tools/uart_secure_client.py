#!/usr/bin/env python3
"""64-session UART client for join/leave/rejoin ML-KEM demonstrations."""

import argparse
import hashlib
import statistics
import sys
import time
from pathlib import Path

import serial
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PACKET_BYTES = 64
MAX_SESSIONS = 64
SHARED_SECRET = bytes.fromhex(
    "ee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f"
)
KDF_DOMAIN = b"ZYNQ-PQC-v1"


def default_vector_dir():
    return Path(__file__).resolve().parents[2] / "golden_reference"


def load_vectors(vector_dir):
    public_key = (vector_dir / "public_key.bin").read_bytes()
    kem_ciphertext = (vector_dir / "kem_ciphertext.bin").read_bytes()
    if len(public_key) != 800 or len(kem_ciphertext) != 768:
        raise ValueError("expected ML-KEM-512 public_key.bin and kem_ciphertext.bin")
    return public_key, kem_ciphertext


def derive_session(session_id, public_key, kem_ciphertext):
    transcript = hashlib.sha3_256(
        public_key + kem_ciphertext + session_id.to_bytes(4, "big")
    ).digest()
    material = hashlib.shake_256(
        KDF_DOMAIN + SHARED_SECRET + transcript
    ).digest(72)
    return {
        "sid": session_id,
        "tx_key": material[0:32],
        "tx_prefix": material[32:36],
        "rx_key": material[36:68],
        "rx_prefix": material[68:72],
        "tx_counter": 0,
        "rx_counter": 0,
        "kem_us": 0,
        "rtt_ms": [],
        "hw_rx_us": [],
        "hw_tx_us": [],
        "active": True,
        "user_id": None,
    }


def make_empty_sessions():
    return [
        {
            "active": False,
            "sid": 0,
            "user_id": None,
            "tx_counter": 0,
            "rx_counter": 0,
            "kem_us": 0,
            "rtt_ms": [],
            "hw_rx_us": [],
            "hw_tx_us": [],
        }
        for _ in range(MAX_SESSIONS)
    ]


def build_nonce(prefix, counter):
    return prefix + counter.to_bytes(8, "big")


def build_aad(session_id, counter, length):
    return (
        session_id.to_bytes(4, "big")
        + counter.to_bytes(8, "big")
        + bytes((length, 0, 0, 0))
    )


def read_protocol_line(port, timeout=60.0):
    deadline = time.monotonic() + timeout
    prefixes = ("READY ", "RESP ", "ERR ", "BYE", "LEFT ", "STATUS ")
    while time.monotonic() < deadline:
        raw = port.readline()
        if not raw:
            continue
        line = raw.decode("ascii", errors="replace").strip()
        if line.startswith(prefixes):
            return line
    raise TimeoutError("ZedBoard response timeout")


def send_line(port, text):
    port.write((text + "\n").encode("ascii"))
    port.flush()
    return read_protocol_line(port)


def join_session(port, sessions, slot, vectors, user_id, join_events):
    if slot not in range(MAX_SESSIONS):
        raise ValueError("slot must be 0..63")
    line = send_line(port, f"OPEN {slot}")
    if line.startswith("ERR "):
        raise RuntimeError(line)
    fields = line.split()
    if len(fields) != 4 or fields[0] != "READY":
        raise RuntimeError(f"malformed READY: {line}")

    returned_slot = int(fields[1])
    session_id = int(fields[2], 16)
    kem_us = int(fields[3])
    if returned_slot != slot:
        raise RuntimeError(f"slot mismatch: {line}")

    public_key, kem_ciphertext = vectors
    state = derive_session(session_id, public_key, kem_ciphertext)
    state["kem_us"] = kem_us
    state["user_id"] = user_id
    sessions[slot] = state
    join_events.append(kem_us)
    print(
        f"[JOIN] user={user_id} slot={slot} session={session_id:08x} "
        f"ML-KEM={kem_us} us"
    )


def leave_session(port, sessions, slot):
    if slot not in range(MAX_SESSIONS) or not sessions[slot]["active"]:
        raise ValueError("slot is not active")
    old = sessions[slot]
    line = send_line(port, f"LEAVE {slot}")
    if line.startswith("ERR "):
        raise RuntimeError(line)
    fields = line.split()
    if len(fields) != 3 or fields[0] != "LEFT" or int(fields[1]) != slot:
        raise RuntimeError(f"malformed LEFT: {line}")
    if int(fields[2], 16) != old["sid"]:
        raise RuntimeError(f"session mismatch: {line}")
    sessions[slot] = make_empty_sessions()[0]
    print(
        f"[LEAVE] user={old['user_id']} slot={slot} "
        f"session={old['sid']:08x}"
    )


def board_status(port):
    line = send_line(port, "STATUS")
    if line.startswith("ERR "):
        raise RuntimeError(line)
    fields = line.split()
    if len(fields) != 4 or fields[0] != "STATUS":
        raise RuntimeError(f"malformed STATUS: {line}")
    count = int(fields[1])
    bitmap = (int(fields[2], 16) << 32) | int(fields[3], 16)
    print(f"[STATUS] active={count}/64 bitmap={bitmap:016x}")
    return count, bitmap


def secure_echo(port, sessions, slot, plaintext, verbose=True):
    if len(plaintext) > PACKET_BYTES:
        raise ValueError("message must be at most 64 UTF-8 bytes")
    if slot not in range(MAX_SESSIONS) or not sessions[slot]["active"]:
        raise ValueError("selected slot is not active")

    state = sessions[slot]
    tx_counter = state["tx_counter"]
    padded = plaintext + bytes(PACKET_BYTES - len(plaintext))
    request = ChaCha20Poly1305(state["tx_key"]).encrypt(
        build_nonce(state["tx_prefix"], tx_counter),
        padded,
        build_aad(state["sid"], tx_counter, len(plaintext)),
    )
    ciphertext, tag = request[:-16], request[-16:]
    command = (
        f"DATA {slot} {tx_counter:016x} {len(plaintext)} "
        f"{ciphertext.hex()} {tag.hex()}"
    )

    begin = time.perf_counter()
    line = send_line(port, command)
    rtt_ms = (time.perf_counter() - begin) * 1000.0
    if line.startswith("ERR "):
        raise RuntimeError(line)

    fields = line.split()
    if len(fields) != 8 or fields[0] != "RESP":
        raise RuntimeError(f"malformed response: {line}")
    response_slot = int(fields[1])
    response_counter = int(fields[2], 16)
    response_length = int(fields[3])
    hw_rx_us, hw_tx_us = int(fields[4]), int(fields[5])
    response_ciphertext = bytes.fromhex(fields[6])
    response_tag = bytes.fromhex(fields[7])
    if response_slot != slot or response_counter != state["rx_counter"]:
        raise RuntimeError("response slot/counter mismatch")

    response_padded = ChaCha20Poly1305(state["rx_key"]).decrypt(
        build_nonce(state["rx_prefix"], response_counter),
        response_ciphertext + response_tag,
        build_aad(state["sid"], response_counter, response_length),
    )
    response_plaintext = response_padded[:response_length]
    if response_plaintext != plaintext:
        raise RuntimeError("secure echo plaintext mismatch")

    state["tx_counter"] += 1
    state["rx_counter"] += 1
    state["rtt_ms"].append(rtt_ms)
    state["hw_rx_us"].append(hw_rx_us)
    state["hw_tx_us"].append(hw_tx_us)
    if verbose:
        print(f"[user {state['user_id']} slot {slot}] plaintext : {plaintext!r}")
        print(f"[user {state['user_id']} slot {slot}] ciphertext: {ciphertext.hex()}")
        print(f"[user {state['user_id']} slot {slot}] tag       : {tag.hex()}")
        print(f"[user {state['user_id']} slot {slot}] decrypted : {response_plaintext!r}")
        print(
            f"[PASS] HW RX={hw_rx_us} us, HW TX={hw_tx_us} us, "
            f"UART RTT={rtt_ms:.3f} ms\n"
        )


def active_slots(sessions):
    return [slot for slot, state in enumerate(sessions) if state["active"]]


def show_stats(sessions, join_events, leaves):
    slots = active_slots(sessions)
    packets = sum(len(state["rtt_ms"]) for state in sessions)
    print(
        f"\nactive={len(slots)}/64 joins={len(join_events)} "
        f"leaves={leaves} packets={packets}"
    )
    if join_events:
        print(
            f"ML-KEM avg={statistics.mean(join_events):.1f} us "
            f"min={min(join_events)} us max={max(join_events)} us"
        )
    print("slot user session   packets KEM(us) RX(us) TX(us) RTT(ms)")
    for slot in slots:
        state = sessions[slot]
        count = len(state["rtt_ms"])
        rx = f"{statistics.mean(state['hw_rx_us']):.1f}" if count else "-"
        tx = f"{statistics.mean(state['hw_tx_us']):.1f}" if count else "-"
        rtt = f"{statistics.mean(state['rtt_ms']):.3f}" if count else "-"
        print(
            f"{slot:>4} {state['user_id']:>4} {state['sid']:08x} "
            f"{count:>7} {state['kem_us']:>7} {rx:>6} {tx:>6} {rtt:>7}"
        )
    print()


def run_rounds(port, sessions, rounds):
    slots = active_slots(sessions)
    if rounds <= 0 or not slots:
        raise ValueError("round count must be positive and a session must be active")
    packets = 0
    payload_bytes = 0
    begin = time.perf_counter()
    for round_index in range(rounds):
        for slot in slots:
            message = f"slot-{slot} round-{round_index}".encode("ascii")
            secure_echo(port, sessions, slot, message, verbose=False)
            packets += 1
            payload_bytes += len(message)
    elapsed = time.perf_counter() - begin
    print(
        f"[ROUND] {packets} packets, {elapsed:.3f} s, "
        f"payload throughput={payload_bytes / elapsed:.1f} byte/s"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default="COM3")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--vector-dir", type=Path, default=default_vector_dir())
    args = parser.parse_args()

    vectors = load_vectors(args.vector_dir)
    sessions = make_empty_sessions()
    join_events = []
    next_user_id = 0
    leaves = 0
    selected_slot = None

    with serial.Serial(args.port, args.baud, timeout=0.25) as port:
        port.reset_input_buffer()
        port.reset_output_buffer()
        board_status(port)
        print(
            "Commands: /join [slot], /leave <slot>, /fill <count>, "
            "/churn <count>, /user <slot>, /round <count>, "
            "/status, /stats, /quit"
        )

        while True:
            prompt = "secure[no-session]> " if selected_slot is None else (
                f"secure[slot{selected_slot}]> "
            )
            text = input(prompt).strip()
            if text == "/quit":
                port.write(b"QUIT\n")
                port.flush()
                break
            if text == "/status":
                board_status(port)
                continue
            if text == "/stats":
                show_stats(sessions, join_events, leaves)
                continue
            if text.startswith("/join"):
                fields = text.split()
                if len(fields) == 2:
                    slot = int(fields[1])
                else:
                    free = [i for i in range(MAX_SESSIONS)
                            if not sessions[i]["active"]]
                    if not free:
                        raise ValueError("all 64 slots are active")
                    slot = free[0]
                join_session(
                    port, sessions, slot, vectors, next_user_id, join_events
                )
                next_user_id += 1
                selected_slot = slot
                continue
            if text.startswith("/leave "):
                slot = int(text.split()[1])
                leave_session(port, sessions, slot)
                leaves += 1
                if selected_slot == slot:
                    slots = active_slots(sessions)
                    selected_slot = slots[0] if slots else None
                continue
            if text.startswith("/fill "):
                target = int(text.split()[1])
                if target not in range(MAX_SESSIONS + 1):
                    raise ValueError("fill count must be 0..64")
                while len(active_slots(sessions)) < target:
                    slot = next(i for i in range(MAX_SESSIONS)
                                if not sessions[i]["active"])
                    join_session(
                        port, sessions, slot, vectors,
                        next_user_id, join_events
                    )
                    next_user_id += 1
                    selected_slot = slot
                board_status(port)
                continue
            if text.startswith("/churn "):
                count = int(text.split()[1])
                if count <= 0:
                    raise ValueError("churn count must be positive")
                if not active_slots(sessions):
                    join_session(
                        port, sessions, 0, vectors,
                        next_user_id, join_events
                    )
                    next_user_id += 1
                begin = time.perf_counter()
                kem_begin = len(join_events)
                for index in range(count):
                    slots = active_slots(sessions)
                    slot = slots[index % len(slots)]
                    leave_session(port, sessions, slot)
                    leaves += 1
                    join_session(
                        port, sessions, slot, vectors,
                        next_user_id, join_events
                    )
                    next_user_id += 1
                    secure_echo(
                        port, sessions, slot,
                        f"new-user-{next_user_id}".encode("ascii"),
                        verbose=False,
                    )
                elapsed = time.perf_counter() - begin
                new_kem = join_events[kem_begin:]
                print(
                    f"[CHURN] {count} leave+join+secure-packet events, "
                    f"{elapsed:.3f} s, {count / elapsed:.2f} events/s, "
                    f"ML-KEM avg={statistics.mean(new_kem):.1f} us"
                )
                selected_slot = slot
                continue
            if text.startswith("/user "):
                slot = int(text.split()[1])
                if slot not in range(MAX_SESSIONS) or not sessions[slot]["active"]:
                    raise ValueError("slot must be an active slot in 0..63")
                selected_slot = slot
                continue
            if text.startswith("/round "):
                run_rounds(port, sessions, int(text.split()[1]))
                continue

            if selected_slot is None:
                print("No active session. Use /join or /fill first.")
                continue
            encoded = text.encode("utf-8")
            if len(encoded) > PACKET_BYTES:
                print("Message is longer than 64 UTF-8 bytes.")
                continue
            secure_echo(port, sessions, selected_slot, encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
