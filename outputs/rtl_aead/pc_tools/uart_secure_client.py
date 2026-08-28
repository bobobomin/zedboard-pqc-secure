#!/usr/bin/env python3
"""Four-session UART client and benchmark for the ZedBoard secure echo."""

import argparse
import statistics
import sys
import time

import serial
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PACKET_BYTES = 64
SESSION_MATERIAL = (
    (0x01020304, "71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a", "7d3fe84c", "a814fc7382a5f27c46909f915772cbf64b5c247c32b443c83bc2b328ef94de96", "a72e02aa"),
    (0x01020305, "3747b554cce3e11905507ad1caaf503dd48fdabb9f9f9614cdb9f77ae59c126a", "a7688ca4", "3adaa86fb5980c3a234256b22c334a257edc36f09669d54fe2a112fb08d1e4f0", "42886c54"),
    (0x01020306, "9319c9e1353b4dc0ed516cbf9bf278abddc4a52ef0ea7158ee4b11a8de1ab375", "1aaa8951", "33401e0e03826bcb2302ff1f8f649e1e88eff34de3989cc283a5746745875432", "ea53648b"),
    (0x01020307, "dcd6fcd7087201dbe6c31dc1d47c3dba92991b7c656201ff704d400d7cb290ce", "b05807d5", "9c1afc5cf1f924b714808e6b5f2e17ab1c4d511c578657ae07edbd4d4482696e", "a17037e6"),
)


def make_sessions():
    sessions = []
    for sid, tx_key, tx_prefix, rx_key, rx_prefix in SESSION_MATERIAL:
        sessions.append({
            "sid": sid, "tx_key": bytes.fromhex(tx_key),
            "tx_prefix": bytes.fromhex(tx_prefix),
            "rx_key": bytes.fromhex(rx_key),
            "rx_prefix": bytes.fromhex(rx_prefix),
            "tx_counter": 0, "rx_counter": 0, "kem_us": 0,
            "rtt_ms": [], "hw_rx_us": [], "hw_tx_us": [],
        })
    return sessions


def build_nonce(prefix, counter):
    return prefix + counter.to_bytes(8, "big")


def build_aad(session_id, counter, length):
    return (session_id.to_bytes(4, "big") + counter.to_bytes(8, "big")
            + bytes((length, 0, 0, 0)))


def read_protocol_line(port, timeout=60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = port.readline()
        if not raw:
            continue
        line = raw.decode("ascii", errors="replace").strip()
        if line.startswith(("READY ", "RESP ", "ERR ", "BYE")):
            return line
    raise TimeoutError("ZedBoard response timeout")


def open_session(port, sessions, slot):
    port.write(f"OPEN {slot}\n".encode("ascii"))
    port.flush()
    line = read_protocol_line(port)
    if line.startswith("ERR "):
        raise RuntimeError(line)
    fields = line.split()
    if len(fields) != 4 or fields[0] != "READY":
        raise RuntimeError(f"malformed READY: {line}")
    returned_slot, session_id, kem_us = int(fields[1]), int(fields[2], 16), int(fields[3])
    if returned_slot != slot or session_id != sessions[slot]["sid"]:
        raise RuntimeError(f"session mismatch: {line}")
    sessions[slot]["tx_counter"] = 0
    sessions[slot]["rx_counter"] = 0
    sessions[slot]["kem_us"] = kem_us
    print(f"[OPEN] user {slot}: session={session_id:08x}, ML-KEM={kem_us} us")


def secure_echo(port, sessions, slot, plaintext, verbose=True):
    if len(plaintext) > PACKET_BYTES:
        raise ValueError("message must be at most 64 UTF-8 bytes")
    state = sessions[slot]
    tx_counter = state["tx_counter"]
    padded = plaintext + bytes(PACKET_BYTES - len(plaintext))
    request = ChaCha20Poly1305(state["tx_key"]).encrypt(
        build_nonce(state["tx_prefix"], tx_counter), padded,
        build_aad(state["sid"], tx_counter, len(plaintext)))
    ciphertext, tag = request[:-16], request[-16:]
    command = (f"DATA {slot} {tx_counter:016x} {len(plaintext)} "
               f"{ciphertext.hex()} {tag.hex()}\n")

    begin = time.perf_counter()
    port.write(command.encode("ascii"))
    port.flush()
    line = read_protocol_line(port)
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
        build_aad(state["sid"], response_counter, response_length))
    response_plaintext = response_padded[:response_length]
    if response_plaintext != plaintext:
        raise RuntimeError("secure echo plaintext mismatch")

    state["tx_counter"] += 1
    state["rx_counter"] += 1
    state["rtt_ms"].append(rtt_ms)
    state["hw_rx_us"].append(hw_rx_us)
    state["hw_tx_us"].append(hw_tx_us)
    if verbose:
        print(f"[user {slot}] plaintext : {plaintext!r}")
        print(f"[user {slot}] ciphertext: {ciphertext.hex()}")
        print(f"[user {slot}] tag       : {tag.hex()}")
        print(f"[user {slot}] decrypted : {response_plaintext!r}")
        print(f"[PASS] HW RX={hw_rx_us} us, HW TX={hw_tx_us} us, UART RTT={rtt_ms:.3f} ms\n")


def show_stats(sessions):
    print("\nuser packets  ML-KEM(us)  avg RX(us)  avg TX(us)  avg RTT(ms)")
    for slot, state in enumerate(sessions):
        count = len(state["rtt_ms"])
        if count:
            print(f"{slot:>4} {count:>7} {state['kem_us']:>11} "
                  f"{statistics.mean(state['hw_rx_us']):>11.1f} "
                  f"{statistics.mean(state['hw_tx_us']):>11.1f} "
                  f"{statistics.mean(state['rtt_ms']):>12.3f}")
        else:
            print(f"{slot:>4} {0:>7} {state['kem_us']:>11}          -          -            -")
    print()


def run_rounds(port, sessions, rounds):
    if rounds <= 0:
        raise ValueError("round count must be positive")
    packets = 0
    payload_bytes = 0
    begin = time.perf_counter()
    for round_index in range(rounds):
        for slot in range(4):
            message = f"user-{slot} round-{round_index}".encode("ascii")
            secure_echo(port, sessions, slot, message, verbose=False)
            packets += 1
            payload_bytes += len(message)
    elapsed = time.perf_counter() - begin
    print(f"[ROUND] {packets} packets, {elapsed:.3f} s, "
          f"payload throughput={payload_bytes / elapsed:.1f} byte/s")
    show_stats(sessions)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default="COM3")
    parser.add_argument("--baud", type=int, default=115200)
    args = parser.parse_args()
    sessions = make_sessions()

    with serial.Serial(args.port, args.baud, timeout=0.25) as port:
        port.reset_input_buffer()
        port.reset_output_buffer()
        for slot in range(4):
            open_session(port, sessions, slot)

        selected_slot = 0
        print("Commands: /user 0..3, /round N, /stats, /reopen N, /quit")
        while True:
            text = input(f"secure[user{selected_slot}]> ")
            if text == "/quit":
                port.write(b"QUIT\n")
                port.flush()
                break
            if text == "/stats":
                show_stats(sessions)
                continue
            if text.startswith("/user "):
                selected_slot = int(text.split()[1])
                if selected_slot not in range(4):
                    raise ValueError("user must be 0..3")
                continue
            if text.startswith("/reopen "):
                slot = int(text.split()[1])
                if slot not in range(4):
                    raise ValueError("slot must be 0..3")
                open_session(port, sessions, slot)
                continue
            if text.startswith("/round "):
                run_rounds(port, sessions, int(text.split()[1]))
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
