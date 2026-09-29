"""Send HELLO to a board over UART and print its reply (board A/B check)."""
import sys
import time

import serial

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
s = serial.Serial(port, 115200, timeout=0.5)
s.reset_input_buffer()
for _ in range(3):
    s.write(b"HELLO\n")
    t = time.time()
    while time.time() - t < 3:
        line = s.readline().decode("ascii", errors="replace").strip()
        if line.startswith("HELLO"):
            print(f"{port}: board {line.split()[1]}  OK")
            sys.exit(0)
print(f"{port}: no HELLO reply (firmware not running or wrong port)")
sys.exit(1)
