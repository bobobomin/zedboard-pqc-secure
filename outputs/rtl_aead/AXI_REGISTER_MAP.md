# AXI4-Lite register maps

The final `mlkem_secure_channel_complete_axi_top` has one ML-KEM load/control
slave port and one AEAD traffic slave port. Both reach the same protected
session table.

## AEAD traffic port

All registers are 32-bit. Multiword byte strings use little-endian word
packing: protocol bytes 0..3 occupy bits 0..31 of word 0.

| Offset | Name | Description |
|---:|---|---|
| `0x000` | VERSION | `{0x0004, NUM_SESSIONS, SLOT_WIDTH}`; default `0x00044006` |
| `0x004` | CONTROL | bit 0 START, bit 1 DECRYPT, bit 8 CLEAR_DONE |
| `0x008` | STATUS | bit 0 BUSY, 1 DONE, 2 AUTH_OK, 3 ERROR, 5 REQ_PENDING, 6 FAULT_DETECTED |
| `0x00C` | REQUEST_SLOT | Session-table slot 0..63 |
| `0x010` | DATA_LEN | Meaningful plaintext bytes, 0..64 |
| `0x014` | COUNTER_LO | Received counter for decryption |
| `0x018` | COUNTER_HI | Received counter for decryption |
| `0x01C` | RSP_COUNTER_LO | Counter used in the completed request |
| `0x020` | RSP_COUNTER_HI | Counter used in the completed request |
| `0x024` | FAULT | bit 8 fault detected, bits 7:0 fault code |
| `0x028` | RSP_SLOT | Slot returned by the completed request |
| `0x100..0x13C` | INPUT_DATA[0..15] | Plaintext or ciphertext, fixed 64 bytes |
| `0x140..0x14C` | INPUT_TAG[0..3] | Received tag for decryption |
| `0x180..0x1BC` | OUTPUT_DATA[0..15] | Ciphertext or authenticated plaintext |
| `0x1C0..0x1CC` | OUTPUT_TAG[0..3] | Generated/calculated tag |

## Request sequence

```text
wait STATUS.BUSY=0 and STATUS.REQ_PENDING=0
write CONTROL.CLEAR_DONE
write slot, length, counter, input data, and optional input tag
write CONTROL.START plus optional CONTROL.DECRYPT
poll STATUS.DONE
check AUTH_OK and ERROR
read response counter, output data, and output tag
```

The wrapper contains no request FIFO. Software must not modify request
registers between START and completion of the current operation.

## ML-KEM session installation

For the final dual-AXI top this is automatic after protected Decaps; software
must not use the standalone manual configuration/KDF registers described
below.

## ML-KEM load/control port

| Offset | Name | Description |
|---:|---|---|
| `0x00` | VERSION | `0x00020000` |
| `0x04` | CONTROL | bit 0 START, bit 8 CLEAR_DONE |
| `0x08` | STATUS | bit 1 BUSY, bit 2 DONE, bit 3 FAIL |
| `0x0C` | SLOT | Destination session slot 0..63 |
| `0x10` | SESSION_ID | 32-bit protocol session ID |
| `0x20` | MEM_REGION | 0 secret key, 1 ciphertext |
| `0x24` | MEM_ADDR | Auto-incrementing 32-bit word address |
| `0x28` | MEM_DATA | Data read/write window |

## Session installation policy

The board-facing 64-session top does not expose traffic-key or manual KDF
registers. PL computes the KDF and atomically marks a slot valid only after a
successful protected ML-KEM decapsulation. This prevents the traffic AXI port
from bypassing the handshake.
