# Four-session AEAD arbiter

## Data flow

```text
four request ports
       |
round-robin selector
       |
session context lookup
       |
nonce/AAD builder
       |
one shared ChaCha20-Poly1305 engine
       |
per-request response port
```

Each session context contains:

```text
valid
protocol session_id
TX key / RX key
TX nonce prefix / RX nonce prefix
TX counter / RX expected counter
```

Configuration resets both counters to zero. The encryption path uses the
stored TX counter and increments it after success. The decryption path accepts
only the expected RX counter and increments it only after tag verification.

## Request processing

```text
IDLE
  -> round-robin grant
  -> validate session, length, and RX counter
  -> build nonce = direction_prefix || BE64(counter)
  -> build AAD = BE32(session_id) || BE64(counter) || data_len || 0x000000
  -> start shared AEAD engine
  -> wait for completion
  -> update the successful direction counter
  -> hold response until rsp_ready
```

Invalid sessions, lengths above 64, replayed counters, and invalid tags return
`rsp_error=1`, `rsp_auth_ok=0`, and an all-zero data field.

## Current replay policy

The first demo uses strict in-order reception:

```text
received_counter == expected_rx_counter
```

This is easy to demonstrate and guarantees no nonce reuse. If UDP packet
reordering must be supported later, replace this comparison with a sliding
replay window and bitmap.

## Integration boundary

The flattened four-port interface is intended for RTL simulation. For the
Zynq build, the next wrapper should expose descriptors and payload buffers over
AXI/BRAM rather than routing thousands of packet bits to physical FPGA pins.
