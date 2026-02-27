# Protocol Specification — Synaptics 06cb:00da (FS7605)

> **Last updated:** 2026-02-27

---

## Summary

The `06cb:00da` is a Synaptics FS7605 fingerprint sensor found in ThinkPad E14/E15 laptops.
It shares some basic commands with the Validity90 family (`138a:0090`, `138a:0097`, `06cb:009a`)
but has a **fundamentally different firmware** with a different command set for provisioning.

**Current status:** Sensor is in state `0x03` (not provisioned). Flash is empty.
We need a USB capture from the Windows Synaptics driver to discover the provisioning protocol.

---

## USB Interface

| Parameter | Value |
|-----------|-------|
| Vendor ID | `0x06cb` (Synaptics) |
| Product ID | `0x00da` (FS7605) |
| Bulk OUT | Endpoint `0x01` |
| Bulk IN | Endpoint `0x81` |
| Interrupt IN | Endpoint `0x83` |
| Timeout | 10s (bulk), 5s (interrupt) |

---

## Error Code Format

2-byte responses with format `XX YY`:

| Code | Meaning | Seen on |
|------|---------|---------|
| `00 00` | Success / ACK | `0x00`, `0x05`, `0x7c`, `0x8d`, `0x3f 01`, `0x3f 02` |
| `01 04` | Unknown command | 213 of 256 single-byte cmds |
| `03 04` | Parameter error | `0x93`, `0x3f` with invalid sub-byte, `0xae` with invalid sub |
| `04 04` | State error (blocked) | `0x81`, `0x86`, `0x87`, `0x9f`, `0xa2`, `0xa5`, `0xec`, `0xed`, `0xfe`, `0x9e XX`, `0xa4 XX` |
| `05 04` | Needs parameters | 24 commands (see below) |
| `e5 06` | Not available | `0x3f 03` |
| `e7 06` | Not provisioned | MSG6 (`0x40 01 01...`) |

---

## Full Command Map (state=0x03, unprovisioned)

### Commands that return data or ACK

| Cmd | Response | Notes |
|-----|----------|-------|
| `0x00` | `00 00` (2 bytes) | NOP / status OK |
| `0x01` | 38 bytes | MSG1 — ROM info / probe. Last byte = state (`0x03`) |
| `0x05` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0x19` | 68 bytes | MSG2 — device state query |
| `0x3e` | 52 bytes | MSG5 — flash/partition info. Flash is empty (`ff ff ff ff`) |
| `0x3f 0x01` | `00 00` (2 bytes) | ACK — flash/partition operation? |
| `0x3f 0x02` | `00 00` (2 bytes) | ACK — flash/partition operation? |
| `0x7c` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0x8d` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0xae 0x00` | 270 bytes | Sensor config/calibration dump (TLV format, see below) |

### Commands recognized but need parameters (`05 04`)

```
0x0d  0x39  0x3f  0x40  0x41  0x57  0x73  0x7f
0x80  0x82  0x8e  0x90  0x96  0x99  0x9e  0xa0
0xa1  0xa3  0xa4  0xa6  0xa9  0xaa  0xab  0xae
```

Of these, when tested with `cmd + sub-byte` (0x00-0xff):
- Most returned `01 04` or `05 04` for all sub-bytes
- **`0x9e XX`** — all return `04 04` (state-blocked, needs provisioning)
- **`0xa4 XX`** — all return `04 04` (state-blocked, needs provisioning)
- **`0xae 0x00`** — returns 270 bytes (only sub=0x00 valid, rest `03 04`)
- **`0x3f`** — sub=0x01 ACK, sub=0x02 ACK, sub=0x03 `e5 06`, rest `03 04`

### Commands blocked by state (`04 04`)

```
0x81  0x86  0x87  0x9f  0xa2  0xa5  0xec  0xed  0xfe
```

These will likely work after the sensor is provisioned (state != 0x03).

### Special behaviors

| Cmd | Behavior |
|-----|----------|
| `0x06` | **USB disconnect** — sensor crashes (bare byte). With full blob payload → `01 04` |
| `0x44` | **TLS mode** — responds with TLS Alert, then reverts to raw mode |
| `0x93` | Returns `03 04` (unique — parameter error as single byte) |

### Commands confirmed NOT to exist (`01 04`)

These Validity90/python-validity commands do NOT exist on 06cb:00da firmware:

```
0x06 (blob)     0x07 (HW read)   0x08 (HW write)  0x1a (commit)
0x43 (ROM/FW)   0x4f (partition)  0x50 (finalize)   0x75 (identify)
```

---

## Actual Responses (hex dumps)

### RSP1 — `0x01` (38 bytes)

```
00 00 55 8f 21 5e 11 d2 2f 00 0a 01 01 41 01 c1
00 00 2a 8f 4e b0 70 50 03 a1 00 00 00 00 01 00
00 00 00 00 00 03
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-7 | `55 8f 21 5e 11 d2` | Device serial/ID (unique per unit) |
| 9 | `0x0a` | Firmware version? (V90: `0x06`) |
| 10 | `0x01` | Protocol version? (V90: `0x07`) |
| 12 | `0x41` | Capabilities? (V90: `0x30`) |
| **37** | **`0x03`** | **State: not provisioned** (V90: `0x07` = ready) |

### RSP2 — `0x19` (68 bytes)

```
00 00 00 03 01 02 00 00 00 00 00 00 00 00 00 00
08 42 00 90 00 00 00 00 57 15 e3 01 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 3 | `0x03` | State (matches RSP1) |
| 4-5 | `01 02` | Sub-state or version? |
| 16-19 | `08 42 00 90` | `00 90` may reference 138a:0090 sensor family |
| 24-27 | `57 15 e3 01` | Firmware version/timestamp (0x01e31557) |

### RSP5 — `0x3e` (52 bytes)

```
00 00 ff ff ff ff ff ff ff ff ff ff ff ff 03 00
01 00 04 00 00 00 00 51 00 e0 09 00 02 00 07 00
00 f0 09 51 00 10 00 00 03 00 00 00 00 e0 09 51
00 10 00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-13 | `ff ff ff ff...` | **Flash is empty** (no calibration/provisioning data) |
| 14 | `0x03` | Partition count? Or state again |

---

## 0xae — Sensor Config/Calibration Dump (270 bytes)

### TLV Record Format

`[u16le type] [u16le total_size] [data: total_size - 4 bytes]`

Where `total_size` **includes** the 4-byte header itself.

### Parsed Records

```
Offset  Type    Total  Data   Content
------  ------  -----  ----   -------
0x00    —       2      —      Status: 00 00 (OK)
0x02    0x0011  16     12     ADC/live sensor readings (3x int32, fluctuate ±5)
0x12    0x0022  36     32     Main config (threshold=20000, flags, calibration)
0x36    0x0032  36     32     Calibration pairs (0x7777 markers, gain/offset?)
0x5a    0x0041  32     28     Scan config (GPIO/register addresses?)
0x7a    0x0052  12     8      Short config (1 bit fluctuates)
0x86    0x0061  20     16     Config block
0x9a    0x0072  16     12     Config block (all zeros)
0xaa    0x0081  20     16     Config block (2 bytes fluctuate)
0xbe    0x0091  52     48     Large block (memory layout?)
0xf2    0x00a1  28     24     Memory addresses (0x00037120, 0x000370f8)
```

**Total: 16+36+36+32+12+20+16+20+52+28 = 268 + 2 (status) = 270 bytes ✓**

### Fluctuating Bytes (4 of 270)

| Offset | Record | Values observed | Likely meaning |
|--------|--------|-----------------|----------------|
| `0x006` | reg 0x11, data[0] | {0x24, 0x26, 0x28, 0x29} | ADC reading LSB |
| `0x07e` | reg 0x52, data[0] | {0x00, 0x40} | Status bit |
| `0x0ba` | reg 0x81, data[12] | {0x0e, 0x26} | Unknown |
| `0x0bb` | reg 0x81, data[13] | {0x00, 0x01} | Unknown |

---

## TLS Behavior

### Entering TLS mode

Sending `0x44` (with or without additional bytes) always returns:
```
15 03 03 00 02 02 2f
```

This is a TLS Alert: **fatal (2) / illegal_parameter (47)**.

The sensor cannot establish TLS because flash is empty — no certificates or keys.
After the alert, the sensor automatically reverts to raw mode.

### Tested TLS approaches (all failed)

| Approach | Result |
|----------|--------|
| `0x44` alone | TLS Alert: illegal_parameter |
| `0x44` + Client Hello (1-byte prefix) | Same alert |
| `0x44` + V90-style Client Hello | Same alert |
| Two-stage: `0x44` → alert → Client Hello | Alert, then `01 04` |
| `44 00 00 00` + Client Hello (V90 prefix) | Same alert |
| Raw `16 03 03...` Client Hello | `01 04` (unknown cmd) |
| `0x44` with sub-bytes 0x00-0x0f | All same alert |

**Conclusion:** TLS requires provisioning first. The flash must contain certs/keys before TLS can work.

---

## What the Validity90 Provisioning Protocol Looks Like (does NOT work on 06cb:00da)

The python-validity / Validity90 C prototype uses these commands for provisioning:

| Command | Purpose | 06cb:00da result |
|---------|---------|------------------|
| `0x06 0x02 ...` (blob) | Encrypted init/config | **`01 04` — unknown** |
| `0x07 ...` | Read HW register | **`01 04` — unknown** |
| `0x08 ...` | Write HW register | **`01 04` — unknown** |
| `0x75` | Identify sensor | **`01 04` — unknown** |
| `0x4f ...` (blob) | Partition flash + install certs | **`01 04` — unknown** |
| `0x50` | Finalize provisioning | **`01 04` — unknown** |
| `0x1a` | Commit/cleanup | **`01 04` — unknown** |

**None of these commands exist on the 06cb:00da firmware.**
The provisioning protocol is completely different and must be discovered via USB capture.

---

## What We Know Must Be True

Based on the sensor's behavior, the provisioning protocol for 06cb:00da must:

1. **Write certificates and keys to flash** — currently empty (`ff ff ff ff`)
2. **Change sensor state from 0x03 to 0x07** (or similar provisioned state)
3. **Use commands from the recognized set** — likely some of the 24 `05 04` commands with correct payloads
4. **Possibly use `0x40` with a different payload** — since `0x40 01 01...` returns `e7 06` (not provisioned) rather than `01 04` (unknown), the command IS recognized
5. **Enable TLS** — after provisioning, `0x44` should complete a TLS handshake instead of alerting
6. **Unblock `0x9e` and `0xa4`** — these return `04 04` (state error), meaning they work after provisioning

---

## USB Capture Guide

See [USB_CAPTURE_GUIDE.md](USB_CAPTURE_GUIDE.md) for instructions on capturing the Windows driver traffic.

---

## Validity90 Protocol (Reference)

*Kept for comparison — this is what works on `138a:0090` / `138a:0097` but NOT on `06cb:00da`.*

### Initialization Sequence

| Step | OUT | IN | Size |
|------|-----|-----|------|
| MSG1 | `01` | RSP1 | 38 bytes, last=0x07 |
| MSG2 | `19` | RSP2 | 68 bytes |
| MSG3 | `43 02` | RSP3 | 84 bytes |
| MSG4 | `06 02 ...` (229 bytes) | RSP4 | 2 bytes `00 00` |
| MSG5 | `3e` | RSP5 | 76 bytes |
| MSG6 | `40 01 01 00 00 00 00 00 00 00 10 00 00` | RSP6 | ~3800 bytes |

### RSP6 TLV Format

```
[8-byte header]
[TLV records until type 0xFFFF]

Each record:
  type:  uint16 LE
  size:  uint16 LE
  hash:  32 bytes SHA-256
  data:  <size> bytes
```

| Type | Content |
|------|---------|
| 0x0003 | TLS Certificate (ECDSA pubkey) |
| 0x0004 | Encrypted ECDSA private key |
| 0x0006 | ECDH public key |
| 0xFFFF | End marker |

### Key Derivation

```
factory_key = [71 7c d7 2d ... 4b ec 20 33]  (32 bytes)
serial = product_name\0 + product_serial\0

master_key = TLS-PRF(factory_key, "GWK", serial, 32)
ecdsa_privkey = AES-256-CBC-decrypt(rsp6_record_0x0004, master_key)

pre_master = ECDH(device_privkey, sensor_ecdh_pubkey)
master_secret = TLS-PRF(pre_master, "master secret", client_random + server_random, 48)
key_block = TLS-PRF(master_secret, "key expansion", client_random + server_random, 288)
```

### TLS 1.2 Handshake

- Cipher: `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA` (0xc005)
- All records prefixed with `44 00 00 00`
- ECDH on P-256 (secp256r1)
- MAC-then-encrypt: HMAC-SHA256 + AES-256-CBC
- Static IV: `4b 77 62 ff a9 03 c1 1e 6f d8 35 93 17 2d 54 ef`
- Custom padding (pad bytes = `pad_len - 1`, repeated)

### Image Format

- 144x144 pixels, 8-bit grayscale
- 3 chunks via `0x51` command
- Chunk 1: offset 0x12, Chunks 2-3: offset 0x06
