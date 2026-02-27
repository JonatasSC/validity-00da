# Protocol Specification — Synaptics 06cb:00da

Based on the Validity90 reverse engineering of sensors `138a:0090`, `138a:0097`, `06cb:009a`.
This document will be updated as we discover differences specific to `06cb:00da`.

## USB Interface

| Parameter | Value |
|-----------|-------|
| Vendor ID | `0x06cb` (Synaptics) |
| Product ID | `0x00da` (FS7605) |
| Bulk OUT | Endpoint `0x01` |
| Bulk IN | Endpoint `0x81` |
| Interrupt IN | Endpoint `0x83` |
| Timeout | 10s (bulk), 5s (interrupt) |

## Initialization Sequence

### MSG1 — Probe

| Direction | Data |
|-----------|------|
| OUT | `01` |
| IN (RSP1) | 38 bytes, last byte = state (0x07=initialized, 0x02=needs setup) |

### MSG2 — Init state query

| Direction | Data |
|-----------|------|
| OUT | `19` |
| IN (RSP2) | 68 bytes |

### MSG3 — Configuration query

| Direction | Data |
|-----------|------|
| OUT | `43 02` |
| IN (RSP3) | 84 bytes (partition table / flash layout) |

### MSG4 — Secure blob

| Direction | Data |
|-----------|------|
| OUT | 229 bytes starting with `06 02 00 00 01 39...` |
| IN (RSP4) | 2 bytes: `00 00` (ACK) |

### MSG5 — State query

| Direction | Data |
|-----------|------|
| OUT | `3e` |
| IN (RSP5) | 76 bytes (calibration/partition info) |

### MSG6 — Request crypto material

| Direction | Data |
|-----------|------|
| OUT | `40 01 01 00 00 00 00 00 00 00 10 00 00` |
| IN (RSP6) | ~3800 bytes (TLV records with crypto keys) |

## RSP6 Format

```
[8-byte header]
[TLV records...]
[0xFFFF terminator]
```

Each TLV record:
```
type:   uint16 LE
size:   uint16 LE
hash:   32 bytes (SHA-256 of data)
data:   <size> bytes
```

### Record Types

| Type | Content |
|------|---------|
| 0x0003 | TLS Certificate (ECDSA public key at offset 0x08/0x4c, LE) |
| 0x0004 | Encrypted ECDSA private key (AES-256-CBC, prefix 0x02) |
| 0x0006 | ECDH public key (same format as 0x0003) |
| 0x0000-0x0002, 0x0005 | Unknown/padding |
| 0xFFFF | End marker |

### Key Derivation

1. Read system serial: `product_name\0 + product_serial\0` from `/sys/class/dmi/id/`
2. Master key = `TLS-PRF(FACTORY_KEY, "GWK", serial, 32)`
3. Decrypt ECDSA private key with AES-256-CBC using master key
4. Key format after decryption: `X[32] + Y[32] + d[32]` (all little-endian, reverse each component)

## TLS 1.2 Handshake

All TLS records are prefixed with `44 00 00 00` when sent over USB.

### Client Hello

```
44 00 00 00                    # USB prefix
16 03 03 00 43                 # TLS Handshake record, length=0x43
01 00 00 3f                    # Client Hello, length=0x3f
03 03                          # TLS 1.2
[32 bytes client random]
07 00 00 00 00 00 00 00        # Session ID (7 bytes)
04 c0 05 00 3d                 # Cipher suites: ECDH_ECDSA_WITH_AES_256_CBC_SHA + AES_256_CBC_SHA256
00                             # Compression: none
0a                             # Extensions length
00 04 00 02 00 17              # supported_groups: secp256r1
00 0b 00 02 01 00              # ec_point_formats: uncompressed
```

### Server Hello

- Contains server random (32 bytes at offset 0x0b)
- Session ID: `TLS\x90\x0c\xb8\x01` (device-specific)
- Cipher suite: `0xc005`

### Client Response (Certificate + Key Exchange + Verify + Finished)

1. **Certificate**: Device certificate from RSP6
2. **Client Key Exchange**: ECDHE public key (uncompressed point, 65 bytes)
3. **Certificate Verify**: ECDSA signature (DER, must be exactly 0x48 bytes)
4. **Change Cipher Spec**: `14 03 03 00 01 01`
5. **Encrypted Finished**: MAC-then-encrypt of `14 00 00 0c [verify_data]`

### Key Derivation (TLS)

```
pre_master = ECDH(device_privkey, sensor_ecdh_pubkey)
master_secret = TLS-PRF(pre_master, "master secret", client_random + server_random, 48)
key_block = TLS-PRF(master_secret, "key expansion", client_random + server_random, 288)
```

### Key Block Layout (288 bytes)

| Offset | Size | Key |
|--------|------|-----|
| 0x00 | 32 | client_write_MAC_key |
| 0x20 | 32 | server_write_MAC_key |
| 0x40 | 32 | client_write_key (AES-256) |
| 0x60 | 32 | server_write_key (AES-256) |
| 0x80 | 16 | client_write_IV |
| 0x90 | 16 | server_write_IV |

## MAC-then-Encrypt (Application Data)

1. Build header: `[type(1), 0x03, 0x03, len_hi, len_lo]`
2. HMAC = HMAC-SHA256(client_write_MAC_key, header + data)
3. Payload = data + HMAC (32 bytes)
4. Padding: pad to 16-byte boundary, pad bytes = `pad_len - 1`
5. Encrypt: AES-256-CBC with static IV `4b 77 62 ff a9 03 c1 1e 6f d8 35 93 17 2d 54 ef`
6. Result: IV + ciphertext

## Sensor Commands (over TLS)

### LED Control

| Command | Description |
|---------|-------------|
| `39 20 bf 02 00 ff ff...` (121 bytes) | Green LED solid |
| `39 ee 02 00 00 4b 00...` (121 bytes) | Red LED blink 3x |
| `39 f4 01 00 00 f4 01...` (121 bytes) | Green LED blink |

### Scan

| Step | Command |
|------|---------|
| Setup 1 | `08 5c 20 00 80 07 00 00 00 04` |
| Setup 2 | `07 80 20 00 80 04` |
| Scan matrix | `02 98 00 00 00 23 00 00...` |
| Read data | `51 00 20 00 00` (3 chunks) |
| DB verify | `5e 02 ff 03 00 05 00 01 00 00 00 00 00` |
| Reset 1 | `60 00 00 00 00` |
| Reset 2 | `62 00 00 00 00` |

### Interrupt Patterns (endpoint 0x83)

| Pattern | Meaning |
|---------|---------|
| `00 00 00 00 00` | Waiting for finger |
| `02 00 40 10 00` | Finger down |
| `03 40 01 00 00` | Scanning |
| `03 41 03 00 40` | Scan completed |
| `03 43 04 00 41` | Scan succeeded |
| `03 60 07 00 40` | Too short |
| `03 20 07 00 00` | Too fast |

### Image Format

- Resolution: 144x144 pixels (8-bit grayscale)
- Read in 3 chunks via `51` command
- Chunk 1: payload starts at offset 0x12
- Chunks 2-3: payload starts at offset 0x06

---

## Differences from Validity90 (06cb:00da specific)

> This section will be populated as we test against the actual hardware.

- [ ] Does MSG1 return the same RSP1 format?
- [ ] Is MSG4 (secure blob) the same?
- [ ] Are the RSP6 record types identical?
- [ ] Image resolution: 144x144 or different?
- [ ] Same interrupt patterns?
- [ ] Same LED command format?
