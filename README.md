# validity-00da

Driver prototype for the Synaptics `06cb:00da` (FS7605) fingerprint sensor found in ThinkPad E14/E15 laptops.

Based on reverse engineering from the [Validity90](https://github.com/nmikhailov/Validity90) project which supports similar sensors (`138a:0090`, `138a:0097`, `06cb:009a`).

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Setup & environment | Done |
| 1 | Probe (does sensor respond?) | Pending |
| 2 | Full init (MSG1-MSG6, key extraction) | Pending |
| 3 | TLS handshake | Pending |
| 4 | Sensor commands (scan, verify) | Pending |

## Setup

### Dependencies

```bash
pip install -r requirements.txt
```

### udev rules (avoid sudo)

Create `/etc/udev/rules.d/99-validity-00da.rules`:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="06cb", ATTR{idProduct}=="00da", MODE="0666", GROUP="plugdev"
```

Then reload:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Verify device is detected

```bash
lsusb | grep 06cb:00da
```

## Usage

### Phase 1: Probe the sensor

```bash
sudo python3 scripts/probe.py
```

Sends MSG1 (`0x01`) and checks if the sensor responds with the expected Validity90 protocol.

### Phase 2: Full initialization

```bash
sudo python3 scripts/init_full.py
```

Runs MSG1-MSG6 sequence and extracts TLS certificate, ECDSA private key, and ECDH public key from RSP6.

### Phase 3: TLS handshake

```bash
sudo python3 scripts/handshake.py
```

Establishes encrypted TLS 1.2 session with the sensor.

### Phase 4: Scan fingerprint

```bash
sudo python3 scripts/scan.py [output.png]
```

Captures a fingerprint image and verifies against the on-device database.

### Dump raw traffic

```bash
sudo python3 scripts/dump_traffic.py
```

Logs all USB exchanges to `logs/` for protocol analysis.

## Architecture

```
validity00da/
├── constants.py     # Static bytes, keys, init sequences from Validity90
├── usb_device.py    # pyusb wrapper (open/read/write/interrupt)
├── protocol.py      # Init sequence MSG1-MSG6, RSP6 parsing
├── crypto.py        # TLS-PRF, AES-256-CBC, ECDH, ECDSA, key derivation
├── tls_session.py   # Custom TLS 1.2 handshake + encrypted communication
└── sensor.py        # High-level commands (LED, scan, verify)
```

## Protocol Overview

The sensor uses a custom protocol over USB bulk transfers:

1. **Init phase**: 6 message exchanges (MSG1-MSG6) to initialize the sensor and extract cryptographic material
2. **TLS handshake**: Modified TLS 1.2 with ECDH_ECDSA_WITH_AES_256_CBC_SHA, all records prefixed with `0x44 0x00 0x00 0x00`
3. **Encrypted commands**: Sensor control (LED, scan, verify) over the TLS channel

See [PROTOCOL.md](PROTOCOL.md) for the full protocol specification.

## References

- [Validity90](https://github.com/nmikhailov/Validity90) - C prototype for `138a:0090` family
- [python-validity](https://github.com/nicegreengorilla/python-validity) - Python driver for `06cb:009a`
