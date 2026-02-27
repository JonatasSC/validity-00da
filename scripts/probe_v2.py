#!/usr/bin/env python3
"""
Script 1c: Smart probe for 06cb:00da.

Findings so far:
- Sensor uses Validity90 raw init protocol (MSG1 = 0x01)
- May start in TLS mode from previous session, needs reset first
- RSP1 last byte = 0x03 (vs 0x07 on Validity90)

This script:
1. Sends MSG1 to check state
2. If TLS Alert received, sensor was in TLS mode — MSG1 reset it
3. Sends MSG1 again to get clean RSP1
4. Tries MSG2-MSG6 to see how far we get

Usage: sudo .venv/bin/python3 scripts/probe_v2.py
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import (
    INIT_MSG1, INIT_MSG2, INIT_MSG3, INIT_MSG4, INIT_MSG5, INIT_MSG6,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def is_tls_alert(data: bytes) -> bool:
    """Check if response is a TLS Alert record."""
    return len(data) >= 3 and data[0] == 0x15 and data[1] == 0x03 and data[2] == 0x03


def analyze_rsp1(data: bytes):
    """Analyze RSP1 structure and compare with Validity90."""
    log.info("RSP1 analysis:")
    log.info("  Length: %d bytes (Validity90 expects 38)", len(data))
    log.info("  Bytes 0-1 (status): %s", data[0:2].hex())
    log.info("  Bytes 2-7 (device info): %s", data[2:8].hex())

    if len(data) >= 12:
        log.info("  Byte 9 (version?): 0x%02x (Validity90: 0x06)", data[9])
        log.info("  Byte 10-11: 0x%02x 0x%02x (Validity90: 0x07 0x01)", data[10], data[11])
        log.info("  Byte 12 (config?): 0x%02x (Validity90: 0x30)", data[12])

    if len(data) > 0:
        last = data[-1]
        log.info("  Last byte (state): 0x%02x", last)
        if last == 0x07:
            log.info("    -> INITIALIZED (same as Validity90, ready for MSG2-MSG6)")
        elif last == 0x02:
            log.info("    -> NEEDS SETUP (first-time init required)")
        elif last == 0x03:
            log.info("    -> STATE 0x03 (unknown — may need different init path)")
        else:
            log.info("    -> UNKNOWN STATE")


def try_init_sequence(dev):
    """Try sending MSG2-MSG6 and log responses."""
    messages = [
        ("MSG2", INIT_MSG2, "State query"),
        ("MSG3", INIT_MSG3, "Config query"),
        ("MSG4", INIT_MSG4, "Secure blob"),
        ("MSG5", INIT_MSG5, "State query 2"),
        ("MSG6", INIT_MSG6, "Request crypto"),
    ]

    for name, msg, desc in messages:
        log.info("")
        log.info("=== %s — %s (%d bytes) ===", name, desc, len(msg))
        log.info("Sending: %s", msg[:16].hex() + ("..." if len(msg) > 16 else ""))

        try:
            dev.write(msg)
            time.sleep(0.1)
            rsp = dev.read(timeout=5000)
            log.info("Response (%d bytes):", len(rsp))
            # Show first 128 bytes max
            print(hex_dump(rsp[:128], "  "))
            if len(rsp) > 128:
                log.info("  ... (%d more bytes)", len(rsp) - 128)

            # Save raw
            with open(os.path.join(LOGS_DIR, f"probe_v2_{name.lower()}.bin"), "wb") as f:
                f.write(rsp)

            # Check for error responses
            if len(rsp) == 2 and rsp == b"\x00\x00":
                log.info("  -> ACK (success)")
            elif is_tls_alert(rsp):
                log.warning("  -> TLS Alert! Sensor dropped to TLS mode")
                return False

        except Exception as e:
            log.error("  -> FAILED: %s", e)
            log.error("  Sensor may not support %s in this state", name)
            return False

    return True


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        # Step 1: Send MSG1 (may get TLS Alert if sensor is in TLS mode)
        log.info("=== Step 1: First MSG1 (reset TLS state if needed) ===")
        dev.write(INIT_MSG1)
        time.sleep(0.1)
        rsp1 = dev.read(timeout=5000)
        log.info("First response (%d bytes):", len(rsp1))
        print(hex_dump(rsp1, "  "))

        with open(os.path.join(LOGS_DIR, "probe_v2_rsp1_first.bin"), "wb") as f:
            f.write(rsp1)

        if is_tls_alert(rsp1):
            log.info("Got TLS Alert — sensor was in TLS mode, now reset")
            log.info("Sending MSG1 again...")
            time.sleep(0.5)

            dev.write(INIT_MSG1)
            time.sleep(0.1)
            rsp1 = dev.read(timeout=5000)
            log.info("Second response (%d bytes):", len(rsp1))
            print(hex_dump(rsp1, "  "))

            with open(os.path.join(LOGS_DIR, "probe_v2_rsp1_second.bin"), "wb") as f:
                f.write(rsp1)

        if is_tls_alert(rsp1):
            log.error("Still getting TLS Alert after retry. Sensor stuck in TLS mode.")
            log.info("Try: unplug/replug the sensor, or reboot")
            sys.exit(1)

        # Step 2: Analyze RSP1
        log.info("")
        log.info("=== Step 2: RSP1 Analysis ===")
        analyze_rsp1(rsp1)

        last_byte = rsp1[-1] if len(rsp1) > 0 else 0

        # Step 3: Try init sequence regardless of state
        log.info("")
        log.info("=== Step 3: Init Sequence (MSG2-MSG6) ===")
        log.info("Attempting MSG2-MSG6 (state byte=0x%02x)...", last_byte)

        success = try_init_sequence(dev)

        if success:
            log.info("")
            log.info("=== SUCCESS: Full init sequence completed! ===")
        else:
            log.info("")
            log.info("=== Init sequence stopped (see errors above) ===")

    except Exception as e:
        log.error("Fatal: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
