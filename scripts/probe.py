#!/usr/bin/env python3
"""
Script 1: Probe the sensor.
Sends MSG1 (0x01) and logs the response.
Tests if the sensor responds to the Validity90 protocol.

Usage: sudo python3 scripts/probe.py
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import INIT_MSG1

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    dev = USBDevice()

    if not dev.open():
        log.error("Failed to open device. Is the sensor connected? Do you have permissions?")
        log.info("Try: sudo python3 %s", sys.argv[0])
        log.info("Or configure udev rules (see README.md)")
        sys.exit(1)

    try:
        log.info("Sending MSG1 (0x01) to sensor 06cb:00da...")
        dev.write(INIT_MSG1)

        log.info("Reading response...")
        rsp = dev.read(timeout=5000)

        log.info("RSP1 received (%d bytes):", len(rsp))
        print(hex_dump(rsp))

        # Analyze response
        if len(rsp) == 0:
            log.warning("Empty response - sensor may not support this protocol")

        elif len(rsp) >= 38:
            last_byte = rsp[-1]
            log.info("Last byte: 0x%02x", last_byte)

            if last_byte == 0x07:
                log.info("SUCCESS: Sensor initialized! Ready for MSG2-MSG6.")
            elif last_byte == 0x02:
                log.info("Sensor needs setup (first-time initialization)")
            else:
                log.info("Unknown state byte: 0x%02x", last_byte)

            # Check VID/PID in response (bytes 10-11 often contain device info)
            log.info("Response structure matches Validity90 format: %s",
                     "YES" if len(rsp) in range(36, 42) else "MAYBE (unexpected length)")

        else:
            log.warning("Short response (%d bytes) - protocol may differ", len(rsp))
            log.info("Compare with expected RSP1 (38 bytes) from Validity90")

        # Save raw response
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "logs", "probe_rsp1.bin")
        with open(log_path, "wb") as f:
            f.write(rsp)
        log.info("Raw response saved to %s", log_path)

    except Exception as e:
        log.error("Error: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
