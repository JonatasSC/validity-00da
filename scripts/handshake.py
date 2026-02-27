#!/usr/bin/env python3
"""
Script 3: TLS handshake test.
Performs full init + TLS handshake with the sensor.

Usage: sudo python3 scripts/handshake.py
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import full_init
from validity00da.tls_session import TLSSession

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    dev = USBDevice()

    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        log.info("=== Phase 1: Init ===")
        keys = full_init(dev)
        log.info("Keys extracted successfully")

        log.info("=== Phase 2: TLS Handshake ===")
        tls = TLSSession(dev, keys)
        tls.handshake()

        log.info("=== TLS Session Established ===")
        log.info("Client write key: %s", tls.client_write_key.hex())
        log.info("Server write key: %s", tls.server_write_key.hex())

    except Exception as e:
        log.error("Handshake failed: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
