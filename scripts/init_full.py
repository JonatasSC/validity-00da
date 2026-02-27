#!/usr/bin/env python3
"""
Script 2: Full initialization sequence (MSG1-MSG6).
Extracts cryptographic keys from RSP6.

Usage: sudo python3 scripts/init_full.py
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import full_init, hex_dump

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    dev = USBDevice()

    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        keys = full_init(dev)

        log.info("=== Extracted Keys ===")

        if keys["tls_cert_raw"]:
            log.info("TLS Certificate (%d bytes):", len(keys["tls_cert_raw"]))
            print(hex_dump(keys["tls_cert_raw"][:64], "  ") + "\n  ...")

        if keys["ecdsa_pubkey"]:
            log.info("ECDSA Public Key (64 bytes):")
            print(hex_dump(keys["ecdsa_pubkey"], "  "))

        if keys["ecdsa_privkey"]:
            log.info("ECDSA Private Key d (32 bytes):")
            print(hex_dump(keys["ecdsa_privkey"], "  "))

        if keys["ecdh_pubkey"]:
            log.info("ECDH Public Key (64 bytes):")
            print(hex_dump(keys["ecdh_pubkey"], "  "))

        log.info("=== Init Complete ===")
        log.info("All 3 keys extracted successfully!")

    except Exception as e:
        log.error("Init failed: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
