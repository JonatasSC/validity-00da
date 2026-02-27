#!/usr/bin/env python3
"""
Script 4: Capture fingerprint image.
Performs full init + TLS + scan, saves image as PNG.

Usage: sudo python3 scripts/scan.py [output.png]
"""

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import full_init
from validity00da.tls_session import TLSSession
from validity00da.sensor import Sensor
from validity00da.constants import IMAGE_WIDTH, IMAGE_HEIGHT

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def save_image(data: bytes, filename: str, width: int = IMAGE_WIDTH, height: int = IMAGE_HEIGHT):
    """Save raw grayscale image as PNG."""
    try:
        from PIL import Image
        img = Image.frombytes("L", (width, height), data)
        img.save(filename)
        log.info("Image saved: %s (%dx%d)", filename, width, height)
    except ImportError:
        # Fallback: save raw
        raw_name = filename.rsplit(".", 1)[0] + ".raw"
        with open(raw_name, "wb") as f:
            f.write(data)
        log.info("Pillow not installed, saved raw: %s", raw_name)


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "fingerprint.png"

    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        log.info("=== Initializing ===")
        keys = full_init(dev)

        log.info("=== TLS Handshake ===")
        tls = TLSSession(dev, keys)
        tls.handshake()

        log.info("=== Scanning ===")
        sensor = Sensor(tls)
        image, matched, finger_id = sensor.scan_and_verify()

        if image:
            save_image(image, output)

            # Also save raw
            raw_path = output.rsplit(".", 1)[0] + ".raw"
            with open(raw_path, "wb") as f:
                f.write(image)
            log.info("Raw image saved: %s", raw_path)

        if matched:
            log.info("Fingerprint MATCHES DB! Finger ID: %d", finger_id)
        else:
            log.info("Fingerprint not recognized (unknown)")

    except Exception as e:
        log.error("Scan failed: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
