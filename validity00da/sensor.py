"""
High-level sensor commands: LED control, fingerprint scan, verify.
All commands are sent over an established TLS session.
"""

import logging
from typing import Optional, Tuple

from .tls_session import TLSSession
from .constants import (
    LED_GREEN_ON, LED_RED_BLINK, LED_GREEN_BLINK,
    SCAN_SETUP1, SCAN_SETUP2, SCAN_READ_DATA, SCAN_MATRIX,
    DB_VERIFY, RESET_CMD1, RESET_CMD2,
    INT_WAITING_FINGER, INT_FINGER_DOWN, INT_FINGER_DOWN_ALT,
    INT_SCANNING, INT_SCAN_COMPLETED, INT_SCAN_OK, INT_SCAN_OK_V97,
    INT_SCAN_TOO_SHORT, INT_SCAN_TOO_SHORT2, INT_SCAN_TOO_FAST,
    IMAGE_WIDTH, IMAGE_HEIGHT,
)

log = logging.getLogger(__name__)


class Sensor:
    """High-level interface to the fingerprint sensor."""

    def __init__(self, tls: TLSSession):
        self.tls = tls

    # ── LED commands ──

    def led_green_on(self):
        """Turn green LED on (solid)."""
        log.info("LED: green on")
        self.tls.app_cmd(LED_GREEN_ON)

    def led_red_blink(self):
        """Blink red LED 3 times."""
        log.info("LED: red blink")
        self.tls.app_cmd(LED_RED_BLINK)

    def led_green_blink(self):
        """Blink green LED."""
        log.info("LED: green blink")
        self.tls.app_cmd(LED_GREEN_BLINK)

    # ── Scan commands ──

    def scan_fingerprint(self) -> Optional[bytes]:
        """
        Capture a fingerprint image.

        Returns raw image data (IMAGE_WIDTH * IMAGE_HEIGHT bytes) or None on failure.
        The image is 8-bit grayscale, 144x144 pixels (may differ for 00da).
        """
        log.info("Starting fingerprint scan")

        # Turn on green LED
        self.led_green_on()

        # Setup (optional but included for completeness)
        self.tls.app_cmd(SCAN_SETUP1)
        self.tls.app_cmd(SCAN_SETUP2)

        # Send scan matrix program
        self.tls.app_cmd(SCAN_MATRIX)

        # Wait for scan via interrupts
        scan_result = self._wait_for_scan()
        if not scan_result:
            log.error("Scan failed")
            self.led_red_blink()
            return None

        # Read image in 3 chunks
        image = self._read_image()
        log.info("Captured image: %d bytes", len(image))

        return image

    def verify_fingerprint(self, image: Optional[bytes] = None) -> Tuple[bool, int]:
        """
        Verify captured fingerprint against on-device DB.
        Returns (matched, finger_id). finger_id > 0 means match.
        """
        log.info("Verifying fingerprint against DB")
        self.tls.app_cmd(DB_VERIFY)

        # Wait for match result interrupt
        finger_id = -1
        while True:
            interrupt = self.tls.dev.read_interrupt(timeout=5000)
            if interrupt is None:
                log.warning("Verification timeout")
                break

            log.info("Verify interrupt: %s", interrupt.hex())
            if len(interrupt) >= 3 and interrupt[0] == 0x03:
                finger_id = interrupt[2]
                break

        # Reset for next scan
        self._reset()

        if finger_id > 0:
            log.info("Match! Finger ID: %d", finger_id)
            self.led_green_blink()
            return True, finger_id
        else:
            log.info("No match (unknown fingerprint)")
            self.led_red_blink()
            return False, 0

    def scan_and_verify(self) -> Tuple[Optional[bytes], bool, int]:
        """
        Complete scan + verify flow.
        Returns (image_data, matched, finger_id).
        """
        image = self.scan_fingerprint()
        if image is None:
            return None, False, 0

        matched, finger_id = self.verify_fingerprint()
        return image, matched, finger_id

    # ── Internal helpers ──

    def _wait_for_scan(self) -> bool:
        """Wait for interrupt sequence indicating scan complete. Returns success."""
        log.info("Waiting for finger...")

        while True:
            interrupt = self.tls.dev.read_interrupt()
            if interrupt is None:
                continue

            log.debug("Interrupt: %s", interrupt.hex())

            if interrupt == INT_WAITING_FINGER:
                log.info("Waiting for finger...")

            elif interrupt in (INT_FINGER_DOWN, INT_FINGER_DOWN_ALT):
                log.info("Finger detected on sensor")

            elif interrupt == INT_SCANNING:
                log.info("Scanning in progress...")

            elif interrupt == INT_SCAN_COMPLETED:
                log.info("Scan completed")

            elif interrupt in (INT_SCAN_OK, INT_SCAN_OK_V97):
                log.info("Scan succeeded!")
                return True

            elif interrupt in (INT_SCAN_TOO_SHORT, INT_SCAN_TOO_SHORT2):
                log.warning("Scan failed: finger removed too quickly")
                return False

            elif interrupt == INT_SCAN_TOO_FAST:
                log.warning("Scan failed: finger moved too fast")
                return False

            else:
                log.debug("Unknown interrupt: %s", interrupt.hex())

    def _read_image(self) -> bytes:
        """Read fingerprint image data in 3 chunks."""
        image = bytearray()

        # Chunk 1: offset 0x12
        rsp1 = self.tls.app_cmd(SCAN_READ_DATA)
        image.extend(rsp1[0x12:])

        # Chunk 2: offset 0x06
        rsp2 = self.tls.app_cmd(SCAN_READ_DATA)
        image.extend(rsp2[0x06:])

        # Chunk 3: offset 0x06
        rsp3 = self.tls.app_cmd(SCAN_READ_DATA)
        image.extend(rsp3[0x06:])

        return bytes(image[:IMAGE_WIDTH * IMAGE_HEIGHT])

    def _reset(self):
        """Reset sensor state for next operation."""
        self.tls.app_cmd(RESET_CMD1)
        self.tls.app_cmd(RESET_CMD2)
