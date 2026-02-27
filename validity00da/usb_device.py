"""
USB communication wrapper using pyusb.
Handles open/read/write/interrupt for the fingerprint sensor.
"""

import logging
from typing import Optional

import usb.core
import usb.util

from .constants import (
    VENDOR_ID, PRODUCT_ID,
    EP_OUT, EP_IN, EP_INTERRUPT,
    USB_TIMEOUT, INTERRUPT_TIMEOUT,
)

log = logging.getLogger(__name__)


class USBDevice:
    """Low-level USB communication with the fingerprint sensor."""

    def __init__(self, vid: int = VENDOR_ID, pid: int = PRODUCT_ID):
        self.vid = vid
        self.pid = pid
        self.dev: Optional[usb.core.Device] = None

    def open(self) -> bool:
        """Find and claim the USB device. Returns True on success."""
        self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.dev is None:
            log.error("Device %04x:%04x not found", self.vid, self.pid)
            return False

        log.info(
            "Found device %04x:%04x on bus %d addr %d",
            self.vid, self.pid, self.dev.bus, self.dev.address,
        )

        # Detach kernel driver if active
        if self.dev.is_kernel_driver_active(0):
            log.info("Detaching kernel driver")
            self.dev.detach_kernel_driver(0)

        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        log.info("Device opened and interface claimed")
        return True

    def close(self):
        """Release the USB device."""
        if self.dev is not None:
            usb.util.release_interface(self.dev, 0)
            usb.util.dispose_resources(self.dev)
            self.dev = None
            log.info("Device closed")

    def write(self, data: bytes, timeout: int = USB_TIMEOUT) -> int:
        """Send data via bulk OUT endpoint. Returns bytes written."""
        assert self.dev is not None, "Device not opened"
        log.debug("USB WRITE (%d bytes): %s", len(data), data.hex())
        written = self.dev.write(EP_OUT, data, timeout=timeout)
        return written

    def read(self, size: int = 0x100000, timeout: int = USB_TIMEOUT) -> bytes:
        """Read data from bulk IN endpoint."""
        assert self.dev is not None, "Device not opened"
        data = self.dev.read(EP_IN, size, timeout=timeout)
        result = bytes(data)
        log.debug("USB READ (%d bytes): %s", len(result), result.hex())
        return result

    def cmd(self, data: bytes, timeout: int = USB_TIMEOUT) -> bytes:
        """Send command and read response."""
        self.write(data, timeout=timeout)
        return self.read(timeout=timeout)

    def read_interrupt(self, timeout: int = INTERRUPT_TIMEOUT) -> Optional[bytes]:
        """Read interrupt transfer. Returns None on timeout."""
        assert self.dev is not None, "Device not opened"
        try:
            data = self.dev.read(EP_INTERRUPT, 0x100, timeout=timeout)
            result = bytes(data)
            log.debug("USB INT (%d bytes): %s", len(result), result.hex())
            return result
        except usb.core.USBTimeoutError:
            return None
        except usb.core.USBError as e:
            if "timed out" in str(e).lower():
                return None
            raise

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
