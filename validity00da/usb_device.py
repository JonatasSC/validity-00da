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

        # Detach kernel driver if active (Linux only)
        try:
            if self.dev.is_kernel_driver_active(0):
                log.info("Detaching kernel driver")
                self.dev.detach_kernel_driver(0)
        except NotImplementedError:
            pass  # Not supported on Windows

        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        log.info("Device opened and interface claimed")
        return True

    def reset(self):
        """USB reset the device. Re-finds it since reset changes the address."""
        assert self.dev is not None, "Device not opened"
        log.info("Resetting USB device")
        try:
            self.dev.reset()
        except usb.core.USBError:
            pass  # Reset often causes a transient error

        # Device gets a new address after reset — must re-find it
        import time
        usb.util.dispose_resources(self.dev)
        self.dev = None
        time.sleep(1.5)

        self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.dev is None:
            raise RuntimeError("Device not found after USB reset")

        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except NotImplementedError:
            pass  # Not supported on Windows

        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        log.info("Device reset complete (bus %d addr %d)", self.dev.bus, self.dev.address)

    def close(self):
        """Release the USB device."""
        if self.dev is not None:
            try:
                usb.util.release_interface(self.dev, 0)
            except usb.core.USBError:
                pass
            try:
                usb.util.dispose_resources(self.dev)
            except usb.core.USBError:
                pass
            self.dev = None
            log.info("Device closed")

    @property
    def is_connected(self) -> bool:
        """Check if device handle is still valid."""
        if self.dev is None:
            return False
        try:
            self.dev.get_active_configuration()
            return True
        except (usb.core.USBError, usb.core.NoBackendError):
            return False

    def reopen(self) -> bool:
        """Close and re-open the device (e.g. after it disconnected)."""
        self.close()
        import time
        time.sleep(2)
        return self.open()

    def write(self, data: bytes, timeout: int = USB_TIMEOUT) -> int:
        """Send data via bulk OUT endpoint. Returns bytes written."""
        assert self.dev is not None, "Device not opened"
        log.debug("USB WRITE (%d bytes): %s", len(data), data.hex())
        written = self.dev.write(EP_OUT, data, timeout=timeout)
        return written

    def read(self, size: int = 0x100000, timeout: int = USB_TIMEOUT) -> Optional[bytes]:
        """Read data from bulk IN endpoint. Returns None on timeout."""
        assert self.dev is not None, "Device not opened"
        try:
            data = self.dev.read(EP_IN, size, timeout=timeout)
            result = bytes(data)
            log.debug("USB READ (%d bytes): %s", len(result), result.hex())
            return result
        except usb.core.USBTimeoutError:
            log.debug("USB READ timeout")
            return None
        except usb.core.USBError as e:
            if "timed out" in str(e).lower():
                log.debug("USB READ timeout")
                return None
            raise

    def cmd(self, data: bytes, timeout: int = USB_TIMEOUT) -> Optional[bytes]:
        """Send command and read response. Returns None on timeout."""
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
