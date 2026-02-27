"""
Protocol handling: init sequences MSG1-MSG6, response parsing.
"""

import logging
from typing import Tuple

from .usb_device import USBDevice
from .constants import (
    INIT_MSG1, INIT_MSG2, INIT_MSG3, INIT_MSG4, INIT_MSG5, INIT_MSG6,
    RSP1_INITIALIZED,
)
from .crypto import parse_rsp6, get_system_serial

log = logging.getLogger(__name__)


def hex_dump(data: bytes, prefix: str = "") -> str:
    """Format bytes as hex dump string."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part}")
    return "\n".join(lines)


def send_msg1(dev: USBDevice) -> Tuple[bytes, bool]:
    """
    Send MSG1 (0x01) and parse RSP1.
    Returns (response_bytes, sensor_initialized).
    The last byte of RSP1 indicates state:
    - 0x07: sensor initialized, proceed with MSG2-MSG6
    - other: sensor needs setup
    """
    log.info("Sending MSG1 (probe)")
    rsp = dev.cmd(INIT_MSG1)
    log.info("RSP1 (%d bytes):\n%s", len(rsp), hex_dump(rsp, "  "))

    initialized = len(rsp) > 0 and rsp[-1] == RSP1_INITIALIZED
    if initialized:
        log.info("Sensor reports initialized (last byte=0x%02x)", rsp[-1])
    else:
        last = rsp[-1] if len(rsp) > 0 else 0
        log.warning("Sensor NOT initialized (last byte=0x%02x)", last)

    return rsp, initialized


def send_init_sequence(dev: USBDevice) -> bytes:
    """
    Send MSG2-MSG6 and return RSP6 (large response with crypto material).
    Assumes MSG1 was already sent and sensor is initialized.
    """
    log.info("Sending MSG2 (0x19)")
    rsp2 = dev.cmd(INIT_MSG2)
    log.info("RSP2 (%d bytes):\n%s", len(rsp2), hex_dump(rsp2, "  "))

    log.info("Sending MSG3 (0x43 0x02)")
    rsp3 = dev.cmd(INIT_MSG3)
    log.info("RSP3 (%d bytes):\n%s", len(rsp3), hex_dump(rsp3, "  "))

    log.info("Sending MSG4 (secure blob, %d bytes)", len(INIT_MSG4))
    rsp4 = dev.cmd(INIT_MSG4)
    log.info("RSP4 (%d bytes):\n%s", len(rsp4), hex_dump(rsp4, "  "))

    log.info("Sending MSG5 (0x3e)")
    rsp5 = dev.cmd(INIT_MSG5)
    log.info("RSP5 (%d bytes):\n%s", len(rsp5), hex_dump(rsp5, "  "))

    log.info("Sending MSG6 (final init, %d bytes)", len(INIT_MSG6))
    rsp6 = dev.cmd(INIT_MSG6)
    log.info("RSP6 (%d bytes)", len(rsp6))

    return rsp6


def full_init(dev: USBDevice) -> dict:
    """
    Perform complete initialization: MSG1-MSG6, parse RSP6.
    Returns dict with crypto material from parse_rsp6().
    """
    rsp1, initialized = send_msg1(dev)

    if not initialized:
        raise RuntimeError(
            f"Sensor not initialized (last byte=0x{rsp1[-1]:02x}). "
            "May need setup sequence first."
        )

    rsp6 = send_init_sequence(dev)

    serial = get_system_serial()
    log.info("System serial (%d bytes): %s", len(serial), serial)

    # Try VirtualBox serial first (for testing), then real serial
    vbox_serial = b"VirtualBox\x00" + b"0\x00"
    try:
        keys = parse_rsp6(rsp6, vbox_serial)
        log.info("RSP6 parsed with VirtualBox serial")
    except (ValueError, Exception):
        keys = parse_rsp6(rsp6, serial)
        log.info("RSP6 parsed with system serial")

    return keys
