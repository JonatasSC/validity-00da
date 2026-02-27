#!/usr/bin/env python3
"""
Utility: Log all raw USB traffic to/from the sensor.
Useful for protocol analysis and debugging.

Usage: sudo python3 scripts/dump_traffic.py [output_file]
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import INIT_MSG1, INIT_MSG2, INIT_MSG3, INIT_MSG4, INIT_MSG5, INIT_MSG6

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def dump_exchange(dev, msg_name, msg_data, log_file):
    """Send a message and log both directions."""
    timestamp = time.strftime("%H:%M:%S")

    entry = f"\n[{timestamp}] >>> {msg_name} ({len(msg_data)} bytes)\n"
    entry += hex_dump(msg_data, "  ") + "\n"

    dev.write(msg_data)

    try:
        rsp = dev.read(timeout=5000)
        entry += f"[{timestamp}] <<< RSP ({len(rsp)} bytes)\n"
        entry += hex_dump(rsp, "  ") + "\n"
    except Exception as e:
        entry += f"[{timestamp}] <<< ERROR: {e}\n"
        rsp = b""

    print(entry)
    if log_file:
        log_file.write(entry)

    return rsp


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", f"dump_{int(time.time())}.log"
    )

    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    messages = [
        ("MSG1", INIT_MSG1),
        ("MSG2", INIT_MSG2),
        ("MSG3", INIT_MSG3),
        ("MSG4", INIT_MSG4),
        ("MSG5", INIT_MSG5),
        ("MSG6", INIT_MSG6),
    ]

    try:
        with open(output, "w") as f:
            f.write(f"# USB Traffic Dump - 06cb:00da\n")
            f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

            for name, data in messages:
                rsp = dump_exchange(dev, name, data, f)

                # Save raw responses
                bin_path = output.rsplit(".", 1)[0] + f"_{name.lower()}.bin"
                with open(bin_path, "wb") as bf:
                    bf.write(rsp)

                if name == "MSG1" and (len(rsp) == 0 or rsp[-1] != 0x07):
                    log.warning("Sensor not initialized, stopping after MSG1")
                    break

        log.info("Traffic dump saved to %s", output)

    except Exception as e:
        log.error("Dump failed: %s", e)
        raise
    finally:
        dev.close()


if __name__ == "__main__":
    main()
