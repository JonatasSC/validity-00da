#!/usr/bin/env python3
"""
Script 2a: Attempt provisioning sequence for 06cb:00da.

Follows the setup() sequence from the Validity90 C prototype (main.c),
which was captured from the Windows Synaptics driver for 06cb:00da.

Setup sequence (C prototype):
  Step 2:  0x19 (MSG2) — query state
  Step 4:  0x06 blob (init_sequence_msg4, 485 bytes) — encrypted config
  Step 5:  0x3e (MSG5) — flash info
  Step 6:  0x08 ... — write HW register
  Step 7:  0x07 ... — read HW register
  Step 8:  0x75 — identify
  Step 9:  0x06 blob (setup_sequence_config_data, 11333 bytes) — large config
  Step 5b: 0x3e (MSG5 again)
  Step 10: 0x3e (flash info again)
  Step 11: 0x4f blob (877 bytes) — partition flash + certs
  Step 12: 0x01 (MSG1) — ROM info
  Step 13: 0x50 — finalize provisioning
  Step 14: 0x1a — commit/cleanup

Usage: sudo .venv/bin/python3 scripts/provision.py
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.constants import INIT_MSG1, INIT_MSG2, INIT_MSG5
from validity00da.setup_blobs import (
    INIT_SEQUENCE_MSG4,
    SETUP_SEQUENCE_MSG6,
    SETUP_SEQUENCE_MSG7,
    SETUP_SEQUENCE_MSG8,
    SETUP_SEQUENCE_CONFIG_DATA,
    SETUP_SEQUENCE_MSG11,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def send_and_log(dev, data, name, timeout=5000, expect_disconnect=False):
    """Send command, read response, log everything. Returns (response, success)."""
    log.info("")
    log.info("--- %s (%d bytes) ---", name, len(data))
    log.info("  Send: %s%s", data.hex()[:60], "..." if len(data) > 30 else "")

    try:
        dev.write(data)
    except Exception as e:
        log.error("  WRITE FAILED: %s", e)
        if expect_disconnect:
            return None, False
        return None, False

    time.sleep(0.1)
    rsp = dev.read(timeout=timeout)

    if rsp is None:
        log.warning("  Response: TIMEOUT")
        return None, False

    log.info("  Response: %d bytes — %s%s",
             len(rsp), rsp.hex()[:80],
             "..." if len(rsp) > 40 else "")

    # Classify response
    if len(rsp) >= 2 and rsp[0:2] == b"\x00\x00":
        if len(rsp) == 2:
            log.info("  → ACK (00 00)")
        else:
            log.info("  → OK + %d bytes data", len(rsp))
        return rsp, True
    elif len(rsp) == 2 and rsp == b"\x01\x04":
        log.error("  → ERROR: Unknown command (01 04)")
        return rsp, False
    elif len(rsp) == 2 and rsp == b"\x05\x04":
        log.error("  → ERROR: Needs parameters (05 04)")
        return rsp, False
    elif len(rsp) == 2 and rsp[1] == 0x04:
        log.error("  → ERROR: %02x 04", rsp[0])
        return rsp, False
    elif len(rsp) == 2 and rsp[1] == 0x06:
        log.error("  → ERROR: %02x 06", rsp[0])
        return rsp, False
    elif len(rsp) >= 3 and rsp[0] == 0x15:
        log.error("  → TLS Alert")
        return rsp, False
    else:
        log.info("  → Data response (%d bytes)", len(rsp))
        return rsp, True


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    results = []

    try:
        # USB Reset
        log.info("=== USB Reset ===")
        try:
            dev.reset()
        except Exception:
            pass

        # Step 1: MSG1 to establish raw mode and check state
        rsp, ok = send_and_log(dev, INIT_MSG1, "Step 1: MSG1 (0x01) — ROM info")
        if not ok or rsp is None:
            log.error("Cannot communicate with sensor")
            sys.exit(1)
        if len(rsp) >= 38:
            state = rsp[-1]
            log.info("  Sensor state: 0x%02x %s", state,
                     "(not provisioned)" if state == 0x03 else
                     "(initialized)" if state == 0x07 else "(unknown)")
        results.append(("MSG1", ok, len(rsp) if rsp else 0))

        # Step 2: MSG2 (query state)
        rsp, ok = send_and_log(dev, INIT_MSG2, "Step 2: MSG2 (0x19) — query state")
        results.append(("MSG2", ok, len(rsp) if rsp else 0))

        # Step 4: Init blob (0x06 + encrypted config, 485 bytes)
        rsp, ok = send_and_log(dev, INIT_SEQUENCE_MSG4,
                               "Step 4: Init blob (0x06, 485 bytes)",
                               timeout=10000, expect_disconnect=True)
        results.append(("Init blob", ok, len(rsp) if rsp else 0))

        if rsp is None or not dev.is_connected:
            log.warning("Device may have disconnected after 0x06 blob, attempting reconnect...")
            time.sleep(2)
            if not dev.reopen():
                log.error("Cannot reconnect!")
                sys.exit(1)
            # Re-enter raw mode
            rsp_msg1 = dev.cmd(INIT_MSG1, timeout=3000)
            if rsp_msg1:
                log.info("  Reconnected, MSG1: %d bytes", len(rsp_msg1))

        # Step 5: MSG5 (flash info)
        rsp, ok = send_and_log(dev, INIT_MSG5, "Step 5: MSG5 (0x3e) — flash info")
        results.append(("MSG5", ok, len(rsp) if rsp else 0))

        # Step 6: Write HW register (0x08 ...)
        rsp, ok = send_and_log(dev, SETUP_SEQUENCE_MSG6,
                               "Step 6: Write HW register (0x08)")
        results.append(("HW write", ok, len(rsp) if rsp else 0))

        # Step 7: Read HW register (0x07 ...)
        rsp, ok = send_and_log(dev, SETUP_SEQUENCE_MSG7,
                               "Step 7: Read HW register (0x07)")
        results.append(("HW read", ok, len(rsp) if rsp else 0))

        # Step 8: Identify (0x75)
        rsp, ok = send_and_log(dev, SETUP_SEQUENCE_MSG8,
                               "Step 8: Identify (0x75)")
        results.append(("Identify", ok, len(rsp) if rsp else 0))

        # Step 9: Large config blob (0x06, 11333 bytes)
        rsp, ok = send_and_log(dev, SETUP_SEQUENCE_CONFIG_DATA,
                               "Step 9: Config data (0x06, 11333 bytes)",
                               timeout=15000, expect_disconnect=True)
        results.append(("Config blob", ok, len(rsp) if rsp else 0))

        if rsp is None or not dev.is_connected:
            log.warning("Device may have disconnected after config blob, attempting reconnect...")
            time.sleep(2)
            if not dev.reopen():
                log.error("Cannot reconnect!")
                # Try to continue anyway
            else:
                rsp_msg1 = dev.cmd(INIT_MSG1, timeout=3000)
                if rsp_msg1:
                    log.info("  Reconnected, MSG1: %d bytes", len(rsp_msg1))

        # Step 5b: MSG5 again
        rsp, ok = send_and_log(dev, INIT_MSG5, "Step 5b: MSG5 (0x3e) — flash info again")
        results.append(("MSG5 (2)", ok, len(rsp) if rsp else 0))

        # Step 10: MSG5 (flash info, same as 0x3e)
        rsp, ok = send_and_log(dev, bytes([0x3e]),
                               "Step 10: Flash info (0x3e) — check partitions")
        results.append(("MSG5 (3)", ok, len(rsp) if rsp else 0))

        # Step 11: Partition flash (0x4f, 877 bytes)
        rsp, ok = send_and_log(dev, SETUP_SEQUENCE_MSG11,
                               "Step 11: Partition flash (0x4f, 877 bytes)",
                               timeout=15000)
        results.append(("Partition", ok, len(rsp) if rsp else 0))
        if rsp and ok and len(rsp) > 2:
            log.info("  *** PARTITION RESPONSE: %d bytes ***", len(rsp))
            log.info("  Full hex: %s", rsp.hex())

        # Step 12: MSG1 (ROM info again — check if state changed)
        rsp, ok = send_and_log(dev, INIT_MSG1, "Step 12: MSG1 (0x01) — check new state")
        results.append(("MSG1 (2)", ok, len(rsp) if rsp else 0))
        if rsp and len(rsp) >= 38:
            new_state = rsp[-1]
            log.info("  *** NEW STATE: 0x%02x %s ***", new_state,
                     "(PROVISIONED!)" if new_state == 0x07 else
                     "(still not provisioned)" if new_state == 0x03 else
                     f"(changed to 0x{new_state:02x}!)")

        # Step 13: Finalize (0x50)
        rsp, ok = send_and_log(dev, bytes([0x50]),
                               "Step 13: Finalize provisioning (0x50)",
                               timeout=15000)
        results.append(("Finalize", ok, len(rsp) if rsp else 0))
        if rsp and ok and len(rsp) > 2:
            log.info("  *** FINALIZE RESPONSE: %d bytes ***", len(rsp))
            log.info("  First 80 hex: %s", rsp.hex()[:160])
            log.info("  Last 80 hex: %s", rsp.hex()[-160:])

        # Step 14: Commit (0x1a)
        rsp, ok = send_and_log(dev, bytes([0x1a]),
                               "Step 14: Commit (0x1a)")
        results.append(("Commit", ok, len(rsp) if rsp else 0))

        # Final MSG1 to check state
        rsp, ok = send_and_log(dev, INIT_MSG1, "Final: MSG1 — check final state")
        if rsp and len(rsp) >= 38:
            final_state = rsp[-1]
            log.info("  *** FINAL STATE: 0x%02x ***", final_state)

        # ── Summary ──
        log.info("")
        log.info("=== SUMMARY ===")
        for name, ok, size in results:
            status = "OK" if ok else "FAIL"
            log.info("  %-20s %s (%d bytes)", name, status, size)

        # Save report
        report_path = os.path.join(LOGS_DIR, "provision_results.txt")
        with open(report_path, "w") as f:
            f.write(f"# Provisioning attempt — {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for name, ok, size in results:
                f.write(f"  {name}: {'OK' if ok else 'FAIL'} ({size} bytes)\n")
        log.info("Report saved to %s", report_path)

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
