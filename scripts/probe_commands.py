#!/usr/bin/env python3
"""
Script 1d: Command discovery for 06cb:00da.

Probes which command bytes the sensor accepts by sending each one
and classifying the response. Handles device disconnections gracefully.

Usage: sudo .venv/bin/python3 scripts/probe_commands.py

The sensor may disconnect mid-scan — the script will reconnect and continue.
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import INIT_MSG1

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def ensure_raw_mode(dev):
    """Send MSG1 to get sensor into raw init mode. Reconnects if needed."""
    if not dev.is_connected:
        log.info("Device disconnected, reconnecting...")
        if not dev.reopen():
            log.error("Failed to reconnect")
            return False

    for attempt in range(3):
        try:
            dev.write(INIT_MSG1)
        except Exception:
            log.info("Write failed, reconnecting...")
            if not dev.reopen():
                return False
            continue

        time.sleep(0.1)
        rsp = dev.read(timeout=3000)

        if rsp is None:
            log.warning("MSG1 timeout, attempt %d/3", attempt + 1)
            time.sleep(1)
            continue

        if len(rsp) >= 38 and rsp[0:2] == b"\x00\x00":
            log.info("Sensor in raw mode (state=0x%02x)", rsp[-1])
            return True

        if len(rsp) >= 3 and rsp[0] == 0x15:
            log.info("TLS Alert, retrying... (%d/3)", attempt + 1)
            time.sleep(0.5)
            continue

        log.info("MSG1 response (%d bytes): %s", len(rsp), rsp.hex()[:40])
        return True  # Something responded, consider it working

    return False


def probe_cmd(dev, cmd_bytes, timeout=1500):
    """Send command, return (response_bytes_or_None, category_string)."""
    try:
        dev.write(cmd_bytes)
    except Exception:
        return None, "disconnected"

    time.sleep(0.05)
    rsp = dev.read(timeout=timeout)

    if rsp is None:
        return None, "timeout"
    if rsp == b"\x01\x04":
        return rsp, "error_0104"
    if len(rsp) >= 3 and rsp[0] == 0x15:
        return rsp, "tls_alert"
    return rsp, "data"


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        # Initial reset
        log.info("=== USB Reset ===")
        try:
            dev.reset()
        except Exception as e:
            log.warning("Reset: %s — continuing", e)

        if not ensure_raw_mode(dev):
            log.error("Cannot get sensor into raw mode")
            sys.exit(1)

        results = {}

        # ── Single-byte command scan ──
        log.info("")
        log.info("=== Single-byte command scan (0x00-0xFF) ===")
        log.info("~4 minutes, reconnects automatically if sensor drops...")

        for cmd in range(0x100):
            if cmd == 0x01:
                results[cmd] = (b"(MSG1 - skipped)", "skip")
                continue

            rsp, cat = probe_cmd(dev, bytes([cmd]))
            results[cmd] = (rsp, cat)

            if cat == "data":
                log.info("  0x%02x -> %d bytes: %s", cmd, len(rsp),
                         rsp.hex()[:64] + ("..." if len(rsp.hex()) > 64 else ""))

            elif cat in ("tls_alert", "disconnected"):
                log.info("  0x%02x -> %s, reconnecting...", cmd, cat)
                time.sleep(0.5)
                if not ensure_raw_mode(dev):
                    log.error("Lost device at cmd 0x%02x, saving partial results", cmd)
                    break

            if cmd > 0 and cmd % 32 == 0:
                log.info("  ... scanned up to 0x%02x", cmd)

        # ── Multi-byte commands ──
        log.info("")
        log.info("=== Known multi-byte commands ===")
        if not ensure_raw_mode(dev):
            log.warning("Could not enter raw mode for Part 2, skipping")
        else:
            known_cmds = [
                ("ROM info (43 01)",       bytes([0x43, 0x01])),
                ("FW version (43 04)",     bytes([0x43, 0x04])),
                ("Partition (43 02)",      bytes([0x43, 0x02])),
                ("Partition (43 03)",      bytes([0x43, 0x03])),
                ("Flash (43 05)",          bytes([0x43, 0x05])),
                ("Flash (43 06)",          bytes([0x43, 0x06])),
                ("Cleanup (1a)",           bytes([0x1a])),
                ("DB info (45)",           bytes([0x45])),
                ("Get children (46 00)",   bytes([0x46, 0x00])),
                ("Query (75)",             bytes([0x75])),
                ("Blob (06 01)",           bytes([0x06, 0x01])),
                ("Blob (06 02)",           bytes([0x06, 0x02])),
                ("Init 40 00",             bytes([0x40, 0x00])),
                ("Init 40 01",             bytes([0x40, 0x01])),
                ("Init 40 02",             bytes([0x40, 0x02])),
                ("Send init (17)",         bytes([0x17])),
                ("WoE (20)",               bytes([0x20])),
            ]

            for name, cmd in known_cmds:
                rsp, cat = probe_cmd(dev, cmd)

                if cat == "data":
                    log.info("  %-30s -> %d bytes: %s", name, len(rsp),
                             rsp.hex()[:60] + ("..." if len(rsp.hex()) > 60 else ""))
                elif cat == "error_0104":
                    log.info("  %-30s -> error (01 04)", name)
                elif cat == "timeout":
                    log.info("  %-30s -> timeout", name)
                else:
                    log.info("  %-30s -> %s", name, cat)
                    if cat in ("tls_alert", "disconnected"):
                        if not ensure_raw_mode(dev):
                            log.warning("Lost device, stopping Part 2")
                            break

        # ── Report ──
        responding = {k: v for k, v in results.items() if v[1] == "data"}
        errors = {k: v for k, v in results.items() if v[1] == "error_0104"}
        timeouts = {k: v for k, v in results.items() if v[1] == "timeout"}
        alerts = {k: v for k, v in results.items() if v[1] == "tls_alert"}
        disconn = {k: v for k, v in results.items() if v[1] == "disconnected"}

        log.info("")
        log.info("=== RESULTS ===")
        log.info("Data responses: %d", len(responding))
        for cmd, (rsp, _) in sorted(responding.items()):
            log.info("  0x%02x: %d bytes — %s", cmd, len(rsp),
                     rsp.hex()[:80] + ("..." if len(rsp.hex()) > 80 else ""))
        log.info("Error (01 04): %d", len(errors))
        log.info("Timeout: %d", len(timeouts))
        log.info("TLS Alert: %d", len(alerts))
        log.info("Disconnected: %d", len(disconn))

        report_path = os.path.join(LOGS_DIR, "command_scan_results.txt")
        with open(report_path, "w") as f:
            f.write("# Command scan results for 06cb:00da\n")
            f.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("## Data responses:\n")
            for cmd, (rsp, _) in sorted(responding.items()):
                f.write(f"  0x{cmd:02x}: {len(rsp):4d} bytes — {rsp.hex()}\n")
            f.write(f"\n## Error (01 04): {len(errors)}\n")
            f.write("  " + " ".join(f"0x{c:02x}" for c in sorted(errors.keys())) + "\n")
            f.write(f"\n## Timeout: {len(timeouts)}\n")
            if timeouts:
                f.write("  " + " ".join(f"0x{c:02x}" for c in sorted(timeouts.keys())) + "\n")
            f.write(f"\n## TLS Alert: {len(alerts)}\n")
            if alerts:
                f.write("  " + " ".join(f"0x{c:02x}" for c in sorted(alerts.keys())) + "\n")
            f.write(f"\n## Disconnected: {len(disconn)}\n")
            if disconn:
                f.write("  " + " ".join(f"0x{c:02x}" for c in sorted(disconn.keys())) + "\n")

        log.info("Report saved to %s", report_path)

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
