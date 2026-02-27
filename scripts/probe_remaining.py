#!/usr/bin/env python3
"""
Script 1f: Explore remaining 05 04 commands with multi-byte payloads.

Commands that returned 05 04 (recognized, needs params) but NOT yet explored:
  0x0d, 0x39, 0x41, 0x57, 0x73, 0x7f, 0x80, 0x82, 0x8e, 0x90,
  0x96, 0x99, 0x9e, 0xa0, 0xa1, 0xa3, 0xa4, 0xa6, 0xa9, 0xaa,
  0xab, 0xae

Strategy:
  1. For each command, try cmd + 1 byte (0x00-0x0f) to find valid sub-commands
  2. For hits, try cmd + sub + more bytes to discover payload format
  3. Also try common payload patterns (all zeros, incrementing, etc.)

Usage: sudo .venv/bin/python3 scripts/probe_remaining.py
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

# Commands that returned 05 04 — excluding 0x40 and 0x3f (already explored)
TARGETS = [
    0x39, 0x41, 0x57, 0x73, 0x7f, 0x80, 0x82, 0x8e,
    0x90, 0x96, 0x99, 0x9e, 0xa0, 0xa1, 0xa3, 0xa4,
    0xa6, 0xa9, 0xaa, 0xab, 0xae, 0x0d,
]


def ensure_raw_mode(dev):
    if not dev.is_connected:
        if not dev.reopen():
            return False
    for attempt in range(3):
        try:
            dev.write(INIT_MSG1)
        except Exception:
            if not dev.reopen():
                return False
            continue
        time.sleep(0.1)
        rsp = dev.read(timeout=3000)
        if rsp and len(rsp) >= 38 and rsp[0:2] == b"\x00\x00":
            return True
        if rsp and rsp[0] == 0x15:
            time.sleep(0.3)
            continue
        if rsp:
            return True
        time.sleep(0.5)
    return False


def probe(dev, data):
    try:
        dev.write(data)
    except Exception:
        return None, "disconnected"
    time.sleep(0.05)
    rsp = dev.read(timeout=2000)
    if rsp is None:
        return None, "timeout"
    if len(rsp) == 2:
        if rsp == b"\x00\x00":
            return rsp, "ack"
        if rsp[1] == 0x04:
            return rsp, f"error_{rsp[0]:02x}04"
        return rsp, f"short_{rsp.hex()}"
    if len(rsp) >= 3 and rsp[0] == 0x15:
        return rsp, "tls_alert"
    return rsp, f"data_{len(rsp)}b"


def explore_cmd(dev, cmd, report_lines):
    """Try cmd + sub-byte, then deeper probes for hits."""
    log.info("")
    log.info("=== 0x%02x ===", cmd)
    report_lines.append(f"\n## 0x{cmd:02x}")
    hits = []

    # Phase 1: cmd + 1 byte (0x00-0xff)
    for sub in range(0x100):
        data = bytes([cmd, sub])
        rsp, cat = probe(dev, data)

        if cat in ("disconnected", "tls_alert"):
            log.info("  0x%02x 0x%02x -> %s, reconnecting...", cmd, sub, cat)
            time.sleep(0.5)
            ensure_raw_mode(dev)
            continue

        # Filter out "unknown cmd" and "needs params" — we want actual responses
        if cat not in ("error_0104", "error_0504", "timeout"):
            hits.append((sub, rsp, cat))
            log.info("  0x%02x 0x%02x -> %s: %s", cmd, sub, cat,
                     rsp.hex()[:60] if rsp else "")
            report_lines.append(f"  sub=0x{sub:02x}: {cat} ({len(rsp) if rsp else 0} bytes)"
                                f" — {rsp.hex() if rsp else ''}")

    # Phase 2: For interesting hits, try 3rd byte
    for sub, rsp, cat in hits:
        if cat in ("ack", "error_0504") or cat.startswith("data_"):
            log.info("  --- Deep probe: 0x%02x 0x%02x + 3rd byte ---", cmd, sub)
            for b3 in range(0x10):
                for payload in [
                    bytes([cmd, sub, b3]),
                    bytes([cmd, sub, b3] + [0x00] * 4),
                    bytes([cmd, sub, b3] + [0x00] * 10),
                ]:
                    rsp2, cat2 = probe(dev, payload)
                    if cat2 not in ("error_0104", "error_0504", "timeout",
                                    "error_0304"):
                        log.info("    %s -> %s: %s", payload.hex(), cat2,
                                 rsp2.hex()[:60] if rsp2 else "")
                        report_lines.append(
                            f"  deep {payload.hex()}: {cat2} ({len(rsp2) if rsp2 else 0}b)"
                            f" — {rsp2.hex()[:80] if rsp2 else ''}")
                    if cat2 in ("disconnected", "tls_alert"):
                        ensure_raw_mode(dev)

    if not hits:
        report_lines.append("  (no hits — all 01 04 / 05 04)")

    return hits


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        log.info("=== USB Reset ===")
        try:
            dev.reset()
        except Exception:
            pass
        if not ensure_raw_mode(dev):
            log.error("Cannot enter raw mode")
            sys.exit(1)

        report_lines = [f"# Remaining command scan — {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        all_hits = {}

        for cmd in TARGETS:
            if not ensure_raw_mode(dev):
                log.error("Lost device before 0x%02x", cmd)
                break
            hits = explore_cmd(dev, cmd, report_lines)
            all_hits[cmd] = hits

        # Summary
        log.info("")
        log.info("=== SUMMARY ===")
        interesting = {k: v for k, v in all_hits.items() if v}
        if interesting:
            for cmd, hits in interesting.items():
                log.info("0x%02x: %d hits", cmd, len(hits))
                for sub, rsp, cat in hits:
                    log.info("  sub=0x%02x: %s (%d bytes)", sub, cat,
                             len(rsp) if rsp else 0)
        else:
            log.info("No interesting responses found in any command.")

        report_path = os.path.join(LOGS_DIR, "remaining_scan_results.txt")
        with open(report_path, "w") as f:
            f.write("\n".join(report_lines) + "\n")
        log.info("Report saved to %s", report_path)

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
