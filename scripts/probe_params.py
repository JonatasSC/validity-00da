#!/usr/bin/env python3
"""
Script 1e: Parameter exploration for known commands on 06cb:00da.

Commands that returned 05 04 (recognized, needs params):
  0x39 (LED), 0x40 (init/crypto), 0x41, 0x57, 0x73, 0x7f, 0x80, 0x82,
  0x8e, 0x90, 0x96, 0x99, 0x9e, 0xa0, 0xa1, 0xa3, 0xa4, 0xa6, 0xa9,
  0xaa, 0xab, 0xae, 0x0d, 0x3f

This script focuses on 0x40 (crypto request) and 0x3f with various sub-commands.

Usage: sudo .venv/bin/python3 scripts/probe_params.py
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import INIT_MSG1, INIT_MSG6

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def ensure_raw_mode(dev):
    """Get sensor into raw init mode."""
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


def probe(dev, data, name=""):
    """Send data, read response. Returns (response, category)."""
    desc = name or data.hex()
    try:
        dev.write(data)
    except Exception:
        return None, "disconnected"

    time.sleep(0.05)
    rsp = dev.read(timeout=2000)
    if rsp is None:
        return None, "timeout"

    cat = "data"
    if len(rsp) == 2:
        if rsp == b"\x00\x00":
            cat = "ack"
        elif rsp[1] == 0x04:
            cat = f"error_{rsp[0]:02x}04"
        else:
            cat = f"short_{rsp.hex()}"
    elif len(rsp) >= 3 and rsp[0] == 0x15:
        cat = "tls_alert"

    return rsp, cat


def explore_command(dev, base_cmd, name, sub_range=range(0x100)):
    """Try base_cmd + 1 byte sub-command for all values in sub_range."""
    log.info("--- %s (0x%02x + sub) ---", name, base_cmd)
    hits = []

    for sub in sub_range:
        data = bytes([base_cmd, sub])
        rsp, cat = probe(dev, data)

        if cat == "disconnected" or cat == "tls_alert":
            log.info("  0x%02x 0x%02x -> %s, reconnecting...", base_cmd, sub, cat)
            time.sleep(0.5)
            ensure_raw_mode(dev)
            continue

        if cat not in ("error_0104", "error_0504", "timeout"):
            hits.append((sub, rsp, cat))
            log.info("  0x%02x 0x%02x -> %s (%d bytes): %s",
                     base_cmd, sub, cat, len(rsp) if rsp else 0,
                     rsp.hex()[:60] if rsp else "")

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

        all_results = {}

        # ── 1. Explore 0x40 (init/crypto request) ──
        # Validity90 MSG6 is: 40 01 01 00 00 00 00 00 00 00 10 00 00
        log.info("")
        log.info("=== Explore 0x40 (init/crypto request) ===")
        hits_40 = explore_command(dev, 0x40, "Init/crypto", range(0x100))
        all_results["0x40"] = hits_40

        if not ensure_raw_mode(dev):
            log.error("Lost device")
            sys.exit(1)

        # For any 0x40 sub-commands that responded, try with more bytes
        for sub, rsp, cat in hits_40:
            if cat in ("ack", "data") or (cat.startswith("error_") and cat != "error_0104"):
                log.info("")
                log.info("=== Deep probe: 0x40 0x%02x + third byte ===", sub)
                for b3 in range(0x10):
                    # Try varying length payloads
                    for payload in [
                        bytes([0x40, sub, b3]),
                        bytes([0x40, sub, b3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00]),
                    ]:
                        rsp2, cat2 = probe(dev, payload)
                        if cat2 not in ("error_0104", "error_0504", "timeout"):
                            log.info("  %s -> %s (%d bytes): %s",
                                     payload.hex(), cat2, len(rsp2) if rsp2 else 0,
                                     rsp2.hex()[:60] if rsp2 else "")
                        if cat2 in ("disconnected", "tls_alert"):
                            ensure_raw_mode(dev)

        # ── 2. Explore 0x3f ──
        log.info("")
        log.info("=== Explore 0x3f ===")
        ensure_raw_mode(dev)
        hits_3f = explore_command(dev, 0x3f, "Cmd 0x3f", range(0x100))
        all_results["0x3f"] = hits_3f

        # ── 3. Explore 0x0d ──
        log.info("")
        log.info("=== Explore 0x0d ===")
        ensure_raw_mode(dev)
        hits_0d = explore_command(dev, 0x0d, "Cmd 0x0d", range(0x20))
        all_results["0x0d"] = hits_0d

        # ── 4. Try known Validity90-style commands with full payload ──
        log.info("")
        log.info("=== Full Validity90 command variants ===")
        ensure_raw_mode(dev)

        full_cmds = [
            # MSG6 variants
            ("MSG6 original",      INIT_MSG6),
            ("MSG6 sub=00",        bytes([0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])),
            ("MSG6 sub=02",        bytes([0x40, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])),
            ("MSG6 sub=03",        bytes([0x40, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00])),
            # Short 0x40 variants
            ("0x40 01 00",         bytes([0x40, 0x01, 0x00])),
            ("0x40 01 01",         bytes([0x40, 0x01, 0x01])),
            ("0x40 01 02",         bytes([0x40, 0x01, 0x02])),
            ("0x40 01 01 00 00",   bytes([0x40, 0x01, 0x01, 0x00, 0x00])),
            # 0x82 variants (recognized cmd)
            ("0x82 00",            bytes([0x82, 0x00])),
            ("0x82 01",            bytes([0x82, 0x01])),
            ("0x82 00 00",         bytes([0x82, 0x00, 0x00])),
            # 0x90 variants
            ("0x90 00",            bytes([0x90, 0x00])),
            ("0x90 01",            bytes([0x90, 0x01])),
        ]

        for name, cmd in full_cmds:
            rsp, cat = probe(dev, cmd, name)
            if rsp and cat not in ("error_0104",):
                log.info("  %-25s -> %s (%d bytes): %s",
                         name, cat, len(rsp),
                         rsp.hex()[:60] + ("..." if rsp and len(rsp.hex()) > 60 else ""))
            else:
                log.info("  %-25s -> %s", name, cat)

            if cat in ("disconnected", "tls_alert"):
                ensure_raw_mode(dev)

        # ── Summary ──
        log.info("")
        log.info("=== SUMMARY ===")
        for group, hits in all_results.items():
            if hits:
                log.info("%s: %d sub-commands responded", group, len(hits))
                for sub, rsp, cat in hits:
                    log.info("  sub=0x%02x: %s (%d bytes) %s",
                             sub, cat, len(rsp) if rsp else 0,
                             rsp.hex()[:40] if rsp else "")

        # Save report
        report_path = os.path.join(LOGS_DIR, "param_scan_results.txt")
        with open(report_path, "w") as f:
            f.write(f"# Parameter scan results — {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for group, hits in all_results.items():
                f.write(f"\n## {group}\n")
                for sub, rsp, cat in hits:
                    f.write(f"  sub=0x{sub:02x}: {cat} ({len(rsp) if rsp else 0} bytes)")
                    if rsp:
                        f.write(f" — {rsp.hex()}")
                    f.write("\n")
        log.info("Report saved to %s", report_path)

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
