#!/usr/bin/env python3
"""
Script 1g: Deep analysis of 0xae 0x00 response (270-byte config/calibration dump).

1. Read the response multiple times to identify fluctuating vs static bytes
2. Parse the TLV-like structure
3. Try to correlate with known Validity90 config structures

Usage: sudo .venv/bin/python3 scripts/analyze_ae.py
"""

import logging
import sys
import os
import time
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.constants import INIT_MSG1

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


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


def read_ae(dev):
    """Send 0xae 0x00 and return response."""
    dev.write(bytes([0xae, 0x00]))
    time.sleep(0.05)
    return dev.read(timeout=2000)


def hex_line(data, offset, length=16):
    """Format hex dump line."""
    chunk = data[offset:offset + length]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"  {offset:04x}: {hex_part:<48s}  {ascii_part}"


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        try:
            dev.reset()
        except Exception:
            pass
        if not ensure_raw_mode(dev):
            log.error("Cannot enter raw mode")
            sys.exit(1)

        # ── 1. Read multiple samples to find fluctuating bytes ──
        log.info("=== Reading 0xae 0x00 — 10 samples ===")
        samples = []
        for i in range(10):
            rsp = read_ae(dev)
            if rsp and len(rsp) >= 4 and rsp[0:2] == b"\x00\x00":
                samples.append(rsp)
                log.info("  Sample %d: %d bytes", i + 1, len(rsp))
            else:
                log.warning("  Sample %d: unexpected response: %s", i + 1,
                            rsp.hex()[:40] if rsp else "None")
            time.sleep(0.2)

        if not samples:
            log.error("No valid samples!")
            sys.exit(1)

        ref = samples[0]
        log.info("")
        log.info("=== Full hex dump (sample 1, %d bytes) ===", len(ref))
        for off in range(0, len(ref), 16):
            log.info(hex_line(ref, off))

        # ── 2. Find fluctuating bytes ──
        log.info("")
        log.info("=== Byte stability analysis ===")
        fluctuating = []
        for pos in range(len(ref)):
            values = set()
            for s in samples:
                if pos < len(s):
                    values.add(s[pos])
            if len(values) > 1:
                fluctuating.append((pos, values))

        if fluctuating:
            log.info("Fluctuating bytes (%d):", len(fluctuating))
            for pos, vals in fluctuating:
                vals_str = ", ".join(f"0x{v:02x}" for v in sorted(vals))
                log.info("  offset 0x%03x: {%s}", pos, vals_str)
        else:
            log.info("All bytes are stable across %d reads!", len(samples))

        # ── 3. Parse as TLV-like records ──
        log.info("")
        log.info("=== Attempting TLV parse (after 2-byte status) ===")
        data = ref[2:]  # Skip 00 00 status
        offset = 0
        record_num = 0

        while offset + 4 <= len(data):
            rec_type = struct.unpack_from("<H", data, offset)[0]
            rec_size = struct.unpack_from("<H", data, offset + 2)[0]

            if rec_type == 0xFFFF:
                log.info("  Record %d @ 0x%03x: type=0xFFFF (end marker)", record_num, offset + 2)
                break

            if rec_size == 0 or offset + 4 + rec_size > len(data):
                # Try interpreting differently
                log.info("  Record %d @ 0x%03x: type=0x%04x size=0x%04x (invalid, stopping TLV parse)",
                         record_num, offset + 2, rec_type, rec_size)
                break

            rec_data = data[offset + 4:offset + 4 + rec_size]
            log.info("  Record %d @ 0x%03x: type=0x%04x size=%d",
                     record_num, offset + 2, rec_type, rec_size)
            log.info("    data: %s", rec_data.hex()[:80] + ("..." if len(rec_data.hex()) > 80 else ""))

            # Try to interpret as int32 values if size is multiple of 4
            if rec_size % 4 == 0 and rec_size >= 4:
                int32s = struct.unpack_from(f"<{rec_size // 4}i", rec_data)
                log.info("    as int32[]: %s", list(int32s))

            offset += 4 + rec_size
            record_num += 1

        # ── 4. Try alternate parse: fixed-size fields ──
        log.info("")
        log.info("=== Alternate parse: 16-bit type + 16-bit length prefix per record ===")
        # Maybe the format is: [type:u8] [length:u8] [data...] instead of 16-bit
        data = ref[2:]
        offset = 0
        record_num = 0

        while offset + 2 <= len(data):
            rec_type = data[offset]
            rec_size = data[offset + 1]

            if rec_type == 0xFF:
                log.info("  Record %d @ 0x%03x: type=0xFF (end?)", record_num, offset + 2)
                break

            if rec_size == 0 or offset + 2 + rec_size > len(data):
                log.info("  Record %d @ 0x%03x: type=0x%02x size=0x%02x (invalid, stopping)",
                         record_num, offset + 2, rec_type, rec_size)
                break

            rec_data = data[offset + 2:offset + 2 + rec_size]
            log.info("  Record %d @ 0x%03x: type=0x%02x size=%d data=%s",
                     record_num, offset + 2, rec_type, rec_size,
                     rec_data.hex()[:60] + ("..." if len(rec_data.hex()) > 60 else ""))

            offset += 2 + rec_size
            record_num += 1

        # ── 5. Try yet another parse: Synaptics register dump ──
        # Some Synaptics sensors use: [register_id:u16le] [register_len:u16le] [data...]
        log.info("")
        log.info("=== Parse as register dump (u16le id + u16le len + data) ===")
        data = ref[2:]
        offset = 0
        record_num = 0

        while offset + 4 <= len(data):
            reg_id = struct.unpack_from("<H", data, offset)[0]
            reg_len = struct.unpack_from("<H", data, offset + 2)[0]

            # Sanity check: reg_len should be reasonable
            if reg_len > 256 or offset + 4 + reg_len > len(data):
                # dump remaining as raw
                remaining = data[offset:]
                log.info("  Remaining %d bytes @ 0x%03x: %s",
                         len(remaining), offset + 2, remaining.hex()[:80])
                break

            rec_data = data[offset + 4:offset + 4 + reg_len]
            log.info("  Reg 0x%04x (%3d bytes) @ 0x%03x: %s",
                     reg_id, reg_len, offset + 2,
                     rec_data.hex()[:60] + ("..." if len(rec_data.hex()) > 60 else ""))

            offset += 4 + reg_len
            record_num += 1

        # ── Save full analysis ──
        report_path = os.path.join(LOGS_DIR, "ae_analysis.txt")
        with open(report_path, "w") as f:
            f.write(f"# 0xae 0x00 analysis — {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Response size: {len(ref)} bytes\n")
            f.write(f"Samples collected: {len(samples)}\n\n")

            f.write("## Full hex dump\n")
            for off in range(0, len(ref), 16):
                f.write(hex_line(ref, off) + "\n")

            f.write(f"\n## Fluctuating bytes: {len(fluctuating)}\n")
            for pos, vals in fluctuating:
                vals_str = ", ".join(f"0x{v:02x}" for v in sorted(vals))
                f.write(f"  offset 0x{pos:03x}: {{{vals_str}}}\n")

            f.write("\n## Raw samples (hex)\n")
            for i, s in enumerate(samples):
                f.write(f"  Sample {i}: {s.hex()}\n")

        log.info("")
        log.info("Report saved to %s", report_path)

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
