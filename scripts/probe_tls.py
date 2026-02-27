#!/usr/bin/env python3
"""
Script 1b: Probe the sensor with TLS Client Hello.

The 06cb:00da responded to MSG1 with a TLS Alert (15 03 03),
meaning it already speaks TLS. This script tries:

1. TLS Client Hello WITH USB prefix (44 00 00 00)
2. TLS Client Hello WITHOUT USB prefix
3. Raw Client Hello (no prefix, no record header)

Usage: sudo .venv/bin/python3 scripts/probe_tls.py
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.protocol import hex_dump
from validity00da.constants import TLS_CLIENT_HELLO, CLIENT_RANDOM

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def parse_tls_record(data: bytes) -> dict:
    """Parse a TLS record header."""
    if len(data) < 5:
        return {"error": "too short for TLS record"}

    content_types = {
        0x14: "ChangeCipherSpec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "ApplicationData",
    }

    alert_descriptions = {
        0: "close_notify", 10: "unexpected_message",
        20: "bad_record_mac", 40: "handshake_failure",
        42: "bad_certificate", 47: "illegal_parameter",
        48: "unknown_ca", 50: "decode_error",
        51: "decrypt_error", 70: "protocol_version",
        71: "insufficient_security", 80: "internal_error",
        86: "inappropriate_fallback", 90: "user_canceled",
        100: "no_renegotiation", 109: "missing_extension",
        110: "unsupported_extension", 112: "unrecognized_name",
    }

    ct = data[0]
    ver_major = data[1]
    ver_minor = data[2]
    length = (data[3] << 8) | data[4]
    payload = data[5:5 + length]

    result = {
        "content_type": content_types.get(ct, f"unknown(0x{ct:02x})"),
        "version": f"{ver_major}.{ver_minor}" + (" (TLS 1.2)" if ver_major == 3 and ver_minor == 3 else ""),
        "length": length,
        "payload_hex": payload.hex() if payload else "",
    }

    if ct == 0x15 and len(payload) >= 2:
        level = "warning" if payload[0] == 1 else "fatal" if payload[0] == 2 else f"unknown({payload[0]})"
        desc = alert_descriptions.get(payload[1], f"unknown(0x{payload[1]:02x})")
        result["alert_level"] = level
        result["alert_description"] = desc
    elif ct == 0x15 and len(payload) > 2:
        result["note"] = "Alert payload > 2 bytes — likely encrypted"

    if ct == 0x16 and len(payload) >= 4:
        hs_types = {
            0: "HelloRequest", 1: "ClientHello", 2: "ServerHello",
            11: "Certificate", 12: "ServerKeyExchange",
            13: "CertificateRequest", 14: "ServerHelloDone",
            15: "CertificateVerify", 16: "ClientKeyExchange",
            20: "Finished",
        }
        hs_type = payload[0]
        result["handshake_type"] = hs_types.get(hs_type, f"unknown(0x{hs_type:02x})")

    return result


def try_probe(dev, name, data):
    """Send data, read response, log and parse."""
    log.info("--- %s (%d bytes) ---", name, len(data))
    log.info("Sending:\n%s", hex_dump(data[:64], "  "))

    try:
        dev.write(data)
        time.sleep(0.1)
        rsp = dev.read(timeout=5000)

        log.info("Response (%d bytes):\n%s", len(rsp), hex_dump(rsp, "  "))

        # Try to parse as TLS
        parsed = parse_tls_record(rsp)
        log.info("Parsed: %s", parsed)

        # Also check if response starts with 44 00 00 00 (USB prefix)
        if len(rsp) >= 4 and rsp[:4] == b"\x44\x00\x00\x00":
            log.info("Response has USB prefix! Parsing inner TLS:")
            inner = parse_tls_record(rsp[4:])
            log.info("Inner: %s", inner)

        # Save raw
        safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "")
        with open(os.path.join(LOGS_DIR, f"probe_tls_{safe_name}.bin"), "wb") as f:
            f.write(rsp)

        return rsp

    except Exception as e:
        log.error("Error: %s", e)
        return None


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Failed to open device")
        sys.exit(1)

    try:
        # Test 1: TLS Client Hello WITH USB prefix (44 00 00 00) — Validity90 style
        hello_with_prefix = bytearray(TLS_CLIENT_HELLO)
        hello_with_prefix[0x0f:0x0f + 0x20] = CLIENT_RANDOM
        rsp1 = try_probe(dev, "ClientHello with USB prefix (44 00 00 00)", bytes(hello_with_prefix))

        # Small delay between attempts
        time.sleep(0.5)

        # Test 2: TLS Client Hello WITHOUT USB prefix — standard TLS
        hello_no_prefix = bytes(hello_with_prefix[4:])  # Skip 44 00 00 00
        rsp2 = try_probe(dev, "ClientHello without prefix (raw TLS)", hello_no_prefix)

        time.sleep(0.5)

        # Test 3: Just the handshake bytes (no TLS record layer)
        # Handshake: Client Hello starting at offset 9
        hello_bare = bytes(hello_with_prefix[9:])
        rsp3 = try_probe(dev, "Bare handshake (no record header)", hello_bare)

        # Summary
        log.info("")
        log.info("=== SUMMARY ===")
        for name, rsp in [("With prefix", rsp1), ("No prefix", rsp2), ("Bare", rsp3)]:
            if rsp and len(rsp) >= 5:
                ct = rsp[0]
                if ct == 0x16:
                    log.info("%s: Got Handshake response! PROTOCOL WORKS", name)
                elif ct == 0x15:
                    log.info("%s: Got Alert (sensor rejected)", name)
                else:
                    log.info("%s: Got 0x%02x (unexpected)", name, ct)

                # Check with prefix stripped
                if len(rsp) >= 9 and rsp[:4] == b"\x44\x00\x00\x00" and rsp[4] == 0x16:
                    log.info("%s: Got prefixed Handshake response! PROTOCOL WORKS", name)
            elif rsp:
                log.info("%s: Short response (%d bytes)", name, len(rsp))
            else:
                log.info("%s: No response", name)

    finally:
        dev.close()


if __name__ == "__main__":
    main()
