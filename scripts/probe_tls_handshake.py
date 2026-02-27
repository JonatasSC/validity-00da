#!/usr/bin/env python3
"""
Script 1h: Try TLS handshake with the 06cb:00da sensor.

We know:
- 0x44 enters TLS mode (responds with TLS Alert 15 03 03)
- 44 00 00 00 prefix causes timeout
- Raw 16 03 03... returns 01 04

This script tries various TLS approaches to find the right framing:
1. 0x44 alone → read alert → then send Client Hello separately
2. 0x44 + Client Hello in one write (1-byte prefix)
3. Client Hello with no prefix after 0x44 triggers TLS
4. Two-stage: 0x44, read response, then raw TLS Client Hello

Usage: sudo .venv/bin/python3 scripts/probe_tls_handshake.py
"""

import logging
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from validity00da.constants import INIT_MSG1, CLIENT_RANDOM

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


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


def build_client_hello():
    """Build a TLS 1.2 Client Hello (no USB prefix)."""
    # Handshake: Client Hello
    handshake_body = bytearray()
    # TLS version 1.2
    handshake_body.extend(b"\x03\x03")
    # Client random (32 bytes)
    handshake_body.extend(CLIENT_RANDOM)
    # Session ID length=0 (no session)
    handshake_body.append(0x00)
    # Cipher suites: 1 suite (2 bytes length + 2 bytes suite)
    handshake_body.extend(b"\x00\x02")
    handshake_body.extend(b"\xc0\x05")  # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    # Compression methods: 1 method (null)
    handshake_body.extend(b"\x01\x00")
    # Extensions
    extensions = bytearray()
    # supported_groups extension
    extensions.extend(b"\x00\x0a")  # type: supported_groups
    extensions.extend(b"\x00\x04")  # length
    extensions.extend(b"\x00\x02\x00\x17")  # secp256r1
    # ec_point_formats
    extensions.extend(b"\x00\x0b")  # type: ec_point_formats
    extensions.extend(b"\x00\x02")  # length
    extensions.extend(b"\x01\x00")  # uncompressed
    # Extensions length
    handshake_body.extend(len(extensions).to_bytes(2, "big"))
    handshake_body.extend(extensions)

    # Handshake header: type=ClientHello (0x01), length
    handshake = bytearray()
    handshake.append(0x01)
    handshake.extend(len(handshake_body).to_bytes(3, "big"))
    handshake.extend(handshake_body)

    # TLS Record header: type=Handshake (0x16), version=TLS 1.2, length
    record = bytearray()
    record.extend(b"\x16\x03\x03")
    record.extend(len(handshake).to_bytes(2, "big"))
    record.extend(handshake)

    return bytes(record)


def build_client_hello_v90():
    """Build Client Hello matching the Validity90 template exactly (without USB prefix)."""
    return bytes([
        # TLS Record: Handshake, TLS 1.2, length=0x43
        0x16, 0x03, 0x03, 0x00, 0x43,
        # Handshake: Client Hello, length=0x3f
        0x01, 0x00, 0x00, 0x3f,
        # TLS version 1.2
        0x03, 0x03,
        # Client random (32 bytes)
        *CLIENT_RANDOM,
        # Session ID length=7, then 7 zero bytes
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        # Cipher suites: 2 suites (4 bytes)
        0x04,
        0xc0, 0x05,  # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        0x00, 0x3d,  # TLS_RSA_WITH_AES_256_CBC_SHA256
        # Compression methods: none
        0x00,
        # Extensions (10 bytes)
        0x0a,
        0x00, 0x04, 0x00, 0x02, 0x00, 0x17,  # supported_groups: secp256r1
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  # ec_point_formats: uncompressed
    ])


def try_approach(dev, name, data_to_send, expect_multi=False):
    """Send data, read response(s), report what happened."""
    log.info("")
    log.info("=== %s ===", name)
    log.info("  Sending %d bytes: %s", len(data_to_send), data_to_send.hex()[:80])

    try:
        dev.write(data_to_send)
    except Exception as e:
        log.info("  WRITE FAILED: %s", e)
        return None

    time.sleep(0.1)

    responses = []
    for i in range(3 if expect_multi else 1):
        rsp = dev.read(timeout=3000)
        if rsp is None:
            log.info("  Read %d: timeout", i + 1)
            break
        responses.append(rsp)
        log.info("  Read %d: %d bytes — %s", i + 1, len(rsp),
                 rsp.hex()[:80] + ("..." if len(rsp.hex()) > 80 else ""))

        # Classify
        if len(rsp) >= 5 and rsp[0] == 0x16 and rsp[1] == 0x03:
            hs_type = rsp[5] if len(rsp) > 5 else 0
            types = {0x02: "ServerHello", 0x0b: "Certificate", 0x0c: "ServerKeyExchange",
                     0x0d: "CertificateRequest", 0x0e: "ServerHelloDone"}
            log.info("  → TLS Handshake record! Type: 0x%02x (%s)", hs_type,
                     types.get(hs_type, "unknown"))
        elif len(rsp) >= 3 and rsp[0] == 0x15:
            alert_level = rsp[5] if len(rsp) > 5 else rsp[3] if len(rsp) > 3 else 0
            alert_desc = rsp[6] if len(rsp) > 6 else rsp[4] if len(rsp) > 4 else 0
            levels = {1: "warning", 2: "fatal"}
            descs = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
                     40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
                     47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error",
                     51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
                     80: "internal_error", 90: "user_canceled", 100: "no_renegotiation"}
            log.info("  → TLS Alert! Level=%s(%d) Desc=%s(%d)",
                     levels.get(alert_level, "?"), alert_level,
                     descs.get(alert_desc, "?"), alert_desc)
        elif rsp == b"\x01\x04":
            log.info("  → Error: unknown command (01 04)")
        elif rsp == b"\x05\x04":
            log.info("  → Error: needs parameters (05 04)")
        elif rsp == b"\x00\x00":
            log.info("  → ACK (00 00)")
        elif len(rsp) == 2 and rsp[1] == 0x04:
            log.info("  → Error: %02x 04", rsp[0])

        if not expect_multi:
            break
        time.sleep(0.1)

    return responses


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

        ch_standard = build_client_hello()
        ch_v90 = build_client_hello_v90()

        # ── Test 1: 0x44 alone ──
        try_approach(dev, "Test 1: 0x44 alone", bytes([0x44]))
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 2: 0x44 as 1-byte prefix + TLS Client Hello ──
        data = bytes([0x44]) + ch_standard
        try_approach(dev, "Test 2: 0x44 prefix + standard Client Hello", data, expect_multi=True)
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 3: 0x44 as 1-byte prefix + V90 Client Hello ──
        data = bytes([0x44]) + ch_v90
        try_approach(dev, "Test 3: 0x44 prefix + V90 Client Hello", data, expect_multi=True)
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 4: Send 0x44, then Client Hello in separate write ──
        log.info("")
        log.info("=== Test 4: Two-stage — 0x44 then Client Hello ===")
        dev.write(bytes([0x44]))
        time.sleep(0.1)
        rsp1 = dev.read(timeout=2000)
        log.info("  After 0x44: %d bytes — %s", len(rsp1) if rsp1 else 0,
                 rsp1.hex() if rsp1 else "timeout")

        # Now in TLS mode, send raw Client Hello
        dev.write(ch_standard)
        time.sleep(0.1)
        rsp2 = dev.read(timeout=3000)
        log.info("  After Client Hello: %d bytes — %s", len(rsp2) if rsp2 else 0,
                 rsp2.hex()[:80] if rsp2 else "timeout")
        if rsp2:
            rsp3 = dev.read(timeout=2000)
            if rsp3:
                log.info("  Extra read: %d bytes — %s", len(rsp3), rsp3.hex()[:80])
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 5: V90 style with 44 00 00 00 prefix ──
        data = bytes([0x44, 0x00, 0x00, 0x00]) + ch_v90
        try_approach(dev, "Test 5: V90 full prefix (44 00 00 00) + V90 Client Hello", data)
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 6: Raw Client Hello without any prefix ──
        try_approach(dev, "Test 6: Raw TLS Client Hello (no prefix)", ch_standard)
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 7: 0x44 then V90 Client Hello separately ──
        log.info("")
        log.info("=== Test 7: Two-stage — 0x44 then V90 Client Hello ===")
        dev.write(bytes([0x44]))
        time.sleep(0.1)
        rsp1 = dev.read(timeout=2000)
        log.info("  After 0x44: %d bytes — %s", len(rsp1) if rsp1 else 0,
                 rsp1.hex() if rsp1 else "timeout")
        dev.write(ch_v90)
        time.sleep(0.1)
        rsp2 = dev.read(timeout=3000)
        log.info("  After V90 Client Hello: %d bytes — %s", len(rsp2) if rsp2 else 0,
                 rsp2.hex()[:80] if rsp2 else "timeout")
        if rsp2:
            rsp3 = dev.read(timeout=2000)
            if rsp3:
                log.info("  Extra read: %d bytes — %s", len(rsp3), rsp3.hex()[:80])
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 8: Just the handshake content (no record header) after 0x44 ──
        # Maybe the sensor treats 0x44 as "switch to TLS" and then reads
        # raw handshake bytes without the TLS record framing
        handshake_body = ch_standard[5:]  # Skip TLS record header
        log.info("")
        log.info("=== Test 8: Two-stage — 0x44 then handshake body only ===")
        dev.write(bytes([0x44]))
        time.sleep(0.1)
        rsp1 = dev.read(timeout=2000)
        log.info("  After 0x44: %d bytes — %s", len(rsp1) if rsp1 else 0,
                 rsp1.hex() if rsp1 else "timeout")
        dev.write(handshake_body)
        time.sleep(0.1)
        rsp2 = dev.read(timeout=3000)
        log.info("  After handshake body: %d bytes — %s", len(rsp2) if rsp2 else 0,
                 rsp2.hex()[:80] if rsp2 else "timeout")
        time.sleep(0.3)
        ensure_raw_mode(dev)

        # ── Test 9: 0x44 with sub-byte parameters (like 0x44 0x01, 0x44 0x02) ──
        log.info("")
        log.info("=== Test 9: 0x44 with sub-bytes ===")
        for sub in range(0x10):
            data = bytes([0x44, sub])
            try:
                dev.write(data)
            except Exception:
                ensure_raw_mode(dev)
                continue
            time.sleep(0.05)
            rsp = dev.read(timeout=2000)
            if rsp:
                cat = "tls_alert" if (len(rsp) >= 3 and rsp[0] == 0x15) else "other"
                if rsp == b"\x01\x04":
                    cat = "unknown_cmd"
                elif rsp == b"\x05\x04":
                    cat = "needs_params"
                log.info("  0x44 0x%02x -> %s: %d bytes — %s", sub, cat, len(rsp), rsp.hex()[:40])
            else:
                log.info("  0x44 0x%02x -> timeout", sub)

            if rsp and len(rsp) >= 3 and rsp[0] == 0x15:
                time.sleep(0.2)
                ensure_raw_mode(dev)

        log.info("")
        log.info("=== Done ===")

    except Exception as e:
        log.error("Fatal: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
