#!/usr/bin/env python3
"""
Probe de comandos via TLS tunnel — testa quais comandos o sensor aceita.

Envia cada comando (single byte) via TLS e classifica a resposta:
  - 00 00: ACK/success
  - 01 04: Unknown command
  - 03 04: Parameter error
  - 04 04: State blocked
  - 05 04: Needs parameters
  - Outros: dados reais

Foca nos comandos identificados pelo synaTudor como relevantes para provisioning.

Uso:
  sudo python3 scripts/tls_probe_commands.py
  sudo PROBE_ALL=1 python3 scripts/tls_probe_commands.py  # scan 0x00-0xFF

Log: logs/tls_probe_commands.txt
"""

import sys
import os
import hashlib
import hmac as hmac_mod
import struct
import secrets
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice

# Reuse from tls_provision
from scripts.tls_provision import (
    Logger, TlsSession, tls_prf_sha256, tls_prf_sha384,
    do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_commands.txt")

# synaTudor command map
CMD_NAMES = {
    0x00: "NOP",
    0x01: "GET_VERSION",
    0x05: "ACK_UNKNOWN",
    0x0d: "UNKNOWN_0D",
    0x0e: "PROVISION",
    0x10: "RESET_OWNERSHIP",
    0x19: "GET_START_INFO",
    0x39: "UNKNOWN_39",
    0x3e: "FLASH_INFO",
    0x3f: "FLASH_OP",
    0x40: "MSG6_INIT",
    0x41: "UNKNOWN_41",
    0x44: "TLS_DATA",
    0x4f: "TAKE_OWNERSHIP_EX2",
    0x50: "GET_CERTIFICATE_EX",
    0x57: "UNKNOWN_57",
    0x73: "UNKNOWN_73",
    0x7c: "ACK_7C",
    0x7f: "FRAME_ACQ",
    0x80: "FRAME_FINISH",
    0x81: "FRAME_STATE_SET",
    0x82: "FRAME_STATE_GET",
    0x86: "EVENT_CONFIG",
    0x87: "EVENT_READ",
    0x8d: "ACK_8D",
    0x8e: "SENSOR_INFO",
    0x90: "UNKNOWN_90",
    0x93: "PAIR",
    0x96: "UNKNOWN_96",
    0x99: "UNKNOWN_99",
    0x9e: "DB2_GET_DB_INFO",
    0x9f: "DB2_GET_OBJ_LIST",
    0xa0: "DB2_GET_OBJ_INFO",
    0xa1: "DB2_GET_OBJ_DATA",
    0xa2: "DB2_WRITE_OBJ",
    0xa3: "DB2_DELETE_OBJ",
    0xa4: "DB2_CLEANUP",
    0xa5: "DB2_FORMAT",
    0xa6: "UNKNOWN_A6",
    0xa9: "UNKNOWN_A9",
    0xaa: "UNKNOWN_AA",
    0xab: "UNKNOWN_AB",
    0xae: "SENSOR_CONFIG",
    0xec: "UNKNOWN_EC",
    0xed: "UNKNOWN_ED",
    0xfe: "UNKNOWN_FE",
}

# Status codes
STATUS_NAMES = {
    b"\x00\x00": "SUCCESS/ACK",
    b"\x01\x04": "UNKNOWN_CMD",
    b"\x03\x04": "PARAM_ERROR",
    b"\x04\x04": "STATE_BLOCKED",
    b"\x05\x04": "NEEDS_PARAMS",
    b"\xe5\x06": "NOT_AVAILABLE",
    b"\xe7\x06": "NOT_PROVISIONED",
}


def classify_response(rsp):
    """Classify a TLS command response."""
    if rsp is None:
        return "TIMEOUT/ALERT"
    if len(rsp) == 2:
        status = STATUS_NAMES.get(rsp, f"STATUS_{rsp.hex()}")
        return status
    return f"DATA({len(rsp)}B)"


def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")

    probe_all = os.environ.get("PROBE_ALL", "0") == "1"

    if probe_all:
        # Scan all 256 commands
        cmds = list(range(0x100))
        log.info("Mode: FULL SCAN (0x00-0xFF)")
    else:
        # Only interesting commands from synaTudor + known commands
        cmds = [
            0x00, 0x01, 0x05,                          # Basic
            0x0e, 0x10,                                  # Provisioning
            0x19, 0x3e, 0x3f,                           # State/Flash
            0x4f, 0x50,                                  # Ownership/Cert
            0x7c, 0x7f, 0x80, 0x81, 0x82,              # Frame
            0x86, 0x87,                                  # Events
            0x8d, 0x8e,                                  # Sensor info
            0x93,                                         # Pair
            0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,  # DB2
            0xae,                                         # Sensor config
            0xec, 0xed, 0xfe,                            # Unknown but recognized
        ]
        log.info(f"Mode: TARGETED ({len(cmds)} commands)")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)
    log.info(f"Sensor: bus {dev.dev.bus} addr {dev.dev.address}")

    try:
        # Setup: Pre-TLS → PAIR → Reset → Pre-TLS → TLS
        log.separator()
        log.info("Setup: Pre-TLS + PAIR + Reset + TLS")

        pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        log.info("PAIR...")
        pairing_data = do_pair(dev, log)
        if not pairing_data:
            log.error("PAIR falhou!")
            return

        dev.reset()
        time.sleep(1)
        pre_tls_phase(dev, log, round_num=3)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        log.info("TLS Handshake...")
        session = do_handshake(dev, log, pairing_data)
        if not session:
            log.error("TLS falhou!")
            return

        # Probe commands
        log.separator()
        log.info("=== PROBE START ===")

        results = {}
        alerts = 0

        # Skip dangerous commands that crash the sensor
        skip_cmds = {0x05, 0x06, 0x0e, 0x10, 0x44, 0x93}
        skip_reason = {
            0x05: "ACK (pode desestabilizar sessao)",
            0x06: "USB disconnect",
            0x0e: "PROVISION (USB disconnect)",
            0x10: "RESET_OWNERSHIP (USB disconnect)",
            0x44: "TLS_DATA (recursivo)",
            0x93: "PAIR (ja feito)",
        }

        for cmd in cmds:
            name = CMD_NAMES.get(cmd, "")
            label = f"0x{cmd:02x}" + (f" ({name})" if name else "")

            if cmd in skip_cmds:
                log.info(f"  {label:35s} → SKIPPED ({skip_reason[cmd]})")
                results[cmd] = ("SKIPPED", None)
                continue

            try:
                rsp = session.command(bytes([cmd]), raw=True, timeout=3000)
            except Exception as e:
                log.error(f"  {label:35s} → USB ERROR: {e}")
                results[cmd] = ("USB_ERROR", None)
                break

            cls = classify_response(rsp)
            results[cmd] = (cls, rsp)

            # Log concisely
            if rsp and len(rsp) > 2:
                log.info(f"  {label:35s} → {cls}: {rsp[:32].hex()}{'...' if len(rsp) > 32 else ''}")
            else:
                log.info(f"  {label:35s} → {cls}")

            if rsp is None:
                alerts += 1
                if alerts >= 2:
                    log.error("Muitos alerts seguidos — sessao TLS morta")
                    break
            else:
                alerts = 0

            time.sleep(0.2)  # More delay between commands for stability

        # Summary
        log.separator()
        log.info("=== SUMMARY ===")

        categories = {}
        for cmd, (cls, rsp) in results.items():
            categories.setdefault(cls, []).append(cmd)

        for cls in sorted(categories.keys()):
            cmds_list = categories[cls]
            cmds_hex = [f"0x{c:02x}" for c in cmds_list]
            log.info(f"  {cls:20s}: {', '.join(cmds_hex)}")

        # Highlight interesting results (data responses)
        log.separator("-", 40)
        log.info("Comandos com dados (potencialmente uteis):")
        for cmd, (cls, rsp) in results.items():
            if rsp and len(rsp) > 2:
                name = CMD_NAMES.get(cmd, "")
                log.info(f"  0x{cmd:02x} {name:25s} {len(rsp):4d} bytes: {rsp[:48].hex()}")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        dev.close()
        log.separator()
        log.info(f"Log: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
