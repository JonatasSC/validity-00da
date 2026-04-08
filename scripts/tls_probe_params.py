#!/usr/bin/env python3
"""
Probe de comandos com parametros via TLS tunnel.

Testa os 14 comandos que retornaram NEEDS_PARAMS (05 04) no scan anterior,
enviando com formatos conhecidos do synaTudor e pre-TLS.

Uso:
  sudo python3 scripts/tls_probe_params.py

Log: logs/tls_probe_params.txt
"""

import sys
import os
import struct
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice
from scripts.tls_provision import (
    Logger, TlsSession, tls_prf_sha256, tls_prf_sha384,
    do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_params.txt")

# Status codes
STATUS = {
    b"\x00\x00": "OK",
    b"\x01\x04": "UNKNOWN_CMD",
    b"\x03\x04": "PARAM_ERROR",
    b"\x04\x04": "STATE_BLOCKED",
    b"\x05\x04": "NEEDS_PARAMS",
    b"\xe5\x06": "NOT_AVAILABLE",
    b"\xe7\x06": "NOT_PROVISIONED",
    b"\xcc\x05": "NOT_READY",
    b"\xb8\x06": "STATUS_B806",
}


def status_str(rsp):
    if rsp is None:
        return "TIMEOUT/ALERT"
    if len(rsp) == 2:
        return STATUS.get(rsp, f"0x{rsp.hex()}")
    return f"DATA({len(rsp)}B)"


def setup_tls(log):
    """Full setup: Pre-TLS → PAIR → Reset → Pre-TLS → TLS."""
    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        return None, None

    log.info(f"Sensor: bus {dev.dev.bus} addr {dev.dev.address}")

    # Pre-TLS
    pre_tls_phase(dev, log, round_num=1)
    time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)

    # PAIR
    log.info("PAIR...")
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        log.error("PAIR falhou!")
        dev.close()
        return None, None

    # Reset + Re-init
    dev.reset()
    time.sleep(1)
    pre_tls_phase(dev, log, round_num=3)
    time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)

    # TLS
    log.info("TLS Handshake...")
    session = do_handshake(dev, log, pairing_data)
    if not session:
        log.error("TLS falhou!")
        dev.close()
        return None, None

    log.info("*** Setup completo ***")
    return dev, session


def probe_0x8e(session, log):
    """0x8e SENSOR_INFO — subcomandos do pre-TLS."""
    log.separator()
    log.info("=== 0x8e SENSOR_INFO (subcomandos) ===")

    subs = [
        (0x09, "Sensor info"),
        (0x1a, "Config/calibracao"),
        (0x2e, "Calibration blob"),
        (0x2f, "Firmware version"),
    ]

    for sub, desc in subs:
        # Formato pre-TLS: [0x8e] [sub] [0x00 0x02] [13 zeros]
        cmd = bytes([0x8e, sub]) + b"\x00\x02" + b"\x00" * 13
        log.info(f"  0x8e 0x{sub:02x} ({desc}): {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            log.info(f"    → {status_str(rsp)}: {rsp[:48].hex()}{'...' if len(rsp) > 48 else ''}")
        else:
            log.warn(f"    → {status_str(rsp)}")
        time.sleep(0.2)


def probe_0x82(session, log):
    """0x82 FRAME_STATE_GET — dimensoes do frame."""
    log.separator()
    log.info("=== 0x82 FRAME_STATE_GET ===")

    # synaTudor: send 0x82 with no extra data via framed command
    # Our sensor needs params — try different formats
    tests = [
        ("bare + 0x00", bytes([0x82, 0x00])),
        ("bare + 4 zeros", bytes([0x82]) + b"\x00" * 4),
        ("sub 0x00 + padding", bytes([0x82, 0x00, 0x00, 0x02]) + b"\x00" * 13),
        ("sub 0x01", bytes([0x82, 0x01])),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            s = status_str(rsp)
            log.info(f"    → {s}: {rsp[:48].hex()}{'...' if len(rsp) > 48 else ''}")
            if len(rsp) > 2:
                log.info(f"    DADOS! {len(rsp)} bytes")
        else:
            log.warn(f"    → {status_str(rsp)}")
            break  # Alert = session dead
        time.sleep(0.2)


def probe_0x87(session, log):
    """0x87 EVENT_READ — ler eventos pendentes."""
    log.separator()
    log.info("=== 0x87 EVENT_READ ===")

    tests = [
        ("bare + 0x00", bytes([0x87, 0x00])),
        ("+ 4 zeros", bytes([0x87]) + b"\x00" * 4),
        ("+ mask u32", bytes([0x87]) + struct.pack("<I", 0xFFFFFFFF)),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            log.info(f"    → {status_str(rsp)}: {rsp[:48].hex()}")
            if len(rsp) > 2:
                return
        else:
            break
        time.sleep(0.2)


def probe_db2(session, log):
    """DB2 commands — database de fingerprints."""
    log.separator()
    log.info("=== DB2 Commands ===")

    # 0x9e DB2_GET_DB_INFO — info do database
    # synaTudor: send with db_id parameter
    db_cmds = [
        ("0x9e DB_INFO + db_id=0", bytes([0x9e]) + struct.pack("<H", 0)),
        ("0x9e DB_INFO + db_id=1", bytes([0x9e]) + struct.pack("<H", 1)),
        ("0x9e DB_INFO + 4 zeros", bytes([0x9e]) + b"\x00" * 4),
        ("0xa0 OBJ_INFO + obj_id=0", bytes([0xa0]) + struct.pack("<HH", 0, 0)),
        ("0xa5 FORMAT + db_id=0", bytes([0xa5]) + struct.pack("<H", 0)),
        ("0xa4 CLEANUP + db_id=0", bytes([0xa4]) + struct.pack("<H", 0)),
    ]

    for desc, cmd in db_cmds:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            s = status_str(rsp)
            log.info(f"    → {s}: {rsp[:64].hex()}")
            if len(rsp) > 2:
                log.info(f"    DADOS! {len(rsp)} bytes")
        else:
            log.warn(f"    → ALERT/TIMEOUT")
            break
        time.sleep(0.2)


def probe_0x3f(session, log):
    """0x3f FLASH_OP — operacoes de flash."""
    log.separator()
    log.info("=== 0x3f FLASH_OP ===")

    # Pre-TLS: 0x3f 0x01 e 0x3f 0x02 retornam ACK
    tests = [
        ("sub 0x01", bytes([0x3f, 0x01])),
        ("sub 0x02", bytes([0x3f, 0x02])),
        ("sub 0x03", bytes([0x3f, 0x03])),
        ("sub 0x00", bytes([0x3f, 0x00])),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            log.info(f"    → {status_str(rsp)}: {rsp.hex()}")
        else:
            break
        time.sleep(0.2)


def probe_0xae(session, log):
    """0xae SENSOR_CONFIG — config do sensor."""
    log.separator()
    log.info("=== 0xae SENSOR_CONFIG ===")

    # Pre-TLS: 0xae 0x00 retorna 270 bytes
    tests = [
        ("sub 0x00", bytes([0xae, 0x00])),
        ("sub 0x01", bytes([0xae, 0x01])),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            s = status_str(rsp)
            log.info(f"    → {s}: {rsp[:48].hex()}{'...' if len(rsp) > 48 else ''}")
            if len(rsp) > 2:
                log.info(f"    DADOS! {len(rsp)} bytes")
        else:
            break
        time.sleep(0.2)


def probe_frame(session, log):
    """0x7f/0x80 FRAME_ACQ/FINISH — aquisicao de frame."""
    log.separator()
    log.info("=== 0x7f/0x80 FRAME ===")

    tests = [
        ("0x7f + 0x00", bytes([0x7f, 0x00])),
        ("0x7f + flags u32=0", bytes([0x7f]) + struct.pack("<I", 0)),
        ("0x80 + 0x00", bytes([0x80, 0x00])),
        ("0x80 + flags u32=0", bytes([0x80]) + struct.pack("<I", 0)),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            log.info(f"    → {status_str(rsp)}: {rsp[:48].hex()}")
        else:
            break
        time.sleep(0.2)


def probe_0xfe(session, log):
    """0xfe UNKNOWN — comando desconhecido."""
    log.separator()
    log.info("=== 0xfe UNKNOWN ===")

    tests = [
        ("+ 0x00", bytes([0xfe, 0x00])),
        ("+ 0x01", bytes([0xfe, 0x01])),
        ("+ 4 zeros", bytes([0xfe]) + b"\x00" * 4),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            log.info(f"    → {status_str(rsp)}: {rsp.hex()}")
        else:
            break
        time.sleep(0.2)


def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")

    try:
        dev, session = setup_tls(log)
        if not session:
            return

        # Probe each command group
        probe_0x8e(session, log)
        probe_0x82(session, log)
        probe_0xae(session, log)
        probe_db2(session, log)
        probe_0x3f(session, log)
        probe_0x87(session, log)
        probe_frame(session, log)
        probe_0xfe(session, log)

        log.separator()
        log.info("*** PROBE COMPLETE ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        if 'dev' in dir() and dev:
            dev.close()
        log.separator()
        log.info(f"Log: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
