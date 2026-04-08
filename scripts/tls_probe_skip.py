#!/usr/bin/env python3
"""
Probe dos comandos que foram skipados nos scans anteriores.

Testa 0x0e (PROVISION), 0x44, 0x93 via TLS tunnel com 8B payload.
Esses foram excluidos por serem perigosos, mas podem ser o cmd de provisioning.

RISCO: 0x0e e 0x10 podem causar USB disconnect. Script trata isso.

Log: logs/tls_probe_skip.txt
"""

import sys
import os
import struct
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice
from scripts.tls_provision import (
    Logger, TlsSession, tls_prf_sha256, tls_prf_sha384,
    do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_skip.txt")

STATUS = {
    b"\x00\x00": "OK",
    b"\x01\x04": "UNKNOWN_CMD",
    b"\x03\x04": "PARAM_ERROR",
    b"\x05\x04": "NEEDS_PARAMS",
    b"\x06\x04": "ACCESS_DENIED",
    b"\xe5\x06": "NOT_AVAILABLE",
    b"\xe7\x06": "NOT_PROVISIONED",
    b"\xcc\x05": "NOT_READY",
}


def setup_tls(log):
    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        return None, None

    pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)

    log.info("PAIR...")
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        dev.close()
        return None, None

    dev.reset(); time.sleep(1)
    pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)

    log.info("TLS...")
    session = do_handshake(dev, log, pairing_data)
    if not session:
        dev.close()
        return None, None

    log.info("*** Setup OK ***")
    return dev, session


def test_cmd(session, log, cmd_byte, payload, desc):
    """Testa um comando, trata exceptions."""
    cmd = bytes([cmd_byte]) + payload
    log.info(f"  {desc}: {cmd.hex()}")
    try:
        rsp = session.command(cmd, raw=True, timeout=3000)
    except Exception as e:
        log.warn(f"    → EXCEPTION: {e}")
        return None, False  # rsp, session_alive

    if rsp is None:
        log.warn(f"    → TIMEOUT/ALERT — possivel disconnect")
        return None, False

    s = STATUS.get(rsp[:2], f"0x{rsp[:2].hex()}") if len(rsp) >= 2 else "?"
    if len(rsp) > 2:
        log.info(f"    → DATA({len(rsp)}B): {rsp.hex()}")
        if len(rsp) == 34:
            log.info(f"    *** 34 BYTES! POSSIVEL PROVISIONING! ***")
    else:
        log.info(f"    → {s}: {rsp.hex()}")

    return rsp, True


def main():
    log = Logger(LOG_FILE)
    log.info("Teste dos comandos skipados: 0x0e, 0x44, 0x93")
    log.info("RISCO: 0x0e pode causar USB disconnect")

    try:
        dev, session = setup_tls(log)
        if not session:
            return

        alive = True

        def reconnect():
            nonlocal dev, session, alive
            log.info("  Reconectando...")
            try:
                dev.close()
            except Exception:
                pass
            time.sleep(2)
            dev, session = setup_tls(log)
            if session:
                alive = True
                log.info("  Reconectado!")
                return True
            else:
                log.error("  Falha ao reconectar")
                alive = False
                return False

        # === Comandos a testar (ordem: menos perigoso primeiro) ===
        tests = [
            ("0x93 PAIR via TLS", 0x93, [
                ("8 zeros", b"\x00" * 8),
                ("01+7zeros", b"\x01" + b"\x00" * 7),
            ]),
            ("0x06", 0x06, [
                ("8 zeros", b"\x00" * 8),
            ]),
            ("0x0e PROVISION", 0x0e, [
                ("8 zeros", b"\x00" * 8),
                ("01+7zeros", b"\x01" + b"\x00" * 7),
                ("03+7zeros", b"\x03" + b"\x00" * 7),
                ("u32=1+4zeros", struct.pack("<I", 1) + b"\x00" * 4),
                ("u16=1 u16=0 4zeros", struct.pack("<HH", 1, 0) + b"\x00" * 4),
                ("ff*8", b"\xff" * 8),
            ]),
            ("0x10 RESET_OWNERSHIP", 0x10, [
                ("8 zeros", b"\x00" * 8),
            ]),
        ]

        for section_name, cmd_byte, payloads in tests:
            if not alive:
                if not reconnect():
                    break

            log.separator()
            log.info(f"=== {section_name} ===")

            for desc, pl in payloads:
                if not alive:
                    if not reconnect():
                        break

                rsp, alive = test_cmd(session, log, cmd_byte, pl, f"0x{cmd_byte:02x} {desc}")
                if not alive:
                    log.warn(f"  Session morreu apos 0x{cmd_byte:02x} {desc}")
                time.sleep(0.2)

        # Estado final
        if alive:
            log.separator()
            log.info("=== Estado final ===")
            rsp, _ = test_cmd(session, log, 0x01, b"", "0x01 GET_VERSION")
            if rsp and len(rsp) >= 38:
                log.info(f"  Estado: 0x{rsp[-1]:02x}")

        log.separator()
        log.info("*** DONE ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        if 'dev' in dir() and dev:
            try:
                dev.close()
            except Exception:
                pass
        log.close()
        print(f"\nLog: {LOG_FILE}")


if __name__ == "__main__":
    main()
