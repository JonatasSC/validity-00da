#!/usr/bin/env python3
"""
Probe de comandos com 9 bytes (1B cmd + 8B payload).

A captura teste1.pcap mostra que o primeiro comando pos-TLS tem:
  OUT: 9B plaintext → IN: 34B plaintext (2B status + 32B dados)

Testa todos os comandos conhecidos com 8 bytes de zeros e variantes.

Log: logs/tls_probe_9B.txt
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
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_9B.txt")

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

# Comandos perigosos — NUNCA testar
SKIP = {0x06, 0x0e, 0x10, 0x44, 0x93}


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


def main():
    log = Logger(LOG_FILE)
    log.info("Objetivo: encontrar cmd de 9B que retorna 34B (captura pos-TLS)")
    log.info("Formato: 1B cmd + 8B payload (zeros) → esperamos 34B resposta")

    try:
        dev, session = setup_tls(log)
        if not session:
            return

        # Fase 1: Testar todos os comandos conhecidos com 8 zeros
        log.separator()
        log.info("=== FASE 1: Todos cmds + 8 zeros ===")

        found = []
        for cmd_byte in range(0x100):
            if cmd_byte in SKIP:
                continue

            cmd = bytes([cmd_byte]) + b"\x00" * 8
            try:
                rsp = session.command(cmd, raw=True)
            except Exception as e:
                log.error(f"  0x{cmd_byte:02x}: EXCEPTION {e}")
                break

            if rsp is None:
                log.warn(f"  0x{cmd_byte:02x}: ALERT/TIMEOUT — session dead")
                break

            if len(rsp) == 34:
                log.info(f"  0x{cmd_byte:02x}: *** 34B! *** {rsp.hex()}")
                found.append((cmd_byte, rsp))
            elif len(rsp) > 2 and len(rsp) != 34:
                log.info(f"  0x{cmd_byte:02x}: DATA({len(rsp)}B) {rsp[:24].hex()}...")
            # Skip logging 2B status responses to keep log clean

            time.sleep(0.08)

        log.separator()
        if found:
            log.info(f"*** ENCONTRADOS {len(found)} comandos com 34B! ***")
            for cmd_byte, rsp in found:
                log.info(f"  0x{cmd_byte:02x}: {rsp.hex()}")
        else:
            log.info("Nenhum comando retornou 34B com 8 zeros.")

        # Fase 2: Se nao achou, testar 0x8e com formato curto (sub + 7 zeros)
        if not found:
            log.separator()
            log.info("=== FASE 2: 0x8e com 8B (sub + 7 zeros) ===")

            for sub in range(0x40):
                cmd = bytes([0x8e, sub]) + b"\x00" * 7
                try:
                    rsp = session.command(cmd, raw=True)
                except Exception:
                    log.error(f"  0x8e 0x{sub:02x}: EXCEPTION")
                    break

                if rsp is None:
                    log.warn(f"  0x8e 0x{sub:02x}: session dead")
                    break

                if len(rsp) == 34:
                    log.info(f"  0x8e 0x{sub:02x}: *** 34B! *** {rsp.hex()}")
                    found.append((0x8e00 + sub, rsp))
                elif len(rsp) > 2:
                    log.info(f"  0x8e 0x{sub:02x}: DATA({len(rsp)}B)")

                time.sleep(0.08)

        # Fase 3: Testar com payloads nao-zero (0x01, u32=1, etc)
        if not found:
            log.separator()
            log.info("=== FASE 3: Comandos candidatos com payloads variados ===")

            # Cmds que aceitam params: 0x39, 0x40, 0x41, 0x57, 0x82, 0x87, 0xae, 0xfe
            candidates = [0x39, 0x40, 0x41, 0x57, 0x82, 0x87, 0xae, 0xfe,
                         0x3f, 0x7f, 0x80, 0x9e, 0xa0, 0xa1, 0xa5]

            payloads_8b = [
                ("01+7zeros", b"\x01" + b"\x00" * 7),
                ("u32=1+4zeros", struct.pack("<I", 1) + b"\x00" * 4),
                ("u16=1+6zeros", struct.pack("<H", 1) + b"\x00" * 6),
                ("ff*8", b"\xff" * 8),
                ("01020000+4zeros", b"\x01\x02\x00\x00" + b"\x00" * 4),
                ("03+7zeros", b"\x03" + b"\x00" * 7),
            ]

            for cmd_byte in candidates:
                for desc, payload in payloads_8b:
                    cmd = bytes([cmd_byte]) + payload
                    try:
                        rsp = session.command(cmd, raw=True)
                    except Exception:
                        break

                    if rsp is None:
                        break

                    if len(rsp) == 34:
                        log.info(f"  0x{cmd_byte:02x} {desc}: *** 34B! *** {rsp.hex()}")
                        found.append((cmd_byte, rsp))
                    elif len(rsp) > 2:
                        log.info(f"  0x{cmd_byte:02x} {desc}: DATA({len(rsp)}B)")

                    time.sleep(0.08)

        # Estado final
        log.separator()
        log.info("=== Estado final ===")
        try:
            rsp = session.command(b"\x01", raw=True)
            if rsp and len(rsp) >= 38:
                log.info(f"  Estado: 0x{rsp[-1]:02x}")
        except Exception:
            log.warn("  Session dead, nao conseguiu checar estado")

        log.separator()
        if found:
            log.info(f"*** TOTAL: {len(found)} comandos retornaram 34B ***")
        else:
            log.info("*** NENHUM comando retornou 34B — precisa captura USB ***")
        log.info("*** DONE ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        if 'dev' in dir() and dev:
            dev.close()
        log.close()
        print(f"\nLog: {LOG_FILE}")


if __name__ == "__main__":
    main()
