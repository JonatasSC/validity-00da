#!/usr/bin/env python3
"""
Testa se a sequencia pos-TLS desbloqueia DB2/frame.

Sequencia completa do driver Windows:
  1. 0x82 subcmd=02,param=07 → 34B (frame dimensions)
  2. 0x80 param2=0x02,param5=0x00 → 2B (frame setup)
  3. 0x81 → 2B (frame commit)
  4. Testar DB2 e frame commands

Log: logs/tls_test_unlock.txt
Uso: sudo python3 scripts/tls_test_unlock.py
"""

import sys
import os
import time
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import Logger, do_pair, do_handshake
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(PROJECT_DIR, "logs", "tls_test_unlock.txt")


def cmd(session, log, name, data, expect=None):
    """Envia comando, loga, retorna resposta."""
    log.info(f"  {name}: TX={data.hex()}")
    rsp = session.command(data, raw=True, timeout=5000)
    if rsp:
        status = "OK" if rsp[:2] == b"\x00\x00" else f"ERR={rsp[:2].hex()}"
        log.info(f"  {name}: RX={len(rsp)}B {rsp.hex()} [{status}]")
        if expect and len(rsp) != expect:
            log.warn(f"  {name}: esperava {expect}B, recebeu {len(rsp)}B")
    else:
        log.warn(f"  {name}: timeout")
    return rsp


def main():
    log = Logger(LOG_FILE)
    log.info("Teste: sequencia pos-TLS + DB2/frame unlock")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)

    try:
        # Setup
        log.separator()
        log.info("SETUP: Pre-TLS + PAIR + TLS")
        pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        pairing_data = do_pair(dev, log)
        if not pairing_data:
            log.error("PAIR falhou!")
            return

        dev.reset()
        time.sleep(1)
        pre_tls_phase(dev, log, round_num=3)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        session = do_handshake(dev, log, pairing_data)
        if not session:
            log.error("TLS handshake falhou!")
            return

        # ============================================================
        # Estado ANTES da sequencia
        # ============================================================
        log.separator()
        log.info("ESTADO ANTES DA SEQUENCIA:")
        cmd(session, log, "GET_VERSION", bytes([0x01]), 38)
        time.sleep(0.1)
        cmd(session, log, "GET_START_INFO", bytes([0x19]), 68)
        time.sleep(0.1)

        # DB2 antes
        log.info("DB2 antes da sequencia:")
        cmd(session, log, "DB2_GET_DB_INFO", bytes([0x9e]), 2)
        time.sleep(0.1)

        # ============================================================
        # SEQUENCIA POS-TLS (driver Windows)
        # ============================================================
        log.separator()
        log.info("SEQUENCIA POS-TLS:")

        # CMD 1: frame dimensions
        rsp1 = cmd(session, log, "CMD1: 0x82 dims",
                    bytes.fromhex("820000000000000207"), 34)
        if not rsp1 or rsp1[:2] != b"\x00\x00":
            log.error("CMD1 falhou!")
            return
        time.sleep(0.1)

        # CMD 2: frame setup
        rsp2 = cmd(session, log, "CMD2: 0x80 setup",
                    bytes.fromhex("800000000200000000"), 2)
        if not rsp2:
            log.error("CMD2 falhou!")
            return
        time.sleep(0.1)

        # CMD 3: frame commit
        rsp3 = cmd(session, log, "CMD3: 0x81 commit",
                    bytes([0x81]), 2)
        if not rsp3:
            log.error("CMD3 falhou!")
            return
        time.sleep(0.1)

        # ============================================================
        # ESTADO DEPOIS DA SEQUENCIA
        # ============================================================
        log.separator()
        log.info("ESTADO DEPOIS DA SEQUENCIA:")

        # Checar estado
        rsp = cmd(session, log, "GET_VERSION", bytes([0x01]), 38)
        if rsp and len(rsp) >= 38:
            state = rsp[-1]
            log.info(f"  Estado sensor: 0x{state:02x}")
        time.sleep(0.1)

        rsp = cmd(session, log, "GET_START_INFO", bytes([0x19]), 68)
        time.sleep(0.1)

        # ============================================================
        # TESTAR DB2 (antes dava 06 04 = ACCESS_DENIED)
        # ============================================================
        log.separator()
        log.info("TESTE DB2 (antes: ACCESS_DENIED 06 04):")

        db2_cmds = [
            ("DB2_GET_DB_INFO", bytes([0x9e])),
            ("DB2_GET_RECORD_INFO", bytes([0x9f])),
            ("DB2_GET_DATA", bytes([0xa0])),
            ("DB2_CHECK", bytes([0xa3])),
            ("DB2_FORMAT", bytes([0xa5])),
        ]
        for name, data in db2_cmds:
            cmd(session, log, name, data)
            time.sleep(0.1)

        # ============================================================
        # TESTAR FRAME COMMANDS
        # ============================================================
        log.separator()
        log.info("TESTE FRAME COMMANDS:")

        # 0x82 com outros subcmds
        cmd(session, log, "FRAME_STATE subcmd=00",
            bytes.fromhex("820000000000000000"))
        time.sleep(0.1)
        cmd(session, log, "FRAME_STATE subcmd=01",
            bytes.fromhex("820000000000000100"))
        time.sleep(0.1)

        # 0x7f frame acquire (9B)
        # FUN_1801090d0: byte[1-2]=counter, byte[5-6]=0xFFFF, byte[7-8]=3
        cmd(session, log, "FRAME_ACQ",
            bytes.fromhex("7f0000000000ffff0003"))
        time.sleep(0.1)

        # ============================================================
        # TESTAR COMANDOS EXTRAS
        # ============================================================
        log.separator()
        log.info("TESTE EXTRAS:")

        # 0x3e flash info
        cmd(session, log, "FLASH_INFO", bytes([0x3e]))
        time.sleep(0.1)

        # 0x40 com 32 zeros (antes: ACCESS_DENIED)
        cmd(session, log, "CMD_0x40 32zeros",
            bytes([0x40]) + b"\x00" * 32)
        time.sleep(0.1)

        # 0x86 event config
        cmd(session, log, "EVENT_CONFIG", bytes([0x86]))
        time.sleep(0.1)

        log.separator()
        log.info("*** TESTE COMPLETO ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        dev.close()
        log.close()
        print(f"\nLog: {LOG_FILE}")


if __name__ == "__main__":
    main()
