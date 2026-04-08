#!/usr/bin/env python3
"""
Testa os 3 comandos pos-TLS descobertos via RE do synaTEE108.signed.dll.

Sequencia do driver Windows apos TLS handshake:
  CMD 1: 0x82 subcmd=02,param=07 → 34B (frame dimensions) — CONFIRMADO
  CMD 2: 0x80 (frame finish/setup) → 2B status
  CMD 3: 0x81 (bare) → 2B status

Log: logs/tls_test_post_tls.txt
Uso: sudo python3 scripts/tls_test_post_tls.py
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
LOG_FILE = os.path.join(PROJECT_DIR, "logs", "tls_test_post_tls.txt")


def test_cmd(session, log, name, cmd_bytes, expect_len=None):
    """Envia comando e loga resultado."""
    log.info(f"CMD: {name}")
    log.hex_dump(f"  TX", cmd_bytes)
    try:
        rsp = session.command(cmd_bytes, raw=True, timeout=5000)
        if rsp:
            log.info(f"  RX: {len(rsp)}B: {rsp.hex()}")
            if expect_len and len(rsp) == expect_len:
                log.info(f"  *** MATCH! {len(rsp)}B como esperado ***")
            return rsp
        else:
            log.warn(f"  RX: timeout")
            return None
    except Exception as e:
        log.error(f"  ERRO: {e}")
        return None


def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")
    log.info("Teste: 3 comandos pos-TLS (RE synaTEE108)")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)

    try:
        # Setup: Pre-TLS → PAIR → Reset → Pre-TLS → TLS
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
        # CMD 1: 0x82 subcmd=02,param=07 (frame dimensions)
        # Confirmado: retorna 34 bytes
        # ============================================================
        log.separator()
        log.info("=== CMD 1: 0x82 frame dimensions (9B -> 34B) ===")
        cmd1 = bytes.fromhex("820000000000000207")
        rsp1 = test_cmd(session, log, "0x82 dims", cmd1, expect_len=34)
        if not rsp1:
            log.error("CMD 1 falhou, abortando")
            return
        time.sleep(0.1)

        # ============================================================
        # CMD 3: 0x81 bare (1B -> 2B) — testar primeiro, mais simples
        # ============================================================
        log.separator()
        log.info("=== CMD 3: 0x81 bare (1B -> 2B) ===")
        cmd3 = bytes([0x81])
        rsp3 = test_cmd(session, log, "0x81 bare", cmd3, expect_len=2)
        time.sleep(0.1)

        # ============================================================
        # CMD 2: 0x80 frame setup (9B -> 2B)
        # FUN_180109440: quando (param_2 & 2) != 0, size=9
        # Payload: byte[1-4] = param_2 (byte-swapped), byte[5-8] = param_5
        # Testar varias combinacoes
        # ============================================================
        log.separator()
        log.info("=== CMD 2: 0x80 frame setup (9B -> 2B) ===")

        # Hipotese 1: param_2 com bit 1 set (flag "bVar1")
        # FUN_1800f3e10 = byte-swap 32-bit (big-endian)
        # Se param_2 = 2 (bit 1 set), param_5 = 0
        variants_0x80 = [
            ("param2=0x02 param5=0x00",
             b"\x80" + struct.pack(">I", 2) + struct.pack(">I", 0)),
            ("param2=0x02 param5=0x01",
             b"\x80" + struct.pack(">I", 2) + struct.pack(">I", 1)),
            ("param2=0x03 param5=0x00",
             b"\x80" + struct.pack(">I", 3) + struct.pack(">I", 0)),
            ("param2=0x06 param5=0x00",
             b"\x80" + struct.pack(">I", 6) + struct.pack(">I", 0)),
            ("all zeros",
             b"\x80" + b"\x00" * 8),
            ("param2=0x02 param5=0x03",
             b"\x80" + struct.pack(">I", 2) + struct.pack(">I", 3)),
        ]

        for name, cmd in variants_0x80:
            rsp = test_cmd(session, log, f"0x80 {name}", cmd, expect_len=2)
            if rsp is None:
                log.warn("Sessao morta, parando variantes 0x80")
                break
            time.sleep(0.1)

        # ============================================================
        # Bonus: testar sequencia completa na ordem da captura
        # CMD1 (0x82) -> CMD2 (0x80) -> CMD3 (0x81)
        # ============================================================
        log.separator()
        log.info("=== SEQUENCIA COMPLETA (nova sessao TLS) ===")
        log.info("Nota: reutilizando sessao existente")

        # Repetir CMD1
        rsp = test_cmd(session, log, "SEQ: 0x82 dims", cmd1, expect_len=34)
        if rsp:
            time.sleep(0.1)
            # CMD2 com melhor candidato
            cmd2_best = b"\x80" + struct.pack(">I", 2) + struct.pack(">I", 0)
            rsp = test_cmd(session, log, "SEQ: 0x80 setup", cmd2_best, expect_len=2)
            if rsp:
                time.sleep(0.1)
                # CMD3
                test_cmd(session, log, "SEQ: 0x81 commit", cmd3, expect_len=2)

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
