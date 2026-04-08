#!/usr/bin/env python3
"""
Testa comando 0x82 com payload descoberto via RE do synaTEE108.signed.dll.

FUN_180109900 (get frame dimensions):
  - cmd: 0x82, 9 bytes total
  - byte[7] = 0x02, byte[8] = 0x07
  - resposta esperada: 0x22 = 34 bytes

Payload: 82 00 00 00 00 00 00 02 07

Log: logs/tls_test_0x82.txt
Uso: sudo python3 scripts/tls_test_0x82.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import Logger, do_pair, do_handshake
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(PROJECT_DIR, "logs", "tls_test_0x82.txt")


def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")
    log.info("Teste: 0x82 com subcmd=0x02, param=0x07 (frame dimensions)")

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
        # Teste 1: Comando exato do driver Windows (FUN_180109900)
        # 82 00 00 00 00 00 00 02 07
        # ============================================================
        log.separator()
        log.info("TESTE 1: 0x82 subcmd=0x02 param=0x07 (9B, espera 34B)")

        cmd_frame_dim = bytes.fromhex("82 00 00 00 00 00 00 02 07".replace(" ", ""))
        log.hex_dump("Enviando", cmd_frame_dim)

        rsp = session.command(cmd_frame_dim, raw=True)
        if rsp:
            log.info(f"Resposta: {len(rsp)} bytes")
            log.hex_dump("0x82 subcmd=02 param=07", rsp)

            if len(rsp) >= 34:
                log.info("*** 34 BYTES! BATE COM A CAPTURA! ***")
                # Parse frame dimensions (ushorts big-endian a partir de offset 0x0e)
                import struct
                for i, off in enumerate([0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e]):
                    if off + 2 <= len(rsp):
                        val = struct.unpack(">H", rsp[off:off+2])[0]
                        log.info(f"  dim[{i}] @ 0x{off:02x} = {val} (0x{val:04x})")
            elif len(rsp) == 2:
                log.info(f"  Status: {rsp.hex()}")
        else:
            log.warn("Sem resposta")

        # ============================================================
        # Teste 2: Variantes pra comparar
        # ============================================================
        log.separator("-", 40)
        log.info("TESTE 2: Variantes de 0x82")

        variants = [
            ("subcmd=00 param=00", "82 00 00 00 00 00 00 00 00"),
            ("subcmd=01 param=00", "82 00 00 00 00 00 00 01 00"),
            ("subcmd=02 param=00", "82 00 00 00 00 00 00 02 00"),
            ("subcmd=00 param=07", "82 00 00 00 00 00 00 00 07"),
        ]

        for name, hex_str in variants:
            cmd = bytes.fromhex(hex_str.replace(" ", ""))
            log.info(f"  {name}: {cmd.hex()}")
            try:
                rsp = session.command(cmd, raw=True, timeout=3000)
                if rsp:
                    log.info(f"    -> {len(rsp)}B: {rsp.hex()}")
                else:
                    log.warn(f"    -> timeout")
                    break
            except Exception as e:
                log.error(f"    -> erro: {e}")
                break
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
