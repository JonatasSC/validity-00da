#!/usr/bin/env python3
"""
Encontrar qual comando retorna 34 bytes — o primeiro comando da fase de provisioning.

Testa todos os comandos conhecidos com 8 bytes de parametros (9 bytes total)
para encontrar qual retorna exatamente 34 bytes.

Log: logs/tls_find_34b.txt
"""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_find_34b.txt")

# Skip dangerous commands
SKIP = {0x06, 0x0e, 0x10, 0x44, 0x93}

log = Logger(LOG_FILE)
log.info("=== Find 34B response command ===")
log.info("Testing all cmds with 8 zero bytes (9B total)")

dev = USBDevice()
if not dev.open():
    log.error("Sensor nao encontrado!")
    sys.exit(1)

try:
    # Setup
    pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        sys.exit(1)
    dev.reset(); time.sleep(1)
    pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)
    session = do_handshake(dev, log, pairing_data)
    if not session:
        sys.exit(1)

    log.separator()
    log.info("=== SCAN: cmd + 8 zeros ===")

    # Test all commands 0x00-0xFF with 8 zero bytes
    alerts = 0
    found = []

    for cmd in range(0x100):
        if cmd in SKIP:
            continue

        payload = bytes([cmd]) + b"\x00" * 8
        try:
            rsp = session.command(payload, raw=True, timeout=2000)
        except Exception as e:
            log.error(f"  0x{cmd:02x}: USB ERROR — {e}")
            break

        if rsp is None:
            alerts += 1
            if alerts >= 2:
                log.error("  Sessao morta")
                break
            continue
        else:
            alerts = 0

        if len(rsp) == 34:
            log.info(f"  *** 0x{cmd:02x}: 34B MATCH! *** → {rsp.hex()}")
            found.append((cmd, rsp))
        elif len(rsp) > 2 and len(rsp) != 34:
            log.info(f"  0x{cmd:02x}: {len(rsp)}B data → {rsp[:32].hex()}")
        # Skip logging 2B status codes to keep output clean

        time.sleep(0.05)

    log.separator()
    log.info("=== RESULTS ===")
    if found:
        for cmd, rsp in found:
            log.info(f"  0x{cmd:02x} → 34B: {rsp.hex()}")
    else:
        log.info("  Nenhum comando retornou 34 bytes com 8 zeros")
        log.info("  Proximo: testar com outros padroes de parametros")

    log.separator()
    log.info("*** SCAN COMPLETE ***")

except Exception as e:
    log.error(f"Excecao: {e}")
    import traceback
    log.error(traceback.format_exc())
finally:
    dev.close()
    log.close()
    print(f"\nLog: {LOG_FILE}")
