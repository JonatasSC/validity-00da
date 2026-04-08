#!/usr/bin/env python3
"""
Teste: enviar comandos de 'commit' apos PAIR, antes do reset.

Hipotese: o PAIR funciona mas o sensor precisa de um comando extra
para persistir os dados de pairing antes do reset/TLS.

Testa: 0x3f 0x01, 0x3f 0x02, 0x7c, 0x8d, 0x05, 0x00
apos PAIR e antes do reset. Depois verifica se MSG6 (0x40)
deixa de retornar 'e7 06' (NOT PROVISIONED) via TLS.

Log: logs/tls_pair_commit.txt
"""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_pair_commit.txt")

log = Logger(LOG_FILE)
log.info("=== PAIR + Commit test ===")

dev = USBDevice()
if not dev.open():
    log.error("Sensor nao encontrado!")
    sys.exit(1)

try:
    # Pre-TLS
    pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)

    # PAIR
    log.separator()
    log.info("PAIR...")
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        sys.exit(1)

    # Commit commands AFTER PAIR, BEFORE reset
    log.separator()
    log.info("=== Commit commands apos PAIR ===")

    commit_cmds = [
        ("0x3f 0x01 (flash op 1)", bytes([0x3f, 0x01])),
        ("0x3f 0x02 (flash op 2)", bytes([0x3f, 0x02])),
        ("0x7c (ACK)", bytes([0x7c])),
        ("0x8d (ACK)", bytes([0x8d])),
        ("0x05 (ACK)", bytes([0x05])),
        ("0x00 (NOP)", bytes([0x00])),
    ]

    for desc, cmd in commit_cmds:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = dev.cmd(cmd)
        if rsp:
            log.info(f"    -> {rsp.hex()} ({len(rsp)}B)")
        else:
            log.warn(f"    -> timeout/sem resposta")
        time.sleep(0.1)

    # Check state before reset
    log.info("Estado antes do reset:")
    rsp = dev.cmd(b"\x01")
    if rsp and len(rsp) >= 38:
        log.info(f"  Estado: 0x{rsp[-1]:02x}")

    # Reset + Re-init
    log.separator()
    log.info("Reset + Re-init")
    dev.reset(); time.sleep(1)
    pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)

    # Check state after reset
    log.info("Estado apos reset:")
    rsp = dev.cmd(b"\x01")
    if rsp and len(rsp) >= 38:
        state = rsp[-1]
        log.info(f"  Estado: 0x{state:02x}")
        if state != 0x03:
            log.info(f"  >>> ESTADO MUDOU! Era 0x03, agora 0x{state:02x}")

    # TLS
    log.separator()
    log.info("TLS Handshake...")
    session = do_handshake(dev, log, pairing_data)
    if not session:
        log.error("TLS falhou!")
        sys.exit(1)

    # Test MSG6 via TLS — still NOT PROVISIONED?
    log.separator()
    log.info("=== Teste MSG6 via TLS ===")

    # MSG6 V90 format
    msg6 = bytes.fromhex("40010100000000000000100000")
    log.info(f"  MSG6 V90: {msg6.hex()}")
    rsp = session.command(msg6, raw=True)
    if rsp:
        if rsp == bytes.fromhex("e706"):
            log.info(f"    -> e7 06 (STILL NOT PROVISIONED)")
        elif len(rsp) > 2:
            log.info(f"    -> DATA ({len(rsp)}B): {rsp[:48].hex()}")
            log.info(f"    >>> MSG6 RETORNOU DADOS! PROVISIONING PODE TER FUNCIONADO!")
        else:
            log.info(f"    -> status: {rsp.hex()}")
    else:
        log.warn(f"    -> ALERT/TIMEOUT")

    # Also test DB2
    log.info("  DB2 GET_DB_INFO:")
    rsp = session.command(bytes([0x9e]) + struct.pack("<H", 0), raw=True)
    if rsp:
        if rsp == bytes.fromhex("0604"):
            log.info(f"    -> 06 04 (still blocked)")
        elif len(rsp) > 2:
            log.info(f"    -> DATA ({len(rsp)}B): {rsp.hex()}")
            log.info(f"    >>> DB2 RETORNOU DADOS!")
        else:
            log.info(f"    -> status: {rsp.hex()}")

    log.separator()
    log.info("*** COMPLETE ***")

except Exception as e:
    log.error(f"Excecao: {e}")
    import traceback
    log.error(traceback.format_exc())
finally:
    dev.close()
    log.close()
    print(f"\nLog: {LOG_FILE}")
