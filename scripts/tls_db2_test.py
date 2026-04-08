#!/usr/bin/env python3
"""Teste focado em DB2, Frame e comandos com parametros via TLS."""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_db2_test.txt")

log = Logger(LOG_FILE)
log.info("=== DB2 + Frame + Params Test ===")

dev = USBDevice()
if not dev.open():
    log.error("Sensor nao encontrado!")
    sys.exit(1)

try:
    # Setup
    pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)
    log.info("PAIR...")
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        sys.exit(1)
    dev.reset(); time.sleep(1)
    pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)
    log.info("TLS...")
    session = do_handshake(dev, log, pairing_data)
    if not session:
        sys.exit(1)

    log.separator()
    log.info("=== TESTS ===")

    tests = [
        # DB2
        ("0xa5 FORMAT db=0 (2B)",        bytes([0xa5]) + struct.pack("<H", 0)),
        ("0xa5 FORMAT db=0 (4B)",        bytes([0xa5]) + struct.pack("<I", 0)),
        ("0x9e DB_INFO db=0 (2B)",       bytes([0x9e]) + struct.pack("<H", 0)),
        ("0x9e DB_INFO db=0 (4B)",       bytes([0x9e]) + struct.pack("<I", 0)),
        ("0x9e DB_INFO db=1 (2B)",       bytes([0x9e]) + struct.pack("<H", 1)),
        # Frame
        ("0x82 FRAME_GET 8e-fmt",        bytes([0x82, 0x00, 0x00, 0x02]) + b"\x00" * 13),
        ("0x82 FRAME_GET + 0x00",        bytes([0x82, 0x00])),
        ("0x82 FRAME_GET + 4 zeros",     bytes([0x82]) + b"\x00" * 4),
        ("0x81 FRAME_SET bare",          bytes([0x81])),
        ("0x81 FRAME_SET + 0x00",        bytes([0x81, 0x00])),
        # Events
        ("0x87 EVENT_READ + 4 zeros",    bytes([0x87]) + b"\x00" * 4),
        ("0x87 EVENT_READ + mask=FF",    bytes([0x87]) + struct.pack("<I", 0xFFFFFFFF)),
        # MSG6 / init
        ("0x40 MSG6 bare",              bytes([0x40])),
        ("0x40 MSG6 + 01 01",           bytes([0x40, 0x01, 0x01])),
        ("0x0d UNKNOWN bare",           bytes([0x0d])),
        ("0x0d UNKNOWN + 0x00",         bytes([0x0d, 0x00])),
        # Sensor config with param
        ("0xae CONFIG sub=0x00",         bytes([0xae, 0x00])),
        # Cleanup/format
        ("0xa4 CLEANUP db=0",           bytes([0xa4]) + struct.pack("<H", 0)),
        ("0xa3 DELETE db=0 obj=0",      bytes([0xa3]) + struct.pack("<HH", 0, 0)),
    ]

    for desc, cmd in tests:
        log.info(f"  {desc}: {cmd.hex()}")
        rsp = session.command(cmd, raw=True)
        if rsp:
            if len(rsp) == 2:
                log.info(f"    -> status: {rsp.hex()}")
            else:
                log.info(f"    -> DATA ({len(rsp)}B): {rsp[:64].hex()}{'...' if len(rsp) > 64 else ''}")
        else:
            log.warn(f"    -> ALERT/TIMEOUT — sessao morta")
            break
        time.sleep(0.2)

    log.separator()
    log.info("*** TEST COMPLETE ***")

except Exception as e:
    log.error(f"Excecao: {e}")
    import traceback
    log.error(traceback.format_exc())
finally:
    dev.close()
    log.close()
    print(f"\nLog: {LOG_FILE}")
