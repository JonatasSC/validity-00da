#!/usr/bin/env python3
"""
Probe aprofundado do 0x40 com variantes de parametros.
Objetivo: encontrar o formato que retorna 34 bytes.

Log: logs/tls_probe_0x40_params.txt
"""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_probe_0x40_params.txt")

log = Logger(LOG_FILE)
log.info("=== 0x40 deep probe — searching for 34B response ===")

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
    log.info("=== 0x40 PARAMETER SCAN ===")

    tests = [
        # Byte scan: 0x40 + sub (0x00-0x10) + 7 zeros
        *[(f"0x40 sub=0x{s:02x} + 7 zeros", bytes([0x40, s]) + b"\x00" * 7) for s in range(0x11)],

        # V90 MSG6 variations
        ("V90: 40 01 01 ... 10 00 00", bytes.fromhex("40010100000000000000100000")),
        ("V90 short: 40 01 01 00 00 00 00 00", bytes([0x40, 0x01, 0x01]) + b"\x00" * 5),
        ("40 01 01 + u32=0x1000", bytes([0x40, 0x01, 0x01]) + struct.pack("<I", 0x1000) + b"\x00"),
        ("40 01 01 + u16=0x1000 + u16=0", bytes([0x40, 0x01, 0x01]) + struct.pack("<HH", 0x1000, 0) + b"\x00"),

        # Different sub + length combos
        ("40 02 00 + 6 zeros", bytes([0x40, 0x02, 0x00]) + b"\x00" * 6),
        ("40 02 01 + 6 zeros", bytes([0x40, 0x02, 0x01]) + b"\x00" * 6),
        ("40 03 00 + 6 zeros", bytes([0x40, 0x03, 0x00]) + b"\x00" * 6),

        # Also test 0x0d (unknown, needs params) with 8 bytes
        ("0x0d + 8 zeros", bytes([0x0d]) + b"\x00" * 8),
        ("0x0d sub=0x01 + 7 zeros", bytes([0x0d, 0x01]) + b"\x00" * 7),
        ("0x0d sub=0x02 + 7 zeros", bytes([0x0d, 0x02]) + b"\x00" * 7),

        # 0x39 (unknown, needs params in pre-TLS)
        ("0x39 + 8 zeros", bytes([0x39]) + b"\x00" * 8),
        ("0x39 sub=0x01 + 7 zeros", bytes([0x39, 0x01]) + b"\x00" * 7),

        # 0x57 (unknown, needs params)
        ("0x57 + 8 zeros", bytes([0x57]) + b"\x00" * 8),
        ("0x57 sub=0x01 + 7 zeros", bytes([0x57, 0x01]) + b"\x00" * 7),

        # 0x73 (unknown, needs params)
        ("0x73 + 8 zeros", bytes([0x73]) + b"\x00" * 8),
        ("0x73 sub=0x01 + 7 zeros", bytes([0x73, 0x01]) + b"\x00" * 7),

        # 0x96 (unknown, needs params)
        ("0x96 + 8 zeros", bytes([0x96]) + b"\x00" * 8),
        ("0x96 sub=0x01 + 7 zeros", bytes([0x96, 0x01]) + b"\x00" * 7),

        # 0x99 (unknown, needs params)
        ("0x99 + 8 zeros", bytes([0x99]) + b"\x00" * 8),
        ("0x99 sub=0x01 + 7 zeros", bytes([0x99, 0x01]) + b"\x00" * 7),

        # 0xfe (unknown)
        ("0xfe + 8 zeros", bytes([0xfe]) + b"\x00" * 8),
        ("0xfe sub=0x01 + 7 zeros", bytes([0xfe, 0x01]) + b"\x00" * 7),
    ]

    for desc, cmd in tests:
        rsp = session.command(cmd, raw=True, timeout=2000)
        if rsp is None:
            log.warn(f"  {desc}: ALERT/TIMEOUT — sessao morta!")
            break

        if len(rsp) == 34:
            log.info(f"  *** {desc}: 34B MATCH! *** → {rsp.hex()}")
        elif len(rsp) > 2:
            log.info(f"  {desc}: {len(rsp)}B data → {rsp[:32].hex()}")
        else:
            status = rsp.hex()
            # Only log non-trivial statuses
            if status not in ("0504", "0104"):
                log.info(f"  {desc}: status {status}")
            else:
                log.info(f"  {desc}: {status}")
        time.sleep(0.1)

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
