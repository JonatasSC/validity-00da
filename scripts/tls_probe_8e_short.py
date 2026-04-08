#!/usr/bin/env python3
"""
Probe 0x8e com formato curto (9 bytes) em vez do formato pre-TLS (16 bytes).
Na captura, comandos de 9B retornam 18B (FW version) e 34B (desconhecido).
Talvez 0x8e use formato diferente dentro do TLS.

Tambem testa outros comandos de 2 bytes (cmd+sub) com 7 bytes extras.

Log: logs/tls_probe_8e_short.txt
"""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_probe_8e_short.txt")

log = Logger(LOG_FILE)
log.info("=== 0x8e short format + 34B hunt ===")

dev = USBDevice()
if not dev.open():
    log.error("Sensor nao encontrado!")
    sys.exit(1)

try:
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

    # Part 1: 0x8e with short format (9 bytes = 0x8e + sub + 7 zeros)
    log.info("=== Part 1: 0x8e short format (9B) ===")
    for sub in [0x09, 0x1a, 0x2e, 0x2f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x0a, 0x0b, 0x10, 0x20, 0x30, 0x40, 0x50]:
        cmd = bytes([0x8e, sub]) + b"\x00" * 7
        rsp = session.command(cmd, raw=True, timeout=2000)
        if rsp is None:
            log.warn(f"  0x8e 0x{sub:02x} (9B): ALERT — sessao morta!")
            break
        if len(rsp) == 34:
            log.info(f"  *** 0x8e 0x{sub:02x} (9B): 34B MATCH! *** → {rsp.hex()}")
        elif len(rsp) > 2:
            log.info(f"  0x8e 0x{sub:02x} (9B): {len(rsp)}B → {rsp[:32].hex()}")
        else:
            log.info(f"  0x8e 0x{sub:02x} (9B): {rsp.hex()}")
        time.sleep(0.1)

    # Part 2: 0x8e with different padding patterns
    log.separator("-", 40)
    log.info("=== Part 2: 0x8e 0x09 with different formats ===")
    formats_8e = [
        ("16B pre-TLS", bytes([0x8e, 0x09, 0x00, 0x02]) + b"\x00" * 13),
        ("9B zeros",    bytes([0x8e, 0x09]) + b"\x00" * 7),
        ("5B zeros",    bytes([0x8e, 0x09]) + b"\x00" * 3),
        ("3B",          bytes([0x8e, 0x09, 0x00])),
        ("2B bare",     bytes([0x8e, 0x09])),
        ("9B with 0x02",bytes([0x8e, 0x09, 0x02]) + b"\x00" * 6),
        ("9B with 0x01",bytes([0x8e, 0x09, 0x01]) + b"\x00" * 6),
    ]
    for desc, cmd in formats_8e:
        rsp = session.command(cmd, raw=True, timeout=2000)
        if rsp is None:
            log.warn(f"  {desc}: ALERT!")
            break
        if len(rsp) == 34:
            log.info(f"  *** {desc}: 34B MATCH! *** → {rsp.hex()}")
        elif len(rsp) > 2:
            log.info(f"  {desc}: {len(rsp)}B → {rsp[:32].hex()}")
        else:
            log.info(f"  {desc}: {rsp.hex()}")
        time.sleep(0.1)

    # Part 3: Commands that accept params — scan sub-bytes with 7 zeros (9B total)
    # Focus on commands we haven't fully explored
    log.separator("-", 40)
    log.info("=== Part 3: Other cmds with sub-byte scan (9B) ===")
    for cmd_byte in [0x90, 0xa6, 0xa9, 0xaa, 0xab]:
        for sub in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20]:
            cmd = bytes([cmd_byte, sub]) + b"\x00" * 7
            rsp = session.command(cmd, raw=True, timeout=2000)
            if rsp is None:
                log.warn(f"  0x{cmd_byte:02x} 0x{sub:02x}: ALERT!")
                break
            if len(rsp) == 34:
                log.info(f"  *** 0x{cmd_byte:02x} 0x{sub:02x}: 34B MATCH! *** → {rsp.hex()}")
            elif len(rsp) > 2:
                log.info(f"  0x{cmd_byte:02x} 0x{sub:02x}: {len(rsp)}B → {rsp[:32].hex()}")
            # Skip 2B status logging for cleanliness
            time.sleep(0.05)

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
