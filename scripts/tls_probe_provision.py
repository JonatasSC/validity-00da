#!/usr/bin/env python3
"""
Probe de comandos de provisioning pos-TLS.

A captura Windows mostra 3 comandos pos-TLS com tamanhos:
  OUT: 33, 33, 25 bytes → IN: 58, 26, 26 bytes

Hipotese: sao comandos IOTA_READ (0x8e) ou similares com subcomandos
que configuram o sensor.

Tambem testa: 0x40 (MSG6/GET_CERTIFICATE_EX) com payloads,
e variantes de 0x82 (FRAME_STATE_GET).

Log: logs/tls_probe_provision.txt
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
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_provision.txt")

STATUS = {
    b"\x00\x00": "OK",
    b"\x01\x04": "UNKNOWN_CMD",
    b"\x03\x04": "PARAM_ERROR",
    b"\x04\x04": "STATE_BLOCKED",
    b"\x05\x04": "NEEDS_PARAMS",
    b"\x06\x04": "ACCESS_DENIED",
    b"\xe5\x06": "NOT_AVAILABLE",
    b"\xe7\x06": "NOT_PROVISIONED",
    b"\xcc\x05": "NOT_READY",
    b"\xb8\x06": "STATUS_B806",
    b"\xb7\x06": "STATUS_B706",
}

def status_str(rsp):
    if rsp is None:
        return "TIMEOUT/ALERT"
    if len(rsp) == 2:
        return STATUS.get(rsp, f"0x{rsp.hex()}")
    return f"DATA({len(rsp)}B)"

def send_cmd(session, log, desc, cmd):
    """Envia comando e loga resultado."""
    log.info(f"  {desc}: {cmd.hex()}")
    try:
        rsp = session.command(cmd, raw=True)
    except Exception as e:
        log.error(f"    → EXCEPTION: {e}")
        return None
    if rsp:
        s = status_str(rsp)
        if len(rsp) > 48:
            log.info(f"    → {s}: {rsp[:48].hex()}...")
        else:
            log.info(f"    → {s}: {rsp.hex()}")
    else:
        log.warn(f"    → {status_str(rsp)}")
    time.sleep(0.15)
    return rsp


def setup_tls(log):
    """Full setup: Pre-TLS → PAIR → Reset → Pre-TLS → TLS."""
    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        return None, None

    log.info(f"Sensor: bus {dev.dev.bus} addr {dev.dev.address}")

    pre_tls_phase(dev, log, round_num=1)
    time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)

    log.info("PAIR...")
    pairing_data = do_pair(dev, log)
    if not pairing_data:
        log.error("PAIR falhou!")
        dev.close()
        return None, None

    dev.reset()
    time.sleep(1)
    pre_tls_phase(dev, log, round_num=3)
    time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)

    log.info("TLS Handshake...")
    session = do_handshake(dev, log, pairing_data)
    if not session:
        log.error("TLS falhou!")
        dev.close()
        return None, None

    log.info("*** Setup completo ***")
    return dev, session


def probe_msg6_variants(session, log):
    """0x40 MSG6/GET_CERTIFICATE_EX com diferentes payloads."""
    log.separator()
    log.info("=== 0x40 MSG6 com payloads ===")

    tests = [
        ("bare", bytes([0x40])),
        ("+ 0x00", bytes([0x40, 0x00])),
        ("+ 0x01", bytes([0x40, 0x01])),
        ("+ 0x02", bytes([0x40, 0x02])),
        ("+ 0x03", bytes([0x40, 0x03])),
        ("+ u16=0", bytes([0x40]) + struct.pack("<H", 0)),
        ("+ u16=1", bytes([0x40]) + struct.pack("<H", 1)),
        ("+ 4 zeros", bytes([0x40]) + b"\x00" * 4),
        ("+ 32 zeros", bytes([0x40]) + b"\x00" * 32),
    ]

    for desc, cmd in tests:
        rsp = send_cmd(session, log, desc, cmd)
        if rsp is None:
            break


def probe_0x39_iota(session, log):
    """0x39 IOTA_FIND — busca de registros IOTA."""
    log.separator()
    log.info("=== 0x39 IOTA_FIND ===")

    # synaTudor usa IOTA_FIND pra localizar dados no sensor
    # Formato possivel: [0x39] [u16 iota_type] [u16 iota_id]
    tests = [
        ("type=0 id=0", bytes([0x39]) + struct.pack("<HH", 0, 0)),
        ("type=1 id=0", bytes([0x39]) + struct.pack("<HH", 1, 0)),
        ("type=0 id=1", bytes([0x39]) + struct.pack("<HH", 0, 1)),
        ("+ 8 zeros", bytes([0x39]) + b"\x00" * 8),
        ("+ 0x01", bytes([0x39, 0x01])),
        ("+ 0x02", bytes([0x39, 0x02])),
    ]

    for desc, cmd in tests:
        rsp = send_cmd(session, log, desc, cmd)
        if rsp is None:
            break


def probe_0x57_unknown(session, log):
    """0x57 UNKNOWN — retornou 06 04 antes, tentar com params."""
    log.separator()
    log.info("=== 0x57 UNKNOWN ===")

    tests = [
        ("+ 0x00", bytes([0x57, 0x00])),
        ("+ 0x01", bytes([0x57, 0x01])),
        ("+ 4 zeros", bytes([0x57]) + b"\x00" * 4),
    ]

    for desc, cmd in tests:
        rsp = send_cmd(session, log, desc, cmd)
        if rsp is None:
            break


def probe_0x41_unknown(session, log):
    """0x41 — retornou 05 04 antes."""
    log.separator()
    log.info("=== 0x41 UNKNOWN ===")

    tests = [
        ("+ 0x00", bytes([0x41, 0x00])),
        ("+ 0x01", bytes([0x41, 0x01])),
        ("+ 4 zeros", bytes([0x41]) + b"\x00" * 4),
        ("+ 8 zeros", bytes([0x41]) + b"\x00" * 8),
        ("+ 16 zeros", bytes([0x41]) + b"\x00" * 16),
        ("+ 32 zeros", bytes([0x41]) + b"\x00" * 32),
    ]

    for desc, cmd in tests:
        rsp = send_cmd(session, log, desc, cmd)
        if rsp is None:
            break


def probe_0x82_extended(session, log):
    """0x82 FRAME_STATE_GET — mais variantes de params."""
    log.separator()
    log.info("=== 0x82 FRAME_STATE_GET (extended) ===")

    # synaTudor frame_state_get format: [0x82] [u8 param_id]
    # Ou pode ser: [0x82] [u16 param] [u16 param]
    tests = [
        ("sub 0x02", bytes([0x82, 0x02])),
        ("sub 0x03", bytes([0x82, 0x03])),
        ("sub 0x04", bytes([0x82, 0x04])),
        ("sub 0x05", bytes([0x82, 0x05])),
        ("sub 0x06", bytes([0x82, 0x06])),
        ("sub 0x08", bytes([0x82, 0x08])),
        ("sub 0x09", bytes([0x82, 0x09])),
        ("sub 0x0a", bytes([0x82, 0x0a])),
        ("sub 0x10", bytes([0x82, 0x10])),
        ("sub 0xff", bytes([0x82, 0xff])),
        ("2B: 01 00", bytes([0x82, 0x01, 0x00])),
        ("4B: all zeros", bytes([0x82, 0x00, 0x00, 0x00])),
        ("6B: 00*5", bytes([0x82]) + b"\x00" * 5),
        ("8B: 00*7", bytes([0x82]) + b"\x00" * 7),
    ]

    for desc, cmd in tests:
        rsp = send_cmd(session, log, desc, cmd)
        if rsp is None:
            break
        # Se retornou dados, parar e analisar
        if rsp and len(rsp) > 2:
            log.info(f"    *** FRAME_STATE_GET FUNCIONOU! ***")


def probe_provision_sequence(session, log):
    """Tenta reproduzir a sequencia de provisioning da captura.

    Captura: 3 comandos pos-TLS
      OUT: 33, 33, 25B → IN: 58, 26, 26B

    O primeiro cmd retorna 58B (34B plaintext = status(2) + 32B dados)
    Candidatos para cmd de 33B plaintext:
      - 0x8e com subcomando desconhecido (33B = 1+sub+payload)
      - 0x39 IOTA_FIND com params (33B)
      - 0x41 com payload
    """
    log.separator()
    log.info("=== Sequencia de provisioning (33B cmds) ===")

    # 33B plaintext = algum comando com ~32B de payload
    # Possibilidades: subcomandos do 0x8e que nao testamos
    log.info("--- 0x8e subcomandos extras ---")
    tested_subs = {0x09, 0x1a, 0x2e, 0x2f}
    interesting = []

    for sub in range(0x00, 0x40):
        if sub in tested_subs:
            continue
        cmd = bytes([0x8e, sub]) + b"\x00\x02" + b"\x00" * 13
        try:
            rsp = session.command(cmd, raw=True)
        except Exception:
            log.error(f"    0x8e 0x{sub:02x}: EXCEPTION (session dead?)")
            break
        if rsp and len(rsp) > 2:
            s = status_str(rsp)
            log.info(f"  0x8e 0x{sub:02x}: {s} — {rsp[:32].hex()}{'...' if len(rsp) > 32 else ''}")
            interesting.append((sub, rsp))
        elif rsp and rsp != b"\x05\x04":
            log.info(f"  0x8e 0x{sub:02x}: {rsp.hex()}")
        time.sleep(0.1)

    if interesting:
        log.info(f"--- Encontrados {len(interesting)} subcomandos com dados! ---")
    else:
        log.info("--- Nenhum subcomando novo com dados ---")


def probe_check_state(session, log):
    """Verifica estado apos todos os testes."""
    log.separator()
    log.info("=== Estado final ===")

    # GET_VERSION
    rsp = send_cmd(session, log, "0x01 GET_VERSION", bytes([0x01]))
    if rsp and len(rsp) >= 38:
        state = rsp[-1]
        log.info(f"    Estado: 0x{state:02x}")

    # GET_START_INFO
    rsp = send_cmd(session, log, "0x19 GET_START_INFO", bytes([0x19]))
    if rsp and len(rsp) >= 2:
        log.info(f"    Start info: {rsp.hex()}")

    # MSG6
    rsp = send_cmd(session, log, "0x40 MSG6", bytes([0x40]))
    if rsp:
        log.info(f"    MSG6: {rsp.hex()}")


def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")
    log.info(f"Objetivo: encontrar os 3 comandos de provisioning da captura")
    log.info(f"Captura: OUT 33,33,25B → IN 58,26,26B")

    try:
        dev, session = setup_tls(log)
        if not session:
            return

        # Probes em ordem de probabilidade
        probe_provision_sequence(session, log)  # 0x8e subcomandos extras
        probe_0x82_extended(session, log)       # frame state
        probe_msg6_variants(session, log)       # MSG6 com payloads
        probe_0x39_iota(session, log)           # IOTA_FIND
        probe_0x41_unknown(session, log)        # 0x41 desconhecido
        probe_0x57_unknown(session, log)        # 0x57 desconhecido
        probe_check_state(session, log)         # estado final

        log.separator()
        log.info("*** PROBE PROVISION COMPLETE ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        if 'dev' in dir() and dev:
            dev.close()
        log.separator()
        log.info(f"Log: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
