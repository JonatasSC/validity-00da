#!/usr/bin/env python3
"""
Probe 0x40 (GET_CERTIFICATE_EX) com payloads derivados da sessao TLS.

A captura Windows mostra: 33B out → 58B in como primeiro comando pos-TLS.
33B = 0x40 + 32 bytes payload. Os 32 bytes sao provavelmente um hash/nonce.

Testa: SHA-256 de certs, randoms, master secret, etc.

Log: logs/tls_probe_0x40.txt
"""

import sys
import os
import hashlib
import struct
import time
import secrets
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice
from scripts.tls_provision import (
    Logger, TlsSession, tls_prf_sha256, tls_prf_sha384,
)
from scripts.tls_handshake import pre_tls_phase

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "tls_probe_0x40.txt")

STATUS = {
    b"\x00\x00": "OK",
    b"\x01\x04": "UNKNOWN_CMD",
    b"\x03\x04": "PARAM_ERROR",
    b"\x05\x04": "NEEDS_PARAMS",
    b"\x06\x04": "ACCESS_DENIED",
    b"\xe7\x06": "NOT_PROVISIONED",
}


def do_pair_extended(dev, log):
    """PAIR que retorna dados extras."""
    pw = bytes.fromhex('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
    hs_key_bytes = tls_prf_sha256(pw[:16], "HS_KEY_PAIR_GEN", pw[16:] + b'\xaa\xaa', 32)
    hs_key_int = int(hs_key_bytes[::-1].hex(), 16)
    hs_privkey = ec.derive_private_key(hs_key_int, ec.SECP256R1(), default_backend())

    pair_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pair_pub = pair_privkey.public_key().public_numbers()
    pair_x = pair_pub.x.to_bytes(32, 'big')
    pair_y = pair_pub.y.to_bytes(32, 'big')

    pair_cert = bytearray(400)
    struct.pack_into("<HH", pair_cert, 0, 0x5f3f, 23)
    pair_cert[4:36] = pair_x[::-1]
    pair_cert[72:104] = pair_y[::-1]
    pair_cert[141] = 0x00
    signbytes = bytes(pair_cert[0:142])
    der_sig = hs_privkey.sign(signbytes, ec.ECDSA(hashes.SHA256()))
    struct.pack_into("<H", pair_cert, 142, len(der_sig))
    pair_cert[144:144 + len(der_sig)] = der_sig

    dev.write(b"\x93" + bytes(pair_cert))
    rsp = dev.read(timeout=10000)

    if rsp and len(rsp) >= 802 and rsp[0:2] == b"\x00\x00":
        host_echo = bytes(rsp[2:402])
        sensor_cert_raw = bytes(rsp[402:802])
        sensor_x = sensor_cert_raw[4:36][::-1]
        sensor_y = sensor_cert_raw[72:104][::-1]
        tls_cert = b"PR" + host_echo[0:398]

        log.info("  *** PAIR OK! ***")
        return {
            "privkey": pair_privkey,
            "tls_cert": tls_cert,
            "sensor_x": sensor_x,
            "sensor_y": sensor_y,
            "host_echo": host_echo,
            "sensor_cert_raw": sensor_cert_raw,
            "pair_cert": bytes(pair_cert),
            "hs_key_bytes": hs_key_bytes,
        }
    else:
        log.error(f"  PAIR falhou: {rsp[:4].hex() if rsp else 'timeout'}")
        return None


def do_handshake_extended(dev, log, pair_data):
    """TLS handshake que retorna session + todos os valores cripto."""
    ecdsa_privkey = pair_data["privkey"]
    ecdh_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_pub = ecdh_privkey.public_key().public_numbers()
    ecdh_x = ecdh_pub.x.to_bytes(32, 'big')
    ecdh_y = ecdh_pub.y.to_bytes(32, 'big')

    hs_sha256 = hashlib.sha256()

    client_random = secrets.token_bytes(32)
    ch_body = bytearray()
    ch_body += b"\x03\x03" + client_random
    ch_body += b"\x07" + b"\x00" * 7
    ch_body += b"\x00\x0a\xc0\x05\xc0\x2e\x00\x3d\x00\x8d\x00\xa8"
    ch_body += b"\x00\x00\x0a\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00"

    ch_hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + bytes(ch_body)
    hs_sha256.update(ch_hs)
    ch_record = b"\x16\x03\x03" + struct.pack(">H", len(ch_hs)) + ch_hs
    dev.write(b"\x44\x00\x00\x00" + ch_record)

    srv_rsp = dev.read()
    if srv_rsp is None or srv_rsp[0] == 0x15:
        log.error("  ServerHello falhou")
        return None

    rec_len = struct.unpack(">H", srv_rsp[3:5])[0]
    rec_data = srv_rsp[5:5 + rec_len]
    hs_sha256.update(rec_data)
    server_random = bytes(rec_data[6:38])
    log.info(f"  ServerHello OK, cipher 0xc02e")

    msg = bytearray(b"\x44\x00\x00\x00\x16\x03\x03")
    rec_len_pos = len(msg)
    msg += b"\x00\x00"

    cert_raw = pair_data["tls_cert"]
    cert_list = (struct.pack(">I", len(cert_raw))[1:]
                + struct.pack(">I", len(cert_raw))[1:]
                + cert_raw + b"\x00\x00")
    cert_hs = b"\x0b" + struct.pack(">I", len(cert_list))[1:] + cert_list
    msg += cert_hs

    ecdh_point = b"\x04" + ecdh_x + ecdh_y
    cke_hs = b"\x10" + struct.pack(">I", len(ecdh_point))[1:] + ecdh_point
    msg += cke_hs
    hs_sha256.update(cert_hs + cke_hs)

    cv_hash = hs_sha256.copy().digest()
    signature = ecdsa_privkey.sign(cv_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    cv_hs = b"\x0f" + struct.pack(">I", len(signature))[1:] + signature
    msg += cv_hs
    hs_sha256.update(cv_hs)

    struct.pack_into(">H", msg, rec_len_pos, len(msg) - rec_len_pos - 2)
    msg += b"\x14\x03\x03\x00\x01\x01"

    sx = int.from_bytes(pair_data["sensor_x"], "big")
    sy = int.from_bytes(pair_data["sensor_y"], "big")
    sensor_pub = EllipticCurvePublicNumbers(sx, sy, ec.SECP256R1()).public_key(default_backend())
    pms = ecdh_privkey.exchange(ECDH(), sensor_pub)

    seed = client_random + server_random
    master_secret = tls_prf_sha384(pms, "master secret", seed, 48)
    key_block = tls_prf_sha384(master_secret, "key expansion", client_random + server_random, 128)
    cwk = key_block[0:32]
    swk = key_block[32:64]
    civ = key_block[64:68]
    siv = key_block[68:72]

    finished_hash = hs_sha256.digest()
    verify_data = tls_prf_sha384(master_secret, "client finished", finished_hash, 12)
    finished_pt = b"\x14\x00\x00\x0c" + verify_data

    nonce = civ + b"\x00" * 8
    aad = b"\x00" * 8 + b"\x16\x03\x03" + struct.pack(">H", len(finished_pt))
    encrypted = AESGCM(cwk).encrypt(nonce, finished_pt, aad)
    msg += b"\x16\x03\x03" + struct.pack(">H", 8 + len(encrypted)) + b"\x00" * 8 + encrypted

    dev.write(bytes(msg))
    rsp = dev.read(timeout=5000)
    if rsp is None:
        return None

    success = False
    offset = 0
    while offset + 5 <= len(rsp):
        ct = rsp[offset]
        rl = struct.unpack(">H", rsp[offset+3:offset+5])[0]
        if ct == 0x15:
            log.error("  Alert!")
            return None
        elif ct == 0x14:
            pass
        elif ct == 0x16:
            success = True
        offset += 5 + rl

    if not success:
        return None

    log.info("  *** TLS OK! ***")
    session = TlsSession(dev, log, cwk, civ, swk, siv)

    return {
        "session": session,
        "client_random": client_random,
        "server_random": server_random,
        "master_secret": master_secret,
        "pms": pms,
        "finished_hash": finished_hash,
        "verify_data": verify_data,
        "ecdh_x": ecdh_x,
        "ecdh_y": ecdh_y,
    }


def main():
    log = Logger(LOG_FILE)
    log.info(f"Objetivo: payload correto do 0x40 (33B → 58B)")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        return

    try:
        pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        log.info("PAIR...")
        pair_data = do_pair_extended(dev, log)
        if not pair_data:
            return

        dev.reset(); time.sleep(1)
        pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        log.info("TLS...")
        hs = do_handshake_extended(dev, log, pair_data)
        if not hs:
            return

        session = hs["session"]

        # Payloads candidatos (todos 32B)
        payloads = [
            ("SHA256(sensor_cert_raw)", hashlib.sha256(pair_data["sensor_cert_raw"]).digest()),
            ("SHA256(host_echo)", hashlib.sha256(pair_data["host_echo"]).digest()),
            ("SHA256(tls_cert)", hashlib.sha256(pair_data["tls_cert"]).digest()),
            ("SHA256(pair_cert)", hashlib.sha256(pair_data["pair_cert"]).digest()),
            ("client_random", hs["client_random"]),
            ("server_random", hs["server_random"]),
            ("master_secret[:32]", hs["master_secret"][:32]),
            ("PMS[:32]", hs["pms"][:32]),
            ("finished_hash", hs["finished_hash"]),
            ("ecdh_x", hs["ecdh_x"]),
            ("ecdh_y", hs["ecdh_y"]),
            ("sensor_x", pair_data["sensor_x"]),
            ("sensor_y", pair_data["sensor_y"]),
            ("hs_key", pair_data["hs_key_bytes"]),
            ("SHA256(cr+sr)", hashlib.sha256(hs["client_random"] + hs["server_random"]).digest()),
            ("SHA256(ms)", hashlib.sha256(hs["master_secret"]).digest()),
            ("SHA256(PMS)", hashlib.sha256(hs["pms"]).digest()),
            ("sensor_proof", pair_data["sensor_cert_raw"][145:177]),
            ("SHA256(host_signbytes)", hashlib.sha256(pair_data["pair_cert"][0:142]).digest()),
            ("PRF(ms,provision,cr+sr)", tls_prf_sha384(hs["master_secret"], "provision", hs["client_random"] + hs["server_random"], 32)),
            ("PRF(ms,certificate,cr+sr)", tls_prf_sha384(hs["master_secret"], "certificate", hs["client_random"] + hs["server_random"], 32)),
            ("verify_data+pad", hs["verify_data"] + b"\x00" * 20),
            ("32_zeros_baseline", b"\x00" * 32),
        ]

        log.separator()
        log.info(f"=== {len(payloads)} payloads para 0x40 ===")

        for desc, payload in payloads:
            if len(payload) != 32:
                log.warn(f"  {desc}: skip ({len(payload)}B != 32)")
                continue

            cmd = b"\x40" + payload
            log.info(f"  {desc}")

            try:
                rsp = session.command(cmd, raw=True)
            except Exception as e:
                log.error(f"    → EXCEPTION: {e}")
                break

            if rsp is None:
                log.warn(f"    → TIMEOUT/ALERT — session dead")
                break
            elif len(rsp) > 2:
                log.info(f"    → *** DATA({len(rsp)}B)! *** {rsp.hex()}")
                log.info(f"    *** FOUND IT: {desc} ***")
            else:
                s = STATUS.get(rsp, f"0x{rsp.hex()}")
                log.info(f"    → {s}")

            time.sleep(0.15)

        log.separator()
        rsp = session.command(b"\x01", raw=True)
        if rsp and len(rsp) >= 38:
            log.info(f"Estado final: 0x{rsp[-1]:02x}")

        log.info("*** DONE ***")

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
