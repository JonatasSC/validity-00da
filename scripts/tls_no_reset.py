#!/usr/bin/env python3
"""
Teste: PAIR + TLS SEM reset entre eles.

Hipotese: o sensor mantem estado de pairing na mesma sessao USB.
Sem reset, nao precisa "carregar" pairing data — ja esta na memoria.

Fluxo:
  1. Pre-TLS (2x)
  2. PAIR (0x93)
  3. TLS Handshake DIRETO (sem reset, sem pre-TLS extra)
  4. Testa MSG6 (0x40) e DB2 via TLS

Log: logs/tls_no_reset.txt
"""

import sys, os, struct, time, secrets, hashlib
import hmac as hmac_mod
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice
from scripts.tls_provision import Logger, TlsSession, tls_prf_sha256, tls_prf_sha384
from scripts.tls_handshake import pre_tls_phase

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "logs", "tls_no_reset.txt")


def do_pair(dev, log):
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
        host_echo = rsp[2:402]
        sensor_cert = rsp[402:802]
        sensor_x = sensor_cert[4:36][::-1]
        sensor_y = sensor_cert[72:104][::-1]
        tls_cert = b"PR" + bytes(host_echo[0:398])
        log.info("  *** PAIR OK! ***")
        return {
            "privkey": pair_privkey,
            "tls_cert": tls_cert,
            "sensor_x": sensor_x,
            "sensor_y": sensor_y,
        }
    else:
        status = rsp[0:2].hex() if rsp else "timeout"
        log.error(f"  PAIR falhou: {status}")
        return None


def do_handshake(dev, log, pairing_data):
    ecdsa_privkey = pairing_data["privkey"]
    ecdsa_pub = ecdsa_privkey.public_key().public_numbers()
    ecdsa_x = ecdsa_pub.x.to_bytes(32, 'big')
    ecdsa_y = ecdsa_pub.y.to_bytes(32, 'big')

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
    log.info("  ClientHello enviado")

    srv_rsp = dev.read()
    if srv_rsp is None or srv_rsp[0] == 0x15:
        if srv_rsp and srv_rsp[0] == 0x15 and len(srv_rsp) >= 7:
            log.error(f"  TLS Alert: level={srv_rsp[5]}, desc={srv_rsp[6]}")
        else:
            log.error("  ServerHello falhou")
        return None

    rec_len = struct.unpack(">H", srv_rsp[3:5])[0]
    rec_data = srv_rsp[5:5 + rec_len]
    hs_sha256.update(rec_data)

    server_random = bytes(rec_data[6:38])
    sid_len = rec_data[38]
    cipher_off = 39 + sid_len
    selected_cipher = int.from_bytes(rec_data[cipher_off:cipher_off+2], 'big')
    log.info(f"  Cipher: 0x{selected_cipher:04x}")

    use_gcm = (selected_cipher == 0xc02e)
    prf = tls_prf_sha384 if use_gcm else tls_prf_sha256

    msg = bytearray()
    msg += b"\x44\x00\x00\x00\x16\x03\x03"
    rec_len_pos = len(msg)
    msg += b"\x00\x00"

    cert_raw = pairing_data["tls_cert"]
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

    sx = int.from_bytes(pairing_data["sensor_x"], "big")
    sy = int.from_bytes(pairing_data["sensor_y"], "big")
    sensor_pub = EllipticCurvePublicNumbers(sx, sy, ec.SECP256R1()).public_key(default_backend())
    pms = ecdh_privkey.exchange(ECDH(), sensor_pub)

    seed = client_random + server_random
    master_secret = prf(pms, "master secret", seed, 48)
    key_block = prf(master_secret, "key expansion", client_random + server_random, 128)
    client_write_key = key_block[0:32]
    server_write_key = key_block[32:64]
    client_write_iv = key_block[64:68]
    server_write_iv = key_block[68:72]

    finished_hash = hs_sha256.digest()
    verify_data = prf(master_secret, "client finished", finished_hash, 12)
    finished_plaintext = b"\x14\x00\x00\x0c" + verify_data

    explicit_nonce = b"\x00" * 8
    nonce = client_write_iv + explicit_nonce
    aad = b"\x00" * 8 + b"\x16\x03\x03" + struct.pack(">H", len(finished_plaintext))
    aesgcm = AESGCM(client_write_key)
    encrypted = aesgcm.encrypt(nonce, finished_plaintext, aad)
    msg += b"\x16\x03\x03" + struct.pack(">H", 8 + len(encrypted)) + explicit_nonce + encrypted

    dev.write(bytes(msg))
    log.info(f"  Handshake enviado ({len(msg)} bytes)")

    rsp = dev.read(timeout=5000)
    if rsp is None:
        log.error("  Timeout")
        return None

    offset = 0
    success = False
    while offset + 5 <= len(rsp):
        ct = rsp[offset]
        rl = struct.unpack(">H", rsp[offset+3:offset+5])[0]
        if ct == 0x15:
            level = rsp[offset+5] if offset+5 < len(rsp) else 0
            desc = rsp[offset+6] if offset+6 < len(rsp) else 0
            log.error(f"  Alert: level={level}, desc={desc}")
            return None
        elif ct == 0x14:
            log.info("  CCS recebido")
        elif ct == 0x16:
            log.info("  Finished recebido!")
            success = True
        offset += 5 + rl

    if not success:
        return None

    log.info("  *** TLS HANDSHAKE OK! ***")
    return TlsSession(dev, log, client_write_key, client_write_iv,
                      server_write_key, server_write_iv)


def main():
    log = Logger(LOG_FILE)
    log.info("=== TLS sem reset apos PAIR ===")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        sys.exit(1)

    try:
        # Pre-TLS (2x)
        log.separator()
        log.info("FASE 1: Pre-TLS")
        pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        # PAIR
        log.separator()
        log.info("FASE 2: PAIR")
        pairing_data = do_pair(dev, log)
        if not pairing_data:
            return

        # TLS DIRETO (sem reset!)
        log.separator()
        log.info("FASE 3: TLS DIRETO (sem reset)")
        session = do_handshake(dev, log, pairing_data)
        if not session:
            log.error("TLS falhou sem reset!")
            # Fallback: tenta com reset
            log.separator()
            log.info("FALLBACK: Reset + Pre-TLS + TLS")
            dev.reset()
            time.sleep(1)
            pre_tls_phase(dev, log, round_num=3)
            time.sleep(0.1)
            pre_tls_phase(dev, log, round_num=4)
            session = do_handshake(dev, log, pairing_data)
            if not session:
                log.error("TLS tambem falhou com reset!")
                return

        # Testar comandos
        log.separator()
        log.info("FASE 4: Testes via TLS")

        # GET_VERSION
        rsp = session.command(b"\x01", raw=True)
        if rsp and len(rsp) >= 38:
            log.info(f"  GET_VERSION: {len(rsp)}B, estado=0x{rsp[-1]:02x}")
        else:
            log.warn(f"  GET_VERSION: {rsp.hex() if rsp else 'None'}")

        # MSG6 (0x40) — o teste principal
        msg6 = bytes.fromhex("40010100000000000000100000")
        rsp = session.command(msg6, raw=True)
        if rsp:
            if rsp == bytes.fromhex("e706"):
                log.info(f"  MSG6: e7 06 (STILL NOT PROVISIONED)")
            elif len(rsp) > 2:
                log.info(f"  MSG6: {len(rsp)}B DATA! >>> {rsp[:48].hex()}")
                log.info(f"  >>> MSG6 RETORNOU DADOS! PROVISIONING PODE TER FUNCIONADO!")
            else:
                log.info(f"  MSG6: {rsp.hex()}")
        else:
            log.warn(f"  MSG6: ALERT/TIMEOUT")

        # DB2
        rsp = session.command(bytes([0x9e]) + struct.pack("<H", 0), raw=True)
        if rsp:
            if len(rsp) > 2:
                log.info(f"  DB2_GET_DB_INFO: {len(rsp)}B DATA! >>> {rsp.hex()}")
            else:
                log.info(f"  DB2_GET_DB_INFO: {rsp.hex()}")

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


if __name__ == "__main__":
    main()
