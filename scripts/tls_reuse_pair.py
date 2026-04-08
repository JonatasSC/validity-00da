#!/usr/bin/env python3
"""
Teste: PAIR uma vez, depois TLS sem PAIR (reutilizando dados).

Simula o fluxo do driver Windows:
  Sessao 1: Pre-TLS → PAIR → salva dados
  Sessao 2: Reset → Pre-TLS → TLS (com dados salvos, SEM PAIR novo)

Se o sensor mantem o pairing entre resets, o TLS deve funcionar
sem refazer o PAIR.

Log: logs/tls_reuse_pair.txt
"""

import sys, os, struct, time, secrets, hashlib, json
import hmac as hmac_mod
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice
from scripts.tls_provision import Logger, TlsSession, tls_prf_sha256, tls_prf_sha384
from scripts.tls_handshake import pre_tls_phase

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
PAIR_DIR = os.path.join(LOG_DIR, "pairing")
LOG_FILE = os.path.join(LOG_DIR, "tls_reuse_pair.txt")


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

        # Salvar dados
        os.makedirs(PAIR_DIR, exist_ok=True)
        with open(os.path.join(PAIR_DIR, "host_cert.bin"), "wb") as f:
            f.write(host_echo)
        with open(os.path.join(PAIR_DIR, "sensor_cert.bin"), "wb") as f:
            f.write(sensor_cert)
        pem = pair_privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(os.path.join(PAIR_DIR, "host_privkey.pem"), "wb") as f:
            f.write(pem)
        log.info(f"  Pairing data salvo em {PAIR_DIR}/")

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


def load_pairing_data(log):
    """Carrega pairing data salvos de sessao anterior."""
    try:
        with open(os.path.join(PAIR_DIR, "host_privkey.pem"), "rb") as f:
            privkey = load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(os.path.join(PAIR_DIR, "host_cert.bin"), "rb") as f:
            host_echo = f.read()
        with open(os.path.join(PAIR_DIR, "sensor_cert.bin"), "rb") as f:
            sensor_cert = f.read()

        sensor_x = sensor_cert[4:36][::-1]
        sensor_y = sensor_cert[72:104][::-1]
        tls_cert = b"PR" + bytes(host_echo[0:398])

        log.info(f"  Pairing data carregado de {PAIR_DIR}/")
        log.info(f"  Sensor X: {sensor_x.hex()}")
        return {
            "privkey": privkey,
            "tls_cert": tls_cert,
            "sensor_x": sensor_x,
            "sensor_y": sensor_y,
        }
    except FileNotFoundError:
        log.warn("  Sem pairing data salvo!")
        return None


def do_handshake(dev, log, pairing_data):
    ecdsa_privkey = pairing_data["privkey"]
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
        if srv_rsp and len(srv_rsp) >= 7:
            log.error(f"  Alert: level={srv_rsp[5]}, desc={srv_rsp[6]}")
        else:
            log.error("  ServerHello falhou")
        return None

    rec_len = struct.unpack(">H", srv_rsp[3:5])[0]
    rec_data = srv_rsp[5:5 + rec_len]
    hs_sha256.update(rec_data)

    server_random = bytes(rec_data[6:38])
    sid_len = rec_data[38]
    selected_cipher = int.from_bytes(rec_data[39+sid_len:41+sid_len], 'big')
    prf = tls_prf_sha384 if selected_cipher == 0xc02e else tls_prf_sha256

    msg = bytearray(b"\x44\x00\x00\x00\x16\x03\x03")
    rec_len_pos = len(msg)
    msg += b"\x00\x00"

    cert_raw = pairing_data["tls_cert"]
    cert_list = struct.pack(">I", len(cert_raw))[1:] + struct.pack(">I", len(cert_raw))[1:] + cert_raw + b"\x00\x00"
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
    cw_key, sw_key, cw_iv, sw_iv = key_block[0:32], key_block[32:64], key_block[64:68], key_block[68:72]

    finished_hash = hs_sha256.digest()
    verify_data = prf(master_secret, "client finished", finished_hash, 12)
    finished_pt = b"\x14\x00\x00\x0c" + verify_data

    nonce = cw_iv + b"\x00" * 8
    aad = b"\x00" * 8 + b"\x16\x03\x03" + struct.pack(">H", len(finished_pt))
    encrypted = AESGCM(cw_key).encrypt(nonce, finished_pt, aad)
    msg += b"\x16\x03\x03" + struct.pack(">H", 8 + len(encrypted)) + b"\x00" * 8 + encrypted

    dev.write(bytes(msg))
    rsp = dev.read(timeout=5000)
    if rsp is None:
        return None

    offset = 0
    success = False
    while offset + 5 <= len(rsp):
        ct = rsp[offset]
        rl = struct.unpack(">H", rsp[offset+3:offset+5])[0]
        if ct == 0x15:
            log.error(f"  Alert: level={rsp[offset+5]}, desc={rsp[offset+6]}")
            return None
        elif ct == 0x14:
            log.info("  CCS")
        elif ct == 0x16:
            log.info("  Finished!")
            success = True
        offset += 5 + rl

    if not success:
        return None
    return TlsSession(dev, log, cw_key, cw_iv, sw_key, sw_iv)


def main():
    log = Logger(LOG_FILE)
    log.info("=== TLS reuse pairing data ===")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        sys.exit(1)

    try:
        # Fase 1: Pre-TLS + PAIR
        log.separator()
        log.info("FASE 1: Pre-TLS + PAIR")
        pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        pairing_data = do_pair(dev, log)
        if not pairing_data:
            return

        # Fase 2: Reset (simula "reboot")
        log.separator()
        log.info("FASE 2: USB Reset (simula reboot)")
        dev.reset()
        time.sleep(1)

        # Fase 3: Pre-TLS (sem PAIR!) + TLS com dados salvos
        log.separator()
        log.info("FASE 3: Pre-TLS (sem PAIR) + TLS com dados salvos")
        pre_tls_phase(dev, log, round_num=3)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        log.info("  TLS com pairing data da Fase 1...")
        session = do_handshake(dev, log, pairing_data)
        if session:
            log.info("  *** TLS OK com dados reutilizados! ***")
        else:
            log.error("  TLS FALHOU com dados reutilizados")
            log.info("  Tentando com pairing data do disco...")
            saved = load_pairing_data(log)
            if saved:
                dev.reset()
                time.sleep(1)
                pre_tls_phase(dev, log, round_num=5)
                time.sleep(0.1)
                pre_tls_phase(dev, log, round_num=6)
                session = do_handshake(dev, log, saved)
                if session:
                    log.info("  *** TLS OK com dados do disco! ***")
                else:
                    log.error("  TLS tambem falhou com dados do disco")
                    return
            else:
                return

        # Fase 4: Testes
        log.separator()
        log.info("FASE 4: Testes via TLS (sem PAIR nesta sessao)")

        rsp = session.command(b"\x01", raw=True)
        if rsp and len(rsp) >= 38:
            log.info(f"  GET_VERSION: estado=0x{rsp[-1]:02x}")

        msg6 = bytes.fromhex("40010100000000000000100000")
        rsp = session.command(msg6, raw=True)
        if rsp:
            if rsp == bytes.fromhex("e706"):
                log.info("  MSG6: e7 06 (STILL NOT PROVISIONED)")
            elif len(rsp) > 2:
                log.info(f"  MSG6: {len(rsp)}B DATA! >>> {rsp[:48].hex()}")
            else:
                log.info(f"  MSG6: {rsp.hex()}")

        rsp = session.command(bytes([0x9e]) + struct.pack("<H", 0), raw=True)
        if rsp:
            log.info(f"  DB2: {rsp.hex()}" + (f" ({len(rsp)}B)" if len(rsp) > 2 else ""))

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
