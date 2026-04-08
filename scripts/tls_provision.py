#!/usr/bin/env python3
"""
TLS Provisioning — Envia comandos via TLS tunnel para o sensor 06cb:00da.

Fluxo completo:
  1. Pre-TLS (2x)
  2. PAIR (0x93)
  3. USB Reset + Pre-TLS (2x)
  4. TLS Handshake
  5. Comandos via Application Data (criptografado)

Uso:
  sudo python3 scripts/tls_provision.py
  sudo CMDS="0x01,0x82,0x19" python3 scripts/tls_provision.py

Log: logs/tls_provision.txt
"""

import sys
import os
import hashlib
import hmac as hmac_mod
import struct
import secrets
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, ECDH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "tls_provision.txt")


# =============================================================
# Logger (reutilizado do tls_handshake.py)
# =============================================================

class Logger:
    def __init__(self, filepath):
        self.f = open(filepath, "w")
        self._write(f"=== TLS Provision Log — {datetime.now().isoformat()} ===\n")

    def info(self, msg):
        self._write(f"[INFO]  {msg}")
        print(f"INFO  {msg}")

    def warn(self, msg):
        self._write(f"[WARN]  {msg}")
        print(f"WARN  {msg}")

    def error(self, msg):
        self._write(f"[ERROR] {msg}")
        print(f"ERROR {msg}")

    def hex_dump(self, label, data, max_show=32):
        hex_str = data.hex()
        self._write(f"[HEX]   {label} ({len(data)} bytes):")
        for i in range(0, len(hex_str), 64):
            self._write(f"        {hex_str[i:i+64]}")
        if len(data) > max_show:
            print(f"  HEX {label}: {data[:max_show].hex()}... ({len(data)} bytes)")
        else:
            print(f"  HEX {label}: {hex_str}")

    def separator(self, char="=", width=60):
        line = char * width
        self._write(line)
        print(line)

    def _write(self, msg):
        self.f.write(msg + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


# =============================================================
# TLS PRF
# =============================================================

def _p_hash(secret, seed, length, hash_func):
    result = b""
    a = seed
    while len(result) < length:
        a = hmac_mod.new(secret, a, hash_func).digest()
        result += hmac_mod.new(secret, a + seed, hash_func).digest()
    return result[:length]

def tls_prf_sha384(secret, label, seed, length):
    return _p_hash(secret, label.encode("ascii") + seed, length, hashlib.sha384)

def tls_prf_sha256(secret, label, seed, length):
    return _p_hash(secret, label.encode("ascii") + seed, length, hashlib.sha256)


# =============================================================
# TLS Session — encapsulates encryption state
# =============================================================

class TlsSession:
    """Manages TLS Application Data encryption/decryption."""

    def __init__(self, dev, log, client_write_key, client_write_iv,
                 server_write_key, server_write_iv):
        self.dev = dev
        self.log = log
        self.client_key = client_write_key
        self.client_iv = client_write_iv
        self.server_key = server_write_key
        self.server_iv = server_write_iv
        self.client_seq = 1   # Finished was seq=0
        self.server_seq = 1   # Server Finished was seq=0
        self.aesgcm_enc = AESGCM(client_write_key)
        self.aesgcm_dec = AESGCM(server_write_key)

    def send(self, plaintext):
        """Encrypt and send Application Data."""
        self.log.info(f"TLS SEND ({len(plaintext)} bytes): {plaintext.hex()}")

        # Nonce: static_iv(4) + explicit_nonce(8)
        # synaTudor uses random nonce, not sequence number
        use_random_nonce = os.environ.get("RANDOM_NONCE", "1") == "1"
        if use_random_nonce:
            explicit_nonce = secrets.token_bytes(8)
        else:
            explicit_nonce = self.client_seq.to_bytes(8, "big")
        nonce = self.client_iv + explicit_nonce

        # AAD: seq(8) + content_type(1) + version(2) + plaintext_len(2)
        aad = (self.client_seq.to_bytes(8, "big")
               + b"\x17\x03\x03"
               + struct.pack(">H", len(plaintext)))

        # Encrypt (returns ciphertext + 16-byte tag)
        encrypted = self.aesgcm_enc.encrypt(nonce, plaintext, aad)

        # TLS record: type(1) + version(2) + length(2) + explicit_nonce(8) + encrypted
        body = explicit_nonce + encrypted
        record = b"\x17\x03\x03" + struct.pack(">H", len(body)) + body

        # USB prefix: configurable (maybe not needed for Application Data)
        use_prefix = os.environ.get("TLS_PREFIX", "0") == "1"
        if use_prefix:
            msg = b"\x44\x00\x00\x00" + record
        else:
            msg = record
        self.dev.write(msg)
        self.client_seq += 1

        self.log.info(f"  Sent {len(msg)} bytes (seq={self.client_seq - 1})")

    def _decrypt_record(self, rec_data, content_type):
        """Decrypt a single TLS record. Returns plaintext or None."""
        if len(rec_data) < 24:  # 8 nonce + 16 tag minimum
            self.log.error(f"  Record too short for GCM: {len(rec_data)}")
            return None

        explicit_nonce = rec_data[0:8]
        ciphertext = rec_data[8:]
        nonce = self.server_iv + explicit_nonce
        plaintext_len = len(ciphertext) - 16  # subtract GCM tag

        # AAD uses the actual content type (0x15 for Alert, 0x17 for AppData)
        aad = (self.server_seq.to_bytes(8, "big")
               + bytes([content_type]) + b"\x03\x03"
               + struct.pack(">H", plaintext_len))

        try:
            plaintext = self.aesgcm_dec.decrypt(nonce, ciphertext, aad)
            self.server_seq += 1
            return plaintext
        except Exception as e:
            self.log.error(f"  Decrypt FAILED: {e}")
            self.log.info(f"  server_seq: {self.server_seq}, nonce: {nonce.hex()}")
            return None

    def recv(self, timeout=5000):
        """Receive and decrypt Application Data."""
        rsp = self.dev.read(timeout=timeout)
        if rsp is None:
            self.log.warn("  TLS recv: timeout")
            return None

        self.log.info(f"TLS RECV ({len(rsp)} bytes)")
        self.log.hex_dump("Raw response", rsp)

        # Parse TLS record(s) from response
        offset = 0
        results = []

        while offset + 5 <= len(rsp):
            content_type = rsp[offset]
            rec_version = rsp[offset+1:offset+3]
            rec_len = struct.unpack(">H", rsp[offset+3:offset+5])[0]
            rec_data = rsp[offset+5:offset+5+rec_len]

            if content_type == 0x15:  # Alert (may be encrypted!)
                if rec_len == 2:
                    # Unencrypted alert
                    level = rec_data[0]
                    desc = rec_data[1]
                    self.log.error(f"  TLS Alert (plain): level={level}, desc={desc}")
                else:
                    # Encrypted alert — decrypt it
                    plaintext = self._decrypt_record(rec_data, 0x15)
                    if plaintext and len(plaintext) >= 2:
                        level = plaintext[0]
                        desc = plaintext[1]
                        self.log.error(f"  TLS Alert (decrypted): level={level}, desc={desc}")
                    else:
                        self.log.error(f"  TLS Alert: failed to decrypt ({rec_len} bytes)")
                return None

            elif content_type == 0x17:  # Application Data
                plaintext = self._decrypt_record(rec_data, 0x17)
                if plaintext is not None:
                    self.log.info(f"  Decrypted ({len(plaintext)} bytes, seq={self.server_seq - 1}): {plaintext.hex()}")
                    results.append(plaintext)
                else:
                    return None

            else:
                self.log.warn(f"  Unknown content type: 0x{content_type:02x}")

            offset += 5 + rec_len

        if results:
            return b"".join(results)
        return None

    def command(self, cmd_bytes, timeout=5000, raw=False):
        """Send a command and receive response via TLS.

        Commands inside TLS have a 4-byte header (synaTudor framing):
          [u16le status=0] [u16le length] [command data]
        Response also has this header:
          [u16le status] [u16le length] [response data]
        """
        if raw:
            self.send(cmd_bytes)
        else:
            # Add synaTudor command framing
            framed = struct.pack("<HH", 0, len(cmd_bytes)) + cmd_bytes
            self.log.info(f"  Framed command: {framed.hex()}")
            self.send(framed)

        rsp = self.recv(timeout=timeout)
        if rsp is None:
            return None

        if raw:
            return rsp

        # Parse response framing
        if len(rsp) >= 4:
            resp_status, resp_len = struct.unpack("<HH", rsp[0:4])
            self.log.info(f"  Response status: 0x{resp_status:04x}, length: {resp_len}")
            if resp_status != 0:
                self.log.error(f"  Command error: 0x{resp_status:04x}")
            return rsp[4:4+resp_len] if resp_len > 0 else rsp[4:]
        return rsp


# =============================================================
# Reutilizar handshake do tls_handshake.py
# =============================================================

# Import the handshake components
from scripts.tls_handshake import (
    pre_tls_phase, tls_prf_sha256 as _prf256, tls_prf_sha384 as _prf384,
    SS_PUBKEY_PROD, compute_ecdh_premaster,
    ALERT_LEVELS, ALERT_DESCS,
)


def do_pair(dev, log):
    """Execute PAIR command (0x93). Returns pairing_data dict or None."""
    pw = bytes.fromhex('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
    hs_key_bytes = tls_prf_sha256(pw[:16], "HS_KEY_PAIR_GEN", pw[16:] + b'\xaa\xaa', 32)
    hs_key_int = int(hs_key_bytes[::-1].hex(), 16)
    hs_privkey = ec.derive_private_key(hs_key_int, ec.SECP256R1(), default_backend())

    # Generate host keypair
    pair_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pair_pub = pair_privkey.public_key().public_numbers()
    pair_x = pair_pub.x.to_bytes(32, 'big')
    pair_y = pair_pub.y.to_bytes(32, 'big')

    # Build synaTudor cert (no PR, 400B)
    pair_cert = bytearray(400)
    struct.pack_into("<HH", pair_cert, 0, 0x5f3f, 23)
    pair_cert[4:36] = pair_x[::-1]
    pair_cert[72:104] = pair_y[::-1]
    pair_cert[141] = 0x00
    signbytes = bytes(pair_cert[0:142])
    der_sig = hs_privkey.sign(signbytes, ec.ECDSA(hashes.SHA256()))
    struct.pack_into("<H", pair_cert, 142, len(der_sig))
    pair_cert[144:144 + len(der_sig)] = der_sig

    log.info(f"  PAIR cert: {len(der_sig)}B DER sig")
    dev.write(b"\x93" + bytes(pair_cert))
    rsp = dev.read(timeout=10000)

    if rsp and len(rsp) >= 802 and rsp[0:2] == b"\x00\x00":
        host_echo = rsp[2:402]
        sensor_cert = rsp[402:802]
        sensor_x = sensor_cert[4:36][::-1]
        sensor_y = sensor_cert[72:104][::-1]
        tls_cert = b"PR" + bytes(host_echo[0:398])

        log.info("  *** PAIR OK! ***")
        log.info(f"  Sensor X: {sensor_x.hex()}")
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
    """
    Execute TLS handshake. Returns TlsSession or None.
    Replicates the logic from tls_handshake.py but returns session keys.
    """
    ecdsa_privkey = pairing_data["privkey"]
    ecdsa_pub = ecdsa_privkey.public_key().public_numbers()
    ecdsa_x = ecdsa_pub.x.to_bytes(32, 'big')
    ecdsa_y = ecdsa_pub.y.to_bytes(32, 'big')

    ecdh_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_pub = ecdh_privkey.public_key().public_numbers()
    ecdh_x = ecdh_pub.x.to_bytes(32, 'big')
    ecdh_y = ecdh_pub.y.to_bytes(32, 'big')

    hs_sha256 = hashlib.sha256()

    # ClientHello
    client_random = secrets.token_bytes(32)
    ch_body = bytearray()
    ch_body += b"\x03\x03"
    ch_body += client_random
    ch_body += b"\x07" + b"\x00" * 7
    ch_body += b"\x00\x0a"
    ch_body += b"\xc0\x05\xc0\x2e\x00\x3d\x00\x8d\x00\xa8"
    ch_body += b"\x00"
    ch_body += b"\x00\x0a\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00"

    ch_hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + bytes(ch_body)
    hs_sha256.update(ch_hs)

    ch_record = b"\x16\x03\x03" + struct.pack(">H", len(ch_hs)) + ch_hs
    dev.write(b"\x44\x00\x00\x00" + ch_record)
    log.info(f"  ClientHello enviado ({len(ch_record)} bytes)")

    # ServerHello
    srv_rsp = dev.read()
    if srv_rsp is None or srv_rsp[0] == 0x15:
        log.error("  ServerHello falhou")
        return None

    rec_len = struct.unpack(">H", srv_rsp[3:5])[0]
    rec_data = srv_rsp[5:5 + rec_len]
    hs_sha256.update(rec_data)

    # Parse ServerHello
    server_random = bytes(rec_data[6:38])
    sid_len = rec_data[38]
    cipher_off = 39 + sid_len
    selected_cipher = int.from_bytes(rec_data[cipher_off:cipher_off+2], 'big')
    log.info(f"  Cipher: 0x{selected_cipher:04x}, Random: {server_random[:8].hex()}...")

    use_gcm = (selected_cipher == 0xc02e)
    prf = tls_prf_sha384 if use_gcm else tls_prf_sha256

    # Build response: Certificate + CKE + CV + CCS + Finished
    msg = bytearray()
    msg += b"\x44\x00\x00\x00\x16\x03\x03"
    rec_len_pos = len(msg)
    msg += b"\x00\x00"

    # Certificate
    cert_raw = pairing_data["tls_cert"]
    cert_list = (struct.pack(">I", len(cert_raw))[1:]
                + struct.pack(">I", len(cert_raw))[1:]
                + cert_raw + b"\x00\x00")
    cert_hs = b"\x0b" + struct.pack(">I", len(cert_list))[1:] + cert_list
    msg += cert_hs

    # CKE
    ecdh_point = b"\x04" + ecdh_x + ecdh_y
    cke_hs = b"\x10" + struct.pack(">I", len(ecdh_point))[1:] + ecdh_point
    msg += cke_hs

    hs_sha256.update(cert_hs + cke_hs)

    # CertificateVerify
    cv_hash = hs_sha256.copy().digest()
    signature = ecdsa_privkey.sign(cv_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    cv_hs = b"\x0f" + struct.pack(">I", len(signature))[1:] + signature
    msg += cv_hs
    hs_sha256.update(cv_hs)

    # Record length
    struct.pack_into(">H", msg, rec_len_pos, len(msg) - rec_len_pos - 2)

    # CCS
    msg += b"\x14\x03\x03\x00\x01\x01"

    # Key derivation
    sx = int.from_bytes(pairing_data["sensor_x"], "big")
    sy = int.from_bytes(pairing_data["sensor_y"], "big")
    sensor_pub = EllipticCurvePublicNumbers(sx, sy, ec.SECP256R1()).public_key(default_backend())
    pms = ecdh_privkey.exchange(ECDH(), sensor_pub)
    log.info(f"  PMS: {pms[:8].hex()}...")

    seed = client_random + server_random
    master_secret = prf(pms, "master secret", seed, 48)

    # synaTudor: key_expansion uses client_random + server_random (not reversed!)
    key_block = prf(master_secret, "key expansion", client_random + server_random, 128)
    client_write_key = key_block[0:32]
    server_write_key = key_block[32:64]
    client_write_iv = key_block[64:68]
    server_write_iv = key_block[68:72]

    log.info(f"  client_write_key: {client_write_key[:8].hex()}...")
    log.info(f"  server_write_key: {server_write_key[:8].hex()}...")

    # Finished (SHA-256 transcript, SHA-384 PRF)
    finished_hash = hs_sha256.digest()
    verify_data = prf(master_secret, "client finished", finished_hash, 12)
    finished_plaintext = b"\x14\x00\x00\x0c" + verify_data

    explicit_nonce = b"\x00" * 8
    nonce = client_write_iv + explicit_nonce
    aad = b"\x00" * 8 + b"\x16\x03\x03" + struct.pack(">H", len(finished_plaintext))
    aesgcm = AESGCM(client_write_key)
    encrypted = aesgcm.encrypt(nonce, finished_plaintext, aad)
    msg += b"\x16\x03\x03" + struct.pack(">H", 8 + len(encrypted)) + explicit_nonce + encrypted

    # Send
    dev.write(bytes(msg))
    log.info(f"  Handshake enviado ({len(msg)} bytes)")

    # Receive response
    rsp = dev.read(timeout=5000)
    if rsp is None:
        log.error("  Timeout aguardando resposta")
        return None

    # Check for CCS + Finished
    offset = 0
    success = False
    while offset + 5 <= len(rsp):
        ct = rsp[offset]
        rl = struct.unpack(">H", rsp[offset+3:offset+5])[0]
        if ct == 0x15:
            level = rsp[offset+5] if offset+5 < len(rsp) else 0
            desc = rsp[offset+6] if offset+6 < len(rsp) else 0
            log.error(f"  Alert: level={level}, desc={desc} ({ALERT_DESCS.get(desc, '?')})")
            return None
        elif ct == 0x14:
            log.info("  CCS recebido")
        elif ct == 0x16:
            log.info("  Finished recebido!")
            success = True
        offset += 5 + rl

    if not success:
        log.error("  Handshake incompleto")
        return None

    log.info("  *** TLS HANDSHAKE OK! ***")

    tls = TlsSession(dev, log, client_write_key, client_write_iv,
                     server_write_key, server_write_iv)

    # Check if sensor sends anything else after Finished
    log.info("  Checking for post-Finished data from sensor...")
    extra = dev.read(timeout=2000)
    if extra:
        log.info(f"  Post-Finished data: {len(extra)} bytes")
        log.hex_dump("Post-Finished", extra)
        # Try to decrypt if it's Application Data
        if extra[0] == 0x17 and len(extra) > 5:
            rec_len = struct.unpack(">H", extra[3:5])[0]
            rec_data = extra[5:5+rec_len]
            plaintext = tls._decrypt_record(rec_data, 0x17)
            if plaintext:
                log.info(f"  Post-Finished decrypted: {plaintext.hex()}")
    else:
        log.info("  No post-Finished data (timeout)")

    return tls


# =============================================================
# Main
# =============================================================

def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")

    # Parse commands to send
    cmds_str = os.environ.get("CMDS", "0x01,0x82,0x86,0x19,0x3e")
    cmds = [int(c.strip(), 0) for c in cmds_str.split(",")]
    log.info(f"Commands to test: {[f'0x{c:02x}' for c in cmds]}")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)
    log.info(f"Sensor: bus {dev.dev.bus} addr {dev.dev.address}")

    try:
        # Fase 1: Pre-TLS
        log.separator()
        log.info("FASE 1: Pre-TLS")
        pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        # Fase 2: PAIR
        log.separator()
        log.info("FASE 2: PAIR (0x93)")
        pairing_data = do_pair(dev, log)
        if not pairing_data:
            log.error("PAIR falhou!")
            return

        # Fase 3: Reset + Re-init
        log.separator()
        log.info("FASE 3: Reset + Re-init")
        dev.reset()
        time.sleep(1)
        pre_tls_phase(dev, log, round_num=3)
        time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        # Fase 4: TLS Handshake
        log.separator()
        log.info("FASE 4: TLS Handshake")
        session = do_handshake(dev, log, pairing_data)
        if not session:
            log.error("TLS handshake falhou!")
            return

        # Fase 5: Comandos via TLS
        log.separator()
        log.info("FASE 5: Comandos via TLS tunnel")

        raw_mode = os.environ.get("RAW_CMD", "1") == "1"
        log.info(f"  Command mode: {'raw (no framing)' if raw_mode else 'framed (synaTudor header)'}")
        log.info(f"  Nonce mode: {'random' if os.environ.get('RANDOM_NONCE', '1') == '1' else 'sequential'}")

        for cmd in cmds:
            log.separator("-", 40)
            cmd_name = {
                0x01: "GET_VERSION",
                0x82: "FRAME_STATE_GET",
                0x86: "EVENT_CONFIG",
                0x19: "GET_START_INFO",
                0x3e: "FLASH_INFO",
            }.get(cmd, f"CMD_0x{cmd:02x}")

            log.info(f"Enviando {cmd_name} (0x{cmd:02x})")
            rsp = session.command(bytes([cmd]), raw=raw_mode)

            if rsp:
                log.info(f"  Resposta: {len(rsp)} bytes")
                log.hex_dump(f"{cmd_name} response", rsp)

                # Parse known responses
                if cmd == 0x01 and len(rsp) >= 38:
                    state = rsp[-1]
                    log.info(f"  Estado (via TLS): 0x{state:02x}")
                elif len(rsp) == 2:
                    log.info(f"  Status code: {rsp.hex()}")
            else:
                log.warn(f"  Sem resposta para {cmd_name}")
                # Fatal alert kills the session — stop testing
                log.info("  Sessao TLS provavelmente morta, parando testes")
                break

            time.sleep(0.1)

        log.separator()
        log.info("*** PROVISIONING PHASE COMPLETE ***")
        log.info(f"Comandos testados: {len(cmds)}")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        dev.close()
        log.separator()
        log.info(f"Log: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
