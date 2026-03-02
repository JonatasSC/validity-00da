#!/usr/bin/env python3
"""
TLS Handshake com o sensor 06cb:00da (FS7605).

Reproduz a sequencia capturada no teste1.pcap:
  Fase 1: Pre-TLS (2x) — 0x01, 0x8e subs, 0x19
  Fase 2: TLS Handshake — ClientHello, ServerHello, Cert+CKE+CV+CCS+Finished

Log salvo em logs/tls_handshake.txt
Uso: sudo python scripts/tls_handshake.py
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

# Diretorios
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "tls_handshake.txt")


class Logger:
    """Logger que imprime no terminal e salva em arquivo."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.f = open(filepath, "w")
        self._write(f"=== TLS Handshake Log — {datetime.now().isoformat()} ===\n")

    def info(self, msg):
        self._write(f"[INFO]  {msg}")
        print(f"INFO  {msg}")

    def warn(self, msg):
        self._write(f"[WARN]  {msg}")
        print(f"WARN  {msg}")

    def error(self, msg):
        self._write(f"[ERROR] {msg}")
        print(f"ERROR {msg}")

    def debug(self, msg):
        self._write(f"[DEBUG] {msg}")

    def hex_dump(self, label, data, max_bytes=256):
        """Dump hex no arquivo, resumo no terminal."""
        hex_str = data.hex()
        self._write(f"[HEX]   {label} ({len(data)} bytes):")
        # Quebra em linhas de 64 chars (32 bytes)
        for i in range(0, len(hex_str), 64):
            self._write(f"        {hex_str[i:i+64]}")
        # Terminal: so primeiros bytes
        if len(data) > 32:
            print(f"  HEX {label}: {data[:32].hex()}... ({len(data)} bytes)")
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
# Certificado proprietario
# =============================================================

def build_proprietary_cert(ecdsa_x_be, ecdsa_y_be, ecdh_x_be=None):
    """Cert 400 bytes: "PR?_" + flags + ECDSA_X@0x06(LE) + ECDSA_Y@0x4a(LE)

    Structure (from pcap analysis + python-validity cross-reference):
      0x00: "PR?_" header (4 bytes)
      0x04: flags 0x1700 (2 bytes)
      0x06: ECDSA X coordinate (32 bytes, LE)
      0x26: padding (36 bytes zeros)
      0x4a: ECDSA Y coordinate (32 bytes, LE)  ← was 0x4c, FIXED to 0x4a
      0x6a: padding (37 bytes zeros)
      0x8f: signature/key area (35 bytes) - format: 02 20 00 + 32B data
      0xb2: padding (222 bytes zeros)

    Note: V90 cert has Y@0x4c with 8-byte header. 00da has 6-byte header,
    so all offsets shift -2: Y@0x4a (confirmed by P-256 curve validation).
    """
    cert = bytearray(0x190)  # 400 bytes
    cert[0:4] = b"PR\x3f\x5f"
    cert[4:6] = b"\x17\x00"
    cert[0x06:0x26] = ecdsa_x_be[::-1]     # X in little-endian
    cert[0x4a:0x6a] = ecdsa_y_be[::-1]     # Y at 0x4a (NOT 0x4c!)

    # Signature/key area at 0x8f (analogous to V90's cert signature)
    # Format observed in capture: 02 20 00 + 32 bytes
    # These 32 bytes are validated by the sensor (cert rejected without them)
    if ecdh_x_be is not None:
        cert[0x8f] = 0x02       # type/prefix
        cert[0x90] = 0x20       # length (32)
        cert[0x91] = 0x00       # separator
        # Store based on endianness mode
        store_be = os.environ.get("CERT_BE", "0") == "1"
        if store_be:
            cert[0x92:0xb2] = ecdh_x_be  # big-endian (as-is from crypto)
        else:
            cert[0x92:0xb2] = ecdh_x_be[::-1]  # little-endian (reversed)

    return bytes(cert)


# =============================================================
# EC point finder
# =============================================================

def find_ec_points(data, label=""):
    """Procura EC points secp256r1 validos em dados binarios."""
    points = []
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    for i in range(len(data) - 64):
        # Big-endian com prefixo 0x04
        if data[i] == 0x04:
            x = int.from_bytes(data[i+1:i+33], 'big')
            y = int.from_bytes(data[i+33:i+65], 'big')
            if x > 0 and y > 0:
                if (y * y) % p == (pow(x, 3, p) + a * x + b) % p:
                    points.append((i, x, y, 'big'))

        # Little-endian (sem prefixo)
        x_le = int.from_bytes(data[i:i+32], 'little')
        y_le = int.from_bytes(data[i+32:i+64], 'little')
        if x_le > (1 << 128) and y_le > (1 << 128):
            if (y_le * y_le) % p == (pow(x_le, 3, p) + a * x_le + b) % p:
                points.append((i, x_le, y_le, 'little'))

    return points


# =============================================================
# TLS Alert descriptions
# =============================================================

ALERT_LEVELS = {1: "warning", 2: "fatal"}
ALERT_DESCS = {
    0: "close_notify", 10: "unexpected_message",
    20: "bad_record_mac", 21: "decryption_failed",
    22: "record_overflow", 40: "handshake_failure",
    42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 90: "user_canceled",
    100: "no_renegotiation",
}

# =============================================================
# SS Public Key (Sensor Secret) — extracted from synaWudfBioUsb108.dll
# Product 0x0a (06cb:00da), sub-type 0x01
# =============================================================

# Keys stored LE in DLL, converted to BE for crypto operations
SS_PUBKEY_PROD = {
    "x": bytes.fromhex("cb656293b9701806ae3b1a5208e469f465a6a5195bd8b7e39f23650611dcdfdc"),
    "y": bytes.fromhex("a700424ee097b3c159be791089502f40ba571eca91b106b4881f19637e44bfdc"),
}
SS_PUBKEY_NONPROD = {
    "x": bytes.fromhex("33d6208ca5f5da824b46ea1ca25e67327efc0c4ce937d9d844120d6cc08bfe5d"),
    "y": bytes.fromhex("b955e181fc4bf6c62b91afcdf3b61ec718dce7084742c41f57c1f0777c34a0fd"),
}


def compute_ecdh_premaster(ecdh_privkey, sensor_pubkey_dict):
    """Compute ECDH pre-master secret using sensor's SS Public Key."""
    x = int.from_bytes(sensor_pubkey_dict["x"], "big")
    y = int.from_bytes(sensor_pubkey_dict["y"], "big")
    sensor_pub = EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())
    shared_key = ecdh_privkey.exchange(ECDH(), sensor_pub)
    return shared_key  # 32 bytes (raw ECDH shared secret = x-coord)


# Mapa de diagnostico: o que cada erro significa pro nosso progresso
ALERT_DIAGNOSTIC = {
    42: "CERTIFICADO REJEITADO — formato ou conteudo errado",
    40: "HANDSHAKE FALHOU — cipher suite, formato geral, ou sequencia",
    20: "CHAVES ERRADAS — certificado ACEITO, pre-master secret errado!",
    51: "CHAVES ERRADAS — certificado ACEITO, pre-master secret errado!",
    47: "PARAMETRO ILEGAL — campo do handshake com valor invalido",
    10: "MENSAGEM INESPERADA — sequencia ou formato incorreto",
    50: "DECODE ERROR — estrutura TLS malformada",
    80: "ERRO INTERNO do sensor",
}


# =============================================================
# Pre-TLS phase
# =============================================================

def pre_tls_phase(dev, log, round_num=1):
    responses = {}
    log.separator("-", 40)
    log.info(f"Pre-TLS round {round_num}")

    # 0x01: ROM info
    log.info("CMD 0x01: ROM info")
    rsp = dev.cmd(b"\x01")

    # Sensor sem resposta — tentar reset
    if rsp is None:
        log.warn("Sem resposta! Tentando USB reset...")
        dev.reset()
        time.sleep(1)
        rsp = dev.cmd(b"\x01")
        if rsp is None:
            log.error("Sem resposta mesmo apos reset")
            raise RuntimeError("Sensor nao responde")

    # TLS residual — sensor ainda em modo TLS de sessao anterior
    if len(rsp) >= 3 and rsp[0] in (0x15, 0x16, 0x17) and rsp[1:3] == b"\x03\x03":
        log.warn(f"Sensor em modo TLS residual (resposta: {rsp[:7].hex()})")
        log.info("Tentando USB reset para limpar estado...")
        dev.reset()
        time.sleep(1)
        rsp = dev.cmd(b"\x01")
        if rsp is None:
            raise RuntimeError("Sem resposta apos reset de TLS residual")

    responses["rom_info"] = rsp
    log.hex_dump("ROM info", rsp)
    if len(rsp) >= 38:
        state = rsp[-1]
        log.info(f"Estado do sensor: 0x{state:02x}" +
                 (" (nao provisionado)" if state == 0x03 else ""))

    # 0x8e subcommands
    subcmds = [
        ("0x09", "Sensor info"),
        ("0x1a", "Config/calibracao"),
        ("0x2e", "Calibration blob"),
        ("0x2f", "Firmware version"),
    ]
    for sub_hex, desc in subcmds:
        sub = int(sub_hex, 16)
        cmd = bytes([0x8e, sub]) + b"\x00\x02" + b"\x00" * 13
        log.info(f"CMD 0x8e {sub_hex}: {desc}")
        rsp = dev.cmd(cmd)
        if rsp:
            key = desc.lower().replace("/", "_").replace(" ", "_")
            responses[key] = rsp
            if len(rsp) > 100:
                log.info(f"  RSP: {len(rsp)} bytes")
                log.hex_dump(f"0x8e {sub_hex}", rsp)
                # Salvar blobs grandes
                if sub == 0x2e:
                    path = os.path.join(LOG_DIR, f"calibration_r{round_num}.bin")
                    with open(path, "wb") as f:
                        f.write(rsp)
                    log.info(f"  Salvo em {path}")
            else:
                log.info(f"  RSP ({len(rsp)} bytes): {rsp.hex()}")
        else:
            log.warn(f"  Sem resposta para 0x8e {sub_hex}")

    # 0x19: Query state
    log.info("CMD 0x19: Query state")
    dev.write(b"\x19")
    rsp1 = dev.read()
    if rsp1:
        responses["state"] = rsp1
        log.info(f"  RSP ({len(rsp1)} bytes): {rsp1.hex()}")
    rsp2 = dev.read(timeout=2000)
    if rsp2:
        responses["state2"] = rsp2
        log.info(f"  RSP2 ({len(rsp2)} bytes): {rsp2.hex()}")

    return responses


# =============================================================
# TLS Handshake
# =============================================================

def do_tls_handshake(dev, log):
    """Realiza TLS handshake. Retorna True/False/'keys_wrong'."""

    # ── Gerar key pairs ──
    log.separator()
    log.info("Gerando chaves EC")

    ecdsa_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdsa_pub = ecdsa_privkey.public_key().public_numbers()
    ecdsa_x = ecdsa_pub.x.to_bytes(32, 'big')
    ecdsa_y = ecdsa_pub.y.to_bytes(32, 'big')
    log.info(f"ECDSA X: {ecdsa_x.hex()}")
    log.info(f"ECDSA Y: {ecdsa_y.hex()}")

    ecdh_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_pub = ecdh_privkey.public_key().public_numbers()
    ecdh_x = ecdh_pub.x.to_bytes(32, 'big')
    ecdh_y = ecdh_pub.y.to_bytes(32, 'big')
    log.info(f"ECDH X:  {ecdh_x.hex()}")
    log.info(f"ECDH Y:  {ecdh_y.hex()}")

    hs_sha256 = hashlib.sha256()
    hs_sha384 = hashlib.sha384()

    # ── ClientHello ──
    log.separator()
    log.info("Enviando ClientHello")
    client_random = secrets.token_bytes(32)
    log.info(f"Client random: {client_random.hex()}")

    cipher_mode = os.environ.get("CIPHER_MODE", "all")
    log.info(f"  Cipher mode: {cipher_mode}")

    ch_body = bytearray()
    ch_body += b"\x03\x03"
    ch_body += client_random
    ch_body += b"\x07" + b"\x00" * 7               # session_id (7 zeros)
    if cipher_mode == "v90":
        # Only offer 0xc005 (V90-style AES-CBC) — forces V90 cert format
        ch_body += b"\x00\x04"                      # 2 cipher suites
        ch_body += b"\xc0\x05"                      # ECDH_ECDSA_AES256_CBC_SHA
        ch_body += b"\x00\x3d"                      # RSA_AES256_CBC_SHA256
    elif cipher_mode == "cbc":
        # Only CBC ciphers
        ch_body += b"\x00\x02"                      # 1 cipher suite
        ch_body += b"\xc0\x05"                      # ECDH_ECDSA_AES256_CBC_SHA
    else:
        ch_body += b"\x00\x0a"                      # 5 cipher suites
        ch_body += b"\xc0\x05"                      # ECDH_ECDSA_AES256_CBC_SHA
        ch_body += b"\xc0\x2e"                      # ECDH_ECDSA_AES256_GCM_SHA384
        ch_body += b"\x00\x3d"                      # RSA_AES256_CBC_SHA256
        ch_body += b"\x00\x8d"                      # PSK_AES256_CBC_SHA384
        ch_body += b"\x00\xa8"                      # PSK_AES256_GCM_SHA384
    ch_body += b"\x00"                              # compression: none
    ch_body += b"\x00\x0a"                          # extensions (10 bytes)
    ch_body += b"\x00\x04\x00\x02\x00\x17"         # supported_groups: secp256r1
    ch_body += b"\x00\x0b\x00\x02\x01\x00"         # ec_point_formats: uncompressed

    ch_hs = b"\x01" + struct.pack(">I", len(ch_body))[1:] + bytes(ch_body)
    hs_sha256.update(ch_hs)
    hs_sha384.update(ch_hs)

    ch_record = b"\x16\x03\x03" + struct.pack(">H", len(ch_hs)) + ch_hs
    ch_msg = b"\x44\x00\x00\x00" + ch_record

    log.info(f"ClientHello total: {len(ch_msg)} bytes")
    log.hex_dump("ClientHello", ch_msg)
    dev.write(ch_msg)

    # ── ServerHello ──
    log.separator()
    log.info("Aguardando ServerHello")
    srv_rsp = dev.read()
    if srv_rsp is None:
        log.error("Timeout aguardando ServerHello!")
        return False

    log.info(f"ServerHello: {len(srv_rsp)} bytes")
    log.hex_dump("ServerHello raw", srv_rsp)

    # Alert?
    if srv_rsp[0] == 0x15:
        level, desc = srv_rsp[5], srv_rsp[6]
        log.error(f"TLS Alert: {ALERT_LEVELS.get(level, '?')} / {ALERT_DESCS.get(desc, '?')} ({desc})")
        return False

    if srv_rsp[0:3] != b"\x16\x03\x03":
        log.error(f"Resposta inesperada: {srv_rsp[:10].hex()}")
        return False

    # Parse record
    rec_len = struct.unpack(">H", srv_rsp[3:5])[0]
    rec_data = srv_rsp[5:5 + rec_len]
    hs_sha256.update(rec_data)
    hs_sha384.update(rec_data)

    server_random = None
    selected_cipher = None
    pos = 0

    while pos + 4 <= len(rec_data):
        hs_type = rec_data[pos]
        hs_len = int.from_bytes(rec_data[pos+1:pos+4], 'big')
        hs_body = rec_data[pos+4:pos+4+hs_len]

        if hs_type == 0x02:  # ServerHello
            server_version = hs_body[0:2]
            server_random = bytes(hs_body[2:34])
            sid_len = hs_body[34]
            cipher_off = 35 + sid_len
            selected_cipher = int.from_bytes(hs_body[cipher_off:cipher_off+2], 'big')
            log.info(f"  Version: 0x{server_version.hex()}")
            log.info(f"  Random:  {server_random.hex()}")
            log.info(f"  SID:     {hs_body[35:35+sid_len].hex()}")
            log.info(f"  Cipher:  0x{selected_cipher:04x}")
        elif hs_type == 0x0d:
            log.info(f"  CertificateRequest ({hs_len} bytes): {hs_body.hex()}")
        elif hs_type == 0x0e:
            log.info("  ServerHelloDone")
        else:
            log.info(f"  HS msg type=0x{hs_type:02x} len={hs_len}")

        pos += 4 + hs_len

    if server_random is None or selected_cipher is None:
        log.error("ServerHello incompleto")
        return False

    use_gcm = (selected_cipher == 0xc02e)
    prf = tls_prf_sha384 if use_gcm else tls_prf_sha256
    log.info(f"Modo: {'AES-256-GCM + SHA384' if use_gcm else 'AES-256-CBC + SHA256'}")

    # ── Construir resposta ──
    log.separator()
    log.info("Construindo Certificate + CKE + CV + CCS + Finished")

    msg = bytearray()
    msg += b"\x44\x00\x00\x00"   # USB prefix
    msg += b"\x16\x03\x03"       # TLS Handshake
    rec_len_pos = len(msg)
    msg += b"\x00\x00"           # placeholder

    # Certificate (0x0b)
    # Capture shows: cert_list_len = cert_data_len (V90 style, non-standard)
    # Plus 2 trailing zero bytes after cert data
    # Cert proof at 0x92: different modes to test what the sensor expects
    cert_mode = os.environ.get("CERT_MODE", "ecdh_ss_prod")
    log.info(f"  Cert mode: {cert_mode}")

    if cert_mode == "capture":
        # Use exact cert bytes from teste1.pcap — diagnostic test
        # If sensor still says bad_certificate → cert format is not the issue
        # If sensor says decrypt_error → cert accepted! (CV will fail since key mismatch)
        pcap_path = os.path.join(PROJECT_DIR, "Wireshark", "teste1.pcap")
        with open(pcap_path, "rb") as f:
            pcap_raw = f.read()
        # Find cert record in pcap
        pattern = bytes.fromhex("160303022c0b000198")
        pcap_pos = pcap_raw.find(pattern)
        pcap_cert_data = pcap_raw[pcap_pos + 5 + 10 : pcap_pos + 5 + 10 + 400]
        cert_raw = bytes(pcap_cert_data)
        log.info(f"  Using CAPTURE cert (400 bytes from teste1.pcap)")
        log.info(f"  Capture cert header: {cert_raw[:6].hex()}")
        log.info(f"  NOTE: CV will be signed with OUR key (mismatch!)")
        log.info(f"  Expected: different error if cert itself is accepted")
    elif cert_mode == "zeros":
        # No extra bytes — test if sensor cares about them
        cert_proof = None
        log.info("  Cert proof: NONE (zeros)")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_x":
        # Use ECDH X coordinate from CKE
        cert_proof = ecdh_x
        log.info(f"  Cert proof: ECDH X (from CKE)")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_ss_nonprod":
        # ECDH(ECDSA, SS_NonProd)
        ss_x = int.from_bytes(SS_PUBKEY_NONPROD["x"], "big")
        ss_y = int.from_bytes(SS_PUBKEY_NONPROD["y"], "big")
        ss_pub = EllipticCurvePublicNumbers(ss_x, ss_y, ec.SECP256R1()).public_key(default_backend())
        cert_proof = ecdsa_privkey.exchange(ECDH(), ss_pub)
        log.info(f"  Cert proof (ECDH with SS non-prod): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdsa_x":
        # Put ECDSA X itself at 0x92
        cert_proof = ecdsa_x
        log.info(f"  Cert proof: ECDSA X (self-reference)")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_cke_ss_prod":
        # ECDH(ECDH_privkey, SS_Prod) — use CKE key pair instead of ECDSA
        ss_x = int.from_bytes(SS_PUBKEY_PROD["x"], "big")
        ss_y = int.from_bytes(SS_PUBKEY_PROD["y"], "big")
        ss_pub = EllipticCurvePublicNumbers(ss_x, ss_y, ec.SECP256R1()).public_key(default_backend())
        cert_proof = ecdh_privkey.exchange(ECDH(), ss_pub)
        log.info(f"  Cert proof (ECDH CKE*SS_prod): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "sha256_ecdsa":
        # SHA256(ECDSA_X_BE || ECDSA_Y_BE)
        cert_proof = hashlib.sha256(ecdsa_x + ecdsa_y).digest()
        log.info(f"  Cert proof (SHA256 of ECDSA pubkey): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "sha256_ecdsa_le":
        # SHA256(ECDSA_X_LE || ECDSA_Y_LE) — hash the LE form as stored in cert
        cert_proof = hashlib.sha256(ecdsa_x[::-1] + ecdsa_y[::-1]).digest()
        log.info(f"  Cert proof (SHA256 of ECDSA LE): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "random":
        # Random 32 bytes — test if sensor just wants non-zero
        cert_proof = os.urandom(32)
        log.info(f"  Cert proof (RANDOM): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_cross":
        # ECDH(ECDSA_priv, ECDH_pub) — binding between our two key pairs
        ecdh_pub = ecdh_privkey.public_key()
        cert_proof = ecdsa_privkey.exchange(ECDH(), ecdh_pub)
        log.info(f"  Cert proof (ECDH ECDSA*ECDH cross): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_xy":
        # SHA256(ECDH_X || ECDH_Y) — hash of the full ECDH pubkey
        cert_proof = hashlib.sha256(ecdh_x + ecdh_y).digest()
        log.info(f"  Cert proof (SHA256 ECDH XY BE): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode == "ecdh_y":
        # ECDH Y coordinate at 0x92
        cert_proof = ecdh_y
        log.info(f"  Cert proof: ECDH Y (from CKE)")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    elif cert_mode in ("hs_key", "hs_key0"):
        # Host keypair = hs_key (deterministic, derived from hardcoded password)
        # Both sensor and host know this key → sensor can verify cert
        # _tudorSecurityGenHostKeyPair: palGenHSPrivKey() → palCryptoEccKeypairGenerate()
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        pw = bytes.fromhex('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
        hs_key_bytes = tls_prf_sha256(pw[:16], "HS_KEY_PAIR_GEN", pw[16:] + b'\xaa\xaa', 32)
        hs_key_int = int(hs_key_bytes[::-1].hex(), 16)  # LE interpretation
        hs_privkey = ec.derive_private_key(hs_key_int, ec.SECP256R1(), default_backend())
        hs_pub = hs_privkey.public_key().public_numbers()
        hs_x = hs_pub.x.to_bytes(32, 'big')
        hs_y = hs_pub.y.to_bytes(32, 'big')
        log.info(f"  HS key (LE int): {hs_key_int:064x}")
        log.info(f"  HS pubkey X: {hs_x.hex()}")
        log.info(f"  HS pubkey Y: {hs_y.hex()}")

        # OVERRIDE the ECDSA keypair — use hs_key for cert AND CertificateVerify
        ecdsa_privkey = hs_privkey
        ecdsa_pub = hs_pub
        ecdsa_x = hs_x
        ecdsa_y = hs_y
        log.info("  OVERRIDING ecdsa_privkey with hs_key!")

        # Build cert with hs_key's public key
        cert_raw = bytearray(build_proprietary_cert(hs_x, hs_y, ecdh_x_be=None))

        # Set type byte at wire 0x8F
        if cert_mode == "hs_key":
            cert_raw[0x8F] = 0x02  # type byte before hash
        # hs_key0: leave as 0x00

        # Hash internal cert[0:0x8E] = wire[2:0x90]
        hash_input = bytes(cert_raw[2:0x90])  # 142 bytes
        cert_hash = hashlib.sha256(hash_input).digest()
        log.info(f"  Cert hash (internal 0:0x8E): {cert_hash.hex()}")

        # Sign with hs_key (deterministic ECDSA / RFC 6979)
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed as _Prehash
        der_sig = hs_privkey.sign(cert_hash, ec.ECDSA(_Prehash(hashes.SHA256())))
        r_int, s_int = decode_dss_signature(der_sig)
        r_bytes = r_int.to_bytes(32, 'big')
        log.info(f"  ECDSA r (BE): {r_bytes.hex()}")
        log.info(f"  ECDSA s (BE): {s_int.to_bytes(32, 'big').hex()}")

        # Store r at cert[0x92]
        cert_raw[0x8F] = 0x02       # type
        cert_raw[0x90] = 0x20       # sig_len low (32)
        cert_raw[0x91] = 0x00       # sig_len high
        store_le = os.environ.get("CERT_R_LE", "0") == "1"
        if store_le:
            cert_raw[0x92:0xB2] = r_bytes[::-1]
            log.info("  Storing r in LE")
        else:
            cert_raw[0x92:0xB2] = r_bytes
            log.info("  Storing r in BE")
        cert_raw = bytes(cert_raw)
        log.info(f"  HS-key cert: {len(cert_raw)} bytes")
        log.hex_dump("HS-key cert", cert_raw)
    elif cert_mode in ("ecdsa_r", "ecdsa_r0"):
        # RE-discovered: self-signature using ECDSA r-value
        # _tudorSecuritySignHPubK does:
        #   1. SHA-256(internal_cert[0:0x8E]) — 142 bytes, starts at wire[2]
        #   2. ECDSA.sign(host_privkey, hash)
        #   3. Store only r-value (32 bytes) at cert[0x92]
        # Internal cert starts AFTER "PR" prefix (wire offset 2)
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        # Build cert with placeholder proof (zeros)
        cert_raw = bytearray(build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=None))

        # Set type byte at wire 0x8F = 0x02 (before or after hash?)
        if cert_mode == "ecdsa_r":
            cert_raw[0x8F] = 0x02  # type byte set BEFORE hash
        # ecdsa_r0: leave type byte as 0x00 (hash with zeros)

        # Internal cert = wire[2:] — hash covers internal[0:0x8E] = wire[2:0x90]
        hash_input = bytes(cert_raw[2:0x90])  # 142 bytes: "?_" + flags + X + pad + Y + pad + type area
        cert_hash = hashlib.sha256(hash_input).digest()
        log.info(f"  Cert hash input ({len(hash_input)} bytes): {hash_input[:16].hex()}...{hash_input[-4:].hex()}")
        log.info(f"  SHA-256: {cert_hash.hex()}")

        # Sign with ECDSA (RFC 6979 deterministic in OpenSSL)
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed as _Prehash
        der_sig = ecdsa_privkey.sign(cert_hash, ec.ECDSA(_Prehash(hashes.SHA256())))
        r_int, s_int = decode_dss_signature(der_sig)
        r_bytes = r_int.to_bytes(32, 'big')
        log.info(f"  ECDSA r (BE): {r_bytes.hex()}")
        log.info(f"  ECDSA s (BE): {s_int.to_bytes(32, 'big').hex()}")

        # Store r at cert[0x92] — try BE first (standard ECDSA output)
        cert_raw[0x8F] = 0x02       # type
        cert_raw[0x90] = 0x20       # sig_len low (32)
        cert_raw[0x91] = 0x00       # sig_len high
        store_le = os.environ.get("CERT_R_LE", "0") == "1"
        if store_le:
            cert_raw[0x92:0xB2] = r_bytes[::-1]  # little-endian
            log.info("  Storing r in LE")
        else:
            cert_raw[0x92:0xB2] = r_bytes  # big-endian
            log.info("  Storing r in BE")
        cert_raw = bytes(cert_raw)
        log.info(f"  ECDSA-r cert: {len(cert_raw)} bytes")
        log.hex_dump("ECDSA-r cert", cert_raw)
    elif cert_mode == "ecdsa_r_wire":
        # Same as ecdsa_r but hash covers wire[0:0x8E] (including "PR" prefix)
        # In case the internal/wire offset mapping is wrong
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        cert_raw = bytearray(build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=None))
        cert_raw[0x8F] = 0x02

        # Hash wire cert[0:0x8E] — includes "PR" prefix
        hash_input = bytes(cert_raw[0:0x8E])  # 142 bytes: "PR?_" + flags + X + pad + Y + pad
        cert_hash = hashlib.sha256(hash_input).digest()
        log.info(f"  Cert hash input WIRE ({len(hash_input)} bytes): {hash_input[:16].hex()}...{hash_input[-4:].hex()}")
        log.info(f"  SHA-256: {cert_hash.hex()}")

        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed as _Prehash
        der_sig = ecdsa_privkey.sign(cert_hash, ec.ECDSA(_Prehash(hashes.SHA256())))
        r_int, s_int = decode_dss_signature(der_sig)
        r_bytes = r_int.to_bytes(32, 'big')
        log.info(f"  ECDSA r (BE): {r_bytes.hex()}")

        cert_raw[0x8F] = 0x02
        cert_raw[0x90] = 0x20
        cert_raw[0x91] = 0x00
        store_le = os.environ.get("CERT_R_LE", "0") == "1"
        if store_le:
            cert_raw[0x92:0xB2] = r_bytes[::-1]
            log.info("  Storing r in LE")
        else:
            cert_raw[0x92:0xB2] = r_bytes
            log.info("  Storing r in BE")
        cert_raw = bytes(cert_raw)
        log.info(f"  ECDSA-r-wire cert: {len(cert_raw)} bytes")
        log.hex_dump("ECDSA-r-wire cert", cert_raw)
    elif cert_mode == "v90":
        # V90 style: 184-byte cert body only (no embedded sig)
        # Matching ThinkPad-E14-fingerprint spec:
        #   header(8) + X(32) + gap(36) + Y(32) + gap(44) + data3(32) = 184
        # For first test, data3 = zeros (python-validity style)
        from binascii import unhexlify
        ecdsa_x_int = int.from_bytes(ecdsa_x, 'big')
        ecdsa_y_int = int.from_bytes(ecdsa_y, 'big')
        v90_msg = (struct.pack('<LL', 0x17, 0x20) +
                   unhexlify('%064x' % ecdsa_x_int)[::-1] + (b'\x00' * 0x24) +
                   unhexlify('%064x' % ecdsa_y_int)[::-1] + (b'\x00' * 0x4c))
        cert_raw = v90_msg  # 184 bytes, no sig, no padding
        log.info(f"  V90 cert body: {len(cert_raw)} bytes (no embedded sig)")
        log.hex_dump("V90 cert", cert_raw)
    elif cert_mode == "v90_sig":
        # V90 + embedded ECDSA sig (python-validity style, padded to 400)
        pw = bytes.fromhex('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
        hs_key_bytes = tls_prf_sha256(pw[:16], "HS_KEY_PAIR_GEN", pw[16:] + b'\xaa\xaa', 32)
        hs_key_int = int(hs_key_bytes[::-1].hex(), 16)
        hs_privkey = ec.derive_private_key(hs_key_int, ec.SECP256R1(), default_backend())
        log.info(f"  HS key derived: {hs_key_bytes.hex()}")
        from binascii import unhexlify
        ecdsa_x_int = int.from_bytes(ecdsa_x, 'big')
        ecdsa_y_int = int.from_bytes(ecdsa_y, 'big')
        v90_msg = (struct.pack('<LL', 0x17, 0x20) +
                   unhexlify('%064x' % ecdsa_x_int)[::-1] + (b'\x00' * 0x24) +
                   unhexlify('%064x' % ecdsa_y_int)[::-1] + (b'\x00' * 0x4c))
        sig = hs_privkey.sign(v90_msg, ec.ECDSA(hashes.SHA256()))
        log.info(f"  ECDSA sig: {len(sig)} bytes DER")
        cert_raw = v90_msg + struct.pack('<I', len(sig)) + sig
        cert_raw += b'\x00' * (400 - len(cert_raw))
        log.info(f"  V90+sig cert: {len(cert_raw)} bytes")
        log.hex_dump("V90+sig cert", cert_raw)
    else:
        # Default: ECDH(ECDSA, SS_Prod)
        ss_x = int.from_bytes(SS_PUBKEY_PROD["x"], "big")
        ss_y = int.from_bytes(SS_PUBKEY_PROD["y"], "big")
        ss_pub = EllipticCurvePublicNumbers(ss_x, ss_y, ec.SECP256R1()).public_key(default_backend())
        cert_proof = ecdsa_privkey.exchange(ECDH(), ss_pub)
        log.info(f"  Cert proof (ECDH with SS prod): {cert_proof.hex()}")
        cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y, ecdh_x_be=cert_proof)
    cert_entry_len = len(cert_raw)                   # 400
    cert_list_len = cert_entry_len                    # 400 (V90 style: list_len == cert_len)
    cert_list = (struct.pack(">I", cert_list_len)[1:]
                + struct.pack(">I", cert_entry_len)[1:]
                + cert_raw
                + b"\x00\x00")                       # 2 trailing bytes (from capture)
    cert_hs = b"\x0b" + struct.pack(">I", len(cert_list))[1:] + cert_list
    msg += cert_hs
    log.info(f"  Certificate: {len(cert_hs)} bytes (cert={cert_entry_len}, list_len={cert_list_len})")
    log.hex_dump("Certificate HS", cert_hs)

    # ClientKeyExchange (0x10)
    ecdh_point = b"\x04" + ecdh_x + ecdh_y
    cke_hs = b"\x10" + struct.pack(">I", len(ecdh_point))[1:] + ecdh_point
    msg += cke_hs
    log.info(f"  CKE: {len(cke_hs)} bytes")

    # Hash cert + cke
    hs_sha256.update(cert_hs + cke_hs)
    hs_sha384.update(cert_hs + cke_hs)

    # CertificateVerify (0x0f)
    cv_use_sha384 = os.environ.get("CV_SHA384", "0") == "1"
    if cv_use_sha384 and use_gcm:
        cv_hash = hs_sha384.copy().digest()
        log.info(f"  CV hash (SHA384): {cv_hash[:32].hex()}...")
        signature = ecdsa_privkey.sign(cv_hash, ec.ECDSA(Prehashed(hashes.SHA384())))
    else:
        cv_hash = hs_sha256.copy().digest()
        log.info(f"  CV hash (SHA256): {cv_hash.hex()}")
        signature = ecdsa_privkey.sign(cv_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    log.info(f"  Signature: {len(signature)} bytes")
    log.debug(f"  Signature hex: {signature.hex()}")

    cv_hs = b"\x0f" + struct.pack(">I", len(signature))[1:] + signature
    msg += cv_hs
    log.info(f"  CertVerify: {len(cv_hs)} bytes")

    hs_sha256.update(cv_hs)
    hs_sha384.update(cv_hs)

    # Record length
    rec_body_len = len(msg) - rec_len_pos - 2
    struct.pack_into(">H", msg, rec_len_pos, rec_body_len)
    log.info(f"  Handshake record body: {rec_body_len} bytes")

    # CCS
    msg += b"\x14\x03\x03\x00\x01\x01"

    # Pre-master secret via ECDH with sensor's SS Public Key
    log.info("Calculando pre-master secret via ECDH")
    try:
        pms = compute_ecdh_premaster(ecdh_privkey, SS_PUBKEY_PROD)
        log.info(f"  PMS (production key): {pms.hex()}")
    except Exception as e:
        log.error(f"  ECDH falhou com production key: {e}")
        try:
            pms = compute_ecdh_premaster(ecdh_privkey, SS_PUBKEY_NONPROD)
            log.info(f"  PMS (non-production key): {pms.hex()}")
        except Exception as e2:
            log.error(f"  ECDH falhou com non-production key: {e2}")
            pms = b"\x00" * 32
            log.warn("  Usando PMS dummy (zeros)")

    seed = client_random + server_random
    master_secret = prf(pms, "master secret", seed, 48)

    if use_gcm:
        key_block = prf(master_secret, "key expansion", server_random + client_random, 72)
        client_write_key = key_block[0:32]
        client_write_iv = key_block[64:68]
    else:
        key_block = prf(master_secret, "key expansion", server_random + client_random, 160)
        client_write_key = key_block[64:96]
        client_write_iv = key_block[128:144]

    finished_hash = hs_sha384.digest() if use_gcm else hs_sha256.digest()
    verify_data = prf(master_secret, "client finished", finished_hash, 12)
    finished_plaintext = b"\x14\x00\x00\x0c" + verify_data

    if use_gcm:
        explicit_nonce = b"\x00" * 8
        nonce = client_write_iv + explicit_nonce
        aad = b"\x00" * 8 + b"\x16\x03\x03" + struct.pack(">H", len(finished_plaintext))
        aesgcm = AESGCM(client_write_key)
        encrypted = aesgcm.encrypt(nonce, finished_plaintext, aad)
        finished_body = explicit_nonce + encrypted
    else:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        mac_key = key_block[0:32]
        header = b"\x16\x03\x03" + struct.pack(">H", len(finished_plaintext))
        mac_input = b"\x00" * 8 + header + finished_plaintext
        mac = hmac_mod.new(mac_key, mac_input, hashlib.sha256).digest()
        payload = finished_plaintext + mac
        pad_needed = 16 - (len(payload) % 16)
        if pad_needed == 0:
            pad_needed = 16
        payload += bytes([pad_needed - 1] * pad_needed)
        cipher = Cipher(algorithms.AES(client_write_key), modes.CBC(client_write_iv))
        enc = cipher.encryptor()
        finished_body = client_write_iv + enc.update(payload) + enc.finalize()

    msg += b"\x16\x03\x03" + struct.pack(">H", len(finished_body)) + finished_body

    log.info(f"Mensagem total: {len(msg)} bytes")
    log.hex_dump("Mensagem completa", bytes(msg))

    # Salvar binario
    bin_path = os.path.join(LOG_DIR, "client_response.bin")
    with open(bin_path, "wb") as f:
        f.write(bytes(msg))
    log.info(f"Salvo em {bin_path}")

    # ── Enviar ──
    log.separator()
    log.info("Enviando mensagem...")
    dev.write(bytes(msg))

    # ── Resposta ──
    log.info("Aguardando resposta...")
    rsp = dev.read(timeout=5000)
    if rsp is None:
        log.warn("Timeout 5s. Tentando 10s...")
        rsp = dev.read(timeout=10000)

    if rsp is None:
        log.error("TIMEOUT — sensor nao respondeu")
        log.info("Causas possiveis:")
        log.info("  - Sensor travou (precisa USB reset)")
        log.info("  - Mensagem rejeitada silenciosamente")
        return False

    log.info(f"Resposta: {len(rsp)} bytes")
    log.hex_dump("Resposta", rsp)

    # Salvar
    rsp_path = os.path.join(LOG_DIR, "handshake_response.bin")
    with open(rsp_path, "wb") as f:
        f.write(rsp)

    # Analisar
    return analyze_response(rsp, log, dev=dev)


def analyze_response(rsp, log, dev=None):
    """Analisa resposta do sensor. Se warning alert, tenta ler mais dados."""
    offset = 0
    got_warning = False
    while offset + 5 <= len(rsp):
        ct = rsp[offset]
        rec_len = struct.unpack(">H", rsp[offset+3:offset+5])[0]

        if ct == 0x15:  # Alert
            level = rsp[offset+5] if offset+5 < len(rsp) else 0
            desc = rsp[offset+6] if offset+6 < len(rsp) else 0
            log.error(f"TLS Alert: level={level} ({ALERT_LEVELS.get(level, '?')}), "
                      f"desc={desc} ({ALERT_DESCS.get(desc, '?')})")
            diag = ALERT_DIAGNOSTIC.get(desc, "Erro desconhecido")
            log.info(f">>> {diag}")

            if level == 2:  # FATAL — parar
                if desc in (20, 51):
                    return "keys_wrong"
                return False

            # WARNING (level 1) — pode ser informativo, tentar continuar
            log.info(">>> Alert e WARNING (nao fatal). Tentando continuar...")
            got_warning = True
            offset += 5 + rec_len
            continue

        elif ct == 0x14:  # CCS
            log.info(">>> ChangeCipherSpec recebido!")
            offset += 5 + rec_len

        elif ct == 0x16:  # Finished
            log.info(">>> Finished recebido!")
            log.info("*** TLS HANDSHAKE BEM-SUCEDIDO! ***")
            return True

        elif ct == 0x17:  # AppData
            log.info(f">>> Application Data ({rec_len} bytes)")
            offset += 5 + rec_len

        else:
            log.warn(f"Content type desconhecido: 0x{ct:02x}")
            break

    # Se recebemos warning mas nao CCS/Finished, tentar ler mais
    if got_warning and dev is not None:
        log.info("Tentando ler mais dados apos warning alert...")
        for attempt in range(3):
            extra = dev.read(timeout=3000)
            if extra is None:
                log.info(f"  Tentativa {attempt+1}: timeout")
                break
            log.info(f"  Tentativa {attempt+1}: {len(extra)} bytes")
            log.hex_dump(f"Extra data {attempt+1}", extra)

            # Analisar os dados extra
            result = analyze_response(extra, log)
            if result is not None and result is not False:
                return result

    if got_warning:
        log.info("Warning alert recebido mas sem CCS/Finished subsequente")
        return "warning"

    return False


# =============================================================
# Main
# =============================================================

def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)

    log.info(f"Sensor encontrado: bus {dev.dev.bus} addr {dev.dev.address}")

    try:
        # ── Fase 1: Pre-TLS (2x) ──
        log.separator()
        log.info("FASE 1: Pre-TLS")

        r1 = pre_tls_phase(dev, log, round_num=1)
        time.sleep(0.1)
        r2 = pre_tls_phase(dev, log, round_num=2)

        # Buscar EC points
        log.separator("-")
        log.info("Buscando EC points nas respostas pre-TLS...")
        all_points = []
        for name, data in r1.items():
            if data and len(data) >= 65:
                pts = find_ec_points(data, label=name)
                all_points.extend([(name, p) for p in pts])

        if all_points:
            log.info(f"Encontrados {len(all_points)} EC points!")
            for name, (off, x, y, endian) in all_points:
                log.info(f"  {name} @ 0x{off:04x} ({endian})")
                log.info(f"    X: {x:064x}")
                log.info(f"    Y: {y:064x}")
        else:
            log.info("Nenhum EC point encontrado")

        # ── Fase 2: TLS Handshake ──
        log.separator()
        log.info("FASE 2: TLS Handshake")

        result = do_tls_handshake(dev, log)

        log.separator()
        if result is True:
            log.info("*** HANDSHAKE COMPLETO COM SUCESSO! ***")
        elif result == "keys_wrong":
            log.info("PROGRESSO: Certificado aceito! Pre-master secret errado.")
            log.info("Proximo: descobrir chave ECDH do sensor.")
        elif result == "warning":
            log.info("PROGRESSO: Sensor enviou warning alert, nao fatal.")
            log.info("O sensor pode ter aceitado parcialmente. Investigar.")
        else:
            log.info("Handshake falhou. Ver erros acima.")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        dev.close()
        log.info("Sensor desconectado")
        log.separator()
        log.info(f"Log completo salvo em: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
