#!/usr/bin/env python3
"""
Teste do comando PAIR (0x93) para o sensor 06cb:00da.

Baseado no synaTudor (Popax21): sensores Tudor fazem PAIRING antes do TLS.
O comando 0x93 envia um host certificate e recebe de volta:
  - 2 bytes status
  - 400 bytes host cert echo
  - 400 bytes sensor cert

Se o pairing funcionar, tenta TLS handshake usando os certs do pairing.

Uso:
  sudo python3 scripts/test_pair.py                    # Teste 1: PAIR com cert PR (400B)
  sudo PAIR_NO_PR=1 python3 scripts/test_pair.py       # Teste 2: PAIR sem "PR" prefix
  sudo PAIR_CERT_TYPE=0 python3 scripts/test_pair.py   # Teste com cert_type=0x00

Log salvo em logs/test_pair.txt
"""

import sys
import os
import hashlib
import struct
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice

# Diretorios
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "test_pair.txt")


# =============================================================
# Logger
# =============================================================

class Logger:
    def __init__(self, filepath):
        self.f = open(filepath, "w")
        self._write(f"=== Test PAIR Log — {datetime.now().isoformat()} ===\n")

    def info(self, msg):
        self._write(f"[INFO]  {msg}")
        print(f"INFO  {msg}")

    def warn(self, msg):
        self._write(f"[WARN]  {msg}")
        print(f"WARN  {msg}")

    def error(self, msg):
        self._write(f"[ERROR] {msg}")
        print(f"ERROR {msg}")

    def hex_dump(self, label, data):
        hex_str = data.hex()
        self._write(f"[HEX]   {label} ({len(data)} bytes):")
        for i in range(0, len(hex_str), 64):
            self._write(f"        {hex_str[i:i+64]}")
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
# TLS PRF (para derivar hs_key)
# =============================================================

import hmac as hmac_mod

def tls_prf_sha256(secret, label, seed, length):
    full_seed = label.encode("ascii") + seed
    result = b""
    a = full_seed
    while len(result) < length:
        a = hmac_mod.new(secret, a, hashlib.sha256).digest()
        result += hmac_mod.new(secret, a + full_seed, hashlib.sha256).digest()
    return result[:length]


# =============================================================
# Derivar hs_key
# =============================================================

def derive_hs_key():
    """Deriva o hs_key a partir das constantes hardcoded."""
    pw = bytes.fromhex('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
    hs_key_bytes = tls_prf_sha256(pw[:16], "HS_KEY_PAIR_GEN", pw[16:] + b'\xaa\xaa', 32)
    hs_key_int = int(hs_key_bytes[::-1].hex(), 16)  # LE interpretation
    return ec.derive_private_key(hs_key_int, ec.SECP256R1(), default_backend())


# =============================================================
# Construir host certificate para PAIR
# =============================================================

def build_pair_cert(pub_key, signing_key, log, no_pr=False, cert_type=0x00):
    """
    Constroi certificado proprietario para o comando PAIR.

    Formato synaTudor (400 bytes, sem "PR"):
      0x00: magic 0x5f3f (2 bytes LE)
      0x02: curve 0x0017 (2 bytes LE)
      0x04: X (68 bytes: 32 LE + 36 zeros)
      0x48: Y (68 bytes: 32 LE + 36 zeros)
      0x8c: padding (1 byte)
      0x8d: cert_type (1 byte)
      0x8e: sig_len (2 bytes LE)
      0x90: signature (256 bytes, DER ECDSA)
      Total: 2+2+68+68+1+1+2+256 = 400

    Formato com "PR" prefix (400 bytes, inclui "PR"):
      0x00: "PR?_" (4 bytes)
      0x04: flags 0x1700 (2 bytes)
      0x06: X (32 LE) + 0x26: padding (36) = 68 bytes total
      0x4a: Y (32 LE) + 0x6a: padding (37) = 69 bytes total (inclui pad byte)
      0x8f: cert_type (1 byte)
      0x90: sig_len (2 bytes LE)
      0x92: signature (254 bytes max)
      Total: 400
    """
    pub_nums = pub_key.public_numbers()
    x_be = pub_nums.x.to_bytes(32, 'big')
    y_be = pub_nums.y.to_bytes(32, 'big')

    if no_pr:
        # synaTudor format: 400 bytes, starts with magic 0x5f3f
        cert = bytearray(400)
        # Magic + curve
        struct.pack_into("<HH", cert, 0, 0x5f3f, 23)
        # X: 68 bytes (32 value LE + 36 zeros)
        cert[4:36] = x_be[::-1]
        # Y: 68 bytes (32 value LE + 36 zeros)
        cert[72:104] = y_be[::-1]
        # padding byte at 140
        # cert_type at 141
        cert[141] = cert_type
        # signbytes = cert[0:142]
        signbytes = bytes(cert[0:142])

        # Sign with hs_key
        der_sig = signing_key.sign(signbytes, ec.ECDSA(hashes.SHA256()))
        # sig_len at 142-143
        struct.pack_into("<H", cert, 142, len(der_sig))
        # signature at 144
        cert[144:144 + len(der_sig)] = der_sig

        log.info(f"  Cert format: synaTudor (no PR, 400B)")
        log.info(f"  cert_type: 0x{cert_type:02x}")
        log.info(f"  signbytes: {len(signbytes)} bytes")
        log.info(f"  DER sig: {len(der_sig)} bytes")
    else:
        # Wire format with "PR" prefix: 400 bytes
        cert = bytearray(400)
        cert[0:4] = b"PR\x3f\x5f"
        cert[4:6] = b"\x17\x00"
        cert[0x06:0x26] = x_be[::-1]  # X in LE
        cert[0x4a:0x6a] = y_be[::-1]  # Y in LE
        cert[0x8f] = cert_type
        # signbytes = cert[2:0x90] (142 bytes, excludes "PR")
        signbytes = bytes(cert[2:0x90])

        # Sign with hs_key
        der_sig = signing_key.sign(signbytes, ec.ECDSA(hashes.SHA256()))
        # sig_len at 0x90-0x91
        struct.pack_into("<H", cert, 0x90, len(der_sig))
        # signature at 0x92
        cert[0x92:0x92 + len(der_sig)] = der_sig

        log.info(f"  Cert format: with PR prefix (400B)")
        log.info(f"  cert_type: 0x{cert_type:02x}")
        log.info(f"  signbytes: {len(signbytes)} bytes")
        log.info(f"  DER sig: {len(der_sig)} bytes")

    log.hex_dump("Host cert", bytes(cert))
    return bytes(cert), der_sig


# =============================================================
# Parsear resposta do PAIR
# =============================================================

def parse_pair_response(rsp, log):
    """Parsea resposta do PAIR. Esperado: 2 status + 400 host echo + 400 sensor cert."""
    if len(rsp) < 2:
        log.error(f"Resposta muito curta: {len(rsp)} bytes")
        return None

    status = rsp[0:2]
    log.info(f"  Status: {status.hex()}")

    if status == b"\x00\x00":
        log.info("  >>> STATUS OK!")
        if len(rsp) >= 802:
            host_echo = rsp[2:402]
            sensor_cert = rsp[402:802]
            log.info(f"  Host cert echo: {len(host_echo)} bytes")
            log.hex_dump("Host cert echo", host_echo)
            log.info(f"  Sensor cert: {len(sensor_cert)} bytes")
            log.hex_dump("Sensor cert", sensor_cert)

            # Extrair pubkey do sensor cert
            # Tentar ambos os formatos
            log.separator("-", 40)
            log.info("Analisando sensor cert...")

            # Formato com "PR": X@0x06, Y@0x4a
            if sensor_cert[0:4] == b"PR\x3f\x5f":
                sx = sensor_cert[0x06:0x26][::-1]  # LE → BE
                sy = sensor_cert[0x4a:0x6a][::-1]
                log.info(f"  Sensor cert format: PR (wire)")
                log.info(f"  Sensor X: {sx.hex()}")
                log.info(f"  Sensor Y: {sy.hex()}")
            # Formato synaTudor: X@4, Y@72
            elif sensor_cert[0:2] == b"\x3f\x5f":
                sx = sensor_cert[4:36][::-1]
                sy = sensor_cert[72:104][::-1]
                log.info(f"  Sensor cert format: synaTudor (no PR)")
                log.info(f"  Sensor X: {sx.hex()}")
                log.info(f"  Sensor Y: {sy.hex()}")
            else:
                log.warn(f"  Sensor cert header desconhecido: {sensor_cert[:4].hex()}")
                sx = sy = None

            return {
                "host_echo": host_echo,
                "sensor_cert": sensor_cert,
                "sensor_x": sx,
                "sensor_y": sy,
            }
        else:
            log.warn(f"  Status OK mas resposta curta: {len(rsp)} bytes (esperado 802)")
            if len(rsp) > 2:
                log.hex_dump("Extra data", rsp[2:])
            return {"short": True, "data": rsp[2:]}

    elif status == b"\x01\x04":
        log.error("  >>> COMANDO NAO EXISTE (01 04)")
    elif status == b"\x03\x04":
        log.error("  >>> PARAMETER ERROR (03 04) — formato do cert errado?")
    elif status == b"\x04\x04":
        log.error("  >>> STATE ERROR (04 04) — bloqueado por estado")
    elif status == b"\x05\x04":
        log.error("  >>> NEEDS PARAMETERS (05 04) — payload insuficiente")
    else:
        log.error(f"  >>> Status desconhecido: {status.hex()}")
        if len(rsp) > 2:
            log.hex_dump("Full response", rsp)

    return None


# =============================================================
# Pre-TLS fase (simplificada)
# =============================================================

def pre_tls(dev, log):
    """Pre-TLS: 0x01, 0x8e subs, 0x19."""
    log.separator("-", 40)
    log.info("Pre-TLS")

    # 0x01
    log.info("CMD 0x01: ROM info")
    rsp = dev.cmd(b"\x01")
    if rsp is None:
        log.warn("Sem resposta, tentando USB reset...")
        dev.reset()
        time.sleep(1)
        rsp = dev.cmd(b"\x01")
    if rsp is None:
        raise RuntimeError("Sensor nao responde")

    # TLS residual?
    if len(rsp) >= 3 and rsp[0] in (0x15, 0x16, 0x17) and rsp[1:3] == b"\x03\x03":
        log.warn("Sensor em modo TLS residual, resetando...")
        dev.reset()
        time.sleep(1)
        rsp = dev.cmd(b"\x01")
        if rsp is None:
            raise RuntimeError("Sem resposta apos reset")

    if len(rsp) >= 38:
        state = rsp[-1]
        log.info(f"  Estado: 0x{state:02x}" +
                 (" (nao provisionado)" if state == 0x03 else ""))
    log.hex_dump("ROM info", rsp)

    # 0x8e subcommands
    for sub, desc in [(0x09, "Sensor info"), (0x1a, "Config"), (0x2e, "Calibration"), (0x2f, "FW version")]:
        cmd = bytes([0x8e, sub]) + b"\x00\x02" + b"\x00" * 13
        log.info(f"CMD 0x8e 0x{sub:02x}: {desc}")
        r = dev.cmd(cmd)
        if r:
            log.info(f"  RSP: {len(r)} bytes")
        else:
            log.warn("  Sem resposta")

    # 0x19
    log.info("CMD 0x19: Query state")
    dev.write(b"\x19")
    r1 = dev.read()
    if r1:
        log.info(f"  RSP: {len(r1)} bytes — {r1[:8].hex()}...")
    r2 = dev.read(timeout=2000)
    if r2:
        log.info(f"  RSP2: {len(r2)} bytes — {r2.hex()}")


# =============================================================
# Main
# =============================================================

def main():
    log = Logger(LOG_FILE)
    log.info(f"Log: {LOG_FILE}")

    # Config
    no_pr = os.environ.get("PAIR_NO_PR", "0") == "1"
    cert_type = int(os.environ.get("PAIR_CERT_TYPE", "0"), 0)
    log.info(f"Config: no_pr={no_pr}, cert_type=0x{cert_type:02x}")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        log.close()
        sys.exit(1)
    log.info(f"Sensor: bus {dev.dev.bus} addr {dev.dev.address}")

    try:
        # Pre-TLS
        pre_tls(dev, log)

        # Gerar keypair para o host cert
        log.separator()
        log.info("Gerando keypair para PAIR")
        host_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        host_pub = host_privkey.public_key()
        pub_nums = host_pub.public_numbers()
        log.info(f"  Host X: {pub_nums.x.to_bytes(32, 'big').hex()}")
        log.info(f"  Host Y: {pub_nums.y.to_bytes(32, 'big').hex()}")

        # Derivar hs_key para assinar o cert
        hs_key = derive_hs_key()
        hs_pub = hs_key.public_key().public_numbers()
        log.info(f"  HS key X: {hs_pub.x.to_bytes(32, 'big').hex()}")

        # Construir cert
        log.separator()
        log.info("Construindo host certificate")
        cert_bytes, der_sig = build_pair_cert(host_pub, hs_key, log,
                                               no_pr=no_pr, cert_type=cert_type)

        # Enviar PAIR
        log.separator()
        pair_cmd = b"\x93" + cert_bytes
        log.info(f"Enviando PAIR: 0x93 + {len(cert_bytes)} bytes cert = {len(pair_cmd)} bytes total")
        log.hex_dump("PAIR command", pair_cmd[:64])

        dev.write(pair_cmd)

        # Aguardar resposta
        log.info("Aguardando resposta...")
        rsp = dev.read(timeout=10000)

        if rsp is None:
            log.warn("Timeout 10s. Tentando 20s...")
            rsp = dev.read(timeout=20000)

        if rsp is None:
            log.error("TIMEOUT — sensor nao respondeu ao PAIR")
            log.info("Possiveis causas:")
            log.info("  - Comando nao e reconhecido desta forma")
            log.info("  - Sensor travou (precisa USB reset)")
            log.info("  - Precisa de mais setup antes do PAIR")
        else:
            log.info(f"Resposta: {len(rsp)} bytes")
            log.hex_dump("PAIR response", rsp)

            result = parse_pair_response(rsp, log)

            if result and "sensor_cert" in result:
                log.separator()
                log.info("*** PAIRING BEM-SUCEDIDO! ***")
                log.info("Salvando pairing data...")

                # Salvar dados
                pair_dir = os.path.join(LOG_DIR, "pairing")
                os.makedirs(pair_dir, exist_ok=True)

                with open(os.path.join(pair_dir, "host_cert.bin"), "wb") as f:
                    f.write(result["host_echo"])
                with open(os.path.join(pair_dir, "sensor_cert.bin"), "wb") as f:
                    f.write(result["sensor_cert"])

                # Salvar private key (PEM)
                from cryptography.hazmat.primitives.serialization import (
                    Encoding, PrivateFormat, NoEncryption
                )
                pem = host_privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                with open(os.path.join(pair_dir, "host_privkey.pem"), "wb") as f:
                    f.write(pem)

                log.info(f"  Dados salvos em {pair_dir}/")
                log.info("  Proximo passo: TLS handshake com certs do pairing")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        dev.close()
        log.separator()
        log.info(f"Log completo: {LOG_FILE}")
        log.close()
        print(f"\nLog salvo em: {LOG_FILE}")


if __name__ == "__main__":
    main()
