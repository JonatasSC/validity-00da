"""
Cryptographic primitives for the Validity sensor protocol.
- TLS-PRF (HMAC-SHA256 based, RFC 5246)
- AES-256-CBC encrypt/decrypt
- ECDH key exchange (P-256)
- ECDSA signing (P-256)
- RSP6 key extraction
"""

import hashlib
import hmac
import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .constants import FACTORY_KEY, RSP6_TLS_CERT, RSP6_ECDSA_PRIV_ENCRYPTED, RSP6_ECDH_PUB, RSP6_END


def tls_prf(secret: bytes, label: str, seed: bytes, length: int) -> bytes:
    """
    TLS 1.2 PRF using HMAC-SHA256 (RFC 5246 Section 5).
    PRF(secret, label, seed) = P_SHA256(secret, label + seed)
    """
    label_bytes = label.encode("ascii")
    full_seed = label_bytes + seed
    return _p_hash(secret, full_seed, length)


def _p_hash(secret: bytes, seed: bytes, length: int) -> bytes:
    """P_hash expansion using HMAC-SHA256."""
    result = b""
    a = seed  # A(0) = seed
    while len(result) < length:
        a = hmac.new(secret, a, hashlib.sha256).digest()  # A(i)
        result += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return result[:length]


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """
    AES-256-CBC decryption.
    First 16 bytes of data are the IV, rest is ciphertext.
    Removes custom padding (last byte = padding size, all padding bytes = that value).
    """
    iv = data[:0x10]
    ciphertext = data[0x10:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding: last byte indicates padding size
    pad_size = plaintext[-1]
    if pad_size > 0 and pad_size <= 0x10:
        # Verify padding bytes
        if all(b == pad_size for b in plaintext[-pad_size:]):
            plaintext = plaintext[:-pad_size]
    return plaintext


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encryption. Returns IV + ciphertext."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _reverse(data: bytes) -> bytes:
    """Reverse byte order (little-endian <-> big-endian conversion)."""
    return data[::-1]


def get_system_serial() -> bytes:
    """
    Read system serial from DMI data.
    Concatenates product_name + null + product_serial + null.
    """
    try:
        with open("/sys/class/dmi/id/product_name", "r") as f:
            name = f.read().strip()
        with open("/sys/class/dmi/id/product_serial", "r") as f:
            serial = f.read().strip()
        return name.encode() + b"\x00" + serial.encode() + b"\x00"
    except (OSError, PermissionError):
        return b"Unknown\x00Unknown\x00"


def derive_master_key(serial: bytes) -> bytes:
    """Derive AES master key using factory key and system serial via TLS-PRF."""
    return tls_prf(FACTORY_KEY, "GWK", serial, 0x20)


def parse_rsp6(data: bytes, serial: bytes) -> dict:
    """
    Parse RSP6 response to extract cryptographic material.

    RSP6 format:
    - 8 byte header (skip)
    - TLV records until type 0xFFFF:
      - type: uint16 LE
      - size: uint16 LE
      - hash: 32 bytes SHA256
      - data: size bytes

    Returns dict with keys:
    - 'tls_cert_raw': raw TLS certificate data
    - 'ecdsa_privkey': ECDSA private key (d component, 32 bytes, big-endian)
    - 'ecdsa_pubkey': ECDSA public key (X + Y, 64 bytes, big-endian)
    - 'ecdh_pubkey': ECDH public key (X + Y, 64 bytes, big-endian)
    """
    if len(data) < 8:
        raise ValueError(f"RSP6 too short: {len(data)} bytes")

    pos = 8  # Skip header
    result = {
        "tls_cert_raw": None,
        "ecdsa_privkey": None,
        "ecdsa_pubkey": None,
        "ecdh_pubkey": None,
    }

    master_key = derive_master_key(serial)

    while pos < len(data) - 4:
        rec_type = struct.unpack_from("<H", data, pos)[0]
        rec_size = struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4

        if rec_type == RSP6_END:
            break

        if pos + 0x20 + rec_size > len(data):
            break

        rec_hash = data[pos:pos + 0x20]
        pos += 0x20
        rec_data = data[pos:pos + rec_size]
        pos += rec_size

        # Verify SHA256 hash
        calc_hash = hashlib.sha256(rec_data).digest()
        if calc_hash != rec_hash:
            raise ValueError(f"RSP6 hash mismatch for record type 0x{rec_type:04x}")

        if rec_type == RSP6_TLS_CERT:
            result["tls_cert_raw"] = rec_data
            result["ecdsa_pubkey"] = _extract_pubkey(rec_data)

        elif rec_type == RSP6_ECDSA_PRIV_ENCRYPTED:
            result["ecdsa_privkey"] = _decrypt_ecdsa_privkey(rec_data, master_key)

        elif rec_type == RSP6_ECDH_PUB:
            result["ecdh_pubkey"] = _extract_pubkey(rec_data)

    if result["ecdsa_privkey"] is None or result["ecdsa_pubkey"] is None:
        raise ValueError("RSP6 missing ECDSA components")
    if result["ecdh_pubkey"] is None:
        raise ValueError("RSP6 missing ECDH component")

    return result


def _extract_pubkey(data: bytes) -> bytes:
    """
    Extract EC public key (X, Y) from RSP6 record.
    X at offset 0x08, Y at offset 0x4c, both 32 bytes in little-endian.
    Returns 64 bytes (X + Y) in big-endian.
    """
    if len(data) < 0x6c:
        raise ValueError(f"Pubkey data too short: {len(data)}")
    x = _reverse(data[0x08:0x08 + 0x20])
    y = _reverse(data[0x4c:0x4c + 0x20])
    return x + y


def _decrypt_ecdsa_privkey(data: bytes, master_key: bytes) -> bytes:
    """
    Decrypt ECDSA private key from RSP6 record.
    First byte must be 0x02, then 0x80 bytes of encrypted data.
    Decrypted = X(32) + Y(32) + d(32), all in little-endian.
    Returns d component (32 bytes) in big-endian.
    """
    if len(data) < 0x81:
        raise ValueError(f"ECDSA data too short: {len(data)}")
    if data[0] != 0x02:
        raise ValueError(f"ECDSA invalid prefix: 0x{data[0]:02x}")

    decrypted = aes_decrypt(data[1:0x81], master_key)

    # Extract and reverse components
    # x = _reverse(decrypted[0x00:0x20])
    # y = _reverse(decrypted[0x20:0x40])
    d = _reverse(decrypted[0x40:0x60])
    return d


def load_ec_private_key(key_data: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Load EC private key from raw bytes.
    key_data: 96 bytes (X[32] + Y[32] + d[32]), all big-endian.
    """
    x = int.from_bytes(key_data[0:32], "big")
    y = int.from_bytes(key_data[32:64], "big")
    d = int.from_bytes(key_data[64:96], "big")

    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    priv_numbers = ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub_numbers)
    return priv_numbers.private_key(default_backend())


def load_ec_public_key(key_data: bytes) -> ec.EllipticCurvePublicKey:
    """
    Load EC public key from raw bytes.
    key_data: 64 bytes (X[32] + Y[32]), big-endian.
    """
    x = int.from_bytes(key_data[0:32], "big")
    y = int.from_bytes(key_data[32:64], "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return pub_numbers.public_key(default_backend())


def ecdh_derive(private_key: ec.EllipticCurvePrivateKey,
                peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Perform ECDH key exchange, returns 32-byte shared secret."""
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Sign data with ECDSA (SHA256), return DER-encoded signature.
    Retries until signature is exactly 0x48 bytes (as required by protocol).
    """
    while True:
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        if len(signature) == 0x48:
            return signature


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()
