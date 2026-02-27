"""
Custom TLS 1.2 handshake for Validity fingerprint sensors.

The sensor uses a modified TLS 1.2 with:
- 4-byte USB prefix (0x44 0x00 0x00 0x00) on all records
- ECDH_ECDSA_WITH_AES_256_CBC_SHA cipher suite (0xc005)
- Custom certificate format
- MAC-then-encrypt with off-by-one PKCS#7 padding
"""

import hashlib
import logging
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from .usb_device import USBDevice
from .crypto import (
    tls_prf, hmac_sha256, aes_encrypt, aes_decrypt,
    load_ec_private_key, load_ec_public_key,
    ecdh_derive, ecdsa_sign,
)
from .constants import (
    TLS_PREFIX, CLIENT_RANDOM, STATIC_IV,
    TLS_CLIENT_HELLO, DEVICE_PRIVATE_KEY,
)

log = logging.getLogger(__name__)


class TLSSession:
    """Manages a TLS 1.2 session with the fingerprint sensor."""

    def __init__(self, dev: USBDevice, keys: dict):
        """
        Args:
            dev: USB device handle
            keys: dict from parse_rsp6() with ecdsa_privkey, ecdsa_pubkey, ecdh_pubkey, tls_cert_raw
        """
        self.dev = dev
        self.keys = keys

        self.client_random = CLIENT_RANDOM
        self.server_random = b""
        self.master_secret = b""
        self.key_block = b""

        # Key material derived from key_block
        self.client_write_mac_key = b""
        self.server_write_mac_key = b""
        self.client_write_key = b""
        self.server_write_key = b""
        self.client_write_iv = b""
        self.server_write_iv = b""

    def handshake(self):
        """Perform complete TLS handshake."""
        hash_context = hashlib.sha256()
        hash_context2 = hashlib.sha256()

        # ── Step 1: Client Hello ──
        client_hello = bytearray(TLS_CLIENT_HELLO)
        # Insert our client random at offset 0x0f
        client_hello[0x0f:0x0f + 0x20] = self.client_random

        # Hash the handshake portion (after record header, skip USB prefix)
        # Client Hello handshake = bytes at offset 0x09, length 0x43
        hash_context.update(bytes(client_hello[0x09:0x09 + 0x43]))
        hash_context2.update(bytes(client_hello[0x09:0x09 + 0x43]))

        log.info("Sending Client Hello")
        self.dev.write(bytes(client_hello))

        # ── Step 2: Server Hello ──
        server_hello = self.dev.read()
        log.info("Received Server Hello (%d bytes)", len(server_hello))

        # Extract server random at offset 0x0b (32 bytes)
        self.server_random = bytes(server_hello[0x0b:0x0b + 0x20])
        log.info("Server random: %s", self.server_random.hex())

        # Hash server hello handshake portion
        hash_context.update(bytes(server_hello[0x05:0x05 + 0x3d]))
        hash_context2.update(bytes(server_hello[0x05:0x05 + 0x3d]))

        # ── Step 3: Key derivation (ECDH) ──
        priv_key = load_ec_private_key(DEVICE_PRIVATE_KEY)
        ecdh_pub = load_ec_public_key(self.keys["ecdh_pubkey"])

        pre_master_secret = ecdh_derive(priv_key, ecdh_pub)
        log.info("Pre-master secret: %s", pre_master_secret.hex())

        seed = self.client_random + self.server_random
        self.master_secret = tls_prf(pre_master_secret, "master secret", seed, 0x30)
        log.info("Master secret: %s", self.master_secret.hex())

        self.key_block = tls_prf(self.master_secret, "key expansion", seed, 0x120)
        self._split_key_block()

        # ── Step 4: Build Certificate + Key Exchange + Cert Verify + Finished ──
        cert_msg = self._build_certificate_message(priv_key, hash_context, hash_context2)

        log.info("Sending Certificate + KeyExchange + CertVerify + Finished (%d bytes)", len(cert_msg))
        self.dev.write(cert_msg)

        # ── Step 5: Read server's Change Cipher Spec + Finished ──
        server_finished = self.dev.read()
        log.info("Received server Finished (%d bytes)", len(server_finished))

        log.info("TLS handshake complete!")

    def _split_key_block(self):
        """Split the 0x120-byte key block into individual keys."""
        kb = self.key_block
        self.client_write_mac_key = kb[0x00:0x20]
        self.server_write_mac_key = kb[0x20:0x40]
        self.client_write_key = kb[0x40:0x60]
        self.server_write_key = kb[0x60:0x80]
        self.client_write_iv = kb[0x80:0x90]
        self.server_write_iv = kb[0x90:0xa0]

    def _build_certificate_message(self, priv_key, hash_ctx, hash_ctx2) -> bytes:
        """
        Build the combined message containing:
        - Certificate (with device cert and ECDHE public key)
        - Certificate Verify (ECDSA signature)
        - Change Cipher Spec
        - Encrypted Finished
        """
        msg = bytearray()

        # USB prefix
        msg.extend(TLS_PREFIX)

        # TLS Record header: Handshake, TLS 1.2
        msg.extend(b"\x16\x03\x03")

        # Placeholder for record length (fill later)
        record_len_pos = len(msg)
        msg.extend(b"\x00\x00")

        # ── Certificate handshake message ──
        # Handshake type: Certificate (0x0b)
        msg.extend(b"\x0b\x00\x00")

        # Certificate data
        cert_raw = self.keys["tls_cert_raw"] or b"\x00" * 0xb8
        cert_body = bytearray()
        cert_body.extend(b"\x00\x00\xb8")  # Certificate length
        cert_body.extend(b"\x00\x00\xb8")  # First cert length
        cert_body.extend(cert_raw[:0xb8].ljust(0xb8, b"\x00"))

        # Write cert body length
        cert_len = len(cert_body)
        msg.append(cert_len & 0xff)
        msg.extend(cert_body)

        # ── Client Key Exchange ──
        # Get our public key point (uncompressed: 0x04 + X[32] + Y[32])
        priv_x = DEVICE_PRIVATE_KEY[0:32]
        priv_y = DEVICE_PRIVATE_KEY[32:64]
        ecdhe_pub = b"\x04" + priv_x + priv_y

        # Handshake type: Client Key Exchange (0x10)
        msg.extend(b"\x10\x00\x00\x41")
        msg.extend(ecdhe_pub)

        # Hash everything up to here for Certificate Verify
        handshake_start = 4 + 5  # USB prefix + TLS record header
        handshake_data = bytes(msg[handshake_start:])
        hash_ctx.update(handshake_data)
        hash_ctx2.update(handshake_data)

        cert_verify_hash = hash_ctx.copy().digest()

        # ── Certificate Verify ──
        # Load ECDSA private key (from RSP6)
        ecdsa_pubkey = self.keys["ecdsa_pubkey"]
        ecdsa_privkey = self.keys["ecdsa_privkey"]
        ecdsa_key_data = ecdsa_pubkey + ecdsa_privkey
        ecdsa_key = load_ec_private_key(ecdsa_key_data)

        signature = ecdsa_sign(ecdsa_key, cert_verify_hash)

        # Handshake type: Certificate Verify (0x0f), no algorithm prefix
        cert_verify_len = len(signature)
        msg.extend(struct.pack(">BH", 0x0f, cert_verify_len))
        msg.append(0x00)  # Padding
        msg.extend(signature)

        # Update hash for Finished
        # The cert verify handshake record
        cv_start = len(handshake_data)
        hash_ctx2.update(bytes(msg[handshake_start + cv_start:]))

        # Fill record length
        record_data_len = len(msg) - record_len_pos - 2
        struct.pack_into(">H", msg, record_len_pos, record_data_len)

        # ── Change Cipher Spec ──
        msg.extend(b"\x14\x03\x03\x00\x01\x01")

        # ── Encrypted Finished ──
        finished_hash = hash_ctx2.digest()
        finished_verify_data = tls_prf(self.master_secret, "client finished", finished_hash, 0x0c)

        finished_msg = b"\x14\x00\x00\x0c" + finished_verify_data

        encrypted_finished = self._mac_then_encrypt(0x16, finished_msg)

        # TLS record for encrypted handshake
        msg.extend(b"\x16\x03\x03")
        msg.extend(struct.pack(">H", len(encrypted_finished)))
        msg.extend(encrypted_finished)

        return bytes(msg)

    def _mac_then_encrypt(self, content_type: int, data: bytes) -> bytes:
        """
        MAC-then-encrypt as used by the sensor's custom TLS.
        1. Compute HMAC-SHA256 over [type, version, length, data]
        2. Append HMAC to data
        3. Add custom padding
        4. Encrypt with AES-256-CBC
        Returns: IV + ciphertext
        """
        # Build record header for HMAC
        header = bytes([content_type, 0x03, 0x03, (len(data) >> 8) & 0xff, len(data) & 0xff])
        mac_input = header + data
        mac = hmac_sha256(self.client_write_mac_key, mac_input)

        # Data + MAC
        payload = data + mac

        # Custom padding: pad to 16-byte boundary
        pad_needed = 16 - (len(payload) % 16)
        if pad_needed == 0:
            pad_needed = 16
        padding = bytes([pad_needed - 1] * pad_needed)
        padded = payload + padding

        # Encrypt
        iv = STATIC_IV
        ciphertext = aes_encrypt(padded, self.client_write_key, iv)

        return iv + ciphertext

    def _decrypt_and_verify(self, data: bytes) -> bytes:
        """
        Decrypt application data from sensor.
        data: raw ciphertext (IV + encrypted)
        Returns: decrypted payload.
        """
        iv = data[:0x10]
        ciphertext = data[0x10:]

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(self.server_write_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        pad_val = plaintext[-1]
        payload_len = len(plaintext) - 0x20 - (pad_val + 1)
        return plaintext[:payload_len]

    def app_write(self, data: bytes):
        """Send application data over TLS."""
        encrypted = self._mac_then_encrypt(0x17, data)
        # Wrap in TLS record
        record = b"\x17\x03\x03" + struct.pack(">H", len(encrypted)) + encrypted
        self.dev.write(record)

    def app_read(self) -> bytes:
        """Read and decrypt application data from sensor."""
        raw = self.dev.read()
        # Skip TLS record header (5 bytes)
        return self._decrypt_and_verify(raw[5:])

    def app_cmd(self, data: bytes) -> bytes:
        """Send command and read response over TLS."""
        self.app_write(data)
        return self.app_read()
