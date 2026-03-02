#!/usr/bin/env python3
"""
Tenta TLS handshake com o sensor 06cb:00da.
Gera chaves EC proprias e tenta completar o handshake.

Uso: python scripts/try_handshake.py
"""

import sys
import os
import hashlib
import hmac as hmac_mod
import struct
import logging
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from validity00da.usb_device import USBDevice

logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)-5s %(message)s",
)
log = logging.getLogger(__name__)

# =============================================
# TLS-PRF with SHA-384 (for GCM_SHA384 suites)
# =============================================

def _p_hash_sha384(secret, seed, length):
    """P_hash expansion using HMAC-SHA384."""
    result = b""
    a = seed
    while len(result) < length:
        a = hmac_mod.new(secret, a, hashlib.sha384).digest()
        result += hmac_mod.new(secret, a + seed, hashlib.sha384).digest()
    return result[:length]


def tls_prf_sha384(secret, label, seed, length):
    """TLS 1.2 PRF using HMAC-SHA384 (for GCM_SHA384 cipher suites)."""
    label_bytes = label.encode("ascii")
    return _p_hash_sha384(secret, label_bytes + seed, length)


def _p_hash_sha256(secret, seed, length):
    """P_hash expansion using HMAC-SHA256."""
    result = b""
    a = seed
    while len(result) < length:
        a = hmac_mod.new(secret, a, hashlib.sha256).digest()
        result += hmac_mod.new(secret, a + seed, hashlib.sha256).digest()
    return result[:length]


def tls_prf_sha256(secret, label, seed, length):
    """TLS 1.2 PRF using HMAC-SHA256."""
    label_bytes = label.encode("ascii")
    return _p_hash_sha256(secret, label_bytes + seed, length)


# =============================================
# Certificate builder
# =============================================

def build_proprietary_cert(ecdsa_x_be, ecdsa_y_be):
    """
    Build a proprietary certificate (400 bytes) matching the captured format.
    ECDSA public key at offsets 0x06 (X, LE) and 0x4a (Y, LE).
    """
    cert = bytearray(0x190)  # 400 bytes, all zeros

    # Header: "PR?_" magic + extra bytes from capture
    cert[0:4] = b"PR\x3f\x5f"
    cert[4] = 0x17
    cert[5] = 0x00

    # ECDSA public key X at offset 0x06 (32 bytes, little-endian)
    cert[0x06:0x06 + 0x20] = ecdsa_x_be[::-1]  # BE -> LE

    # ECDSA public key Y at offset 0x4a (32 bytes, little-endian)
    cert[0x4a:0x4a + 0x20] = ecdsa_y_be[::-1]  # BE -> LE

    return bytes(cert)


# =============================================
# ECDSA signing (with retry for fixed-length DER)
# =============================================

def ecdsa_sign_sha256(private_key, data):
    """Sign data with ECDSA-SHA256. Returns DER signature."""
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


# =============================================
# Pre-TLS phase
# =============================================

def pre_tls_phase(dev):
    """Run the pre-TLS commands matching the captured sequence."""

    # Step 1: ROM info (0x01)
    log.info("CMD 0x01: ROM info")
    rsp = dev.cmd(b"\x01")
    if rsp is None:
        raise RuntimeError("No response to CMD 0x01")
    log.info("  Response (%d bytes): %s", len(rsp), rsp.hex())
    if len(rsp) >= 38:
        state = rsp[-1]
        log.info("  Sensor state: 0x%02x", state)
    else:
        log.warning("  Unexpected response length: %d", len(rsp))

    # Step 2: 0x8e sub 0x09 - Read sensor info
    log.info("CMD 0x8e 0x09: Read sensor info")
    cmd_8e_09 = bytes.fromhex("8e09000200000000000000000000000000")
    rsp = dev.cmd(cmd_8e_09)
    if rsp:
        log.info("  Response (%d bytes): %s", len(rsp), rsp.hex())

    # Step 3: 0x8e sub 0x1a - Read sensor config
    log.info("CMD 0x8e 0x1a: Read sensor config")
    cmd_8e_1a = bytes.fromhex("8e1a000200000000000000000000000000")
    rsp = dev.cmd(cmd_8e_1a)
    if rsp:
        log.info("  Response (%d bytes): %s", len(rsp), rsp.hex())

    # Step 4: 0x8e sub 0x2e - Read calibration data
    log.info("CMD 0x8e 0x2e: Read calibration data")
    cmd_8e_2e = bytes.fromhex("8e2e000200000000000000000000000000")
    rsp = dev.cmd(cmd_8e_2e)
    if rsp:
        log.info("  Response (%d bytes)", len(rsp))

    # Step 5: 0x8e sub 0x2f - Read firmware info
    log.info("CMD 0x8e 0x2f: Read firmware info")
    cmd_8e_2f = bytes.fromhex("8e2f000200000000000000000000000000")
    rsp = dev.cmd(cmd_8e_2f)
    if rsp:
        log.info("  Response (%d bytes): %s", len(rsp), rsp.hex())

    # Step 6: CMD 0x19 - Query state
    log.info("CMD 0x19: Query state")
    dev.write(b"\x19")
    rsp1 = dev.read()
    if rsp1:
        log.info("  Response 1 (%d bytes): %s", len(rsp1), rsp1.hex())
    rsp2 = dev.read(timeout=2000)
    if rsp2:
        log.info("  Response 2 (%d bytes): %s", len(rsp2), rsp2.hex())

    log.info("Pre-TLS phase complete")


# =============================================
# TLS Handshake
# =============================================

def do_handshake(dev):
    """Perform TLS handshake with the sensor."""

    # Generate EC key pairs
    log.info("=== Generating EC key pairs ===")

    # ECDSA key pair (for certificate and CertificateVerify)
    ecdsa_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdsa_pub = ecdsa_privkey.public_key()
    ecdsa_numbers = ecdsa_pub.public_numbers()
    ecdsa_x = ecdsa_numbers.x.to_bytes(32, 'big')
    ecdsa_y = ecdsa_numbers.y.to_bytes(32, 'big')
    log.info("ECDSA pubkey X: %s", ecdsa_x.hex())
    log.info("ECDSA pubkey Y: %s", ecdsa_y.hex())

    # ECDH key pair (for ClientKeyExchange)
    ecdh_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecdh_pub = ecdh_privkey.public_key()
    ecdh_numbers = ecdh_pub.public_numbers()
    ecdh_x = ecdh_numbers.x.to_bytes(32, 'big')
    ecdh_y = ecdh_numbers.y.to_bytes(32, 'big')
    log.info("ECDH pubkey X: %s", ecdh_x.hex())
    log.info("ECDH pubkey Y: %s", ecdh_y.hex())

    # Hash context for all handshake messages
    # For SHA384 cipher suites, the Finished PRF uses SHA-384
    # But CertificateVerify signs a SHA-256 hash of handshake messages
    # We'll track both
    hash_ctx_sha256 = hashlib.sha256()  # for CertificateVerify
    hash_ctx_sha384 = hashlib.sha384()  # for Finished (GCM_SHA384)

    # ── Step 1: Client Hello ──
    log.info("=== Sending ClientHello ===")
    client_random = secrets.token_bytes(32)
    log.info("Client random: %s", client_random.hex())

    # Build ClientHello matching captured format exactly
    # Body: version(2) + random(32) + sid_len(1) + sid(7) + cs_len(2) + cs(10) + comp(1) + ext(12)
    ch_body = bytearray()
    ch_body.extend(b"\x03\x03")  # version TLS 1.2
    ch_body.extend(client_random)
    ch_body.extend(b"\x07")  # session_id_length = 7
    ch_body.extend(b"\x00" * 7)  # session_id (7 zeros)
    ch_body.extend(b"\x00\x0a")  # cipher_suites_length = 10
    ch_body.extend(b"\xc0\x05")  # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    ch_body.extend(b"\xc0\x2e")  # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    ch_body.extend(b"\x00\x3d")  # TLS_RSA_WITH_AES_256_CBC_SHA256
    ch_body.extend(b"\x00\x8d")  # PSK_WITH_AES_256_CBC_SHA384
    ch_body.extend(b"\x00\xa8")  # PSK_WITH_AES_256_GCM_SHA384
    ch_body.extend(b"\x00")  # compression_methods_length = 0
    # Extensions
    ch_body.extend(b"\x00\x0a")  # extensions_length = 10
    ch_body.extend(b"\x00\x04\x00\x02\x00\x17")  # supported_groups: secp256r1
    ch_body.extend(b"\x00\x0b\x00\x02\x01\x00")  # ec_point_formats: uncompressed

    assert len(ch_body) == 69, f"ClientHello body should be 69 bytes, got {len(ch_body)}"

    # Handshake header
    ch_hs = b"\x01" + struct.pack(">I", len(ch_body))[1:]  # type + 3-byte length
    ch_hs += bytes(ch_body)

    # Hash the handshake message (no TLS record header, no USB prefix)
    hash_ctx_sha256.update(ch_hs)
    hash_ctx_sha384.update(ch_hs)

    # TLS record
    ch_record = b"\x16\x03\x03" + struct.pack(">H", len(ch_hs)) + ch_hs

    # USB prefix
    ch_msg = b"\x44\x00\x00\x00" + ch_record

    log.info("ClientHello total: %d bytes", len(ch_msg))
    log.debug("ClientHello: %s", ch_msg.hex())
    dev.write(ch_msg)

    # ── Step 2: Read ServerHello ──
    log.info("=== Reading ServerHello ===")
    server_rsp = dev.read()
    if server_rsp is None:
        raise RuntimeError("No response to ClientHello (timeout)")

    log.info("Server response (%d bytes): %s", len(server_rsp), server_rsp.hex())

    # Parse TLS record
    if server_rsp[0:3] != b"\x16\x03\x03":
        raise RuntimeError(f"Unexpected response: {server_rsp[:5].hex()}")

    sh_rec_len = struct.unpack(">H", server_rsp[3:5])[0]
    sh_data = server_rsp[5:5 + sh_rec_len]

    # Hash all handshake messages in the record
    hash_ctx_sha256.update(sh_data)
    hash_ctx_sha384.update(sh_data)

    # Parse ServerHello
    pos = 0
    server_random = None
    selected_cipher = None
    server_version = None

    while pos + 4 <= len(sh_data):
        hs_type = sh_data[pos]
        hs_len = int.from_bytes(sh_data[pos + 1:pos + 4], 'big')
        hs_body = sh_data[pos + 4:pos + 4 + hs_len]

        if hs_type == 0x02:  # ServerHello
            server_version = hs_body[0:2]
            server_random = bytes(hs_body[2:34])
            sid_len = hs_body[34]
            cipher_offset = 35 + sid_len
            selected_cipher = int.from_bytes(hs_body[cipher_offset:cipher_offset + 2], 'big')
            log.info("Server version: %s", server_version.hex())
            log.info("Server random: %s", server_random.hex())
            log.info("Selected cipher: 0x%04x", selected_cipher)

        elif hs_type == 0x0d:  # CertificateRequest
            log.info("CertificateRequest received")

        elif hs_type == 0x0e:  # ServerHelloDone
            log.info("ServerHelloDone received")

        pos += 4 + hs_len

    if server_random is None:
        raise RuntimeError("ServerHello not found in response")
    if selected_cipher is None:
        raise RuntimeError("No cipher suite selected")

    # ── Step 3: Determine cipher mode ──
    use_gcm = (selected_cipher == 0xc02e)
    use_sha384 = use_gcm  # GCM_SHA384 uses SHA-384 PRF

    if use_gcm:
        log.info("Using AES-256-GCM with SHA-384 PRF")
        prf = tls_prf_sha384
    else:
        log.info("Using AES-256-CBC with SHA-256 PRF")
        prf = tls_prf_sha256

    # ── Step 4: Key derivation (ECDH) ──
    # For TLS_ECDH_ECDSA, the pre-master secret is from ECDH.
    # But we don't know the sensor's ECDH public key!
    #
    # In TLS_ECDH_ECDSA (static ECDH), the server's ECDH key is in its certificate.
    # But the sensor doesn't send a certificate! So where is the server's ECDH key?
    #
    # Hypothesis: The pre-master secret might just be our ECDH private key
    # applied to some known/fixed point, or the sensor derives it differently.
    #
    # For now, let's just build and send the Certificate + CKE + CertVerify
    # and see if the sensor responds at all. We'll figure out key derivation
    # from the sensor's response.

    log.info("=== Building Certificate + CKE + CertVerify + CCS + Finished ===")

    # Build the combined handshake message
    msg = bytearray()

    # USB prefix
    msg.extend(b"\x44\x00\x00\x00")

    # TLS Record header (placeholder for length)
    msg.extend(b"\x16\x03\x03")
    record_len_pos = len(msg)
    msg.extend(b"\x00\x00")  # placeholder

    # ── Certificate handshake message ──
    cert_raw = build_proprietary_cert(ecdsa_x, ecdsa_y)
    assert len(cert_raw) == 0x190

    # TLS certificate structure:
    # 0b = Certificate type
    # 00 01 98 = handshake body length (408 = 6 + 400 + 2 = nope, let me calc)
    # 00 01 90 = cert list total length (400)
    # 00 01 90 = first cert length (400)
    # [400 bytes cert data]
    cert_list = b"\x00\x01\x90" + b"\x00\x01\x90" + cert_raw
    cert_hs = b"\x0b" + struct.pack(">I", len(cert_list))[1:] + cert_list
    msg.extend(cert_hs)

    log.info("Certificate message: %d bytes", len(cert_hs))

    # ── ClientKeyExchange ──
    # Uncompressed EC point: 04 + X(32) + Y(32)
    ecdh_point = b"\x04" + ecdh_x + ecdh_y
    cke_hs = b"\x10" + struct.pack(">I", len(ecdh_point))[1:] + ecdh_point
    msg.extend(cke_hs)

    log.info("ClientKeyExchange: %d bytes", len(cke_hs))

    # Hash Certificate + CKE for CertificateVerify
    # (hash everything from cert_hs onwards in the record body)
    hs_for_cv = cert_hs + cke_hs
    hash_ctx_sha256.update(hs_for_cv)
    hash_ctx_sha384.update(hs_for_cv)

    # CertificateVerify hash (snapshot)
    cv_hash = hash_ctx_sha256.copy().digest()
    log.info("CertificateVerify hash: %s", cv_hash.hex())

    # ── CertificateVerify ──
    # Sign the handshake hash with our ECDSA key
    signature = ecdsa_sign_sha256(ecdsa_privkey, cv_hash)
    log.info("ECDSA signature (%d bytes): %s", len(signature), signature.hex())

    # CertificateVerify: type 0x0f + 3-byte length + signature
    # The captured format has NO algorithm prefix (direct DER signature)
    cv_hs = b"\x0f" + struct.pack(">I", len(signature))[1:] + signature
    msg.extend(cv_hs)

    # Hash CertificateVerify for Finished
    hash_ctx_sha256.update(cv_hs)
    hash_ctx_sha384.update(cv_hs)

    # Fill in TLS record length
    record_body_len = len(msg) - record_len_pos - 2
    struct.pack_into(">H", msg, record_len_pos, record_body_len)

    # ── Change Cipher Spec ──
    msg.extend(b"\x14\x03\x03\x00\x01\x01")

    # ── Encrypted Finished ──
    if use_sha384:
        finished_hash = hash_ctx_sha384.digest()
    else:
        finished_hash = hash_ctx_sha256.digest()

    # We can't compute the correct Finished without the pre-master secret!
    # But let's try with a dummy to see what the sensor responds.
    #
    # Actually, for TLS_ECDH_ECDSA, the pre-master is from ECDH
    # between our ECDH private key and the server's ECDH public key.
    # Since we don't know the server's key, we'll try:
    #
    # Option A: ECDH with ourselves (shared secret = our private * our public)
    # Option B: Use zeros
    # Option C: Skip Finished and see if sensor responds after CCS

    # Let's try sending without Finished first to see what happens
    # Actually no, let's try a dummy Finished

    # Use a dummy pre-master secret (all zeros)
    dummy_pms = b"\x00" * 32

    seed = client_random + server_random
    master_secret = prf(dummy_pms, "master secret", seed, 48)

    if use_gcm:
        # GCM key block: client_write_key(32) + server_write_key(32) + client_IV(4) + server_IV(4) = 72
        key_block = prf(master_secret, "key expansion", server_random + client_random, 72)
        client_write_key = key_block[0:32]
        server_write_key = key_block[32:64]
        client_write_iv = key_block[64:68]  # 4-byte implicit nonce
        server_write_iv = key_block[68:72]
    else:
        # CBC key block: mac_keys(32+32) + write_keys(32+32) + IVs(16+16) = 160
        key_block = prf(master_secret, "key expansion", server_random + client_random, 160)
        client_write_mac = key_block[0:32]
        server_write_mac = key_block[32:64]
        client_write_key = key_block[64:96]
        server_write_key = key_block[96:128]
        client_write_iv = key_block[128:144]
        server_write_iv = key_block[144:160]

    finished_verify = prf(master_secret, "client finished", finished_hash, 12)
    finished_msg = b"\x14\x00\x00\x0c" + finished_verify

    if use_gcm:
        # GCM encrypt
        # Nonce: client_write_iv(4) + explicit_nonce(8)
        explicit_nonce = b"\x00" * 8  # seq_num = 0
        nonce = client_write_iv + explicit_nonce

        # AAD: seq_num(8) + type(1) + version(2) + length(2)
        seq_num = b"\x00" * 8
        aad = seq_num + b"\x16\x03\x03" + struct.pack(">H", len(finished_msg))

        aesgcm = AESGCM(client_write_key)
        encrypted = aesgcm.encrypt(nonce, finished_msg, aad)

        # TLS record: explicit_nonce(8) + ciphertext + tag(16)
        finished_record_body = explicit_nonce + encrypted
    else:
        # CBC encrypt (simplified, may not be correct)
        # For now just use dummy
        finished_record_body = b"\x00" * 48

    msg.extend(b"\x16\x03\x03")
    msg.extend(struct.pack(">H", len(finished_record_body)))
    msg.extend(finished_record_body)

    log.info("Total message: %d bytes", len(msg))
    log.debug("Message: %s", bytes(msg).hex())

    # Send!
    dev.write(bytes(msg))

    # ── Step 5: Read server response ──
    log.info("=== Reading server response ===")
    rsp = dev.read(timeout=5000)
    if rsp is None:
        log.error("No response from sensor (timeout)")
        log.info("The sensor did not respond. This could mean:")
        log.info("  1. Pre-master secret is wrong (expected)")
        log.info("  2. Certificate format is rejected")
        log.info("  3. The sensor needs a specific key pair")
        return False

    log.info("Server response (%d bytes): %s", len(rsp), rsp.hex())

    # Try to parse
    if rsp[0] == 0x15:
        # Alert
        alert_level = rsp[5] if len(rsp) > 5 else 0
        alert_desc = rsp[6] if len(rsp) > 6 else 0
        alert_levels = {1: "warning", 2: "fatal"}
        alert_descs = {
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
        log.error("TLS Alert: level=%d (%s), desc=%d (%s)",
                   alert_level, alert_levels.get(alert_level, "?"),
                   alert_desc, alert_descs.get(alert_desc, "?"))
        return False

    elif rsp[0:3] == b"\x14\x03\x03":
        log.info("ChangeCipherSpec received!")
        # Check for Finished after CCS
        if len(rsp) > 6 and rsp[6:9] == b"\x16\x03\x03":
            log.info("Finished message follows!")
            return True

    return False


def main():
    dev = USBDevice()
    if not dev.open():
        log.error("Sensor not found. Use Zadig to switch to libusbK driver.")
        sys.exit(1)

    try:
        log.info("========================================")
        log.info("PHASE 1: Pre-TLS")
        log.info("========================================")
        pre_tls_phase(dev)

        log.info("")
        log.info("========================================")
        log.info("PHASE 2: TLS Handshake")
        log.info("========================================")
        success = do_handshake(dev)

        if success:
            log.info("*** TLS HANDSHAKE SUCCEEDED! ***")
        else:
            log.info("Handshake did not complete (expected for first attempt)")
            log.info("Next steps: analyze the error and adjust")

    except Exception as e:
        log.error("Error: %s", e)
        import traceback
        traceback.print_exc()
    finally:
        dev.close()


if __name__ == "__main__":
    main()
