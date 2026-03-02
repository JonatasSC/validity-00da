#!/usr/bin/env python3
"""
Verifica se a assinatura CertificateVerify bate com a chave do ClientKeyExchange.
Tambem tenta encontrar a chave EC no certificado proprietario testando varios offsets.
"""

import sys
import os
import hashlib
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

PCAP_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Wireshark", "teste1.pcap"
)


def find_all(data, pattern):
    results = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos < 0:
            break
        results.append(pos)
        start = pos + 1
    return results


def check_on_curve(x_bytes, y_bytes):
    """Check if (x, y) is on secp256r1. x_bytes and y_bytes are big-endian."""
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    if x == 0 or y == 0:
        return False
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    return (y * y) % p == (x * x * x + a * x + b) % p


def load_pubkey(x_bytes, y_bytes):
    """Load EC public key from big-endian X, Y coordinates."""
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return pub_numbers.public_key(default_backend())


def main():
    if not os.path.exists(PCAP_PATH):
        print(f"Arquivo nao encontrado: {PCAP_PATH}")
        sys.exit(1)

    with open(PCAP_PATH, "rb") as f:
        raw = f.read()

    print(f"Pcap: {len(raw)} bytes\n")

    # ========================================
    # 1. Extract handshake messages
    # ========================================

    # --- Client Hello ---
    # Pattern: TLS record with USB prefix 44000000 then 160303
    # Client Hello in pcap has USB prefix. Let's find the handshake type 0x01
    # The captured ClientHello starts after USB prefix (4 bytes) + TLS record header (5 bytes)
    # Look for the TLS record: 16 03 03 xx xx 01 00 00 (ClientHello)
    ch_pattern = bytes.fromhex("1603030043010000")
    ch_positions = find_all(raw, ch_pattern)

    client_hello_hs = None
    if ch_positions:
        ch_start = ch_positions[0]
        ch_rec_len = int.from_bytes(raw[ch_start + 3:ch_start + 5], 'big')
        client_hello_hs = raw[ch_start + 5:ch_start + 5 + ch_rec_len]
        print(f"Client Hello handshake: {len(client_hello_hs)} bytes")
        print(f"  First bytes: {client_hello_hs[:16].hex()}")
    else:
        # Try alternate pattern - maybe different length
        print("Client Hello com padrao 0x43 nao encontrado, buscando alternativo...")
        # Search for any ClientHello: 16 03 03 then 01 00 00
        for i in range(len(raw) - 10):
            if raw[i:i+3] == b"\x16\x03\x03" and raw[i+5] == 0x01 and raw[i+6:i+8] == b"\x00\x00":
                ch_rec_len = int.from_bytes(raw[i+3:i+5], 'big')
                client_hello_hs = raw[i+5:i+5+ch_rec_len]
                print(f"Client Hello encontrado em offset {i}: {ch_rec_len} bytes")
                print(f"  First bytes: {client_hello_hs[:16].hex()}")
                break

    if client_hello_hs is None:
        print("ERRO: Client Hello nao encontrado!")
        sys.exit(1)

    # --- Server Hello + CertReq + ServerHelloDone ---
    sh_pattern = bytes.fromhex("160303003d020000")
    sh_positions = find_all(raw, sh_pattern)
    server_hello_hs = None
    if sh_positions:
        sh_start = sh_positions[0]
        sh_rec_len = int.from_bytes(raw[sh_start + 3:sh_start + 5], 'big')
        server_hello_hs = raw[sh_start + 5:sh_start + 5 + sh_rec_len]
        print(f"Server Hello record: {sh_rec_len} bytes")

    # --- Certificate + ClientKeyExchange + CertificateVerify ---
    cert_pattern = bytes.fromhex("160303022c0b000198")
    cert_positions = find_all(raw, cert_pattern)

    if not cert_positions:
        print("ERRO: TLS Certificate record nao encontrado!")
        sys.exit(1)

    tls_start = cert_positions[0]
    tls_rec_len = int.from_bytes(raw[tls_start + 3:tls_start + 5], 'big')
    all_handshake = raw[tls_start + 5:tls_start + 5 + tls_rec_len]

    print(f"Combined handshake record: {tls_rec_len} bytes")
    print(f"  First bytes: {all_handshake[:16].hex()}")

    # ========================================
    # 2. Parse individual handshake messages
    # ========================================
    hs_msgs = []
    pos = 0
    while pos + 4 <= len(all_handshake):
        hs_type = all_handshake[pos]
        hs_len = int.from_bytes(all_handshake[pos + 1:pos + 4], 'big')
        hs_data = all_handshake[pos:pos + 4 + hs_len]
        hs_msgs.append((hs_type, hs_len, hs_data, all_handshake[pos + 4:pos + 4 + hs_len]))
        pos += 4 + hs_len

    hs_names = {
        0x01: "ClientHello", 0x02: "ServerHello",
        0x0b: "Certificate", 0x0c: "ServerKeyExchange",
        0x0d: "CertificateRequest", 0x0e: "ServerHelloDone",
        0x0f: "CertificateVerify", 0x10: "ClientKeyExchange", 0x14: "Finished",
    }

    print(f"\nHandshake messages in cert record:")
    cert_hs_raw = None
    cke_hs_raw = None
    cv_hs_raw = None
    cke_pubkey = None
    cv_signature = None
    cert_der = None

    for hs_type, hs_len, full_msg, body in hs_msgs:
        name = hs_names.get(hs_type, f"Unknown(0x{hs_type:02x})")
        print(f"  {name}: {hs_len} bytes")

        if hs_type == 0x0b:  # Certificate
            cert_hs_raw = full_msg
            # Extract certificate DER
            certs_len = int.from_bytes(body[0:3], 'big')
            cert_len = int.from_bytes(body[3:6], 'big')
            cert_der = body[6:6 + cert_len]
            print(f"    Cert length: {cert_len}")

        elif hs_type == 0x10:  # ClientKeyExchange
            cke_hs_raw = full_msg
            if len(body) == 65 and body[0] == 0x04:
                cke_pubkey = body
                print(f"    EC point (65 bytes, uncompressed)")
            elif len(body) > 1 and body[0] == 0x41 and body[1] == 0x04:
                cke_pubkey = body[1:66]
                print(f"    EC point (length-prefixed)")
            else:
                print(f"    Raw: {body[:32].hex()}...")

        elif hs_type == 0x0f:  # CertificateVerify
            cv_hs_raw = full_msg
            cv_signature = body
            print(f"    Signature: {body[:32].hex()}...")

    # ========================================
    # 3. Compute handshake hash for verification
    # ========================================
    print(f"\n{'='*60}")
    print("SIGNATURE VERIFICATION")
    print("=" * 60)

    if cke_pubkey is None:
        print("ERRO: ClientKeyExchange pubkey nao encontrada!")
        sys.exit(1)
    if cv_signature is None:
        print("ERRO: CertificateVerify signature nao encontrada!")
        sys.exit(1)

    kx = cke_pubkey[1:33]
    ky = cke_pubkey[33:65]
    print(f"\nClientKeyExchange EC point:")
    print(f"  X: {kx.hex()}")
    print(f"  Y: {ky.hex()}")
    print(f"  On curve: {check_on_curve(kx, ky)}")

    print(f"\nCertificateVerify signature ({len(cv_signature)} bytes):")
    print(f"  {cv_signature.hex()}")

    # Check if signature starts with DER SEQUENCE
    if cv_signature[0] == 0x30:
        print("  -> DER-encoded ECDSA signature (no algorithm prefix)")
        der_sig = cv_signature
    elif len(cv_signature) > 4 and cv_signature[4] == 0x30:
        # TLS 1.2 format: hash_algo(1) + sign_algo(1) + sig_len(2) + DER signature
        print(f"  -> TLS 1.2 format: hash_algo=0x{cv_signature[0]:02x} sign_algo=0x{cv_signature[1]:02x}")
        sig_len = int.from_bytes(cv_signature[2:4], 'big')
        der_sig = cv_signature[4:4 + sig_len]
        print(f"  -> DER sig length: {sig_len}")
    else:
        print(f"  -> Unknown format, first byte: 0x{cv_signature[0]:02x}")
        der_sig = cv_signature

    # The CertificateVerify signs the hash of all handshake messages
    # BEFORE the CertificateVerify itself.
    # Order: ClientHello + ServerHello(+CertReq+Done) + Certificate + ClientKeyExchange
    #
    # For TLS_ECDH_ECDSA: the signed hash is SHA-256 of all prior handshake messages

    # Method 1: Hash = SHA256(ClientHello_hs + ServerHello_full + Certificate_hs + CKE_hs)
    print(f"\n--- Computing handshake hash ---")

    # We have:
    # - client_hello_hs: the ClientHello handshake message(s)
    # - server_hello_hs: the ServerHello + CertificateRequest + ServerHelloDone
    # - cert_hs_raw: Certificate handshake message
    # - cke_hs_raw: ClientKeyExchange handshake message

    hash_ctx = hashlib.sha256()
    hash_ctx.update(client_hello_hs)
    print(f"  + ClientHello: {len(client_hello_hs)} bytes")
    hash_ctx.update(server_hello_hs)
    print(f"  + ServerHello record: {len(server_hello_hs)} bytes")
    hash_ctx.update(cert_hs_raw)
    print(f"  + Certificate: {len(cert_hs_raw)} bytes")
    hash_ctx.update(cke_hs_raw)
    print(f"  + ClientKeyExchange: {len(cke_hs_raw)} bytes")

    hs_hash = hash_ctx.digest()
    print(f"  = Hash: {hs_hash.hex()}")

    # Try verification with different approaches
    pubkey = load_pubkey(kx, ky)

    # Approach 1: Verify signature over the hash directly
    print(f"\n--- Verification attempts ---")

    # Try 1: signature over raw hash (no extra hashing)
    try:
        pubkey.verify(der_sig, hs_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("  [OK] Approach 1: Sig over SHA256(handshake) with Prehashed -> VALID!")
    except InvalidSignature:
        print("  [FAIL] Approach 1: Sig over SHA256(handshake) with Prehashed")
    except Exception as e:
        print(f"  [ERR] Approach 1: {e}")

    # Try 2: signature over hash, with SHA256 hashing (double hash)
    try:
        pubkey.verify(der_sig, hs_hash, ec.ECDSA(hashes.SHA256()))
        print("  [OK] Approach 2: Sig over SHA256(SHA256(handshake)) -> VALID!")
    except InvalidSignature:
        print("  [FAIL] Approach 2: Sig over SHA256(SHA256(handshake))")
    except Exception as e:
        print(f"  [ERR] Approach 2: {e}")

    # Try 3: Maybe cert is NOT included in the hash (V90 style - hash only CH+SH+CKE)
    hash_ctx3 = hashlib.sha256()
    hash_ctx3.update(client_hello_hs)
    hash_ctx3.update(server_hello_hs)
    hash_ctx3.update(cke_hs_raw)
    hs_hash3 = hash_ctx3.digest()

    try:
        pubkey.verify(der_sig, hs_hash3, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("  [OK] Approach 3: Sig without cert in hash (Prehashed) -> VALID!")
    except InvalidSignature:
        print("  [FAIL] Approach 3: Sig without cert in hash (Prehashed)")
    except Exception as e:
        print(f"  [ERR] Approach 3: {e}")

    # Try 4: Maybe the cert IS the pubkey cert and the signing key is different
    # In ECDH_ECDSA, the CertificateVerify is signed with the ECDSA key,
    # which may be different from the ECDH key in ClientKeyExchange
    # Maybe the cert contains the ECDSA signing key?

    # ========================================
    # 4. Search for EC keys in the certificate
    # ========================================
    print(f"\n{'='*60}")
    print("CERTIFICATE EC KEY SEARCH")
    print("=" * 60)

    if cert_der is None:
        print("No certificate data!")
        sys.exit(1)

    print(f"Certificate: {len(cert_der)} bytes")
    print(f"Non-zero bytes: {sum(1 for b in cert_der if b != 0)}")

    # Brute force: try every possible offset for X (32 bytes) and Y (32 bytes)
    # in both big-endian and little-endian
    found_keys = []

    for x_off in range(0, len(cert_der) - 63):
        x_be = cert_der[x_off:x_off + 32]
        # Skip if too many zeros
        if sum(1 for b in x_be if b != 0) < 20:
            continue

        for y_off in range(x_off + 32, min(x_off + 128, len(cert_der) - 31)):
            y_be = cert_der[y_off:y_off + 32]
            if sum(1 for b in y_be if b != 0) < 20:
                continue

            # Try big-endian
            if check_on_curve(x_be, y_be):
                found_keys.append(("BE", x_off, y_off, x_be, y_be))

            # Try little-endian (reverse)
            x_le = x_be[::-1]
            y_le = y_be[::-1]
            if check_on_curve(x_le, y_le):
                found_keys.append(("LE", x_off, y_off, x_le, y_le))

    if found_keys:
        print(f"\nFound {len(found_keys)} valid EC point(s) in certificate:")
        for endian, x_off, y_off, x_val, y_val in found_keys:
            print(f"\n  [{endian}] X at 0x{x_off:02x}, Y at 0x{y_off:02x}")
            print(f"    X: {x_val.hex()}")
            print(f"    Y: {y_val.hex()}")
            print(f"    Uncompressed: 04{x_val.hex()}{y_val.hex()}")

            # Check if this is the same as ClientKeyExchange
            if x_val == kx and y_val == ky:
                print(f"    *** SAME AS ClientKeyExchange ***")
            else:
                print(f"    (different from ClientKeyExchange)")

            # Try to verify CertificateVerify with this key
            try:
                cert_key = load_pubkey(x_val, y_val)
                cert_key.verify(der_sig, hs_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                print(f"    *** SIGNATURE VALID with this key (Prehashed)! ***")
            except InvalidSignature:
                pass
            except Exception as e:
                print(f"    Verify error: {e}")

            try:
                cert_key = load_pubkey(x_val, y_val)
                cert_key.verify(der_sig, hs_hash, ec.ECDSA(hashes.SHA256()))
                print(f"    *** SIGNATURE VALID with this key (SHA256)! ***")
            except InvalidSignature:
                pass
            except Exception as e:
                pass
    else:
        print("\nNo valid EC points found in certificate via brute-force search")

    # ========================================
    # 5. Check if CKE key == cert key (from known V90 offsets)
    # ========================================
    print(f"\n{'='*60}")
    print("KEY COMPARISON")
    print("=" * 60)

    # V90 offsets for cert key (LE)
    v90_x_le = cert_der[0x08:0x28]
    v90_y_le = cert_der[0x4c:0x6c]
    v90_x_be = v90_x_le[::-1]
    v90_y_be = v90_y_le[::-1]

    print(f"V90-style cert key (LE->BE):")
    print(f"  X: {v90_x_be.hex()}")
    print(f"  Y: {v90_y_be.hex()}")
    print(f"  On curve: {check_on_curve(v90_x_be, v90_y_be)}")

    print(f"\nClientKeyExchange key:")
    print(f"  X: {kx.hex()}")
    print(f"  Y: {ky.hex()}")
    print(f"  Same X: {v90_x_be == kx}")
    print(f"  Same Y: {v90_y_be == ky}")

    # Also compare with DEVICE_PRIVATE_KEY from constants
    from validity00da.constants import DEVICE_PRIVATE_KEY
    dpk_x = DEVICE_PRIVATE_KEY[0:32]
    dpk_y = DEVICE_PRIVATE_KEY[32:64]
    print(f"\nDEVICE_PRIVATE_KEY (V90 constant):")
    print(f"  X: {dpk_x.hex()}")
    print(f"  Y: {dpk_y.hex()}")
    print(f"  Same as CKE X: {dpk_x == kx}")
    print(f"  Same as CKE Y: {dpk_y == ky}")

    # ========================================
    # 6. Try verification with different hash combos
    # ========================================
    print(f"\n{'='*60}")
    print("EXHAUSTIVE VERIFICATION")
    print("=" * 60)

    # Build different hash input combos
    combos = [
        ("CH+SH+Cert+CKE", [client_hello_hs, server_hello_hs, cert_hs_raw, cke_hs_raw]),
        ("CH+SH+CKE", [client_hello_hs, server_hello_hs, cke_hs_raw]),
        ("SH+Cert+CKE", [server_hello_hs, cert_hs_raw, cke_hs_raw]),
        ("Cert+CKE", [cert_hs_raw, cke_hs_raw]),
        ("CH+SH", [client_hello_hs, server_hello_hs]),
    ]

    for combo_name, parts in combos:
        h = hashlib.sha256()
        for p in parts:
            h.update(p)
        digest = h.digest()

        for approach, verify_fn in [
            ("Prehashed", lambda sig, d, k: k.verify(sig, d, ec.ECDSA(utils.Prehashed(hashes.SHA256())))),
            ("SHA256", lambda sig, d, k: k.verify(sig, d, ec.ECDSA(hashes.SHA256()))),
        ]:
            try:
                verify_fn(der_sig, digest, pubkey)
                print(f"  [OK] {combo_name} + {approach} -> VALID!")
            except InvalidSignature:
                pass
            except Exception as e:
                print(f"  [ERR] {combo_name} + {approach}: {e}")

    # Also try with just the hash of the raw concatenated bytes (no SHA256 wrapper)
    print("\n  Testing raw concatenation (no hash)...")
    raw_concat = client_hello_hs + server_hello_hs + cert_hs_raw + cke_hs_raw
    try:
        pubkey.verify(der_sig, raw_concat, ec.ECDSA(hashes.SHA256()))
        print(f"  [OK] Raw concat + SHA256 -> VALID!")
    except InvalidSignature:
        print(f"  [FAIL] Raw concat + SHA256")
    except Exception as e:
        print(f"  [ERR] Raw concat: {e}")


if __name__ == "__main__":
    main()
