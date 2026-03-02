#!/usr/bin/env python3
"""
Extrai e analisa o certificado TLS e handshake completo do teste1.pcap.
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


def hex_dump(data, prefix="", width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def check_on_curve(x_be, y_be):
    """Check if (x, y) is on secp256r1."""
    x = int.from_bytes(x_be, 'big')
    y = int.from_bytes(y_be, 'big')
    if x == 0 or y == 0:
        return False
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    return (y * y) % p == (x * x * x + a * x + b) % p


def main():
    if not os.path.exists(PCAP_PATH):
        print(f"Arquivo nao encontrado: {PCAP_PATH}")
        sys.exit(1)

    with open(PCAP_PATH, "rb") as f:
        raw = f.read()

    print(f"Pcap: {len(raw)} bytes\n")

    # ========================================
    # 1. Find TLS Certificate record
    # ========================================
    pattern = bytes.fromhex("160303022c0b000198")
    positions = find_all(raw, pattern)
    if not positions:
        print("TLS Certificate record nao encontrado!")
        sys.exit(1)

    tls_start = positions[0]
    cert_hs_start = tls_start + 5  # after TLS record header

    print("=" * 60)
    print("CERTIFICATE (host -> sensor)")
    print("=" * 60)

    # Certificate handshake: 0b 00 01 98 = type, 408 bytes
    cert_msg_len = int.from_bytes(raw[cert_hs_start + 1:cert_hs_start + 4], 'big')
    payload = raw[cert_hs_start + 4:cert_hs_start + 4 + cert_msg_len]

    # TLS cert list: 3-byte length + (3-byte cert length + cert data)*
    certs_len = int.from_bytes(payload[0:3], 'big')
    cert_len = int.from_bytes(payload[3:6], 'big')
    cert_der = payload[6:6 + cert_len]

    print(f"  Cert list length: {certs_len}")
    print(f"  Certificate length: {cert_len}")
    print(f"  Non-zero bytes: {sum(1 for b in cert_der if b != 0)}/{len(cert_der)}")
    print()
    print(hex_dump(cert_der, "  "))

    # --- Validity90-style analysis ---
    print("\n--- Validity90-style cert structure ---")
    print(f"  Header (0x00-0x07): {cert_der[0:8].hex()}")
    print(f"    ASCII: {cert_der[0:4]}")

    # EC X at offset 0x08 (32 bytes, little-endian)
    x_le = cert_der[0x08:0x28]
    x_be = x_le[::-1]
    print(f"\n  EC X at 0x08 (LE): {x_le.hex()}")
    print(f"  EC X (BE):         {x_be.hex()}")

    # EC Y at offset 0x4c (32 bytes, little-endian)
    y_le = cert_der[0x4c:0x6c]
    y_be = y_le[::-1]
    print(f"\n  EC Y at 0x4c (LE): {y_le.hex()}")
    print(f"  EC Y (BE):         {y_be.hex()}")

    on_curve = check_on_curve(x_be, y_be)
    print(f"\n  Point on secp256r1: {on_curve}")
    if on_curve:
        print(f"  *** VALID EC PUBLIC KEY (host) ***")
        print(f"  Uncompressed: 04{x_be.hex()}{y_be.hex()}")

    # Extra data at offset 0x8f
    if len(cert_der) > 0x92:
        marker = cert_der[0x8f]
        extra_len = int.from_bytes(cert_der[0x90:0x92], 'little')
        print(f"\n  Extra field at 0x8f:")
        print(f"    Marker: 0x{marker:02x}")
        print(f"    Length: {extra_len}")
        if 0x92 + extra_len <= len(cert_der):
            extra = cert_der[0x92:0x92 + extra_len]
            print(f"    Data (LE): {extra.hex()}")
            print(f"    Data (BE): {extra[::-1].hex()}")

    # ========================================
    # 2. Remaining handshake messages
    # ========================================
    tls_record_len = int.from_bytes(raw[tls_start + 3:tls_start + 5], 'big')
    remaining_start = cert_hs_start + 4 + cert_msg_len
    remaining_end = tls_start + 5 + tls_record_len
    remaining = raw[remaining_start:remaining_end]

    hs_names = {
        0x00: "HelloRequest", 0x01: "ClientHello", 0x02: "ServerHello",
        0x0b: "Certificate", 0x0c: "ServerKeyExchange",
        0x0d: "CertificateRequest", 0x0e: "ServerHelloDone",
        0x0f: "CertificateVerify", 0x10: "ClientKeyExchange", 0x14: "Finished",
    }

    if remaining:
        print(f"\n{'=' * 60}")
        print(f"REMAINING HANDSHAKE ({len(remaining)} bytes)")
        print("=" * 60)

        pos = 0
        while pos + 4 <= len(remaining):
            hs_type = remaining[pos]
            hs_len = int.from_bytes(remaining[pos + 1:pos + 4], 'big')
            name = hs_names.get(hs_type, f"Unknown(0x{hs_type:02x})")
            hs_data = remaining[pos + 4:pos + 4 + hs_len]

            print(f"\n  {name} (type=0x{hs_type:02x}, len={hs_len})")

            if hs_type == 0x10:  # ClientKeyExchange
                print(f"    Raw: {hs_data.hex()}")
                # Check for EC point
                if len(hs_data) == 65 and hs_data[0] == 0x04:
                    kx = hs_data[1:33]
                    ky = hs_data[33:65]
                    print(f"    EC point (uncompressed):")
                    print(f"      X: {kx.hex()}")
                    print(f"      Y: {ky.hex()}")
                    print(f"      On curve: {check_on_curve(kx, ky)}")
                elif len(hs_data) > 1:
                    # Length-prefixed EC point
                    plen = hs_data[0]
                    if plen == 0x41 and len(hs_data) >= 66 and hs_data[1] == 0x04:
                        kx = hs_data[2:34]
                        ky = hs_data[34:66]
                        print(f"    EC point (length-prefixed, uncompressed):")
                        print(f"      X: {kx.hex()}")
                        print(f"      Y: {ky.hex()}")
                        print(f"      On curve: {check_on_curve(kx, ky)}")
                    else:
                        print(f"    (not recognized as EC point)")

            elif hs_type == 0x0f:  # CertificateVerify
                print(f"    Raw ({len(hs_data)} bytes): {hs_data.hex()}")
                # Look for DER ECDSA signature
                if len(hs_data) > 4 and hs_data[0] == 0x30:
                    print(f"    DER ECDSA signature")
                # Or with algorithm prefix (TLS 1.2)
                elif len(hs_data) > 6 and hs_data[2] == 0x00 and hs_data[4] == 0x30:
                    print(f"    Algorithm: {hs_data[0]:02x} {hs_data[1]:02x}")
                    sig = hs_data[4:]
                    print(f"    Signature: {sig.hex()}")

            else:
                if hs_len > 0:
                    print(f"    Raw ({len(hs_data)} bytes): {hs_data[:64].hex()}" +
                          ("..." if len(hs_data) > 64 else ""))

            pos += 4 + hs_len

    # ========================================
    # 3. Parse ServerHello
    # ========================================
    sh_pattern = bytes.fromhex("160303003d020000")
    sh_positions = find_all(raw, sh_pattern)
    if sh_positions:
        print(f"\n{'=' * 60}")
        print("SERVER HELLO (sensor -> host)")
        print("=" * 60)

        sh_rec_start = sh_positions[0]
        sh_rec_len = int.from_bytes(raw[sh_rec_start + 3:sh_rec_start + 5], 'big')
        sh_data = raw[sh_rec_start + 5:sh_rec_start + 5 + sh_rec_len]

        print(f"  TLS record: {sh_rec_len} bytes")
        print(hex_dump(sh_data, "  "))

        # Parse ServerHello
        pos = 0
        while pos + 4 <= len(sh_data):
            hs_type = sh_data[pos]
            hs_len = int.from_bytes(sh_data[pos + 1:pos + 4], 'big')
            name = hs_names.get(hs_type, f"Unknown(0x{hs_type:02x})")
            hs_body = sh_data[pos + 4:pos + 4 + hs_len]

            print(f"\n  {name} (type=0x{hs_type:02x}, len={hs_len})")

            if hs_type == 0x02:  # ServerHello
                version = hs_body[0:2]
                server_random = hs_body[2:34]
                sid_len = hs_body[34]
                sid = hs_body[35:35 + sid_len]
                cipher = hs_body[35 + sid_len:37 + sid_len]
                compression = hs_body[37 + sid_len]
                print(f"    Version: {version.hex()}")
                print(f"    Server Random: {server_random.hex()}")
                print(f"    Session ID ({sid_len}): {sid.hex()}")
                print(f"    Cipher: {cipher.hex()}")
                print(f"    Compression: {compression}")

            elif hs_type == 0x0d:  # CertificateRequest
                print(f"    Raw: {hs_body.hex()}")
                if len(hs_body) >= 1:
                    types_len = hs_body[0]
                    cert_types = hs_body[1:1 + types_len]
                    print(f"    Cert types ({types_len}): {cert_types.hex()}")
                    for ct in cert_types:
                        ct_names = {1: "rsa_sign", 2: "dss_sign",
                                    64: "ecdsa_sign", 65: "rsa_fixed_dh",
                                    66: "dss_fixed_dh"}
                        print(f"      0x{ct:02x} = {ct_names.get(ct, 'unknown')}")

            elif hs_type == 0x0e:  # ServerHelloDone
                print(f"    (empty - standard)")

            pos += 4 + hs_len

    # ========================================
    # 4. Summary
    # ========================================
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print("  Certificate: Proprietary format (NOT X.509)")
    print("  EC public key in cert: offsets 0x08 (X) and 0x4c (Y), little-endian")
    if on_curve:
        print("  Key is VALID on secp256r1")
    print("  Sensor sends: ServerHello + CertificateRequest + ServerHelloDone")
    print("  Sensor does NOT send its own certificate")
    print("  Sensor requests cert type 0x40 = ecdsa_sign")


if __name__ == "__main__":
    main()
