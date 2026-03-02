#!/usr/bin/env python3
"""Extract the full ClientHello from teste1.pcap to understand the exact format."""

import sys
import os

PCAP_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Wireshark", "teste1.pcap"
)

def main():
    with open(PCAP_PATH, "rb") as f:
        raw = f.read()

    # Find TLS ClientHello record
    for i in range(len(raw) - 10):
        if raw[i:i+3] == b"\x16\x03\x03" and raw[i+5] == 0x01 and raw[i+6:i+8] == b"\x00\x00":
            rec_len = int.from_bytes(raw[i+3:i+5], 'big')
            print(f"TLS record at pcap offset {i}")
            print(f"  Record length: {rec_len}")

            # Check for USB prefix before it
            if i >= 4 and raw[i-4:i] == b"\x44\x00\x00\x00":
                print(f"  USB prefix found at offset {i-4}")
                full_msg = raw[i-4:i+5+rec_len]
            else:
                print(f"  No USB prefix (prev 4 bytes: {raw[max(0,i-4):i].hex()})")
                full_msg = raw[i:i+5+rec_len]

            hs = raw[i+5:i+5+rec_len]  # handshake data

            print(f"\nFull message ({len(full_msg)} bytes):")
            # Print as Python bytes literal
            for j in range(0, len(full_msg), 16):
                chunk = full_msg[j:j+16]
                hex_str = " ".join(f"0x{b:02x}," for b in chunk)
                print(f"    {hex_str}")

            print(f"\nHandshake data ({len(hs)} bytes):")

            # Parse ClientHello
            hs_type = hs[0]
            hs_len = int.from_bytes(hs[1:4], 'big')
            body = hs[4:4+hs_len]

            print(f"  Type: 0x{hs_type:02x} (ClientHello)")
            print(f"  Body length: {hs_len}")

            version = body[0:2]
            client_random = body[2:34]
            sid_len = body[34]
            sid = body[35:35+sid_len]
            pos = 35 + sid_len

            print(f"  Version: {version.hex()}")
            print(f"  Client Random: {client_random.hex()}")
            print(f"  Session ID len: {sid_len}")
            print(f"  Session ID: {sid.hex()}")

            # Cipher suites
            cs_len = int.from_bytes(body[pos:pos+2], 'big')
            pos += 2
            print(f"  Cipher suites ({cs_len} bytes, {cs_len//2} suites):")
            for k in range(0, cs_len, 2):
                suite = int.from_bytes(body[pos+k:pos+k+2], 'big')
                names = {
                    0xc005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                    0xc02e: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                    0xc02c: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA256",
                    0xc025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
                    0xc004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
                    0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
                }
                name = names.get(suite, "Unknown")
                print(f"    0x{suite:04x} = {name}")
            pos += cs_len

            # Compression
            comp_len = body[pos]
            pos += 1
            comp = body[pos:pos+comp_len]
            pos += comp_len
            print(f"  Compression ({comp_len}): {comp.hex()}")

            # Extensions
            if pos < len(body):
                ext_len = int.from_bytes(body[pos:pos+2], 'big')
                pos += 2
                print(f"  Extensions ({ext_len} bytes):")
                epos = pos
                while epos < pos + ext_len:
                    ext_type = int.from_bytes(body[epos:epos+2], 'big')
                    ext_data_len = int.from_bytes(body[epos+2:epos+4], 'big')
                    ext_data = body[epos+4:epos+4+ext_data_len]
                    ext_names = {
                        0x000a: "supported_groups",
                        0x000b: "ec_point_formats",
                        0x000d: "signature_algorithms",
                    }
                    print(f"    0x{ext_type:04x} ({ext_names.get(ext_type, 'unknown')}): {ext_data.hex()}")
                    epos += 4 + ext_data_len

            break


if __name__ == "__main__":
    main()
