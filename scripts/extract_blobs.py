#!/usr/bin/env python3
"""
Extract binary blobs from the C prototype's constants.h.
Saves them as Python byte literals for use in provisioning scripts.
"""

import re
import os

CONSTANTS_H = "/tmp/ThinkPad-E14-fingerprint/prototype/constants.h"
OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "validity00da", "setup_blobs.py")


def extract_arrays(source):
    """Extract all byte/dword arrays from C header file."""
    arrays = {}

    # Match: static byte name[] = { ... };  or  const static byte name[] = { ... };
    pattern = re.compile(
        r'(?:const\s+)?static\s+(?:byte|dword)\s+(\w+)\s*\[\]\s*=\s*\{([^}]+)\};',
        re.DOTALL
    )

    for match in pattern.finditer(source):
        name = match.group(1)
        values_str = match.group(2)

        # Extract all hex values
        hex_vals = re.findall(r'0x([0-9a-fA-F]+)', values_str)
        if hex_vals:
            byte_vals = [int(h, 16) for h in hex_vals]
            arrays[name] = bytes(byte_vals)

    return arrays


def main():
    with open(CONSTANTS_H, "r") as f:
        source = f.read()

    arrays = extract_arrays(source)

    print(f"Found {len(arrays)} arrays in constants.h")
    for name, data in sorted(arrays.items()):
        print(f"  {name}: {len(data)} bytes")

    # Write the blobs we need for provisioning
    needed = [
        "init_sequence_msg4",
        "setup_sequence_msg6",
        "setup_sequence_msg7",
        "setup_sequence_msg8",
        "setup_sequence_config_data",
        "setup_sequence_msg11",
    ]

    with open(OUTPUT, "w") as f:
        f.write('"""\n')
        f.write('Binary blobs extracted from Validity90 C prototype constants.h.\n')
        f.write('These are USB captures from the Windows Synaptics driver for 06cb:00da.\n')
        f.write('"""\n\n')

        for name in needed:
            if name in arrays:
                data = arrays[name]
                f.write(f"# {name} ({len(data)} bytes)\n")
                f.write(f"{name.upper()} = bytes([\n")
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
                    f.write(f"    {hex_str},\n")
                f.write("])\n\n")
            else:
                print(f"  WARNING: {name} not found!")

    print(f"\nOutput written to {OUTPUT}")


if __name__ == "__main__":
    main()
