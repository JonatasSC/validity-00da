#!/usr/bin/env python3
"""
Reseta o sensor 06cb:00da para estado de fábrica (0x03).

Uso: sudo .venv/bin/python3 scripts/factory_reset.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice


def main():
    dev = USBDevice()
    if not dev.open():
        print("Sensor não encontrado")
        sys.exit(1)

    try:
        # USB reset pra sair de qualquer modo (TLS, etc)
        print("Resetando sensor...")
        dev.reset()
        time.sleep(1)

        # Checa estado
        rsp = dev.cmd(b"\x01")
        if rsp and len(rsp) >= 38 and rsp[0:2] == b"\x00\x00":
            state = rsp[-1]
            print(f"Estado: 0x{state:02x}", end="")
            if state == 0x03:
                print(" — não provisionado (ok!)")
            else:
                print(f" — provisionado (esperava 0x03)")
        else:
            print("Resposta inesperada:", rsp.hex() if rsp else "timeout")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
