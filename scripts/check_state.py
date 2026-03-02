#!/usr/bin/env python3
"""
Verifica o estado atual do sensor sem modificá-lo.

Uso: venv/Scripts/python scripts/check_state.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validity00da.usb_device import USBDevice

STATES = {
    0x02: "inicialização necessária (first-time setup)",
    0x03: "não provisionado / factory reset (ok para enroll)",
    0x07: "inicializado e pronto",
}


def main():
    dev = USBDevice()
    if not dev.open():
        print("Sensor não encontrado. Verifique o driver (use Zadig para libusbK).")
        sys.exit(1)

    try:
        rsp = dev.cmd(b"\x01")
        if not rsp:
            print("Sem resposta do sensor (timeout).")
            sys.exit(1)

        print(f"Resposta ({len(rsp)} bytes): {rsp.hex()}")

        if len(rsp) >= 38 and rsp[0:2] == b"\x00\x00":
            state = rsp[-1]
            desc = STATES.get(state, "estado desconhecido")
            print(f"\nEstado: 0x{state:02x} — {desc}")
        else:
            print(f"\nResposta inesperada ou incompleta: {rsp.hex()}")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
