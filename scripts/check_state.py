#!/usr/bin/env python3
"""Verifica estado do sensor. Uso: sudo python3 scripts/check_state.py"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validity00da.usb_device import USBDevice

d = USBDevice()
if not d.open():
    print("Sensor nao encontrado!")
    sys.exit(1)

rsp = d.cmd(b"\x01")
if rsp is None:
    print("Sem resposta, tentando reset...")
    d.reset()
    time.sleep(1)
    rsp = d.cmd(b"\x01")

if rsp and len(rsp) >= 38:
    state = rsp[-1]
    print(f"Estado: 0x{state:02x}")
    if state != 0x03:
        print(f">>> ESTADO MUDOU! Era 0x03, agora 0x{state:02x} <<<")
    print(f"Response: {rsp.hex()}")
elif rsp:
    print(f"Resposta ({len(rsp)}B): {rsp.hex()}")
else:
    print("Sem resposta")

d.close()
