#!/usr/bin/env python3
"""
Teste do comando 0x0e (PROVISION) via TLS.

0x0e causa USB disconnect/reboot. Este script:
1. Faz setup completo (Pre-TLS → PAIR → Reset → TLS)
2. Envia 0x0e com diferentes payloads
3. Aguarda reconexao USB
4. Verifica novo estado do sensor

Log: logs/tls_probe_0x0e.txt
"""

import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
from scripts.tls_provision import (
    Logger, TlsSession, do_pair, do_handshake,
)
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "tls_probe_0x0e.txt")


def wait_for_sensor(log, timeout=15):
    """Wait for sensor to reappear on USB after reboot."""
    log.info(f"  Aguardando sensor reconectar (max {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        dev = usb.core.find(idVendor=0x06cb, idProduct=0x00da)
        if dev:
            elapsed = time.time() - start
            log.info(f"  Sensor reconectado em {elapsed:.1f}s!")
            return True
        time.sleep(0.5)
    log.error(f"  Sensor nao reconectou em {timeout}s")
    return False


def check_state_after_reboot(log):
    """Open sensor and check state after reboot."""
    dev = USBDevice()
    if not dev.open():
        log.error("  Nao conseguiu abrir sensor")
        return None, None

    log.info("  Enviando 0x01 (GET_VERSION)...")
    rsp = dev.cmd(b"\x01")
    if rsp is None:
        # Pode estar em modo TLS residual
        log.warn("  Sem resposta, tentando reset...")
        dev.reset()
        time.sleep(1)
        rsp = dev.cmd(b"\x01")

    if rsp and len(rsp) >= 38:
        state = rsp[-1]
        log.info(f"  Estado apos reboot: 0x{state:02x}")
        log.hex_dump("GET_VERSION apos reboot", rsp)
        dev.close()
        return state, rsp
    elif rsp:
        log.info(f"  Resposta ({len(rsp)}B): {rsp.hex()}")
        dev.close()
        return None, rsp
    else:
        log.error("  Sem resposta ao GET_VERSION")
        dev.close()
        return None, None


def test_provision(session, log, payload, desc):
    """Send 0x0e with payload, handle disconnect, check new state."""
    cmd = bytes([0x0e]) + payload
    log.separator("-", 40)
    log.info(f"PROVISION: {desc}")
    log.info(f"  Payload: {cmd.hex()} ({len(cmd)} bytes)")

    try:
        # Send the command
        session.send(cmd)
        log.info("  Comando enviado, aguardando resposta...")

        # Try to read response (may get data before disconnect, or just disconnect)
        try:
            rsp = session.dev.read(timeout=3000)
            if rsp:
                log.info(f"  Resposta antes do disconnect: {len(rsp)}B")
                log.hex_dump("Pre-disconnect response", rsp)

                # Try to decrypt
                if rsp[0] == 0x17 and len(rsp) > 5:
                    rec_len = struct.unpack(">H", rsp[3:5])[0]
                    rec_data = rsp[5:5+rec_len]
                    plaintext = session._decrypt_record(rec_data, 0x17)
                    if plaintext:
                        log.info(f"  Decrypted: {plaintext.hex()}")
                        if len(plaintext) == 2:
                            log.info(f"  Status: {plaintext.hex()}")
                            return "status", plaintext
                elif rsp[0] == 0x15:
                    if len(rsp) >= 7:
                        log.info(f"  TLS Alert: level={rsp[5]}, desc={rsp[6]}")
                    return "alert", rsp
            else:
                log.info("  Timeout na leitura (sensor pode ter desconectado)")
        except Exception as e:
            log.info(f"  USB error na leitura: {e}")

    except Exception as e:
        log.info(f"  USB error no envio: {e}")

    # Sensor probably disconnected — wait for reconnection
    log.info("  Sensor desconectou (esperado para 0x0e)")
    if wait_for_sensor(log):
        time.sleep(2)  # Extra wait for sensor to stabilize
        state, rsp = check_state_after_reboot(log)
        return "reboot", state
    else:
        return "lost", None


def main():
    log = Logger(LOG_FILE)
    log.info("=== 0x0e (PROVISION) Probe via TLS ===")

    dev = USBDevice()
    if not dev.open():
        log.error("Sensor nao encontrado!")
        sys.exit(1)

    try:
        # Setup completo
        log.separator()
        log.info("Setup: Pre-TLS + PAIR + Reset + TLS")

        pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=2)

        log.info("PAIR...")
        pairing_data = do_pair(dev, log)
        if not pairing_data:
            sys.exit(1)

        dev.reset(); time.sleep(1)
        pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
        pre_tls_phase(dev, log, round_num=4)

        log.info("TLS...")
        session = do_handshake(dev, log, pairing_data)
        if not session:
            sys.exit(1)

        # First verify tunnel works
        log.separator()
        log.info("Verificando tunnel...")
        rsp = session.command(b"\x01", raw=True)
        if rsp and len(rsp) >= 38:
            log.info(f"  GET_VERSION OK, estado: 0x{rsp[-1]:02x}")
        else:
            log.error("  Tunnel nao funciona!")
            sys.exit(1)

        # Test PROVISION with different payloads
        log.separator()
        log.info("=== 0x0e PROVISION TESTS ===")

        payloads = [
            (b"", "bare (sem payload)"),
        ]

        for payload, desc in payloads:
            result_type, result_data = test_provision(session, log, payload, desc)

            log.info(f"  Resultado: {result_type}")
            if result_type == "reboot":
                log.info(f"  >>> Novo estado: 0x{result_data:02x}" if result_data is not None else "  >>> Estado desconhecido")
                if result_data is not None and result_data != 0x03:
                    log.info(f"  >>> ESTADO MUDOU! De 0x03 para 0x{result_data:02x}")
            elif result_type == "status":
                log.info(f"  >>> Sensor respondeu sem reboot: {result_data.hex()}")
                # Sensor didn't reboot — try next payload
                continue
            elif result_type == "alert":
                log.info("  >>> TLS Alert recebido")
                continue

            # After reboot, need full re-setup for next test
            # For now just test one payload
            break

        log.separator()
        log.info("*** PROVISION TEST COMPLETE ***")

    except Exception as e:
        log.error(f"Excecao: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        try:
            dev.close()
        except:
            pass
        log.close()
        print(f"\nLog: {LOG_FILE}")


if __name__ == "__main__":
    main()
