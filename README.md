# validity-00da

Driver prototype for the Synaptics `06cb:00da` (FS7605) fingerprint sensor found in ThinkPad E14/E15 laptops.

Based on reverse engineering from the [Validity90](https://github.com/nmikhailov/Validity90) project which supports similar sensors (`138a:0090`, `138a:0097`, `06cb:009a`).

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Setup & environment | Done |
| 1 | Probe / check state (`0x01`) | Done |
| 2 | USB capture — provisioning protocol | Done (teste1.pcap) |
| 3 | Protocolo pre-TLS documentado (`0x8e` subs) | Done |
| 3.5 | Analise do certificado e chaves EC | Done |
| 4 | TLS handshake (cipher `0xc02e` GCM) | Done |
| 5 | Provisioning via TLS tunnel | Em progresso (tunnel funcional) |
| 6 | Enrollment (fingerprint scan) | Pendente |

## Setup

### Dependencies

```bash
pip install -r requirements.txt
```

### Linux (nativo ou WSL2)

#### udev rules (avoid sudo)

Create `/etc/udev/rules.d/99-validity-00da.rules`:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="06cb", ATTR{idProduct}=="00da", MODE="0666", GROUP="plugdev"
```

Then reload:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

#### Verify device is detected

```bash
lsusb | grep 06cb:00da
```

### Windows

1. Instalar Python 3.x de https://python.org (marcar "Add to PATH")
2. `python -m venv venv && venv\Scripts\pip install -r requirements.txt`
3. Instalar [Zadig](https://zadig.akeo.ie/) e trocar o driver do sensor para **libusbK**
4. Copiar `libusb-1.0.dll` para `C:\Windows\System32\` (necessario para pyusb no Windows)

> **Nota:** Com libusbK (Zadig) o pyusb funciona, mas Windows Hello fica bloqueado.
> Para capturar trafego do driver Synaptics, reinstale o driver original e use USBPcap/Wireshark.

### WSL2 + usbipd-win

Para usar o sensor no WSL2:

```powershell
# PowerShell (admin)
winget install usbipd
usbipd list                          # encontrar o BUSID do sensor
usbipd bind --busid <BUSID>
usbipd attach --wsl --busid <BUSID>
```

```bash
# WSL2
lsusb | grep 06cb:00da
sudo python3 scripts/check_state.py
```

## Usage

### Verificar estado do sensor

```bash
python3 scripts/check_state.py
```

Envia `0x01` e mostra o estado atual:
- `0x03` — nao provisionado (factory reset)
- `0x07` — inicializado e pronto

### Factory reset

```bash
python3 scripts/factory_reset.py
```

Reseta o sensor para estado `0x03`.

### Provisioning (em desenvolvimento)

```bash
python3 scripts/provision.py
```

> **Nota:** O script atual usa blobs do Validity90 que NAO funcionam no 06cb:00da.
> O provisioning real usa o comando `0x8e` + TLS handshake (ver PROTOCOL.md).

### Init sequence (Validity90 — referencia)

```bash
python3 scripts/init_full.py
```

Roda sequencia MSG1-MSG6 do Validity90. Requer sensor em state `0x07`.

### TLS handshake (em desenvolvimento)

```bash
python3 scripts/try_handshake.py
```

Tenta TLS handshake com o sensor usando chaves EC geradas. Executa a fase pre-TLS
(0x01, 0x8e, 0x19) e depois o handshake completo com cipher `0xc02e` (AES-256-GCM).

### Analise de captura

```bash
python3 scripts/parse_cert.py           # Extrai cert do pcap
python3 scripts/verify_cert_sig.py      # Verifica assinatura
python3 scripts/extract_client_hello.py # Formato do ClientHello
```

Scripts de analise do `teste1.pcap`. Requerem o arquivo `Wireshark/teste1.pcap`.

## Architecture

```
validity00da/
├── constants.py     # Static bytes, keys, init sequences
├── usb_device.py    # pyusb wrapper (open/read/write/interrupt) — Windows + Linux
├── protocol.py      # Init sequence MSG1-MSG6, RSP6 parsing (Validity90)
├── crypto.py        # TLS-PRF, AES-256-CBC, ECDH, ECDSA, key derivation (V90)
├── tls_session.py   # Custom TLS 1.2 handshake (V90, cipher 0xc005 — precisa atualizacao)
└── sensor.py        # High-level commands (LED, scan, verify)

scripts/
├── check_state.py          # Verifica estado do sensor (0x03/0x07)
├── factory_reset.py        # Reset para estado 0x03
├── try_handshake.py        # Tentativa de TLS handshake com chaves proprias
├── parse_cert.py           # Extrai certificado e handshake do teste1.pcap
├── verify_cert_sig.py      # Verifica assinatura CertificateVerify
├── extract_client_hello.py # Extrai formato do ClientHello do pcap
├── provision.py            # Tentativa de provisioning (blobs V90 — nao funciona)
├── init_full.py            # Init MSG1-MSG6 (V90 reference)
└── handshake.py            # TLS handshake test (V90 — precisa atualizacao)

logs/
└── wireshark_teste1_analysis.txt  # Analise completa do teste1.pcap
```

## Protocol Overview

O sensor usa protocolo customizado sobre USB bulk transfers:

1. **Pre-TLS**: Leitura de info com `0x01`, `0x19`, e `0x8e` (subcomandos 0x09, 0x1a, 0x2e, 0x2f)
2. **TLS handshake**: TLS 1.2 com `TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384` (0xc02e), records do host prefixados com `44 00 00 00`
3. **Provisioning**: Comandos de provisioning enviados dentro do tunel TLS (criptografado)
4. **Enrollment**: Captura de fingerprints tambem via TLS

> **Importante:** O protocolo e diferente do Validity90 (`138a:0090`). Os comandos de provisioning
> (0x06, 0x07, 0x08, 0x75, 0x4f, 0x50, 0x1a) do Validity90 NAO existem neste firmware.

See [PROTOCOL.md](PROTOCOL.md) for the full protocol specification.

## References

- [Validity90](https://github.com/nmikhailov/Validity90) - C prototype for `138a:0090` family
- [python-validity](https://github.com/nicegreengorilla/python-validity) - Python driver for `06cb:009a`
