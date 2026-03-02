# Guia de Captura USB — Windows Driver para 06cb:00da

## Objetivo

Capturar todo o trafego USB entre o driver Synaptics (synaWudfBioUsb.dll) e o sensor
de fingerprint `06cb:00da` durante o **primeiro setup** (provisioning).

Precisamos descobrir:
1. Quais comandos o driver envia para provisionar o sensor
2. Em que ordem
3. Quais payloads usa
4. Como a sessao TLS e estabelecida

---

## O que instalar no Windows

### 1. USBPcap (captura USB)

- Download: https://desowin.org/usbpcap/
- Instala um driver de captura no bus USB
- Se integra com o Wireshark automaticamente

### 2. Wireshark

- Download: https://www.wireshark.org/download.html
- Na instalacao, marcar **USBPcap** quando perguntar
- **IMPORTANTE**: Abrir como Administrador para ver interfaces USBPcap

### 3. Driver do Synaptics (se nao vier pre-instalado)

- Windows Update geralmente instala automaticamente
- Se nao: Lenovo Vantage ou Lenovo Support site
- O driver aparece no Device Manager como "Synaptics FP Sensors (WBF) (PID=00da)"
- **Nota**: O driver pode se reinstalar automaticamente mesmo apos desinstalacao via Device Manager

### 4. Zadig (opcional — para acesso direto via pyusb)

- Download: https://zadig.akeo.ie/
- Trocar driver do sensor para libusbK
- **Cuidado**: Com libusbK ativo, Windows Hello nao funciona e nao ha trafego para capturar

---

## Como capturar (metodo comprovado)

> **Licao aprendida:** O USBPcap so captura bulk transfers de forma confiavel se o Wireshark
> estiver rodando ANTES do driver ser carregado. A melhor forma e capturar apos reboot.

### Metodo que funciona (testado — resultou no teste1.pcap)

1. **Resetar o sensor** para state 0x03 (usando `scripts/factory_reset.py` com Zadig/libusbK)
2. **Trocar de volta** para o driver Synaptics (Device Manager → Update Driver → Search automatically)
3. **Reiniciar a maquina**
4. **Imediatamente apos o boot**, abrir Wireshark como **Administrador**
5. Selecionar a interface **USBPcap** do bus correto
6. **Iniciar captura** — o driver vai provisionar o sensor automaticamente (~18s apos boot)
7. Ir em **Settings → Accounts → Sign-in options → Fingerprint → Set up**
8. Completar enrollment (tocar o dedo ~10 vezes)
9. Parar captura e salvar

### Por que o reboot e necessario

- O USBPcap precisa estar ativo **antes** do driver Synaptics iniciar
- Se instalar o driver com Wireshark ja rodando, o USBPcap perde os primeiros pacotes
- O provisioning acontece nos primeiros segundos apos o driver carregar
- Sem o reboot, voce captura apenas HID interrupt transfers (sem bulk)

### Identificar o bus USB do sensor

No PowerShell:
```powershell
Get-PnpDevice | Where-Object { $_.InstanceId -like "*06CB*00DA*" }
```

Ou no Device Manager: Biometric devices → "Synaptics FP Sensors (WBF) (PID=00da)"

### Limitacoes conhecidas

- **tshark**: Nao consegue abrir interface USBPcap diretamente (`error -5`). Usar GUI do Wireshark.
- **USBPcap mid-session**: Se o driver for instalado DEPOIS do Wireshark iniciar captura,
  os bulk transfers podem nao ser capturados (apenas control + interrupt).
- **WSL2**: O kernel WSL2 nao inclui o modulo `usbmon`, entao nao da para capturar USB no WSL2.
  O sensor funciona via `usbipd-win` mas sem captura.

---

## Filtros uteis no Wireshark

### Filtrar so trafego do sensor

Primeiro, descobrir o device address do sensor. Procurar nos primeiros pacotes por
`GET DESCRIPTOR` que mostra VID=06cb PID=00da. Anotar o `Device` number (ex: `3.15`).

Depois filtrar:
```
usb.device_address == 15
```

Ou filtrar por tipo de transfer:
```
usb.transfer_type == 3 && usb.device_address == 15
```
(transfer_type 3 = Bulk)

### Ver so os dados (OUT = host→sensor, IN = sensor→host)

```
usb.endpoint_address.direction == 0 && usb.device_address == 15
```
(OUT — comandos enviados pro sensor)

```
usb.endpoint_address.direction == 1 && usb.device_address == 15
```
(IN — respostas do sensor)

### Ver payload hex

No painel de detalhes, expandir **USB URB** → **Leftover Capture Data** mostra os bytes raw.

---

## O que procurar na captura

### Filtrar bulk transfers do sensor

Primeiro, descobrir o device address. Pode mudar se o sensor re-enumerar (no teste1.pcap mudou de 4 para 6).

```
usb.transfer_type == 3 && usb.device_address == 6
```

### Fase 1: Pre-TLS (comandos em claro)

Primeiros bulk transfers. Sequencia executada 2x:

| # | OUT | IN | Descricao |
|---|-----|-----|-----------|
| 1 | `01` | 38 bytes | ROM info, state=0x03 |
| 2 | `8e 09 00 02 00...` (17 bytes) | 26 bytes | Sensor info |
| 3 | `8e 1a 00 02 00...` (17 bytes) | 78 bytes | Config/calibracao |
| 4 | `8e 2e 00 02 00...` (17 bytes) | 3586 bytes | Calibration blob |
| 5 | `8e 2f 00 02 00...` (17 bytes) | 18 bytes | Firmware version |
| 6 | `19` | 64+4 bytes | Query state |

### Fase 2: TLS Handshake

Apos a fase 1 (repetida 2x), o driver inicia TLS:

| # | Direcao | Conteudo | Bytes |
|---|---------|----------|-------|
| 1 | OUT | `44 00 00 00` + ClientHello | 82 |
| 2 | IN | ServerHello | 66 |
| 3 | OUT | `44 00 00 00` + Certificate + ChangeCipherSpec + Finished | 616 |
| 4 | IN | ChangeCipherSpec + Finished | 51 |

**Nota**: Records do host tem header `44 00 00 00`. Records do sensor NAO tem.

### Fase 3: Provisioning via TLS

Application Data criptografado (`17 03 03 ...`). Tamanhos tipicos:
- OUT: 33, 33, 25 bytes
- IN: 58, 26, 26 bytes

### Fase 4: Enrollment (fingerprint scan via TLS)

Continua com Application Data criptografado, com ciclos maiores de captura de dedo.
No dozero.pcap: 9 ciclos de ~14631 bytes cada.

---

## Exportando os dados

### Opcao 1: tshark (linha de comando)

No Windows ou no Linux (se copiar o .pcapng):

```bash
# Listar todos os bulk transfers do sensor
tshark -r fingerprint_setup.pcapng -Y "usb.device_address == 15 && usb.transfer_type == 3" \
  -T fields -e frame.number -e usb.endpoint_address -e usb.data_len -e usb.capdata

# Exportar so os OUT (comandos)
tshark -r fingerprint_setup.pcapng \
  -Y "usb.device_address == 15 && usb.endpoint_address == 0x01" \
  -T fields -e frame.number -e usb.capdata > commands_out.txt

# Exportar so os IN (respostas)
tshark -r fingerprint_setup.pcapng \
  -Y "usb.device_address == 15 && usb.endpoint_address == 0x81" \
  -T fields -e frame.number -e usb.capdata > responses_in.txt
```

### Opcao 2: Script Python

Temos um script pronto em `scripts/parse_capture.py` (a ser criado apos a captura)
que vai parsear o .pcapng e extrair a sequencia de comandos automaticamente.

---

## Dicas

- **Capturar o PRIMEIRO setup apos reboot** — e o mais importante porque inclui provisioning + TLS
- O `factory_reset.py` precisa de libusbK (Zadig) ativo para funcionar
- Apos reset, trocar de volta para driver Synaptics e reiniciar
- O arquivo .pcap pode ser grande (50-100 MB com todos os pacotes) — filtrar por bulk do sensor
- **NAO instalar** python-validity ou open-fprintd no Linux — pode confundir o estado
- O driver Synaptics pode se reinstalar automaticamente via Windows Update mesmo apos desinstalacao

---

## Resultado obtido (teste1.pcap)

Captura bem-sucedida incluindo:
1. Sequencia completa pre-TLS (comando `0x8e` com 4 subcomandos)
2. TLS handshake completo (ClientHello → ServerHello → Certs → Finished)
3. Cipher suite real: `TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384` (0xc02e)
4. Provisioning e enrollment via TLS (criptografado)

**Proximo desafio**: Descriptografar o trafego TLS para ver os comandos reais de provisioning.
Opcoes:
- Extrair session keys do driver Windows (SSLKEYLOGFILE ou similar)
- Reimplementar o handshake e derivar as keys a partir do certificado capturado
