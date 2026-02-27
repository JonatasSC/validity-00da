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

### 3. Driver do Synaptics (se nao vier pre-instalado)

- Windows Update geralmente instala automaticamente
- Se nao: Lenovo Vantage ou Lenovo Support site
- O driver aparece no Device Manager como "Synaptics FP Sensors (WBF) (PID=00da)"

---

## Como capturar

### Passo 1: Identificar o bus USB do sensor

1. Abrir **Device Manager**
2. Expandir **Biometric devices** → deve mostrar "Synaptics FP Sensors (WBF) (PID=00da)"
3. Clicar duas vezes → Properties → Details → **Bus reported device description**
4. Anotar em qual **USB Root Hub** esta conectado

OU no PowerShell:
```powershell
Get-PnpDevice | Where-Object { $_.InstanceId -like "*06CB*00DA*" }
```

### Passo 2: Remover pairing anterior (se existir)

Se o sensor ja foi configurado antes no Windows, precisa resetar:
1. **Settings → Accounts → Sign-in options → Fingerprint → Remove**
2. No Device Manager: desinstalar o device e reinstalar
3. Idealmente: sensor deve estar em estado "virgem" (state 0x03)

### Passo 3: Iniciar captura

1. Abrir **Wireshark**
2. Na tela inicial, selecionar a interface **USBPcap** do bus correto
3. **Iniciar captura** (botao play)

### Passo 4: Fazer o setup do fingerprint

1. Ir em **Settings → Accounts → Sign-in options → Fingerprint**
2. Clicar em **Set up** (ou "Get started")
3. Seguir o wizard — tocar o dedo no sensor quando pedir
4. **Completar todo o enrollment** (geralmente pede ~10 toques)

### Passo 5: Parar captura e salvar

1. Parar a captura no Wireshark
2. **File → Save As** → salvar como `fingerprint_setup.pcapng`
3. Copiar o arquivo pro Linux

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

### Fase 1: Identificacao (raw, antes do TLS)

Procurar os primeiros bulk OUT packets. Devem comecar com:
- `01` → RSP1 (38 bytes) — verifica que retorna state=0x03
- `19` → RSP2 (68 bytes)
- `3e` → RSP5 (52 bytes)

Esses ja conhecemos. O **importante** e o que vem DEPOIS.

### Fase 2: Provisioning (o que nao sabemos)

Depois dos comandos conhecidos, o driver vai enviar comandos que nao reconhecemos.
Prestar atencao em:

1. **Comandos novos** — bytes que nao sao `01`, `19`, `3e`
2. **Payloads grandes** (>100 bytes) — provavelmente certificados ou blobs criptografados
3. **Mudanca de estado** — apos algum comando, o sensor vai mudar de state 0x03 para outro
4. **Sequencia de `0x44`** — quando o TLS comecar (Client Hello, Server Hello, etc.)

### Fase 3: TLS Handshake

Apos provisioning, o driver vai iniciar TLS:
- Envio de `0x44` (ou similar) para entrar em modo TLS
- Client Hello (`16 03 03...`)
- Server Hello + Certificate + Key Exchange
- Finished

### Fase 4: Comandos de scan (sobre TLS)

Ja dentro da sessao TLS (dados criptografados):
- Setup de LED
- Configuracao de scan
- Leitura de imagem
- Esses dados serao criptografados (AES-256-CBC)

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

- **Capturar o PRIMEIRO setup** — e o mais importante porque inclui o provisioning completo
- Se possivel, fazer uma **segunda captura** de um login normal (apos setup) pra comparar
- O arquivo .pcapng pode ser grande (10-50 MB) — normal
- Se o sensor ja estiver provisionado pelo Windows e quiser capturar o provisioning do zero,
  pode ser necessario fazer reset de fabrica ou reinstalar o Windows
- **NAO instalar** python-validity ou open-fprintd no Linux antes/depois — pode confundir o estado do sensor

---

## Resultado esperado

Apos a captura, teremos:
1. A sequencia completa de comandos de provisioning
2. Os payloads exatos (incluindo blobs criptografados)
3. O formato correto do TLS handshake para este sensor
4. Os comandos de scan/enroll

Com isso, podemos implementar o provisioning no nosso projeto Python.
