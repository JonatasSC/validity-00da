# Protocol Specification — Synaptics 06cb:00da (FS7605)

> **Last updated:** 2026-02-28

---

## Summary

The `06cb:00da` is a Synaptics FS7605 fingerprint sensor found in ThinkPad E14/E15 laptops.
It shares some basic commands with the Validity90 family (`138a:0090`, `138a:0097`, `06cb:009a`)
but has a **fundamentally different firmware** with a different command set for provisioning.

**Current status:** Protocolo de provisioning parcialmente descoberto via captura USB (`teste1.pcap`).
A fase pre-TLS esta documentada. Certificado proprietario analisado e formato de chaves EC descoberto.
A fase de provisioning real ocorre dentro do tunel TLS (criptografada).

---

## USB Interface

| Parameter | Value |
|-----------|-------|
| Vendor ID | `0x06cb` (Synaptics) |
| Product ID | `0x00da` (FS7605) |
| Bulk OUT | Endpoint `0x01` |
| Bulk IN | Endpoint `0x81` |
| Interrupt IN | Endpoint `0x83` |
| Timeout | 10s (bulk), 5s (interrupt) |

---

## Error Code Format

2-byte responses with format `XX YY`:

| Code | Meaning | Seen on |
|------|---------|---------|
| `00 00` | Success / ACK | `0x00`, `0x05`, `0x7c`, `0x8d`, `0x3f 01`, `0x3f 02` |
| `01 04` | Unknown command | 213 of 256 single-byte cmds |
| `03 04` | Parameter error | `0x93`, `0x3f` with invalid sub-byte, `0xae` with invalid sub |
| `04 04` | State error (blocked) | `0x81`, `0x86`, `0x87`, `0x9f`, `0xa2`, `0xa5`, `0xec`, `0xed`, `0xfe`, `0x9e XX`, `0xa4 XX` |
| `05 04` | Needs parameters | 24 commands (see below) |
| `e5 06` | Not available | `0x3f 03` |
| `e7 06` | Not provisioned | MSG6 (`0x40 01 01...`) |

---

## Full Command Map (state=0x03, unprovisioned)

### Commands that return data or ACK

| Cmd | Response | Notes |
|-----|----------|-------|
| `0x00` | `00 00` (2 bytes) | NOP / status OK |
| `0x01` | 38 bytes | MSG1 — ROM info / probe. Last byte = state (`0x03`) |
| `0x05` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0x19` | 68 bytes | MSG2 — device state query |
| `0x3e` | 52 bytes | MSG5 — flash/partition info. Flash is empty (`ff ff ff ff`) |
| `0x3f 0x01` | `00 00` (2 bytes) | ACK — flash/partition operation? |
| `0x3f 0x02` | `00 00` (2 bytes) | ACK — flash/partition operation? |
| `0x7c` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0x8d` | `00 00` (2 bytes) | ACK — unknown purpose |
| `0xae 0x00` | 270 bytes | Sensor config/calibration dump (TLV format, see below) |

### Commands recognized but need parameters (`05 04`)

```
0x0d  0x39  0x3f  0x40  0x41  0x57  0x73  0x7f
0x80  0x82  0x8e  0x90  0x96  0x99  0x9e  0xa0
0xa1  0xa3  0xa4  0xa6  0xa9  0xaa  0xab  0xae
```

Of these, when tested with `cmd + sub-byte` (0x00-0xff):
- Most returned `01 04` or `05 04` for all sub-bytes
- **`0x9e XX`** — all return `04 04` (state-blocked, needs provisioning)
- **`0xa4 XX`** — all return `04 04` (state-blocked, needs provisioning)
- **`0xae 0x00`** — returns 270 bytes (only sub=0x00 valid, rest `03 04`)
- **`0x3f`** — sub=0x01 ACK, sub=0x02 ACK, sub=0x03 `e5 06`, rest `03 04`

### Commands blocked by state (`04 04`)

```
0x81  0x86  0x87  0x9f  0xa2  0xa5  0xec  0xed  0xfe
```

These will likely work after the sensor is provisioned (state != 0x03).

### Special behaviors

| Cmd | Behavior |
|-----|----------|
| `0x06` | **USB disconnect** — sensor crashes (bare byte). With full blob payload → `01 04` |
| `0x44` | **TLS mode** — responds with TLS Alert, then reverts to raw mode |
| `0x93` | Returns `03 04` (unique — parameter error as single byte) |

### Commands confirmed NOT to exist (`01 04`)

These Validity90/python-validity commands do NOT exist on 06cb:00da firmware:

```
0x06 (blob)     0x07 (HW read)   0x08 (HW write)  0x1a (commit)
0x43 (ROM/FW)   0x4f (partition)  0x50 (finalize)   0x75 (identify)
```

---

## Actual Responses (hex dumps)

### RSP1 — `0x01` (38 bytes)

```
00 00 55 8f 21 5e 11 d2 2f 00 0a 01 01 41 01 c1
00 00 2a 8f 4e b0 70 50 03 a1 00 00 00 00 01 00
00 00 00 00 00 03
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-7 | `55 8f 21 5e 11 d2` | Device serial/ID (unique per unit) |
| 9 | `0x0a` | Firmware version? (V90: `0x06`) |
| 10 | `0x01` | Protocol version? (V90: `0x07`) |
| 12 | `0x41` | Capabilities? (V90: `0x30`) |
| **37** | **`0x03`** | **State: not provisioned** (V90: `0x07` = ready) |

### RSP2 — `0x19` (68 bytes)

```
00 00 00 03 01 02 00 00 00 00 00 00 00 00 00 00
08 42 00 90 00 00 00 00 57 15 e3 01 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 3 | `0x03` | State (matches RSP1) |
| 4-5 | `01 02` | Sub-state or version? |
| 16-19 | `08 42 00 90` | `00 90` may reference 138a:0090 sensor family |
| 24-27 | `57 15 e3 01` | Firmware version/timestamp (0x01e31557) |

### RSP5 — `0x3e` (52 bytes)

```
00 00 ff ff ff ff ff ff ff ff ff ff ff ff 03 00
01 00 04 00 00 00 00 51 00 e0 09 00 02 00 07 00
00 f0 09 51 00 10 00 00 03 00 00 00 00 e0 09 51
00 10 00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-13 | `ff ff ff ff...` | **Flash is empty** (no calibration/provisioning data) |
| 14 | `0x03` | Partition count? Or state again |

---

## 0xae — Sensor Config/Calibration Dump (270 bytes)

### TLV Record Format

`[u16le type] [u16le total_size] [data: total_size - 4 bytes]`

Where `total_size` **includes** the 4-byte header itself.

### Parsed Records

```
Offset  Type    Total  Data   Content
------  ------  -----  ----   -------
0x00    —       2      —      Status: 00 00 (OK)
0x02    0x0011  16     12     ADC/live sensor readings (3x int32, fluctuate ±5)
0x12    0x0022  36     32     Main config (threshold=20000, flags, calibration)
0x36    0x0032  36     32     Calibration pairs (0x7777 markers, gain/offset?)
0x5a    0x0041  32     28     Scan config (GPIO/register addresses?)
0x7a    0x0052  12     8      Short config (1 bit fluctuates)
0x86    0x0061  20     16     Config block
0x9a    0x0072  16     12     Config block (all zeros)
0xaa    0x0081  20     16     Config block (2 bytes fluctuate)
0xbe    0x0091  52     48     Large block (memory layout?)
0xf2    0x00a1  28     24     Memory addresses (0x00037120, 0x000370f8)
```

**Total: 16+36+36+32+12+20+16+20+52+28 = 268 + 2 (status) = 270 bytes ✓**

### Fluctuating Bytes (4 of 270)

| Offset | Record | Values observed | Likely meaning |
|--------|--------|-----------------|----------------|
| `0x006` | reg 0x11, data[0] | {0x24, 0x26, 0x28, 0x29} | ADC reading LSB |
| `0x07e` | reg 0x52, data[0] | {0x00, 0x40} | Status bit |
| `0x0ba` | reg 0x81, data[12] | {0x0e, 0x26} | Unknown |
| `0x0bb` | reg 0x81, data[13] | {0x00, 0x01} | Unknown |

---

## TLS Behavior (state 0x03 — unprovisioned)

Quando o sensor esta em state `0x03`, enviar `0x44` retorna TLS Alert:
```
15 03 03 00 02 02 2f
```
**fatal (2) / illegal_parameter (47)** — flash vazio, sem certificados.

**Porem**, o driver Windows Synaptics consegue fazer TLS handshake com sucesso apos
a fase pre-TLS (ver secao abaixo). O sensor responde ao handshake mesmo em state 0x03.

---

## Protocolo Real Descoberto (captura teste1.pcap — 2026-02-28)

> Capturado via USBPcap apos factory reset + reboot com driver Synaptics instalado.
> Sensor em device address 6 no pcap. 328 bulk transfers capturados.

### Sequencia Completa de Provisioning

```
Fase 1: Pre-TLS (comandos em claro)
  ├── 0x01           → ROM info (38 bytes)
  ├── 0x8e 0x09      → Sensor info (26 bytes)
  ├── 0x8e 0x1a      → Sensor config/calibracao (78 bytes)
  ├── 0x8e 0x2e      → Calibration blob (3586 bytes)
  ├── 0x8e 0x2f      → Firmware version (18 bytes)
  ├── 0x19           → Query state (64+4 bytes)
  └── [Repete tudo acima uma segunda vez]

Fase 2: TLS Handshake
  ├── ClientHello    (host → sensor, com header 44 00 00 00)
  ├── ServerHello    (sensor → host)
  ├── Certificate + ChangeCipherSpec + Finished (host → sensor, com header 44 00 00 00)
  └── ChangeCipherSpec + Finished (sensor → host)

Fase 3: Provisioning via TLS (criptografado)
  └── Sequencia de Application Data records (17 03 03...)

Fase 4: Enrollment (leitura de digitais via TLS)
  └── Ciclos de captura de fingerprint (criptografado)
```

---

### Comando 0x8e — Sensor Information Read

Formato: `8e SS 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` (17 bytes)

Onde `SS` e o subcomando.

| Sub | OUT (hex) | IN size | Descricao |
|-----|-----------|---------|-----------|
| `0x09` | `8e 09 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` | 26 bytes | Sensor info |
| `0x1a` | `8e 1a 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` | 78 bytes | Config/calibracao |
| `0x2e` | `8e 2e 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` | 3586 bytes | Calibration blob (IEEE 754 doubles) |
| `0x2f` | `8e 2f 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` | 18 bytes | Firmware version |

#### RSP 0x8e 0x09 (26 bytes)

```
00 00 14 00 00 00 10 00 09 00 df 0d 00 00 00 00
00 00 0d 00 00 00 00 00 00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-3 | `14 00` | Total length (20) |
| 8 | `09` | Echo do subcomando |
| 10-11 | `df 0d` | Sensor info (0x0ddf = 3551?) |

#### RSP 0x8e 0x1a (78 bytes)

```
00 00 48 00 00 00 44 00 1a 00 ab c2 02 00 be c0
02 00 5b 1b 00 00 0a 00 00 00 44 00 4c 00 64 00
03 00 6b 01 20 03 00 00 00 00 10 27 58 02 a0 0f
6b 03 00 00 19 00 19 00 19 00 19 00 19 00 19 00
19 00 19 00 19 00 19 00 19 00 19 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-3 | `48 00` | Total length (72) |
| 6-7 | `44 00` | Data length (68) |
| 8 | `1a` | Echo do subcomando |
| 10-13 | `ab c2 02 00` | Parametro calibracao 1 (0x0002c2ab) |
| 14-17 | `be c0 02 00` | Parametro calibracao 2 (0x0002c0be) |
| 50+ | `19 00` repeated | Tabela de 13 valores identicos (25) |

#### RSP 0x8e 0x2e (3586 bytes)

Blob grande contendo dados de calibracao:
- Parametros IEEE 754 double precision
- Tabelas de lookup
- Coeficientes de calibracao
- Offsets de sensor

#### RSP 0x8e 0x2f (18 bytes)

```
00 00 0c 00 00 00 08 00 2f 00 01 00 00 01 08 00
00 00
```

| Offset | Value | Meaning |
|--------|-------|---------|
| 0-1 | `00 00` | Status OK |
| 2-3 | `0c 00` | Total length (12) |
| 8 | `2f` | Echo do subcomando |
| 10-11 | `01 00` | Major version? |
| 13 | `01` | Minor version? |
| 14 | `08` | Build/revision? |

---

### TLS Handshake (Real — capturado do driver Windows)

#### Header Proprietario

Todos os TLS records enviados pelo **host** sao prefixados com `44 00 00 00` (4 bytes).
Os records do **sensor** NAO tem esse header.

#### ClientHello

```
OUT: 44 00 00 00                          ← header proprietario
     16 03 03 00 49                       ← TLS Record (Handshake, TLS 1.2, 73 bytes)
     01 00 00 45 03 03                    ← ClientHello, version TLS 1.2
     09 0f 0d e6 50 52 ac ea 8d 7f f4 c5 ← Client Random (32 bytes)
     ab 34 bc 42 55 05 33 20 13 8b 39 a0
     ec 34 9a 7c f2 6c 3f f3
     07                                   ← Session ID length = 7
     00 00 00 00 00 00 00                ← Session ID (7 zeros)
     00 0a                               ← Cipher suites length = 10 (uint16 BE, 5 suites)
     c0 05                                ← TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
     c0 2e                                ← TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
     00 3d                                ← TLS_RSA_WITH_AES_256_CBC_SHA256
     00 8d                                ← PSK_WITH_AES_256_CBC_SHA384
     00 a8                                ← PSK_WITH_AES_256_GCM_SHA384
     00                                   ← Compression methods length = 0
     00 0a                               ← Extensions length = 10
     00 04 00 02 00 17                   ← Extension: supported_groups (secp256r1)
     00 0b 00 02 01 00                   ← Extension: ec_point_formats (uncompressed)
```

Total: 82 bytes (4 USB header + 5 TLS header + 73 handshake)

**Cipher suites oferecidas (em ordem de preferencia):**
1. `0xc005` — TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
2. `0xc02e` — TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
3. `0x003d` — TLS_RSA_WITH_AES_256_CBC_SHA256
4. `0x008d` — TLS_PSK_WITH_AES_256_CBC_SHA
5. `0x00a8` — TLS_PSK_WITH_AES_256_GCM_SHA384

#### ServerHello + CertificateRequest + ServerHelloDone

O sensor envia tudo em um unico TLS record (61 bytes):

```
IN:  16 03 03 00 3d                       ← TLS Record (Handshake, 61 bytes)

     02 00 00 2d                          ← ServerHello (45 bytes)
       03 83                              ← Version 0x0383 (custom, nao e TLS padrao)
       00 01 d1 2f e6 b1 3c b0 98 86     ← Server Random (32 bytes)
       79 5d e4 58 36 f6 1d 21 49 9a
       75 e0 35 2f dc e7 b7 05 08 60
       40 94
       07                                ← Session ID length (7, igual ao ClientHello)
       54 4c 53 e6 b1 3c b0             ← Session ID ("TLS" + 4 bytes)
       c0 2e                             ← Selected cipher: TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
       00                                ← Compression: null

     0d 00 00 04                          ← CertificateRequest (4 bytes)
       01                                ← cert_types_length = 1
       40                                ← ecdsa_sign (0x40)
       00 00                             ← distinguished_names_length = 0 (nenhuma CA)

     0e 00 00 00                          ← ServerHelloDone (0 bytes, padrao)
```

Total: 66 bytes (5 TLS header + 61 handshake)

**Observacoes importantes:**
- **Sensor NAO envia seu proprio certificado** — nao tem ServerCertificate
- **Sensor NAO envia ServerKeyExchange** — chave ECDH do sensor NAO e transmitida
- **Sensor PEDE certificado do host** (CertificateRequest tipo 0x40 = ecdsa_sign)
- **Version 0x0383** nao corresponde a nenhuma versao TLS padrao (pode ser flag customizada)
- **Cipher selecionada: `0xc02e`** — TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384

Diferencas do Validity90:
- V90 usa `0xc005` (AES_256_CBC_SHA) → 06cb:00da usa `0xc02e` (AES_256_GCM_SHA384)
- GCM em vez de CBC — sem MAC separado, usa AEAD
- SHA384 em vez de SHA256 para PRF
- **Sensor nao envia certificado nem ServerKeyExchange** (V90 tambem nao, mas V90 envia chave ECDH via RSP6)

#### Certificate + ClientKeyExchange + CertificateVerify + CCS + Finished (host → sensor)

```
OUT: 44 00 00 00                          ← header proprietario
     16 03 03 02 2c                       ← TLS Record (Handshake, 556 bytes)
     0b 00 01 98                          ← Certificate (408 bytes)
       00 01 90                           ← cert list length (400)
       00 01 90                           ← cert length (400)
       50 52 3f 5f 17 00 ...             ← Cert proprietario ("PR?_" header, NÃO X.509)
       [chave ECDSA em offsets 0x06/0x4a, little-endian]
     10 00 00 41                          ← ClientKeyExchange (65 bytes)
       04 d6 aa 5c 7a 85 f6 9a 6f ...   ← EC point uncompressed (chave ECDH)
     0f 00 47                             ← CertificateVerify (71 bytes)
       00 30 45 02 21 00 cb 9e ad ...    ← Assinatura ECDSA (DER, sem algorithm prefix)
     14 03 03 00 01 01                    ← ChangeCipherSpec
     16 03 03 00 28                       ← Finished (criptografado com AES-256-GCM, 40 bytes)
       5e ab 11 93 ...
```

Total: 616 bytes (4 header + 612 TLS)

**IMPORTANTE:** O host envia DUAS chaves EC diferentes:
- **Chave ECDSA** (dentro do certificado): usada para assinar o CertificateVerify
- **Chave ECDH** (no ClientKeyExchange): usada para derivar o shared secret

#### ChangeCipherSpec + Finished (sensor → host)

```
IN:  14 03 03 00 01 01                    ← ChangeCipherSpec
     16 03 03 00 28                       ← Finished (criptografado, 40 bytes)
     cc 59 93 8e 1d 68 ad 64 f9 3f 96 91
     13 97 4e 54 52 73 5b 0d 52 f5 81 d7
     a3 50 93 20 20 40 a7 ba 77 aa 4f 85
     b0 f4 84 9d
```

Total: 51 bytes

#### Application Data (pos-handshake)

Apos o handshake, toda comunicacao e criptografada com AES-256-GCM:

```
17 03 03 [u16be length] [encrypted payload]
```

Tamanhos tipicos observados:
- OUT: 33, 33, 25 bytes (comandos pequenos)
- IN: 58, 26, 26 bytes (respostas)
- Enrollment: tamanhos maiores com ciclos de captura de dedo

---

### Diferencas entre 06cb:00da e Validity90 (138a:0090)

| Aspecto | Validity90 (138a:0090) | 06cb:00da (FS7605) |
|---------|----------------------|---------------------|
| Pre-TLS init | MSG1-MSG6 (6 comandos) | 0x01 + 0x8e subs + 0x19 (7 comandos, 2x) |
| Key extraction | RSP6 TLV com certs | **Sem RSP6** — chaves geradas pelo host |
| Cert format | Proprietario, header 8 bytes | Proprietario "PR?_", header 6 bytes |
| Cert key offsets | X=0x08, Y=0x4c (LE) | **X=0x06, Y=0x4a (LE)** |
| Provisioning | 0x06/0x07/0x08/0x75/0x4f/0x50/0x1a | Via TLS (criptografado) |
| TLS cipher | `0xc005` AES-256-CBC-SHA | `0xc02e` AES-256-GCM-SHA384 |
| TLS MAC | HMAC-SHA256 + CBC | AEAD (GCM integrado) |
| TLS PRF | HMAC-SHA256 | HMAC-SHA384 (para GCM_SHA384) |
| Server cert | Nao envia | Nao envia |
| CertificateRequest | Pede ecdsa_sign | Pede ecdsa_sign (0x40) |
| ServerKeyExchange | Nao envia | Nao envia |
| Chaves EC | 1 key pair (ECDH = ECDSA) | **2 key pairs separadas** (ECDSA + ECDH) |
| ECDH server key | Via RSP6 record 0x0006 | **Desconhecida** (nao transmitida) |
| Sensor info | MSG3 (`0x43 02`) | `0x8e` com subcomandos |
| Calibration | Desconhecido | `0x8e 0x2e` (3586 bytes, IEEE 754) |

---

## What the Validity90 Provisioning Protocol Looks Like (does NOT work on 06cb:00da)

The python-validity / Validity90 C prototype uses these commands for provisioning:

| Command | Purpose | 06cb:00da result |
|---------|---------|------------------|
| `0x06 0x02 ...` (blob) | Encrypted init/config | **`01 04` — unknown** |
| `0x07 ...` | Read HW register | **`01 04` — unknown** |
| `0x08 ...` | Write HW register | **`01 04` — unknown** |
| `0x75` | Identify sensor | **`01 04` — unknown** |
| `0x4f ...` (blob) | Partition flash + install certs | **`01 04` — unknown** |
| `0x50` | Finalize provisioning | **`01 04` — unknown** |
| `0x1a` | Commit/cleanup | **`01 04` — unknown** |

**None of these commands exist on the 06cb:00da firmware.**
The provisioning protocol is completely different and must be discovered via USB capture.

---

## Analise do Certificado Proprietario

> Resultado de `scripts/verify_cert_sig.py` e `scripts/parse_cert.py`.

### Formato do Certificado (400 bytes)

O certificado enviado pelo host NAO e X.509. E um formato proprietario:

```
Offset  Tam   Conteudo
------  ----  --------
0x00    4     Magic: "PR?_" (50 52 3f 5f)
0x04    2     Flags: 17 00
0x06    32    ECDSA Public Key X (little-endian, secp256r1)
0x26    36    Padding (zeros)
0x4a    32    ECDSA Public Key Y (little-endian, secp256r1)
0x6a    294   Padding (quase tudo zeros)
```

**Total: 400 bytes (0x190), dos quais apenas ~102 bytes sao nao-zero.**

### Offsets das Chaves EC

| Campo | V90 (138a:0090) | 06cb:00da | Diferenca |
|-------|----------------|-----------|-----------|
| EC X offset | 0x08 | **0x06** | -2 bytes |
| EC Y offset | 0x4c | **0x4a** | -2 bytes |
| Byte order | little-endian | little-endian | igual |
| Header size | 8 bytes | 6 bytes | -2 bytes |

O header do 06cb:00da e 2 bytes menor que o do V90, deslocando todos os offsets.

### Chaves EC Descobertas (captura teste1.pcap)

O host envia **duas chaves EC separadas** durante o handshake:

#### 1. Chave ECDSA (dentro do certificado)

Usada para assinar o CertificateVerify. Offsets 0x06/0x4a no cert (LE).

```
X (BE): 8ed84571f55b90cc79fc08ab185fb45cc24a0d64a22025580e620710cbda4107
Y (BE): f039fa1eae8629c78b53ec9fdb669eaaaa7700783834cf8dd151bbf41ec23285
Ponto valido em secp256r1: SIM
```

#### 2. Chave ECDH (no ClientKeyExchange)

Usada para derivar o shared secret (pre-master secret) via ECDH.

```
X (BE): d6aa5c7a85f69a6f38e2f7815ca0b4a7a41554848e75405d1d9fb71303160034
Y (BE): afe245b96f0afb3610099fecd3cbcb17f5438bbb48177a63059d9331149ea0eb
Ponto valido em secp256r1: SIM
```

#### 3. Comparacao com V90

```
V90 DEVICE_PRIVATE_KEY X: 1dd83668e9b07b93123831239oc887cadb822739de7b43d223d7cdd13c770ed2
V90 DEVICE_PRIVATE_KEY Y: d1937002af3b1847c5304c3360cfbfc59b3c67d945063 8da92be65bf818caa7e
```

**Nenhuma das chaves capturadas corresponde ao DEVICE_PRIVATE_KEY do V90.**
As chaves sao provavelmente geradas pelo driver Windows (aleatorias ou derivadas do sistema).

### Verificacao da Assinatura CertificateVerify

**A assinatura CertificateVerify e VALIDA** contra a chave ECDSA do certificado:

```
Hash verificado:     SHA256(ClientHello_hs + ServerHello_hs + Certificate_hs + CKE_hs)
Metodo:              ECDSA com Prehashed SHA-256
Chave de verificacao: Chave ECDSA do certificado (offsets 0x06/0x4a)
Resultado:           *** VALIDA ***
```

Isso confirma que:
1. O CertificateVerify assina o hash SHA-256 de todos os handshake messages anteriores
2. A chave no certificado e a chave publica ECDSA correspondente
3. O driver Windows tem a chave privada ECDSA correspondente
4. A assinatura NAO usa a chave do ClientKeyExchange (sao chaves separadas)

### Implicacoes para Implementacao

1. **Podemos gerar nossas proprias chaves EC** — o sensor em estado 0x03 provavelmente aceita qualquer certificado valido
2. **Precisamos de DUAS key pairs**: ECDSA (cert + assinatura) + ECDH (key exchange)
3. **O pre-master secret vem do ECDH** entre nossa chave privada ECDH e a chave publica ECDH do sensor
4. **Problema: chave ECDH do sensor e desconhecida** — nao e transmitida no handshake
   - Possibilidade: sensor gera e envia apos provisioning (como RSP6 no V90)
   - Possibilidade: chave fixa no firmware
   - Possibilidade: derivada de outro parametro

---

## O Que Sabemos Agora (atualizado 2026-02-28)

Com base na captura `teste1.pcap` e analise criptografica dos scripts `parse_cert.py` e `verify_cert_sig.py`:

### Fatos Confirmados

1. **O provisioning acontece DENTRO do tunel TLS** — nao via comandos raw
2. **O TLS handshake funciona mesmo em state 0x03** — o sensor aceita TLS antes de estar provisionado
3. **O driver le informacoes do sensor 2x antes do TLS** — provavelmente para validacao
4. **Cipher suite real e `0xc02e`** (AES-256-GCM-SHA384) — nao `0xc005` (AES-256-CBC-SHA) como no V90
5. **O certificado e formato proprietario ("PR?_"), NAO X.509** — 400 bytes, maioria zeros
6. **Chave ECDSA no cert em offsets 0x06/0x4a (LE)** — 2 bytes antes dos offsets V90 (0x08/0x4c)
7. **Duas chaves EC separadas**: ECDSA (cert, para assinatura) + ECDH (CKE, para key exchange)
8. **CertificateVerify assina SHA256(todos HS messages) com a chave ECDSA do cert** — verificado!
9. **Sensor NAO envia certificado nem ServerKeyExchange** — chave ECDH do sensor e desconhecida
10. **Sensor pede certificado tipo ecdsa_sign (0x40)** via CertificateRequest
11. **Apos provisioning via TLS, o enrollment tambem usa TLS** — fingerprint images sao criptografadas

### Questoes em Aberto

1. **Onde esta a chave ECDH do sensor?** Nao transmitida no handshake. Possibilidades:
   - Fixa no firmware (hardcoded)
   - Derivada de algum parametro (factory key + serial?)
   - Retornada em algum comando pre-TLS que nao identificamos
   - Sensor aceita handshake sem ECDH real (pre-master = zeros ou derivado diferente)
2. **O sensor aceita qualquer certificado em state 0x03?** Provavel, mas nao confirmado
3. **Qual PRF e usada?** SHA-384 (padrao para GCM_SHA384) ou SHA-256 (customizado)?
4. **Como funciona o GCM neste protocolo?** Nonce implicito + explicito padrao, ou customizado?

### Proximos Passos

1. **Tentar handshake com chaves proprias** (script `try_handshake.py`)
   - Se sensor responder com Alert: analisar o tipo de erro
   - Se sensor responder com CCS+Finished: pre-master secret esta correto
2. **Investigar chave ECDH do sensor**: procurar em respostas pre-TLS ou derivar do firmware
3. **Se handshake funcionar**: enviar comandos de provisioning dentro do tunel TLS
4. **Testar com cipher 0xc005 (CBC)** como fallback se GCM nao funcionar

---

## Capturas Realizadas

| Arquivo | Bulk transfers | Conteudo |
|---------|---------------|----------|
| `teste1.pcap` | 328 | **Pre-TLS + TLS handshake + provisioning + enrollment** |
| `dozero.pcap` | 428 | Somente TLS Application Data (sensor ja provisionado) |
| `remocao_drivers.pcap` | 0 (HID only) | Interrupt transfers HID, sem bulk |
| `tentativa1.pcap` | 0 | Apenas enumeracao USB |
| `tentativa2.pcap` | 0 (HID only) | Interrupt transfers HID, sem bulk |
| `lastteste.pcap` | 0 | Apenas 6 control transfers |
| `lasteteste1.pcap` | 0 | Apenas 6 control transfers |

Analise detalhada dos payloads: [logs/wireshark_teste1_analysis.txt](logs/wireshark_teste1_analysis.txt)

Ver [USB_CAPTURE_GUIDE.md](USB_CAPTURE_GUIDE.md) para instrucoes de captura.

---

## Validity90 Protocol (Reference)

*Kept for comparison — this is what works on `138a:0090` / `138a:0097` but NOT on `06cb:00da`.*

### Initialization Sequence

| Step | OUT | IN | Size |
|------|-----|-----|------|
| MSG1 | `01` | RSP1 | 38 bytes, last=0x07 |
| MSG2 | `19` | RSP2 | 68 bytes |
| MSG3 | `43 02` | RSP3 | 84 bytes |
| MSG4 | `06 02 ...` (229 bytes) | RSP4 | 2 bytes `00 00` |
| MSG5 | `3e` | RSP5 | 76 bytes |
| MSG6 | `40 01 01 00 00 00 00 00 00 00 10 00 00` | RSP6 | ~3800 bytes |

### RSP6 TLV Format

```
[8-byte header]
[TLV records until type 0xFFFF]

Each record:
  type:  uint16 LE
  size:  uint16 LE
  hash:  32 bytes SHA-256
  data:  <size> bytes
```

| Type | Content |
|------|---------|
| 0x0003 | TLS Certificate (ECDSA pubkey) |
| 0x0004 | Encrypted ECDSA private key |
| 0x0006 | ECDH public key |
| 0xFFFF | End marker |

### Key Derivation

```
factory_key = [71 7c d7 2d ... 4b ec 20 33]  (32 bytes)
serial = product_name\0 + product_serial\0

master_key = TLS-PRF(factory_key, "GWK", serial, 32)
ecdsa_privkey = AES-256-CBC-decrypt(rsp6_record_0x0004, master_key)

pre_master = ECDH(device_privkey, sensor_ecdh_pubkey)
master_secret = TLS-PRF(pre_master, "master secret", client_random + server_random, 48)
key_block = TLS-PRF(master_secret, "key expansion", client_random + server_random, 288)
```

### TLS 1.2 Handshake

- Cipher: `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA` (0xc005)
- All records prefixed with `44 00 00 00`
- ECDH on P-256 (secp256r1)
- MAC-then-encrypt: HMAC-SHA256 + AES-256-CBC
- Static IV: `4b 77 62 ff a9 03 c1 1e 6f d8 35 93 17 2d 54 ef`
- Custom padding (pad bytes = `pad_len - 1`, repeated)

### Image Format

- 144x144 pixels, 8-bit grayscale
- 3 chunks via `0x51` command
- Chunk 1: offset 0x12, Chunks 2-3: offset 0x06
