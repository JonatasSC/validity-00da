# CLAUDE.md — Validity 00da

---

## 1. Contexto do Projeto

**Sistema:** Driver Linux para sensor fingerprint Synaptics FS7605 (`06cb:00da`), presente em ThinkPad E14/E15.

**Objetivo:** Reverse engineering completo do protocolo proprietario Synaptics para criar um driver funcional que permita autenticacao biometrica no Linux (integracao com libfprint/fprintd).

**Tipo:** Ferramenta de sistema (driver USB + protocolo TLS customizado). Nao e uma aplicacao web/API — e comunicacao direta com hardware via USB bulk transfers.

**Dominio:**
- Familia de sensores: **Tudor** (codename interno da Synaptics)
- Protocolo: comandos USB proprietarios + TLS 1.2 customizado (cipher `0xc02e`)
- Criptografia: ECDSA P-256, ECDH, AES-256-GCM, TLS-PRF SHA-384
- Referencia principal: [synaTudor](https://github.com/Popax21/synaTudor) (Popax21, branch `rev`)
- Sensor em estado `0x03` — DB2/frame bloqueados (06 04), TLS funcional
- RE de dois DLLs: `synaWudfBioUsb108.dll` (orquestrador, v6.0.32.1108) + `synaTEE108.signed.dll` (crypto/TLS, v6.0.32.1108)
- Driver Windows: Synaptics FP WBF SPI DDK (Extended) 4.8.206.0
- Estado 0x03 NAO bloqueia TLS (modo ECC) — bloqueia DB2 e frame commands
- 3 comandos pos-TLS descobertos: 0x82 (34B dims), 0x80 (2B setup), 0x81 (2B commit)
- RE ~90% completo, provisioning nao encontrado nos DLLs (controle e do firmware)
- Script Frida pronto pra captura Windows (`scripts/frida_hook_tls.js`)

---

## 2. Regras Gerais

### NUNCA
- Rodar comandos `0x06`, `0x0e`, `0x10` em scans automaticos (causam USB disconnect)
- Enviar prefixo `44 00 00 00` em Application Data (so handshake usa)
- Assumir que o protocolo segue TLS padrao (ha desvios criticos documentados)
- Criar arquivos de documentacao fora do vault Obsidian (`docs/` = symlink)
- Commitar sem ser pedido
- Rodar scripts sem verificar sintaxe antes

### DEVE PRIORIZAR
- Testar hipoteses uma de cada vez, sem desviar o foco
- Salvar logs de TODOS os testes em `logs/*.txt`
- Documentar descobertas no Obsidian (vault `docs/`) imediatamente
- Manter `NEXT_STEPS.md` e `MOC - Validity 00da.md` atualizados
- Tratar `USBError` em todos os scripts (sensor pode desconectar a qualquer momento)
- Verificar sintaxe (`python3 -c "import ast; ast.parse(...)"`) antes de pedir para rodar

### DOCUMENTACAO CONTINUA (OBRIGATORIO)
Toda alteracao relevante DEVE ser acompanhada de atualizacao nos docs:

1. **CLAUDE.md** — atualizar quando mudar stack, restricoes, convencoes, estado do projeto, OU quando surgir uma nova direcao/estrategia/hipotese importante
2. **MOC - Validity 00da.md** — atualizar diario de progresso e status das fases
3. **NEXT_STEPS.md** — atualizar quando uma etapa for concluida ou um bloqueador mudar
4. **PROVISIONING.md** — atualizar quando descobrir novos comandos ou respostas
5. **PROTOCOL.md** — atualizar quando descobrir novos detalhes do protocolo
6. **RE_DRIVER.md** — atualizar quando decompilar novas funcoes ou descobrir novos fluxos
7. **MEMORY.md** — atualizar quando descobrir algo que precisa persistir entre sessoes
8. **Novo doc** — criar quando um tema ficar grande demais para caber em um doc existente

**Regra critica:** ao final de cada sessao ou apos cada descoberta significativa, atualizar os docs relevantes ANTES de encerrar. Nao acumular descobertas sem documentar.

**Evolucao continua:** o CLAUDE.md NAO e estatico. Ele deve crescer e evoluir a cada sessao. Sempre que:
- Uma hipotese for confirmada ou descartada → registrar em Restricoes Tecnicas ou como comentario
- Um novo caminho for identificado → adicionar como direcao no contexto
- Um bloqueador mudar → atualizar o estado do projeto no topo
- Uma decisao arquitetural for tomada → documentar o motivo
- Um comando/formato for descoberto → adicionar como restricao ou exemplo

O objetivo e que qualquer sessao futura tenha contexto suficiente no CLAUDE.md + Obsidian + MEMORY.md pra continuar o trabalho sem perder progresso.

**Separacao:** cada doc tem um escopo claro. Nao misturar:
- `PROTOCOL.md` = spec tecnica do protocolo (bytes, formatos, offsets)
- `PROVISIONING.md` = fase 5 especificamente (tunnel TLS, comandos, resultados)
- `NEXT_STEPS.md` = plano de acoes e estado atual dos bloqueadores
- `MOC` = index geral + diario de progresso (entradas curtas, com data)
- `CLAUDE.md` = regras para o Claude (nao e doc tecnico do projeto)

### DEVE EVITAR
- Copiar conteudo entre docs — usar wikilinks `[[NomeDoDoc]]` no Obsidian
- Scripts monoliticos — separar setup (PAIR+TLS) de testes
- Testar muitas variaveis ao mesmo tempo — isolar cada hipotese
- Longos blocos de texto explicativo — ser direto

---

## 3. Estilo de Resposta

- **Idioma:** Portugues brasileiro
- **Formalidade:** Informal, direto, tecnico
- **Tamanho:** Curto. Liderar com a acao ou resultado, nao com explicacao
- **Ordem:** Resultado primeiro, explicacao se necessario depois
- **Codigo:** Comentarios so onde a logica nao e obvia
- **Tabelas:** Usar para comparar resultados de testes
- **Quando travar:** Apresentar opcoes numeradas e deixar o usuario decidir

---

## 4. Stack Tecnica

| Camada | Tecnologia |
|--------|-----------|
| Linguagem | Python 3.13 |
| USB | pyusb 1.3.1 (libusb1 backend) |
| Criptografia | cryptography (hazmat), hashlib, hmac |
| Curva EC | secp256r1 (P-256) |
| TLS | Implementacao manual (nao usa OpenSSL/TLS lib) |
| Cipher suite | `0xc02e` — TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 |
| Analise | Wireshark/USBPcap (capturas .pcap) |
| RE | Ghidra/IDA (driver Windows synaWudfBioUsb108.dll) |
| Docs | Obsidian (vault `Obsidian Vault - Pessoal/validity-00da/`) |
| OS | Debian Linux (kernel 6.12) |

---

## 5. Convencoes do Projeto

### Codigo

- **Variaveis:** snake_case — `client_write_key`, `sensor_cert_data`
- **Funcoes:** snake_case — `do_pair()`, `do_handshake()`, `pre_tls_phase()`
- **Classes:** PascalCase — `TlsSession`, `USBDevice`, `Logger`
- **Constantes:** UPPER_SNAKE — `SS_PUBKEY_PROD`, `LOG_FILE`
- **Hex values:** lowercase com prefixo `0x` — `0x8e`, `0xc02e`
- **Bytes:** `bytes.fromhex("3f5f1700")` ou `b"\x3f\x5f"`

### Estrutura

```
validity00da/     — Modulos reutilizaveis do driver (importados por scripts)
scripts/          — Scripts executaveis (cada um faz uma coisa)
docs/             — Symlink → Obsidian vault (documentacao viva)
logs/             — Output de testes (descartavel, nao versionado)
Wireshark/        — Capturas USB (.pcap)
bin/              — Binarios do driver Windows (para RE)
```

### Separacao de responsabilidades

- `validity00da/` — nunca executa diretamente, so exporta funcoes/classes
- `scripts/` — cada script e autocontido (importa de `validity00da/` e `scripts/`)
- `docs/` — documentacao vive no Obsidian, editada la ou via symlink

---

## 6. Restricoes Tecnicas

- **Nao usar OpenSSL/TLS libs** para o handshake — o protocolo tem desvios que libs padrao nao suportam
- **Nao usar `raw=False`** (framing synaTudor) para comandos via TLS — sensor espera comandos raw
- **Nao inverter seed do key_expansion** — synaTudor usa `client_random + server_random` (nao o padrao TLS)
- **Nao usar SHA-384 para transcript hash** — sempre SHA-256, mesmo com cipher SHA-384
- **Nao enviar cert com "PR" no PAIR** — PAIR usa formato synaTudor (sem "PR", 400B comecando com `3f 5f`)
- **Nao enviar cert sem "PR" no TLS** — TLS usa formato wire ("PR" + echo[0:398] = 400B)
- **Nao skipar USB reset entre PAIR e TLS** — sensor precisa reinicializar apos PAIR
- **Nao reutilizar session keys** — cada TLS handshake gera keys novas
- **Comando 0x40 precisa payload de 32B** — sem payload retorna 05 04, com zeros retorna 06 04
- **DB2 retorna 06 04 no estado 0x03** — acesso negado, nao e problema de params
- **Driver Windows usa dois DLLs** — `synaWudfBioUsb108.dll` (orquestrador) e `synaTEE108.signed.dll` (crypto/TLS real)
- **Dois modos TLS** — ECC (estado 0x03, primeiro pairing) e PSK (provisionado, usa pre-shared key de 64B)
- **Formato 0x82** — precisa de 9 bytes (cmd + 8B payload), retorna 10B. Com 2B nao funciona
- **Primeiro cmd pos-TLS** — 9B plaintext → 34B resposta. Nao encontrado em probe de 256 cmds + variantes
- **Bloqueador atual** — sem decriptar captura ou nova captura USB, nao da pra identificar o cmd de provisioning

---

## 7. Instrucoes para Agente Futuro (Handoff)

Se voce e um novo agente trabalhando neste projeto, leia isto PRIMEIRO:

### Estado atual (2026-04-08)
- TLS handshake **funciona** (PAIR → reset → TLS com cipher 0xc02e)
- 3 comandos pos-TLS **descobertos**: 0x82 (34B dims), 0x80 (2B setup), 0x81 (2B commit)
- Sensor em **estado 0x03** — DB2 retorna ACCESS_DENIED (06 04)
- **Bloqueador**: nao sabemos como provisionar o sensor (mudar estado pra liberar DB2)
- RE dos DLLs Windows **~90% completo** — ver `docs/RE_DRIVER.md`

### Proxima acao planejada
**Captura USB no Windows** com Frida + USBPcap durante primeiro setup do driver.
- Script: `scripts/frida_hook_tls.js` (6 hooks nas funcoes criticas do TEE DLL)
- Guia: `scripts/FRIDA_CAPTURE_GUIDE.md`
- Objetivo: ver os comandos TLS em plaintext que o driver envia durante provisioning

### Se o usuario pedir pra debugar o Frida script
1. O script hookea `synaTEE108.signed.dll` dentro de `WUDFHost.exe`
2. Offsets sao relativos ao image base do DLL (0x180000000 no Ghidra)
3. Hook principal: `FUN_18010ce10` (offset 0x10ce10) — captura TODOS os comandos TLS
4. Se o offset nao bater: o DLL pode ter sido atualizado. Verificar versao (deve ser 6.0.32.1108)
5. Se Frida nao conseguir attach: precisa rodar como admin, antivirus pode bloquear
6. Se nenhum output: sensor pode estar dormindo (tocar nele), ou driver nao carregou DLL

### Se o usuario pedir pra analisar a captura
1. `C:\validity_frida_log.txt` — plaintext de todos os comandos TLS
2. Procurar comandos que NAO sao 0x82/0x80/0x81/0x01/0x19/0x86
3. Qualquer comando novo pode ser o de provisioning
4. Atencao especial a comandos que retornam dados grandes ou mudam o estado

### Se o usuario quiser continuar o RE sem captura
- 21 callers de FUN_18010ce10 nao foram checados (ver RE_DRIVER.md)
- vtable+0x90 e vtable+0xe0 no ProcessPairing estado 3 nao resolvidos
- Buscar funcoes que escrevem no sensor state (0x1e no struct do sensor)

### Onde esta cada coisa
| Info | Arquivo |
|------|---------|
| Regras e restricoes | `CLAUDE.md` (este arquivo) |
| Mapa de comandos | `docs/PROTOCOL.md` |
| RE do driver | `docs/RE_DRIVER.md` (30+ funcoes com RVAs) |
| TLS tunnel format | `docs/PROVISIONING.md` |
| Plano de acoes | `docs/NEXT_STEPS.md` |
| Memoria persistente | `MEMORY.md` (auto memory) |
| Script principal | `scripts/tls_handshake.py` (PAIR + TLS) |
| Script de provisioning | `scripts/tls_provision.py` (TLS + comandos) |
| Frida hook | `scripts/frida_hook_tls.js` |
| Guia captura | `scripts/FRIDA_CAPTURE_GUIDE.md` |

## 8. Filosofia do Projeto

- **Explorar > Planejar** — testar no sensor real antes de teorizar
- **Uma variavel por vez** — isolar hipoteses, nao testar 5 coisas de uma vez
- **Log tudo** — todo teste gera log em `logs/`, toda descoberta vai pro Obsidian
- **Referencia > Invencao** — consultar synaTudor/python-validity antes de inventar protocolo
- **Simplicidade > Elegancia** — scripts descartaveis sao OK, o importante e o resultado
- **Persistir conhecimento** — se descobriu algo, documenta antes de seguir

---

## 9. Exemplos

### Enviar comando via TLS (certo vs errado)

```python
# ERRADO — com prefixo USB e framing
msg = b"\x44\x00\x00\x00" + record  # prefixo so para handshake!
session.command(cmd, raw=False)       # framing synaTudor nao funciona

# CERTO — raw, sem prefixo
session.command(bytes([0x01]), raw=True)  # comando direto
# TLS record enviado sem 44 00 00 00
```

### Construir cert para PAIR vs TLS

```python
# PAIR — formato synaTudor (sem "PR", 400B)
pair_cert = bytearray(400)
struct.pack_into("<HH", pair_cert, 0, 0x5f3f, 23)  # magic + curve
pair_cert[4:36] = x_be[::-1]     # X em LE
pair_cert[72:104] = y_be[::-1]   # Y em LE
# Assinar com hs_key: ECDSA-SHA256 DER completo
der_sig = hs_privkey.sign(signbytes, ec.ECDSA(hashes.SHA256()))

# TLS — formato wire (com "PR", 400B)
tls_cert = b"PR" + host_echo[0:398]  # prepend "PR" ao echo do PAIR
```

### Key derivation (certo vs errado)

```python
# ERRADO — seed padrao TLS
key_block = prf(master, "key expansion", server_random + client_random, 128)

# CERTO — seed synaTudor (nao invertido!)
key_block = prf(master, "key expansion", client_random + server_random, 128)

# ERRADO — transcript SHA-384 para cipher 0xc02e
finished_hash = hs_sha384.digest()

# CERTO — transcript SEMPRE SHA-256, PRF usa SHA-384
finished_hash = hs_sha256.digest()
verify_data = prf_sha384(master, "client finished", finished_hash, 12)
```

### Script de teste (padrao)

```python
#!/usr/bin/env python3
"""Descricao curta do teste. Log: logs/nome_do_teste.txt"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tls_provision import Logger, do_pair, do_handshake
from scripts.tls_handshake import pre_tls_phase
from validity00da.usb_device import USBDevice

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "logs", "nome_do_teste.txt")
log = Logger(LOG_FILE)

dev = USBDevice()
if not dev.open():
    log.error("Sensor nao encontrado!")
    sys.exit(1)

try:
    # Setup: Pre-TLS → PAIR → Reset → Pre-TLS → TLS
    pre_tls_phase(dev, log, round_num=1); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=2)
    pairing_data = do_pair(dev, log)
    dev.reset(); time.sleep(1)
    pre_tls_phase(dev, log, round_num=3); time.sleep(0.1)
    pre_tls_phase(dev, log, round_num=4)
    session = do_handshake(dev, log, pairing_data)

    # Testes aqui
    rsp = session.command(bytes([0x01]), raw=True)

except Exception as e:
    log.error(f"Excecao: {e}")
    import traceback
    log.error(traceback.format_exc())
finally:
    dev.close()
    log.close()
```

### Tratar comandos perigosos em scans

```python
# ERRADO — scan sem protecao
for cmd in range(0x100):
    session.command(bytes([cmd]), raw=True)  # 0x06/0x10 vai crashar!

# CERTO — skip list + try/except
SKIP = {0x06, 0x0e, 0x10, 0x44, 0x93}
for cmd in range(0x100):
    if cmd in SKIP:
        continue
    try:
        rsp = session.command(bytes([cmd]), raw=True, timeout=2000)
    except Exception:
        break  # USB disconnect, parar scan
```

### Documentar no Obsidian (wikilinks)

```markdown
<!-- CERTO — wikilinks para docs na mesma pasta -->
Ver [[PROTOCOL]] para o mapa de comandos.
Historico em [[PLAN_CERT_PROOF]].
Proximos passos em [[NEXT_STEPS]].

<!-- ERRADO — paths absolutos ou copiar conteudo -->
Ver /home/jhow/.../PROTOCOL.md
[copiar 200 linhas do PROTOCOL aqui]
```
