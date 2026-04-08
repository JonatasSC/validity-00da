# Guia de Captura com Frida + USBPcap

## Pré-requisitos no Windows

1. **Frida** — `pip install frida-tools` (PowerShell como admin)
2. **USBPcap** — https://desowin.org/usbpcap/ (instalar, reboot)
3. **Driver Synaptics** instalado e funcionando

## Passo 1: Testar os hooks (antes do teste real)

Antes de desinstalar o driver, testar se o Frida consegue hookear:

```powershell
# PowerShell como ADMIN

# Achar o processo do driver
tasklist /m synaTEE108.signed.dll

# Se aparecer WUDFHost.exe com PID XXXX:
frida -p XXXX -l frida_hook_tls.js --no-pause

# Tocar no sensor pra gerar atividade
# Se aparecer logs no console → hooks funcionando!
```

### Problemas comuns nesse passo:
- **"Failed to attach"** → Frida precisa rodar como admin
- **"Module not found"** → DLL nao carregada, driver nao ativo
- **"Access denied"** → Antivirus bloqueando. Desativar temporariamente
- **Nenhum output** → Sensor dormindo. Tocar no sensor pra acordar

## Passo 2: Captura completa (provisioning)

Depois de confirmar que os hooks funcionam:

```powershell
# 1. Abrir USBPcap e começar captura no bus do sensor
#    Salvar em: C:\validity_capture.pcap

# 2. Desinstalar driver Synaptics:
#    Gerenciador de Dispositivos → Sensor biométrico → Desinstalar
#    Marcar "Excluir software do driver"
#    Reboot

# 3. Após reboot, ANTES de instalar o driver:
#    - Abrir USBPcap (capturando)
#    - NÃO instalar driver ainda

# 4. Preparar Frida pra attach automático:
#    Abrir PowerShell como admin e rodar:
frida-trace -n WUDFHost.exe -l frida_hook_tls.js --no-pause

#    Ou se preferir attach manual após instalação:
#    Instalar driver → esperar carregar → tasklist /m synaTEE108.signed.dll → frida -p PID ...

# 5. Instalar o driver Synaptics
#    O driver vai detectar o sensor → PAIR → TLS → provisioning
#    Tudo será logado em C:\validity_frida_log.txt

# 6. Parar captura USBPcap e Frida
```

## Passo 3: Coletar resultados

Copiar para o projeto Linux:
- `C:\validity_frida_log.txt` — plaintext de TODOS os comandos TLS
- `C:\validity_capture.pcap` — captura USB raw
- Copiar para `logs/` no projeto

## O que o Frida captura (6 hooks):

| Hook | Função | O que captura |
|------|--------|---------------|
| TLS_CMD | FUN_18010ce10 | **Todos os comandos TLS em plaintext** (cmd byte + dados + resposta) |
| CMD_ALLOC | FUN_18010d3f0 | Construção de cada comando (byte + tamanho) |
| PAIR | FUN_180112ae0 | Fluxo PAIR completo + pairing blob |
| TLS_HS | FUN_18010e790 | Início/fim do TLS handshake |
| INIT | FUN_1800fea40 | Início/fim da inicialização |
| SET_PARAM | FUN_1800e8d80 | Todas as chamadas vfmSetParamBlob (opcodes 0x65, 0x69, etc) |

## Formato do log

```
[HH:MM:SS.mmm] PAIR>> tudorSecurityDoPair called, sensor=0x...
[HH:MM:SS.mmm] PAIR>> sensor state=0x03
[HH:MM:SS.mmm] TLS_HS>> tudorTlsEstablishSession called
[HH:MM:SS.mmm] TLS_CMD>> cmd=0x82 inSize=9 data=820000000000000207
[HH:MM:SS.mmm] TLS_CMD<< cmd=0x82 ret=0 outSize=34 data=0000180000001800...
```

## Troubleshooting

### Frida não consegue attach no WUDFHost.exe
O WUDFHost pode reiniciar durante instalação do driver. Solução:
1. Monitorar com `tasklist /m synaTEE108.signed.dll` em loop
2. Attach assim que aparecer
3. Ou usar `frida -n WUDFHost.exe` que tenta automaticamente

### DLL não é encontrada
O processo pode ter múltiplas instâncias de WUDFHost.exe. Verificar qual
carrega a DLL correta com `tasklist /m synaTEE108.signed.dll`.

### Hooks instalados mas sem output
O driver pode não ter feito PAIR/TLS ainda. Verificar Device Manager
se o sensor foi reconhecido. Pode ser necessário aguardar ou reiniciar.

### Output truncado
Se o Frida desconectar, os logs já escritos em C:\validity_frida_log.txt
são preservados (flush a cada linha).
