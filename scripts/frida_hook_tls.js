/**
 * Frida hook para synaTEE108.signed.dll
 *
 * Captura comandos TLS em plaintext dentro do WUDFHost.exe.
 *
 * Offsets derivados do RE no Ghidra (image base 0x180000000):
 *   FUN_18010ce10 = offset 0x10ce10 — TLS command sender (todos os cmds via tunnel)
 *   FUN_180112ae0 = offset 0x112ae0 — tudorSecurityDoPair (PAIR flow)
 *   FUN_18010e790 = offset 0x10e790 — tudorTlsEstablishSession
 *   FUN_18010d3f0 = offset 0x10d3f0 — command buffer allocator (cmd byte + size)
 *   FUN_1800fea40 = offset 0x0fea40 — _tudorInitDevice
 *
 * Uso:
 *   1. Abrir PowerShell como admin
 *   2. Achar o PID do WUDFHost.exe que carrega o driver:
 *      tasklist /m synaTEE108.signed.dll
 *   3. Rodar:
 *      frida -p <PID> -l frida_hook_tls.js --no-pause
 *
 *   OU (attach por nome, pega o primeiro WUDFHost):
 *      frida -n WUDFHost.exe -l frida_hook_tls.js --no-pause
 *
 *   Se o driver ainda nao carregou (instalacao fresh):
 *      frida -f WUDFHost.exe -l frida_hook_tls.js  (spawn mode)
 *      Ou use o script Python wrapper (frida_capture.py)
 *
 * Output: C:\validity_frida_log.txt + console
 */

"use strict";

var LOG_FILE = "C:\\validity_frida_log.txt";
var TEE_DLL = "synaTEE108.signed.dll";
var logHandle = null;

// ============================================================
// Logging
// ============================================================

function log(msg) {
    var ts = new Date().toISOString().slice(11, 23);
    var line = "[" + ts + "] " + msg;
    console.log(line);
    try {
        if (logHandle === null) {
            logHandle = new File(LOG_FILE, "a");
        }
        logHandle.write(line + "\n");
        logHandle.flush();
    } catch (e) {
        // File write failed, console only
    }
}

function hexdump_short(ptr, len) {
    if (ptr.isNull() || len <= 0) return "(null)";
    var max = Math.min(len, 128);
    var bytes = ptr.readByteArray(max);
    var hex = Array.from(new Uint8Array(bytes))
        .map(function(b) { return ("0" + b.toString(16)).slice(-2); })
        .join("");
    if (len > max) hex += "...(" + len + "B total)";
    return hex;
}

// ============================================================
// Wait for DLL to load, then install hooks
// ============================================================

function waitForModule(name, callback) {
    var mod = Process.findModuleByName(name);
    if (mod !== null) {
        log("DLL encontrada: " + name + " base=" + mod.base);
        callback(mod);
        return;
    }
    log("Aguardando " + name + " carregar...");
    var interval = setInterval(function() {
        mod = Process.findModuleByName(name);
        if (mod !== null) {
            clearInterval(interval);
            log("DLL carregada: " + name + " base=" + mod.base);
            callback(mod);
        }
    }, 500);
}

// ============================================================
// Main hooks
// ============================================================

function installHooks(mod) {
    var base = mod.base;
    log("Instalando hooks em " + TEE_DLL + " base=" + base);

    // ----------------------------------------------------------
    // HOOK 1: FUN_18010ce10 — TLS command sender
    //   int FUN_18010ce10(sensor*, uint8_t cmd, input_struct*, output_struct*)
    //   input_struct:  [uint32 size, uint8* data_ptr]  (at offsets 0, 8)
    //   output_struct: [uint32 size, uint8* data_ptr]  (at offsets 0, 8)
    //
    // Captura TODOS os comandos enviados pelo TLS tunnel em plaintext.
    // ----------------------------------------------------------
    var addr_tlsCmd = base.add(0x10ce10);
    log("Hook TLS cmd sender: " + addr_tlsCmd);

    try {
        Interceptor.attach(addr_tlsCmd, {
            onEnter: function(args) {
                this.sensor = args[0];
                this.cmd = args[1].toInt32() & 0xFF;
                this.inputStruct = args[2];
                this.outputStruct = args[3];

                // Read input buffer
                var inSize = 0;
                var inData = ptr(0);
                try {
                    inSize = this.inputStruct.readU32();
                    inData = this.inputStruct.add(8).readPointer();
                } catch(e) {}

                var inHex = hexdump_short(inData, inSize);
                log("TLS_CMD>> cmd=0x" + this.cmd.toString(16) +
                    " inSize=" + inSize + " data=" + inHex);
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                var outSize = 0;
                var outData = ptr(0);
                try {
                    outSize = this.outputStruct.readU32();
                    outData = this.outputStruct.add(8).readPointer();
                } catch(e) {}

                var outHex = hexdump_short(outData, outSize);
                log("TLS_CMD<< cmd=0x" + this.cmd.toString(16) +
                    " ret=" + ret + " outSize=" + outSize +
                    " data=" + outHex);
            }
        });
        log("  [OK] TLS cmd sender hooked");
    } catch(e) {
        log("  [FAIL] TLS cmd sender: " + e);
    }

    // ----------------------------------------------------------
    // HOOK 2: FUN_18010d3f0 — command buffer allocator
    //   uint8* FUN_18010d3f0(uint8_t cmd, uint32_t size)
    //
    // Mostra cada comando sendo construido (cmd byte + tamanho).
    // Util pra confirmar que os hooks estao funcionando.
    // ----------------------------------------------------------
    var addr_cmdAlloc = base.add(0x10d3f0);
    log("Hook cmd alloc: " + addr_cmdAlloc);

    try {
        Interceptor.attach(addr_cmdAlloc, {
            onEnter: function(args) {
                this.cmd = args[0].toInt32() & 0xFF;
                this.size = args[1].toInt32();
            },
            onLeave: function(retval) {
                log("CMD_ALLOC cmd=0x" + this.cmd.toString(16) +
                    " size=" + this.size +
                    " buf=" + retval);
            }
        });
        log("  [OK] cmd alloc hooked");
    } catch(e) {
        log("  [FAIL] cmd alloc: " + e);
    }

    // ----------------------------------------------------------
    // HOOK 3: FUN_180112ae0 — tudorSecurityDoPair
    //   int FUN_180112ae0(sensor*, actionInfo*, param3, param4)
    //
    // Captura o fluxo PAIR completo.
    // ----------------------------------------------------------
    var addr_doPair = base.add(0x112ae0);
    log("Hook DoPair: " + addr_doPair);

    try {
        Interceptor.attach(addr_doPair, {
            onEnter: function(args) {
                this.sensor = args[0];
                log("PAIR>> tudorSecurityDoPair called, sensor=" + this.sensor);

                // Sensor state at offset 0x1e (1 byte)
                try {
                    var state = this.sensor.add(0x1e).readU8();
                    log("PAIR>> sensor state=0x" + state.toString(16));
                } catch(e) {}
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                log("PAIR<< ret=" + ret + " (0x" + (ret >>> 0).toString(16) + ")");

                // After PAIR, check if pairing data was stored
                try {
                    var pairDataSize = this.sensor.add(0xE8).readU32();
                    var pairDataPtr = this.sensor.add(0xF0).readPointer();
                    log("PAIR<< pairingData size=" + pairDataSize +
                        " ptr=" + pairDataPtr);
                    if (pairDataSize > 0 && !pairDataPtr.isNull()) {
                        log("PAIR<< blob=" + hexdump_short(pairDataPtr, pairDataSize));
                    }
                } catch(e) {
                    log("PAIR<< (could not read pairing data: " + e + ")");
                }
            }
        });
        log("  [OK] DoPair hooked");
    } catch(e) {
        log("  [FAIL] DoPair: " + e);
    }

    // ----------------------------------------------------------
    // HOOK 4: FUN_18010e790 — tudorTlsEstablishSession
    //   int FUN_18010e790(sensor*, ...)
    //
    // Marca inicio/fim do TLS handshake.
    // ----------------------------------------------------------
    var addr_tlsEstablish = base.add(0x10e790);
    log("Hook TLS establish: " + addr_tlsEstablish);

    try {
        Interceptor.attach(addr_tlsEstablish, {
            onEnter: function(args) {
                this.sensor = args[0];
                log("TLS_HS>> tudorTlsEstablishSession called");
                try {
                    var state = this.sensor.add(0x1e).readU8();
                    log("TLS_HS>> sensor state=0x" + state.toString(16));
                } catch(e) {}
            },
            onLeave: function(retval) {
                log("TLS_HS<< ret=" + retval.toInt32());
            }
        });
        log("  [OK] TLS establish hooked");
    } catch(e) {
        log("  [FAIL] TLS establish: " + e);
    }

    // ----------------------------------------------------------
    // HOOK 5: FUN_1800fea40 — _tudorInitDevice
    //   void FUN_1800fea40(sensor*, output*, ...)
    //
    // Marca inicio/fim da inicializacao do device.
    // ----------------------------------------------------------
    var addr_initDev = base.add(0x0fea40);
    log("Hook initDevice: " + addr_initDev);

    try {
        Interceptor.attach(addr_initDev, {
            onEnter: function(args) {
                log("INIT>> _tudorInitDevice called");
            },
            onLeave: function(retval) {
                log("INIT<< _tudorInitDevice done");
            }
        });
        log("  [OK] initDevice hooked");
    } catch(e) {
        log("  [FAIL] initDevice: " + e);
    }

    // ----------------------------------------------------------
    // HOOK 6: FUN_1800e8d80 — vfmSetParamBlob
    //   int FUN_1800e8d80(handle, uint opcode, paramBlob*, ...)
    //
    // Captura todas as chamadas de SetParamBlob (0x65, 0x69, etc).
    // ----------------------------------------------------------
    var addr_setParam = base.add(0x0e8d80);
    log("Hook vfmSetParamBlob: " + addr_setParam);

    try {
        Interceptor.attach(addr_setParam, {
            onEnter: function(args) {
                this.handle = args[0];
                this.opcode = args[1].toInt32();
                this.blob = args[2];

                var blobSize = 0;
                var blobData = ptr(0);
                try {
                    blobSize = this.blob.readU32();
                    blobData = this.blob.add(8).readPointer();
                } catch(e) {}

                log("SET_PARAM>> opcode=0x" + this.opcode.toString(16) +
                    " blobSize=" + blobSize);
                if (blobSize > 0 && !blobData.isNull()) {
                    log("SET_PARAM>> data=" + hexdump_short(blobData, blobSize));
                }
            },
            onLeave: function(retval) {
                log("SET_PARAM<< opcode=0x" + this.opcode.toString(16) +
                    " ret=" + retval.toInt32());
            }
        });
        log("  [OK] vfmSetParamBlob hooked");
    } catch(e) {
        log("  [FAIL] vfmSetParamBlob: " + e);
    }

    log("========================================");
    log("Todos os hooks instalados. Aguardando atividade do driver...");
    log("Log: " + LOG_FILE);
    log("========================================");
}

// ============================================================
// Entry point
// ============================================================

log("========================================");
log("Frida hook para Validity 00da (06cb:00da)");
log("Target DLL: " + TEE_DLL);
log("PID: " + Process.id);
log("========================================");

waitForModule(TEE_DLL, installHooks);
