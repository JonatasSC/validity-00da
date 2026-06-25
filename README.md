# validity-00da

Linux fingerprint support and protocol reverse-engineering for the Synaptics
**FS7605** sensor (`06cb:00da`, codename *Tudor*) found in **ThinkPad E14 / E15**
laptops.

This repository covers two parallel tracks:

1. **Working fingerprint auth on Debian** — a reproducible recipe to get
   `fprintd` + PAM (sudo, SDDM login) working *today*, using the Windows
   driver inside a sandboxed Wine layer ([synaTudor]) plus the
   [francescomcrtl/synaptics-00da-linux] patches, adapted for Debian.
   See **[INSTALL-DEBIAN.md](INSTALL-DEBIAN.md)**.
2. **Native Python reverse-engineering** — a from-scratch reimplementation of
   the proprietary USB + custom-TLS protocol in pure Python, for people who
   want a fully open driver with no closed-source DLL. The TLS handshake is
   solved; device provisioning is still blocked.

> **If you just want your fingerprint reader to work on Debian, go straight to
> [INSTALL-DEBIAN.md](INSTALL-DEBIAN.md).** The native track is research.

---

## Why this repo exists

The `06cb:00da` sensor is **not** supported by stock `libfprint`. The only
working open driver is [synaTudor] (a Wine-based shim around the Windows DLLs),
and the only packaged installer for it — [francescomcrtl/synaptics-00da-linux] —
targets **Arch Linux only**. Getting it working on **Debian 13 (trixie)**
requires several non-obvious changes (TOD libfprint build, PAM differences,
DLL version mapping, extra build deps).

This repo documents that Debian path end-to-end, and keeps a parallel pure-Python
RE effort as a long-term route to a DLL-free driver.

---

## Status

### Track 1 — Wine-layer (working)

| Component | Status |
|-----------|--------|
| synaTudor built + installed (`/usr/sbin/tudor/`) | ✅ |
| `tudor_cli` enroll / verify | ✅ |
| libfprint **TOD** built + installed on Debian | ✅ |
| `fprintd-enroll` / `fprintd-verify` | ✅ |
| PAM — `sudo` via fingerprint (password fallback intact) | ✅ |
| PAM — **SDDM** login via fingerprint (KDE Plasma 6 / Wayland) | ✅ |

Verified on Debian 13 (trixie), kernel 6.12, KDE Plasma 6 / Wayland.

### Track 2 — Native Python RE

| Phase | Description | Status |
|-------|-------------|--------|
| 0–3 | Setup, state probing, pre-TLS protocol (`0x8e` subcommands) | Done |
| 3.5 | EC certificate / key analysis | Done |
| 4 | Custom TLS 1.2 handshake (cipher `0xc02e`, AES-256-GCM) | **Done** |
| 5 | Provisioning over the TLS tunnel | **Blocked** (see below) |
| 6 | Enrollment | Not started (native) |

**Native blocker:** the sensor ships in state `0x03`; the TLS tunnel works but
`DB2`/frame commands return `ACCESS_DENIED` (`06 04`). The provisioning command
that unlocks the sensor was not found in the driver DLLs — control appears to
live in the sensor firmware. Without a fresh USB capture of a Windows first-time
setup, the native provisioning step can't be identified. Track 1 sidesteps this
entirely (the DLL does provisioning itself).

---

## Quick start (Debian working path)

```bash
# Full, copy-pasteable recipe with troubleshooting:
#   -> INSTALL-DEBIAN.md
lsusb | grep 06cb:00da    # confirm you actually have this sensor
```

Once installed:

```bash
fprintd-enroll            # enroll right index finger
fprintd-verify            # test
sudo -k && sudo true      # sudo should now prompt for the finger
```

---

## Native track usage (research)

```bash
pip install -r requirements.txt

# udev rule so you don't need sudo (optional):
#   SUBSYSTEM=="usb", ATTR{idVendor}=="06cb", ATTR{idProduct}=="00da", MODE="0666", GROUP="plugdev"

python3 scripts/check_state.py      # read sensor state (0x03 = factory)
python3 scripts/tls_handshake.py    # full PAIR + custom-TLS handshake
```

The custom TLS handshake has several **critical deviations** from standard TLS
(documented inline and in the protocol notes):

- `key_expansion` seed is `client_random + server_random` (not swapped)
- transcript hash is always **SHA-256**, even though the cipher is SHA-384 (PRF uses SHA-384)
- the wire certificate is `"PR"` + `echo[0:398]` (400 bytes)
- ECDH uses an ephemeral CKE; the sensor's cert pubkey is the peer
- `CertificateVerify` is prehashed SHA-256 with no algorithm indicator
- the CKE is a raw `04 || X || Y` point (65 bytes, no length prefix)

> ⚠️ Do **not** run commands `0x06`, `0x0e`, `0x10` in automated scans — they
> cause a USB disconnect. Always wrap sensor I/O in `USBError` handling.

---

## Repository layout

```
validity00da/        Python module — USB device wrapper (pyusb), Linux + Windows
scripts/             Native-track scripts:
                       tls_handshake.py   full PAIR + custom-TLS handshake (the core)
                       tls_provision.py   TLS tunnel + post-TLS commands
                       check_state.py     read sensor state
                       factory_reset.py   reset sensor to state 0x03
                       frida_hook_tls.js  Windows-side capture hook (+ guide)
INSTALL-DEBIAN.md    The Debian install recipe (Track 1)
requirements.txt     Python deps for the native track
```

> **Local-only (gitignored), not in the public tree:** `docs/` (RE notes — a
> personal Obsidian vault, including raw decompiler output of a proprietary DLL),
> `bin/` and `Ghidra/` (Windows driver binaries + Ghidra project), `Wireshark/`
> (USB captures). These are kept out of the repo on purpose. The protocol summary
> above and [INSTALL-DEBIAN.md](INSTALL-DEBIAN.md) are self-contained without them.
> The full exploratory RE script history is preserved in the git log.

---

## How it works (Track 1, high level)

```
fprintd
  └─ libfprint-TOD (1.95.1+tod1)
       └─ libtudor_tod.so            (TOD plugin)
            └─ tudor-host (D-Bus)    (sandboxed: netns, seccomp, read-only fs)
                 └─ Wine
                      └─ Synaptics Windows DLLs (v104, Lenovo)
                           └─ sensor (USB)
```

The closed-source DLLs run inside `tudor-host`, which is sandboxed with a network
namespace (no network), a tight seccomp whitelist, dropped capabilities, and a
read-only root via `pivot_root`. Acceptable for personal use; see the security
notes in [INSTALL-DEBIAN.md](INSTALL-DEBIAN.md#security-notes).

---

## Contributing and forking

This repo is meant to be forked and reused. The most valuable contributions:

- **Debian / Ubuntu install fixes** — if the recipe drifts with newer package
  versions, PRs to [INSTALL-DEBIAN.md](INSTALL-DEBIAN.md) are welcome.
- **A fresh USB capture** of a Windows first-time setup (Frida script in
  `scripts/frida_hook_tls.js`) — this is the single thing that would unblock the
  native provisioning step.
- **Upstreaming Debian support** to [francescomcrtl/synaptics-00da-linux] — the
  Debian-specific deltas documented here (PAM, TOD build, DLL mapping) are the
  basis for that.

If you fork: the native scripts hit real hardware. Keep the danger-command skip
list (`0x06`, `0x0e`, `0x10`) and always handle `USBError`.

---

## Credits

- [synaTudor] (Popax21) — the Wine-layer driver this builds on
- [francescomcrtl/synaptics-00da-linux] — the Arch installer / patches
- [Validity90] (nmikhailov) — C prototype for the `138a:0090` family
- [python-validity] (uunicorn) — Python driver for `06cb:009a`

## License

GPL-2.0 — inherited from [synaTudor]. See [LICENSE](LICENSE).

[synaTudor]: https://github.com/Popax21/synaTudor
[francescomcrtl/synaptics-00da-linux]: https://github.com/francescomcrtl/synaptics-00da-linux
[Validity90]: https://github.com/nmikhailov/Validity90
[python-validity]: https://github.com/uunicorn/python-validity
