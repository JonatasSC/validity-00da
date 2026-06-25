# Fingerprint auth on Debian 13 (trixie) — Synaptics `06cb:00da`

A reproducible recipe to get the Synaptics FS7605 (`06cb:00da`, ThinkPad
E14/E15) working with `fprintd` and PAM on **Debian**, using the
[synaTudor](https://github.com/Popax21/synaTudor) Wine-layer driver plus the
[francescomcrtl/synaptics-00da-linux](https://github.com/francescomcrtl/synaptics-00da-linux)
patches.

The francescomcrtl installer targets **Arch only**. This document is the
**Debian delta** — everything Arch does for free that Debian needs done by hand.

> Verified on Debian 13 (trixie), kernel 6.12, KDE Plasma 6 / Wayland.
> Result: `fprintd-enroll`/`-verify`, `sudo`, and **SDDM login** all work by
> fingerprint, with password fallback intact.

The recipe has two stages. Stage A gets `tudor_cli` working (no fprintd/PAM
yet). Stage B adds the TOD libfprint so `fprintd` and PAM work.

---

## Prerequisites

```bash
lsusb | grep 06cb:00da    # you MUST actually have this sensor
```

Keep a **root shell open in a separate terminal** during the PAM steps
(`sudo -s`). A broken `/etc/pam.d/sudo` can lock you out of `sudo`.

---

## Stage A — build synaTudor (tudor_cli working)

### 1. Dependencies

```bash
sudo apt-get install -y \
    meson ninja-build \
    libfprint-2-dev libglib2.0-dev libgudev-1.0-dev libgusb-dev \
    libusb-1.0-0-dev libnss3-dev libpixman-1-dev \
    libseccomp-dev libdbus-1-dev \
    git pkg-config innoextract wget
```

> `libseccomp-dev` and `libdbus-1-dev` are **not** in the fork's dependency list
> — add them manually or the build fails with `dependency ... not found`.
>
> If an apt mirror 404s on a `+bN` binary rebuild (happened with
> `libcap-dev` in 2026), refresh the lists:
> `sudo rm -f /var/lib/apt/lists/deb.debian.org_debian_dists_trixie_* && sudo apt-get -o Acquire::http::No-Cache=true update`

### 2. Clone the fork

```bash
cd ~/src    # anywhere you like
git clone https://github.com/francescomcrtl/synaptics-00da-linux.git
cd synaptics-00da-linux
```

### 3. Three Debian-specific patches (before building)

The fork's `install.sh` clones synaTudor into `/opt/synaTudor` and builds it.
These three fixes are **not** in upstream `install.sh`:

**(a) Disable the `libfprint-tod` subdir for now** — Debian has no
`libfprint-2-tod-1.pc` yet (we install it in Stage B):

```bash
sudo sed -i "s|^subdir('libfprint-tod')|# subdir('libfprint-tod')  # Debian: no .pc yet|" \
    /opt/synaTudor/meson.build
```

**(b) Revert the v104→v108 DLL mapping** — Lenovo currently ships **v104**
DLLs, but the patch expects v108:

```bash
sudo sed -i 's|src_dll="${dll/104/108}"|src_dll="$dll"|' \
    /opt/synaTudor/libtudor/download_driver.sh
```

**(c) Give your user ownership of `/var/lib/tudor`** — otherwise `tudor_cli`
hangs silently right after `Dropping root privileges`:

```bash
sudo chown -R "$USER:$USER" /var/lib/tudor
```

> `/opt/synaTudor` only exists after the first `install.sh` run reaches the
> clone step. If patching before the first run, run `install.sh` once to let it
> clone, Ctrl-C after the clone, apply the patches, then re-run.

### 4. Run the installer

```bash
sudo ./install.sh
```

Expected: `[1/5]` deps → `[2/5]` clone synaTudor (`/opt/synaTudor`, commit
`31dfdb0`) → `[3/5]` patch → `[4/5]` build (~2–5 min, downloads `r19fp02w.exe`
~2.6 MB from Lenovo) → `[5/5]` enables `tudor-host-launcher.service`.

| Failure | Cause |
|---------|-------|
| `synaFpAdapter108.dll not found` | patch (b) not applied |
| `dependency dbus-1 not found` | `libdbus-1-dev` missing |
| `libseccomp not found` | `libseccomp-dev` missing |
| hangs after "Dropping root privileges" | patch (c) not applied |

The warning about a missing `[Install]` section is benign — the service is
D-Bus-activated.

### 5. Smoke test (tudor_cli)

```bash
sudo /usr/sbin/tudor/tudor_cli /var/lib/tudor/data.db -P0x00da
```

In the prompt: `y` → `e` (enroll) → identity index → finger index (1–10) → touch
several times → `v` (verify) → same identity → touch → `s` (shutdown).

If enroll/verify work, the sensor + DLLs + sandbox are good. Now wire up fprintd.

---

## Stage B — TOD libfprint (fprintd + PAM)

Debian doesn't package the **TOD** (Touch-OEM-Driver) variant of libfprint that
synaTudor's `libtudor_tod.so` plugs into. Only Arch/Ubuntu ship it, so we build
it and install it over the system one (ABI-compatible, same SONAME).

### 1. Build + install libfprint-TOD

```bash
git clone https://gitlab.freedesktop.org/3v1n0/libfprint.git -b tod
cd libfprint
meson setup --prefix=/usr --libdir=lib/x86_64-linux-gnu \
    -Dtod=true -Ddrivers=virtual_image,synaptics build
sudo systemctl stop fprintd
sudo ninja -C build install
sudo ldconfig
```

Verify the `.pc` appeared:

```bash
pkg-config --modversion libfprint-2-tod-1    # expect 1.95.1+tod1
```

> SONAME `libfprint-2.so.2` is unchanged and the ABI is additive (adds
> `fp_sdcp_device_get_type`), so the GNOME/KDE settings panels keep working.
> **Back up the original first:** `sudo cp /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0 /root/libfprint-2.so.2.0.0.bak`

### 2. Pin the packages

```bash
sudo apt-mark hold libfprint-2-2 libfprint-2-dev libpam-fprintd
```

Without this, `apt upgrade` reverts the TOD build.

### 3. Re-enable `libfprint-tod` in synaTudor and rebuild

```bash
sudo sed -i "s|^# subdir('libfprint-tod').*|subdir('libfprint-tod')|" \
    /opt/synaTudor/meson.build
cd ~/src/synaptics-00da-linux
sudo ./install.sh        # NOT --wipe — preserves already-downloaded v104 DLLs
```

> If synaTudor was configured with a stale build dir, reconfigure rather than
> wipe: `meson setup build --reconfigure`.

Verify the TOD plugin landed:

```bash
ls /usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libtudor_tod.so
```

### 4. Restart fprintd and enroll

```bash
sudo systemctl daemon-reload
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl start fprintd

fprintd-list "$USER"      # before enrolling: no prints
fprintd-enroll            # enroll
fprintd-verify            # test  -> verify-match
```

`fprintd-list "$USER"` should report the device as **"Synaptics Tudor (press)"**.

---

## PAM integration

> ⚠️ **Do NOT copy the fork's `pam/sudo` or `pam/sddm` files.** They are written
> for Arch (`system-auth` + `pam_faillock`), which **does not exist on Debian**.
> Copying them verbatim **breaks `sudo`**. On Debian, just insert one line.

### sudo

```bash
sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
sudo sed -i '/^@include common-auth/i auth       sufficient pam_fprintd.so' /etc/pam.d/sudo
```

Result — `pam_fprintd.so` runs first (`sufficient`); on success you're in, on
failure/timeout it falls through to the password (`common-auth`):

```
auth       sufficient pam_fprintd.so
@include common-auth
```

Test in your open root shell:

```bash
sudo -k && sudo true && echo SUDO_OK   # should prompt for the finger
```

Revert if anything is wrong: `sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo`

### SDDM (login screen) — KDE Plasma 6 / Wayland

Same one-line insert, into `/etc/pam.d/sddm`:

```bash
sudo cp /etc/pam.d/sddm /etc/pam.d/sddm.bak
sudo sed -i '/^@include common-auth/i auth sufficient pam_fprintd.so' /etc/pam.d/sddm
```

How it behaves on SDDM 0.21:

- SDDM triggers `pam_fprintd` **when you press Enter / click Log In** (it is
  **not** a passive background scan). It then shows *"Place your finger…"* and
  waits ~30 s.
- Touch the sensor while that message is up → you're logged in.
- If the read fails (dirty finger, bad placement) it shows
  *"Verification timed out"* after 30 s and falls back to the password. Pressing
  Enter again during the wait aborts the fingerprint attempt.

This is expected SDDM behavior — fingerprint support lives in the PAM
conversation, not in a dedicated UI, and third-party themes still relay the
prompt fine.

---

## Reverting everything

```bash
# PAM
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
sudo cp /etc/pam.d/sddm.bak /etc/pam.d/sddm

# libfprint back to Debian stock
sudo apt-mark unhold libfprint-2-2 libfprint-2-dev libpam-fprintd
sudo apt install --reinstall libfprint-2-2 libfprint-2-dev fprintd libpam-fprintd
sudo ldconfig
```

---

## Security notes

The Synaptics DLLs are closed source, but:

- they are the same binaries that would run on native Windows on this laptop;
- they run inside `tudor-host`, sandboxed with a network namespace
  (`CLONE_NEWNET` — no network), a tight seccomp whitelist, zeroed capabilities,
  and a read-only root via `pivot_root`;
- the `tudor-host-launcher` D-Bus interface is root-only;
- synaTudor upstream is pinned to commit `31dfdb0` (reproducible), and the
  fork's patches (`user32.c`, ~213 lines; main patch, ~266 lines) are mechanical
  and have been reviewed.

Conclusion: acceptable for personal use. This is still a proprietary blob behind
a sandbox — decide for yourself.

---

## Persistent artifacts (reference)

| Path | Contents |
|------|----------|
| `/usr/sbin/tudor/{tudor_cli,tudor_host,tudor_host_launcher,libtudor.so}` | synaTudor binaries (DLLs embedded) |
| `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libtudor_tod.so` | TOD driver plugin |
| `/usr/lib/systemd/system/tudor-host-launcher.service` | D-Bus-activated launcher |
| `/var/lib/tudor/data.db` | pairing + enrolled fingers |
| `/opt/synaTudor` | patched synaTudor source (commit `31dfdb0`) |
