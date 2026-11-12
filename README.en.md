# Windows fingerprint sign-in: ZW111 + RP2040 + a custom Credential Provider

[![build](https://github.com/teuchezh/zw111-windows-fingerprint-unlock/actions/workflows/build.yml/badge.svg)](https://github.com/teuchezh/zw111-windows-fingerprint-unlock/actions/workflows/build.yml)

🇷🇺 [Русская версия](README.md)

This is the "proper" way, no keyboard emulation. A "Fingerprint" tile appears on the Windows
sign-in and lock screens. When the ZW111 sensor recognizes a finger, Windows performs a regular
interactive logon through LSA, exactly as if you had typed the password.

```
 ┌──────────┐  UART 57600  ┌────────────┐  USB CDC (COM)  ┌──────────────────────────────┐
 │  ZW111   │◄────────────►│   RP2040   │◄───────────────►│ Windows: LogonUI             │
 │ finger   │              │ K_dev,     │                 │   ZwCredProv.dll             │
 │ templates│              │ K_auth     │                 │   K_pc, K_auth, E(password)  │
 └──────────┘              └────────────┘                 └──────────────────────────────┘
```

## Layout

| Path | What it is |
|---|---|
| `firmware/` | PlatformIO project: firmware for RP2040 (`yd_rp2040`, `pico`) and ESP32-S3 (`esp32s3`). |
| `windows/credprov/` | Credential Provider: COM DLL `ZwCredProv.dll`, loaded by LogonUI. |
| `windows/setup/` | `zwsetup.exe`: console tool for provisioning, enrollment and testing. |
| `windows/gui/` | `zwsetup-gui.exe`: the same in one window, asks for administrator rights itself. |
| `windows/common/` | Shared code: COM port, registry + DPAPI, AES-GCM, protocol, string table (RU/EN). |
| `windows/build/` | Prebuilt x64 `ZwCredProv.dll`, `zwsetup.exe`, `zwsetup-gui.exe` (mingw-w64). |
| `tests/` | SHA-256/HMAC check against Python `hashlib`. |

## Security model

The password is never stored whole on the device, nor in clear text on the PC.

- **The device** holds two 32-byte keys: `K_dev` and `K_auth`.
- **The PC** holds, in `HKLM\SOFTWARE\ZwCredProv` (readable only by SYSTEM and administrators),
  a DPAPI blob with `K_pc`, `K_auth` and the password encrypted with AES-256-GCM under
  `K = SHA256("zwcp-key-v1" || K_dev || K_pc)`.
- The device releases `K_dev` only after:
  1. the PC proves knowledge of `K_auth` by answering `HMAC(K_auth, "zwcp-host-v1" || nonce)` to a fresh device nonce;
  2. the presented finger matches one of the enrolled templates.
  `K_dev` is sent masked: `K_dev XOR HMAC(K_auth, "zwcp-wrap-v1" || nonce)`.
- Writing keys, enrolling and deleting fingers, and wiping all require the **BOOTSEL/USR button to be held**.
  A program on the PC cannot silently re-key the device or add someone else's finger.
- What this buys you:
  - device stolen alone: it holds neither the password nor `K_pc`, there is nothing to decrypt;
  - PC disk stolen alone: without `K_dev` the password cannot be decrypted;
  - malware in the user session: it cannot read the registry key (ACL), so it cannot pass the `K_auth`
    check and extract `K_dev`; while LogonUI holds the COM port open, the port is unavailable to it anyway.
- What it does **not** buy you: whoever has the device **and** administrator/SYSTEM rights on this PC
  already owns the machine. Fingerprint templates stay inside the ZW111 and never leave it.

## Hardware

Verified against the ZW111 with a 6-pin 1.0 mm connector and the VCC-GND **YD-RP2040** board.

| ZW111 connector pin | Signal | YD-RP2040 |
|---|---|---|
| 1 | V_Touch (3.3 V, touch sensor supply) | 3V3 |
| 2 | TouchOut | GP2 (optional, unused by the firmware) |
| 3 | VCC (3.3 V) | 3V3 |
| 4 | TX | GP1 (UART0 RX) |
| 5 | RX | GP0 (UART0 TX) |
| 6 | GND | GND |

Everything is 3.3 V. The ZW111 has an RGB ring LED; the firmware drives it (blue breathing while
waiting for a finger, red flashes on error). On the YD-RP2040 both **BOOT** and **USR** (GP24) count
as physical presence for privileged commands; USR is more convenient. A plain Pico wires the same
way and uses BOOTSEL only. The ZW111 speaks the ZFM/R30x protocol, so the **Adafruit Fingerprint
Sensor Library** is used (default module password `0x00000000`, 57600 baud).

## Prebuilt binaries and CI

GitHub Actions builds the firmware (all environments), the Windows part (MSVC and mingw-w64) and
runs the crypto check on every push. Artifacts are attached to every run on the Actions tab.
Pushing a tag like `v1.0` creates a release with an archive containing `ZwCredProv.dll`,
`zwsetup.exe`, `zwsetup-gui.exe` and the firmware UF2 files.

## Step 1. Firmware (PlatformIO)

```bash
cd firmware
pio run -e yd_rp2040 -t upload
pio device monitor
```

`yd_rp2040` is the default environment; use `-e pico` for a plain Pico. For the first flash hold
BOOT while plugging in USB; if picotool cannot talk to the board (missing WinUSB driver), copy
`.pio/build/yd_rp2040/firmware.uf2` onto the `RPI-RP2` drive by hand. In the monitor (115200)
type `HELLO`, the answer must be `OK ZWCP 1 0 0`. Close the monitor afterwards, otherwise the port
stays busy. Sensor pins are set via `ZW_SENSOR_TX` / `ZW_SENSOR_RX` build flags in `platformio.ini`.

The `esp32s3` environment builds the same firmware for an ESP32-S3 (Serial over native USB, BOOT button
on GPIO0, sensor on GPIO17/GPIO18); it compiles in CI but has not been tested on hardware.

## Step 2. Building the Windows part

Prebuilt binaries are in `windows/build/`. To rebuild:

- **Visual Studio** (x64 Native Tools Command Prompt): `cd windows && build.bat`
- **mingw-w64** (Linux or MSYS2): `cd windows && make`

## Step 3. Setup

### Option A: the `zwsetup-gui.exe` window

Run `windows\build\zwsetup-gui.exe` (it requests administrator rights; `ZwCredProv.dll` must be next
to it). Then the buttons in order:

1. Fill in the user name, domain (`.` for a local account, `MicrosoftAccount` for a Microsoft account),
   the password twice. Click **"1. Set up device and password"**, hold USR on the board when asked, press OK.
2. **"2. Enroll finger into slot"** (slot 1), again with USR held, then follow the log.
3. **"3. Test"**: place your finger, the program decrypts the password and verifies it with LogonUser.
4. **"Register DLL"**: copies `ZwCredProv.dll` to System32 and registers the provider.
5. Win+L: the "Fingerprint" tile is on the lock screen.

"Refresh status" lists all COM ports with their USB ids and the device state. If the port is held
by the PlatformIO monitor, the status says so. The language selector switches the window, the console
tool and the sign-in tile (saved as `Lang` in the registry: `auto`, `ru` or `en`).

### Option B: console `zwsetup.exe` (PowerShell as administrator)

```bat
cd windows\build
copy ZwCredProv.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\ZwCredProv.dll
.\zwsetup.exe provision --user YourName
.\zwsetup.exe enroll --id 1
.\zwsetup.exe test
```

Options: `--domain MicrosoftAccount --user name@outlook.com` for a Microsoft account, `--domain CORP`
for a domain account, `--port COM7` instead of USB-id autodetection, `--usbid "VID_2E8A&PID_800A"`,
`--finger 1` to allow only slot 1, `--debug` for a log at `C:\ProgramData\ZwCredProv\zwcredprov.log`,
`--lang en`. Other commands: `status`, `set-password`, `delete --id N`, `disable` / `enable`,
`lang auto|ru|en`, `wipe`, `uninstall`.

## Microsoft accounts and PIN sign-in

If the sign-in screen offers a PIN and shows your full name, it is most likely a Microsoft account.
The tools detect a local account linked to a Microsoft account and fill in `MicrosoftAccount` and the
e-mail automatically. Then:

1. Use the **Microsoft account password**, not the PIN.
2. In Windows 11 open Settings → Accounts → Sign-in options and **turn off**
   "For improved security, only allow Windows Hello sign-in for Microsoft accounts on this device".
3. If passwordless sign-in is enabled for the Microsoft account (account.microsoft.com → Security),
   the account has no password at all and password logon is impossible. Disable passwordless mode
   or use a local account.

Error `0xC000006D` on the tile means Windows rejected the user name/password pair: check the points
above and then use "Change password" in the window (or `zwsetup set-password`).

## How it works

1. LogonUI loads `ZwCredProv.dll` for `CPUS_LOGON` and `CPUS_UNLOCK_WORKSTATION`. The provider reads
   the configuration and, through `ICredentialProviderSetUserArray`, checks that the configured user is
   actually on the screen (on the lock screen that is the locked user only).
2. A worker thread finds the COM port by USB id (`VID_2E8A`), sends `HELLO`, `NONCE`, `AUTH`.
3. The device turns on its LED and waits for a finger. On a match it sends `MATCH <id> <conf> <wrapped K_dev>`.
4. The provider unmasks `K_dev`, derives `K`, decrypts the password and calls `CredentialsChanged`.
   LogonUI re-queries `GetCredentialCount`, gets "auto-logon with tile 0" and calls `GetSerialization`.
5. `GetSerialization` builds a `KERB_INTERACTIVE_UNLOCK_LOGON` (password protected with `CredProtect`)
   for the `Negotiate` package. The password in memory is wiped right after packing.
6. If LSA rejects the logon (`ReportResult` with an error), the tile shows the error and starts a new handshake.

The device protocol is documented at the top of `firmware/src/main.cpp`.

## Troubleshooting

- No tile: `zwsetup status` shows whether the DLL is registered and the device is found; make sure the
  configured account is on the sign-in screen.
- Enable the debug log (checkbox in the window, or `Debug=1` in the registry) and read
  `C:\ProgramData\ZwCredProv\zwcredprov.log`.
- The DLL stays loaded in `LogonUI.exe`; to replace it, "Register DLL" schedules the copy for the next
  reboot when the file is busy.
- The standard password/PIN tile never goes away, so you cannot lock yourself out.

## ESP32-S3 instead of RP2040

Use the `esp32s3` environment. Platform differences live in the "platform glue" block at the top of
`firmware/src/main.cpp`: random source, physical-presence button and UART pins. Bonus on the S3:
flash encryption protects `K_dev` from being read over USB; the RP2040 has no such protection, which
is why the split-secret scheme matters there.
