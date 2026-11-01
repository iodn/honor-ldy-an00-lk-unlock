# LK unlock patch for HONOR LDY-AN00

Bootloader patching tools for the **HONOR Magic8 Pro Air (LDY-AN00)** on
the tested MagicOS **10.0.0.113(C00E100R101P1)** baseline. The workflow uses temporary root to install
and test a patched LK on **slot B**, then uses that verified fastboot session to
install the same patch on **slot A**.

**Status:** the patched LK booted on both slots of one physical device. Fastboot
reported `FB LockState: UNLOCKED`, and stock Android booted with green/locked reporting. These reported
values are modified by the patch and do not establish verified-boot security. The persistent OEM/TEE `USER LockState` remained `LOCKED`.

> **Advanced, firmware-specific procedure.** An incorrect write can permanently
> brick the phone. B-first testing preserves a stock A copy until the final stage;
> patching A removes that stock recovery candidate. Physical fallback after a
> failed LK authentication has not been demonstrated. Verified backups are required.

## What the patch provides

| Capability | Result |
| --- | --- |
| Fastboot policy gate | Open when the patched LK runs; individual handlers retain their own checks |
| Android boot-state reporting | `green`, `vbmeta.device_state=locked`, `flash.locked=1` (modified reporting) |
| Reboot persistence | The modification remains in each patched LK partition until overwritten |
| Persistent OEM/TEE unlock record | Unchanged: `USER LockState: LOCKED`; `getvar unlocked: no` |
| Secure boot | Still enabled; `getvar secure: yes` |
| Android root | Separate; this LK patch does not install Magisk, KernelSU or persistent root |
| Official firmware updates | Can replace LK and remove the patch |

Patch both slots only after B has been independently verified. This is not an
official unlock token, a generic MediaTek method, or protection against firmware
updates that overwrite the bootloader.

Official downloads and GhostLock status are listed in the
[firmware table](https://github.com/iodn/honor-ldy-an00-ghostlock#firmware-downloads-and-ghostlock-status).
Their LK images are not automatically compatible with this patch.

## Tested starting point

| Item | Required value for the initial B stage |
| --- | --- |
| Model / stock device | `LDY-AN00` / `HNLDY-M` |
| SoC | MediaTek MT6993 |
| Tested firmware | `10.0.0.113(C00E100R101P1)` |
| Android | 16 |
| Kernel | `6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k` |
| Running slot | Stock A, green, locked and marked successful |
| Inactive slot | Stock B, bootable and not marked successful |
| LK partition size | 16,777,216 bytes each |
| Temporary root | GhostLock broker at `/data/local/tmp/su`; SELinux permissive |

The executor additionally requires its exact boot-control baseline, valid CRC,
boot-LUN 1 and the matching boot-control HAL interface. A matching model name
alone is insufficient. Do not edit its expected state to bypass a rejection.

**All commands below run on a Linux computer from this repository's root folder.**
Use one connected phone only. The executor does not expose a serial selector;
for these instructions, disconnect other ADB and fastboot devices.

## Prebuilt release

Download `honor-ldy-an00-lk-unlock-v1.0.0-linux.zip` and `SHA256SUMS` from
[Releases](https://github.com/iodn/honor-ldy-an00-lk-unlock/releases/tag/v1.0.0).
Verify and extract them:

```bash
sha256sum -c SHA256SUMS
unzip honor-ldy-an00-lk-unlock-v1.0.0-linux.zip
cd honor-ldy-an00-lk-unlock-v1.0.0-linux
source scripts/use_prebuilt.sh
```

The release includes both ARM64 boot-control clients. They were built from this
repository using NDK 27.0.12077973 and Android build-tools 35.0.0. The selector
checks both exact hashes and pins the mutation client for this build; the
phone-tested reference build remains documented below. This is an offline
qualified rebuild, not a new hardware unlock trial.

Follow the steps below, but **skip step 3**: no NDK, AIDL compiler or client
compilation is required for the release bundle. The Python dependencies, matching
stock LK input and verified backups are still required. No proprietary firmware
image is included.

## 1. Prepare tools and verified inputs

Required host tools: Python 3 with virtual-environment support, Git, `adb`,
`fastboot` and `sha256sum`. Source builds additionally need an Android AIDL
compiler and NDK **27.0.12077973**; release bundles include the clients. The client
build defaults to the Linux x86_64 NDK toolchain and Android API 34. Install USB
permissions appropriate to the host.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography pyasn1 pyusb
python3 -m pip install 'git+https://github.com/R0rt1z2/liblk@75c8f14f16457b6c53d950d18d1ed7d2a665bed6'
git clone https://github.com/georgiynesterov/lk-unlock.git lk-unlock
git -C lk-unlock checkout 091fc7a18a6cc7063ec4445c4f5c08ab753195a0
export LK_UNLOCK="$PWD/lk-unlock/lk-unlock.py"
```

The firmware images and external dependencies are not bundled. The parser and certificate-bypass revisions above are pinned and were
used to reproduce the exact image. Do not substitute upstream HEAD. **The exact candidate hash below is mandatory**, even if a newer tool
reports success.

Supply the exact firmware's stock LK container as `lk-stock.img`. It is smaller
than a full partition dump. Verify its hash, size and original instruction:

```bash
python3 - <<'CHECK_STOCK'
from pathlib import Path
import hashlib
p = Path('lk-stock.img')
data = p.read_bytes()
expected = '4a2758f3da93142b08059f140c02fd8c4540ff98890081d3e4475f28c9f28f67'
if (len(data) != 7976720 or hashlib.sha256(data).hexdigest() != expected
        or data[0x156A4:0x156A8] != bytes.fromhex('b8ffff97')):
    raise SystemExit('STOP: unsupported stock LK image')
print('STOCK_INPUT_OK')
CHECK_STOCK
```

Prepare a separate, verified backup set before any partition write:

```text
backups/stock/
  lk_a.bin             full 16 MiB raw stock partition
  lk_b.bin             full 16 MiB raw stock partition
  misc.bin
  oeminfo.bin
  seccfg.bin
  preloader_raw_a.bin
  preloader_raw_b.bin
  gpt_primary.bin
  gpt_backup.bin
  MANIFEST.txt         source device/firmware, partition names and byte sizes
  SHA256SUMS           hashes of the backup files
```

Keep another independent copy outside the working folder. Backups can contain
sensitive device data: never commit or upload them. **This repository does not
include a backup-creation helper.** A correct, complete raw backup is a prerequisite,
not something created by `executor.py`.

```bash
export LK_BACKUP_DIR="$PWD/backups/stock"
(cd "$LK_BACKUP_DIR" && sha256sum --check SHA256SUMS)
```

Require every backup check to pass. The executor checks that the manifest/checksum
files exist, but does not validate the entire backup set; independently verify
all files. Its restore path separately hashes the B backup before using it.

## 2. Build and verify the patched image

```bash
python3 scripts/patch_lk.py \
  --in lk-stock.img \
  --out out/lk-fbunlock-override.img \
  --patch 0x156A4:20008052 \
  --patch 0x156D8:7f0e01b9 \
  --patch 0x15910:14000014 \
  --patch 0x1259D0:1f810db9 \
  --patch 0xF0D04:81008052 \
  --patch 0x138E7C:e20308aa \
  --patch 0x17D10:0d000014 \
  --patch 0x24D44:03008052 \
  --bypass override \
  --report out/lk-fbunlock-override.json

printf '%s  %s\n' \
  a2d1c3a7f0afcc87c19fff5daceed5e92b3f15b9a3306f088045f211c654dfc6 \
  out/lk-fbunlock-override.img | sha256sum --check
```

Run the offline recipe regression check before continuing:

```bash
python3 scripts/test_recipe.py --stock lk-stock.img
```

Require `LK_7D_EXACT_RECIPE_EXECUTOR_README_PASS`.

Require `OK`. Expected output size: **7,976,800 bytes**. Eight instruction patches open the fastboot gate, modify green/locked reporting,
and disable the stock bootfail watchdog that otherwise resets LineageOS after
about ten minutes.
The certificate override accounts for the container changes.

The patcher does not enforce the stock hash or old instruction itself; the
input check above and exact output hash are essential. `wrap` and `none` are not
usable alternatives for this procedure.

## 3. Build the boot-control clients

Set `ANDROID_NDK_HOME` to the installed NDK directory and `AIDL` to the AIDL
executable, or make `aidl` available in `PATH`. Then:

```bash
bash scripts/build_aidl_clients.sh
python3 scripts/model_rollback.py
```

Require both client builds to succeed and the model to print `MODEL_OK`.
Outputs go to `scripts/out/`. The executor's reference mutation-client hash is:

```text
2f3d1dea3df37fb64932eddde9f4ab56adc7f55737e594d1d2da46081ae80041
```

If a reviewed local rebuild differs, explicitly pin that local binary:

```bash
export LK_MUTATION_CLIENT_SHA="$(sha256sum scripts/out/inactive_b_client_ver | awk '{print $1}')"
```

Do this only after reviewing the source and toolchain. A hash of a local binary
establishes its identity, not its correctness. Do not replace the pin to accept
an unexplained mismatch or an untrusted downloaded binary.

## 4. Obtain temporary root and run preflight

Use the companion [GhostLock port](https://github.com/iodn/honor-ldy-an00-ghostlock)
on the supported stock A boot. Let its launcher
manage the clean-boot requirement, then keep its root session available. Do not
run another exploit chain on the same boot.

Back in a host terminal at this repository's root:

```bash
adb shell /data/local/tmp/su -c 'id'
adb shell getenforce
adb push scripts/out/read_only_client /data/local/tmp/iboot_readonly
adb shell chmod 755 /data/local/tmp/iboot_readonly
adb shell /data/local/tmp/iboot_readonly
python3 scripts/executor.py preflight
```

Require `uid=0(root)`, `Permissive`, `READONLY_OK` and `PREFLIGHT_OK`.
The client runs as ordinary ADB shell UID 2000; do not run it through `su`.
The broker's kernel SELinux domain cannot resolve the boot HAL service.

The initial baseline is deliberately narrow: both LK partitions stock, A
successful, B not successful, active/current A, no snapshot merge, and the exact
record in `scripts/model_rollback.py`. Stop if any check fails.

## 5. Write and activate B

Run each stage separately. **Do not proceed after a nonzero exit or failed check.**

```bash
python3 scripts/executor.py write-b --execute --authorized-trial --confirm-write-b
```

Require:

```text
WRITE_B_OK 7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae
```

This is the expected SHA-256 of the **full 16 MiB B partition**, not the shorter
container file. A must retain its stock full-partition hash:

```text
989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5
```

Then:

```bash
python3 scripts/executor.py activate --execute --authorized-trial --confirm-activate
```

Require `ACTIVATION_POSTCHECK_OK`, active=1/current=0 and boot-LUN 2.
The executor rereads raw boot-control metadata/CRC, AIDL getters and both LK
hashes; a client success message alone is insufficient. It never reboots.

If completion is unknown (`exit 4` / `STOP_UNKNOWN_STATE` or an equivalent
completion-unknown message), **do not retry, roll back blindly or reboot**.
The underlying operation may still be running. Preserve the output and inspect
the actual state before any further mutation.

## 6. Boot and verify B

Only after the activation post-check succeeds:

```bash
adb reboot bootloader
fastboot getvar current-slot
fastboot oem lock-state info
fastboot getvar unlocked
fastboot getvar secure
```

Expected results:

```text
current-slot: b
FB LockState: UNLOCKED
USER LockState: LOCKED
unlocked: no
secure: yes
```

`unlocked: no` is expected: it reports the unchanged persistent OEM state.
The relevant patched-LK result is `FB LockState: UNLOCKED`.

Boot stock Android on B before considering the A stage:

```bash
fastboot reboot
adb wait-for-device
adb shell getprop sys.boot_completed
adb shell getprop ro.boot.slot_suffix
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.flash.locked
```

Wait for Android to finish booting. Require `1`, `_b`, `green`, `locked` and
`1`, respectively. Temporary GhostLock root is lost on this reboot; that is
expected. If B does not boot normally, **do not patch A**.

## 7. Prepare a full-size image for A

The tested A write used a **16 MiB raw image**, not the shorter container file.
Generate the exact zero-padded image on the host:

```bash
python3 - <<'PREPARE_A'
from pathlib import Path
import hashlib
src = Path('out/lk-fbunlock-override.img').read_bytes()
if (len(src) != 7976800 or hashlib.sha256(src).hexdigest() !=
        'a2d1c3a7f0afcc87c19fff5daceed5e92b3f15b9a3306f088045f211c654dfc6'):
    raise SystemExit('STOP: candidate mismatch')
image = src.ljust(16777216, b'\0')
expected = '7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae'
if hashlib.sha256(image).hexdigest() != expected:
    raise SystemExit('STOP: full-size image mismatch')
Path('out/lk-unlocked-16MiB.img').write_bytes(image)
print('A_IMAGE_OK', len(image), expected)
PREPARE_A
```

Require `A_IMAGE_OK 16777216 7d8762ef…`. Do not use a differently padded image.

## 8. Flash A from the verified B bootloader

**This replaces the remaining stock LK copy.** Keep the original raw backups.
This stage uses bootloader fastboot, not userspace fastbootd; it does not require
running GhostLock again.

```bash
adb reboot bootloader
fastboot getvar current-slot
fastboot oem lock-state info
```

Require slot `b` and `FB LockState: UNLOCKED`. Before writing, read both partitions:

```bash
python3 scripts/fastboot_dump.py --partition lk_a --expected-len 16777216 \
  --expected-sha 989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5 \
  --out out/lk_a-before.wire
python3 scripts/fastboot_dump.py --partition lk_b --expected-len 16777216 \
  --expected-sha 7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae \
  --out out/lk_b-before.wire
```

Require `DUMP_OK` and exit 0 for both. The dump helper checks the extracted payload
length/hash but saves the **framed USB capture**. Its `.wire` files are evidence,
**not raw images to flash**. It selects the first matching USB device by default;
keep only the intended phone connected.

Now write **only `lk_a`**:

```bash
fastboot flash lk_a out/lk-unlocked-16MiB.img
```

Require both the sending and writing operations to report `OKAY`. Do not switch
slots or reboot until independent readback succeeds:

```bash
python3 scripts/fastboot_dump.py --partition lk_a --expected-len 16777216 \
  --expected-sha 7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae \
  --out out/lk_a-after.wire
python3 scripts/fastboot_dump.py --partition lk_b --expected-len 16777216 \
  --expected-sha 7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae \
  --out out/lk_b-after.wire
```

Require `DUMP_OK` for both. This proves A matches the candidate and B is unchanged.
A successful fastboot write alone is not a substitute for readback.

## 9. Boot and verify A

Only after both readbacks pass:

```bash
fastboot set_active a
fastboot reboot bootloader
fastboot getvar current-slot
fastboot oem lock-state info
fastboot getvar secure
```

Require `current-slot: a`, `FB LockState: UNLOCKED`, `USER LockState: LOCKED` and
`secure: yes`. Then boot Android:

```bash
fastboot reboot
adb wait-for-device
adb shell getprop sys.boot_completed
adb shell getprop ro.boot.slot_suffix
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
```

After startup, require `1`, `_a`, `green` and `1`. Both slots now contain the
patched LK. Booting each slot was demonstrated on the test device; it does not
prove that a failed boot will recover automatically on another phone.

Do not rerun the initial B executor on this completed installation: it requires
a stock, locked A baseline and will intentionally reject the patched state.

## Recovery and stop conditions

Stop on any device, image, partition, CRC, boot-LUN, client or readback mismatch.
Do not remove checks, retry a completion-unknown write, or reboot with an
unverified partition/state. The boot-control HAL updates metadata before the
boot-LUN; activation is not atomic.

Before A is patched, stock A is the recovery candidate. After A is patched,
verified B and the external stock backups are the remaining recovery resources;
no automatic recovery is guaranteed. If fastboot is still available from a
known-good patched LK, stock A can be restored using the verified **raw** backup:

```bash
fastboot flash lk_a "$LK_BACKUP_DIR/lk_a.bin"
python3 scripts/fastboot_dump.py --partition lk_a --expected-len 16777216 \
  --expected-sha 989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5 \
  --out out/lk_a-restored.wire
```

Do not reboot or activate A unless restore readback passes. This restore requires
a working fastboot session; it is not a remedy for failure before LK starts.
BROM/DA recovery may require vendor authentication. Do not relock the device or
assume an official update will retain the patch.

## Technical reference

<details>
<summary>Patch mechanism, validation scope and supporting tools</summary>

The normal chain is `preloader > BL2_EXT > LK > Android`. The patch replaces the
boot-time state check's call instruction at raw `0x156A4` with `mov w0, #1`.
The stock store then sets the RAM flag at `state+0x104`. This opens the central
fastboot gate. Seven additional instruction patches force green/locked
reporting, user OEM mode and bootfail watchdog control zero. Individual flash handlers
still enforce their own rules; this is not permission to flash every partition.

The main LK payload changes at eight instruction sites. An unsigned 90-byte CERT2 prefix
supplies its new hashes through BL2_EXT's certificate-extraction scope reset,
while preserving the stock signed TBS. The resulting container is 80 bytes
larger after packing/alignment. CERT1 and the other component payloads remain
stock. The persistent oeminfo `0x82` record, TEE lock and secure-boot root are
not rewritten. Green/locked properties are modified reports, not a guarantee
of AVB enforcement or Play Integrity. The patched gate already permits AVB
verification errors; this does not restore OEM security.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock container | 7,976,720 | `4a2758f3da93142b08059f140c02fd8c4540ff98890081d3e4475f28c9f28f67` |
| Patched container | 7,976,800 | `a2d1c3a7f0afcc87c19fff5daceed5e92b3f15b9a3306f088045f211c654dfc6` |
| Stock full LK partition | 16,777,216 | `989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5` |
| Patched full LK partition | 16,777,216 | `7d8762ef876b29542e66d0e717cd9af253602b3d86e93e7780ef5c2eb3686eae` |

Hardware evidence covers B installation/activation, B fastboot and Android,
A fastboot flashing with full-partition readback, and A fastboot and Android.
Physical fallback after BL2_EXT rejection, power-loss durability, future firmware
compatibility and complete TEE/KeyMint behavior remain unverified.

The boot-control service is `android.hardware.boot.IBootControl/default`,
version 1, interface hash `2400346954240a5de495a1debc81429dd012d7b7`.
Its setter is callable from shell only in the tested permissive boot. The
boot-LUN check reads vendor sysfs and is not an independent SG_IO measurement.
Reboot normally restores enforcing SELinux and removes GhostLock root.

| Tool | Purpose |
| --- | --- |
| [patch_lk.py](scripts/patch_lk.py) | Host-only raw patch and certificate override |
| [executor.py](scripts/executor.py) | B write, activation, rollback and independent checks; never reboots |
| [model_rollback.py](scripts/model_rollback.py) | Exact boot-control baseline, expected records and model self-test |
| [build_aidl_clients.sh](scripts/build_aidl_clients.sh) | Build getter and mutation clients |
| [read_only_client.cpp](scripts/read_only_client.cpp) | Calls getters only; generated full-interface declarations include setters |
| [inactive_b_client.cpp](scripts/inactive_b_client.cpp) | Guarded slot setter with nonce/outcome marker |
| [fastboot_dump.py](scripts/fastboot_dump.py) | Partition payload length/hash checks and framed USB evidence capture |
| [emulate_bl2_cert2_ours.py](scripts/emulate_bl2_cert2_ours.py) | Optional host-only check using an external BL2_EXT harness |

The optional emulator requires the separate `emulate-bl2-cert2.py` research
harness and its inputs, which are not included. If available, set
`BL2_HARNESS_DIR` to its directory and run:

```bash
python3 scripts/emulate_bl2_cert2_ours.py out/lk-fbunlock-override.img
```

Its reported `PASS` covers the modeled verifier, not a full hardware boot.
The preloader fallback is modeled, not physically proven. A successful boot on
one device does not establish a general reliability percentage.

</details>

## Support and contributions

Use the repository's Issues page after publication. Include firmware, command,
exit status and the relevant check output. Redact serial numbers and personal
data. Never upload oeminfo, seccfg, full backups, credentials or activation codes.
Changes to image generation, state expectations or write/activation handling
require review before another hardware trial.

## Credits and license

Temporary root comes from the companion LDY-AN00 GhostLock port and public
CVE-2026-43499 research. Image parsing and the override implementation depend on
[R0rt1z2/liblk](https://github.com/R0rt1z2/liblk) and
[georgiynesterov/lk-unlock](https://github.com/georgiynesterov/lk-unlock).
Related work includes [R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher)
and MediaTek boot-chain research.

The AIDL interface files retain their Apache-2.0 headers. The `lk-unlock` dependency remains under AGPL-3.0; if you redistribute a combined work, its terms apply.

The scripts and README in this repository are provided under the MIT License, copyright (c) 2026 the `lk-patch-ldy-an00` authors.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This is research software for authorized testing on devices you own. No warranty is given. A wrong write can permanently brick the phone.
