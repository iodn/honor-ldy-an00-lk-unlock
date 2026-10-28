#!/usr/bin/env python3
"""Inactive-B executor preflight/post-check validation harness.

Default mode is read-only preflight. Mutation modes (write-b, activate,
rollback) are gated by --execute --authorized-trial and a matching confirmation;
the tested workflow ran them in separate authorized stages. The executor never
reboots.

Independent post-checks are authoritative: ACTIVATE_OK from the client is not
accepted as proof. The executor rereads raw misc+0x800, the boot-LUN sysfs
attribute, the AIDL getters, and the A/B hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import model_rollback as model

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('LK_REPO_ROOT', HERE.parent))
CANDIDATE = Path(os.environ.get(
    'LK_CANDIDATE', ROOT / 'out' / 'lk-fbunlock-override.img'))
STOCK = Path(os.environ.get('LK_STOCK', ROOT / 'lk-stock.img'))
BACKUP_DIR = Path(os.environ.get(
    'LK_BACKUP_DIR', ROOT / 'backups' / 'ldy-an00-20261021-122315'))
MUTATION_CLIENT = Path(os.environ.get(
    'LK_MUTATION_CLIENT', HERE / 'out' / 'inactive_b_client_ver'))

AIDL_DEVICE = os.environ.get('LK_AIDL_DEVICE', '/data/local/tmp/iboot_readonly')
MUTATION_DEVICE = os.environ.get('LK_MUTATION_DEVICE',
                                 '/data/local/tmp/inactive_b_client')
BOOT_LUN_PATH = '/sys/devices/platform/soc/16810000.ufshci/attributes/boot_lun_enabled'
AIDL_SERVICE = 'android.hardware.boot.IBootControl/default'

EXPECTED_CANDIDATE_SHA = 'e771f241dc7f445a2ea4a39989cb1fb81b0ba91f61039497729ec24ca553afe1'
EXPECTED_CANDIDATE_SIZE = 7976800
EXPECTED_STOCK_SHA = '989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5'
EXPECTED_B_AFTER_WRITE = 'a6a1ab4b6c55053887a0a18a52723bb48514a42bc45a507087ded09917385d81'
EXPECTED_INTERFACE_VERSION = 1
EXPECTED_INTERFACE_HASH = '2400346954240a5de495a1debc81429dd012d7b7'
LUN_A = 1
LUN_B = 2

ADB_TIMEOUT = 30
PUSH_TIMEOUT = 60
WRITE_TIMEOUT = 120
CLIENT_TIMEOUT = 90
MARKER_WAIT = 45
MUTATION_CLIENT_SHA = os.environ.get(
    'LK_MUTATION_CLIENT_SHA',
    '2f3d1dea3df37fb64932eddde9f4ab56adc7f55737e594d1d2da46081ae80041')
SETTER_MARKER = '/data/local/tmp/.iboot_setter_done'
WRITE_MARKER = '/data/local/tmp/.iboot_write_done'


@dataclass
class AidlState:
    ok: bool = False
    version: int = -1
    iface_hash: str = ''
    active: int = -1
    current: int = -1
    slots: int = -1
    merge: int = -1
    suffix_a: str = ''
    suffix_b: str = ''
    bootable_a: bool = False
    successful_a: bool = False
    bootable_b: bool = False
    successful_b: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class LiveState:
    record: bytes | None = None
    boot_lun: int | None = None
    enforce: int | None = None
    device: str = ''
    model: str = ''
    verified_boot: str = ''
    flash_locked: str = ''
    slot_suffix: str = ''
    aidl: AidlState = field(default_factory=AidlState)
    lk_a_sha: str = ''
    lk_b_sha: str = ''
    candidate_sha: str = ''
    candidate_size: int = -1
    errors: list[str] = field(default_factory=list)


def adb_shell(cmd: str) -> str:
    try:
        return subprocess.check_output(
            ['adb', 'shell', cmd], text=True, stderr=subprocess.STDOUT,
            timeout=ADB_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise subprocess.CalledProcessError(
            124, cmd, output=f'timeout: {exc}') from exc


def su_shell(cmd: str) -> str:
    return adb_shell(f'/data/local/tmp/su -c "{cmd}"')


def run_cmd(cmd: list[str], timeout: int = ADB_TIMEOUT) -> None:
    subprocess.check_call(cmd, timeout=timeout)


def run_client(arg_line: str) -> int:
    cmd = ['adb', 'shell', f'{MUTATION_DEVICE} {arg_line}']
    try:
        completed = subprocess.run(
            cmd, text=True, capture_output=True, timeout=CLIENT_TIMEOUT)
    except subprocess.TimeoutExpired:
        print('CLIENT_TIMEOUT; treating as ambiguous', file=sys.stderr)
        return 124
    except subprocess.SubprocessError as exc:
        print(f'CLIENT_ERROR: {exc}', file=sys.stderr)
        return 125
    if completed.stdout:
        print(completed.stdout, end='')
    if completed.stderr:
        print(completed.stderr, end='', file=sys.stderr)
    print(f'CLIENT_EXIT={completed.returncode}')
    return completed.returncode


def clear_marker(path: str) -> None:
    try:
        su_shell(f'rm -f {path}')
    except subprocess.CalledProcessError:
        pass


def read_marker(path: str) -> str | None:
    try:
        out = su_shell(f'cat {path}')
    except subprocess.CalledProcessError:
        return None
    return out if 'nonce=' in out else None


def wait_marker(path: str, nonce: str,
                timeout: int = MARKER_WAIT) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = read_marker(path)
        if out is not None and f'nonce={nonce}' in out:
            print(f'MARKER_OK {path}')
            return out
        time.sleep(1)
    print(f'MARKER_MISSING {path} nonce={nonce}')
    return None


def marker_outcome(marker: str | None) -> str:
    if not marker:
        return 'UNKNOWN'
    match = re.search(r'\boutcome=(OK|SERVICE_ERROR|UNKNOWN)\b', marker)
    return match.group(1) if match else 'UNKNOWN'


def run_write_with_marker(command: str, nonce: str,
                          timeout: int = WRITE_TIMEOUT) -> bool:
    clear_marker(WRITE_MARKER)
    full = (f'{command}; sync; blockdev --flushbufs /dev/block/by-name/lk_b; '
            f'echo nonce={nonce} > {WRITE_MARKER}')
    try:
        run_cmd(['adb', 'shell', f'/data/local/tmp/su -c "{full}"'],
                timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print('WRITE_COMMAND_EXCEPTION', exc)
    return wait_marker(WRITE_MARKER, nonce) is not None


def read_aidl() -> AidlState:
    state = AidlState()
    try:
        out = adb_shell(AIDL_DEVICE)
    except subprocess.CalledProcessError as exc:
        state.errors.append(f'AIDL client failed: {exc.output}')
        return state
    fields = {}
    for line in out.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            fields[key.strip()] = value.strip()
    state.ok = 'READONLY_OK' in out
    if not state.ok:
        state.errors.append('AIDL client did not print READONLY_OK')
    try:
        state.version = int(fields.get('interface_version', '-1'))
        state.active = int(fields.get('getActiveBootSlot', '-1'))
        state.current = int(fields.get('getCurrentSlot', '-1'))
        state.slots = int(fields.get('getNumberSlots', '-1'))
        state.merge = int(fields.get('getSnapshotMergeStatus', '-1'))
        state.suffix_a = fields.get('getSuffix(0)', '')
        state.suffix_b = fields.get('getSuffix(1)', '')
        state.bootable_a = fields.get('isSlotBootable(0)', '0') == '1'
        state.successful_a = fields.get('isSlotMarkedSuccessful(0)', '0') == '1'
        state.bootable_b = fields.get('isSlotBootable(1)', '0') == '1'
        state.successful_b = fields.get('isSlotMarkedSuccessful(1)', '0') == '1'
    except ValueError as exc:
        state.errors.append(f'AIDL field parse failed: {exc}')
    state.iface_hash = fields.get('interface_hash', '')
    return state


def read_boot_lun() -> int | None:
    try:
        out = adb_shell(f'cat {BOOT_LUN_PATH}')
    except subprocess.CalledProcessError:
        return None
    match = re.search(r'0x[0-9a-fA-F]+|\b\d+\b', out)
    return int(match.group(0), 0) if match else None


def read_selinux_enforce() -> int | None:
    try:
        out = adb_shell('cat /sys/fs/selinux/enforce')
    except subprocess.CalledProcessError:
        return None
    text = out.strip()
    return int(text) if text in ('0', '1') else None


def read_identity() -> tuple[str, str, str, str, str] | None:
    try:
        out = adb_shell(
            'getprop ro.product.device; getprop ro.product.model; '
            'getprop ro.boot.verifiedbootstate; getprop ro.boot.flash.locked; '
            'getprop ro.boot.slot_suffix')
    except subprocess.CalledProcessError:
        return None
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) < 5:
        return None
    return lines[-5], lines[-4], lines[-3], lines[-2], lines[-1]


def read_misc_record() -> bytes | None:
    try:
        out = su_shell('dd if=/dev/block/by-name/misc bs=1 skip=2048 count=32 '
                       '2>/dev/null | od -An -tx1')
    except subprocess.CalledProcessError:
        return None
    tokens = re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?![0-9a-fA-F])', out)
    if len(tokens) < 32:
        return None
    return bytes.fromhex(''.join(tokens[-32:]))


def read_hashes() -> tuple[str, str]:
    try:
        out = su_shell('sha256sum /dev/block/by-name/lk_a; '
                       'sha256sum /dev/block/by-name/lk_b')
    except subprocess.CalledProcessError:
        return '', ''
    found = {name: sha for sha, name in
             re.findall(r'([0-9a-f]{64})\s+/dev/block/by-name/(lk_[ab])', out)}
    return found.get('lk_a', ''), found.get('lk_b', '')


def read_live() -> LiveState:
    live = LiveState()
    try:
        live.candidate_sha = hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()
        live.candidate_size = CANDIDATE.stat().st_size
    except OSError as exc:
        live.errors.append(f'candidate read failed: {exc}')
    live.aidl = read_aidl()
    live.errors.extend(live.aidl.errors)
    live.boot_lun = read_boot_lun()
    if live.boot_lun is None:
        live.errors.append('boot_lun_enabled unreadable')
    live.enforce = read_selinux_enforce()
    if live.enforce is None:
        live.errors.append('selinux enforce unreadable')
    identity = read_identity()
    if identity is None:
        live.errors.append('device identity unreadable')
    else:
        live.device, live.model, live.verified_boot, live.flash_locked, live.slot_suffix = identity
    live.record = read_misc_record()
    if live.record is None:
        live.errors.append('misc+0x800 unreadable')
    live.lk_a_sha, live.lk_b_sha = read_hashes()
    if not live.lk_a_sha or not live.lk_b_sha:
        live.errors.append('lk_a/lk_b hash read failed')
    return live


def base_live_reasons(live: LiveState) -> list[str]:
    reasons = list(live.errors)
    if live.device != 'HNLDY-M' or live.model != 'LDY-AN00':
        reasons.append(f'device/model {live.device}/{live.model} not HNLDY-M/LDY-AN00')
    if live.verified_boot != 'green':
        reasons.append(f'verifiedbootstate {live.verified_boot} != green')
    if live.flash_locked != '1':
        reasons.append(f'flash.locked {live.flash_locked} != 1')
    if live.slot_suffix != '_a':
        reasons.append(f'slot suffix {live.slot_suffix} != _a')
    if live.candidate_sha != EXPECTED_CANDIDATE_SHA:
        reasons.append(f'candidate hash {live.candidate_sha} != {EXPECTED_CANDIDATE_SHA}')
    if live.candidate_size != EXPECTED_CANDIDATE_SIZE:
        reasons.append(f'candidate size {live.candidate_size} != {EXPECTED_CANDIDATE_SIZE}')
    if live.lk_a_sha != EXPECTED_STOCK_SHA:
        reasons.append(f'lk_a hash {live.lk_a_sha} != stock')
    return reasons


def check_b_write_hash(lk_b_sha: str) -> tuple[bool, list[str]]:
    if lk_b_sha != EXPECTED_B_AFTER_WRITE:
        return False, [f'lk_b hash {lk_b_sha} != expected candidate write hash']
    return True, []


def preflight_common(live: LiveState, b_expected: str,
                     b_label: str) -> tuple[bool, list[str]]:
    reasons = base_live_reasons(live)
    if live.enforce != 0:
        reasons.append(f'selinux enforce {live.enforce} != 0; '
                       'shell setter access would be denied by policy')
    if live.lk_b_sha != b_expected:
        reasons.append(f'lk_b hash {live.lk_b_sha} != {b_label}')
    if live.record != model.baseline:
        reasons.append('misc+0x800 does not match the captured baseline')
    if live.record is not None and not model.decode(live.record)['crc_ok']:
        reasons.append('misc+0x800 CRC invalid')
    if live.boot_lun != LUN_A:
        reasons.append(f'boot_lun {live.boot_lun} != A/LUN{LUN_A}')
    if not live.aidl.ok:
        reasons.append('AIDL read-only gate failed')
    if live.aidl.version != EXPECTED_INTERFACE_VERSION:
        reasons.append(f'interface version {live.aidl.version} != {EXPECTED_INTERFACE_VERSION}')
    if live.aidl.iface_hash != EXPECTED_INTERFACE_HASH:
        reasons.append(f'interface hash {live.aidl.iface_hash} != {EXPECTED_INTERFACE_HASH}')
    if (live.aidl.active, live.aidl.current, live.aidl.slots) != (0, 0, 2):
        reasons.append(f'AIDL active/current/slots = '
                       f'{live.aidl.active}/{live.aidl.current}/{live.aidl.slots}')
    if (live.aidl.suffix_a, live.aidl.suffix_b) != ('_a', '_b'):
        reasons.append(f'AIDL suffixes {live.aidl.suffix_a}/{live.aidl.suffix_b}')
    if not live.aidl.bootable_a or not live.aidl.successful_a:
        reasons.append('AIDL A not bootable/successful')
    if not live.aidl.bootable_b or live.aidl.successful_b:
        reasons.append('AIDL B not bootable or already successful')
    if live.aidl.merge != 0:
        reasons.append(f'VAB merge {live.aidl.merge} != 0')
    for name in ('MANIFEST.txt', 'SHA256SUMS'):
        if not (BACKUP_DIR / name).exists():
            reasons.append(f'backup missing: {BACKUP_DIR / name}')
    return not reasons, reasons


def preflight(live: LiveState) -> tuple[bool, list[str]]:
    return preflight_common(live, EXPECTED_STOCK_SHA, 'stock')


def preflight_activation(live: LiveState) -> tuple[bool, list[str]]:
    return preflight_common(live, EXPECTED_B_AFTER_WRITE,
                            'candidate B write hash')


def rollback_precheck(live: LiveState) -> tuple[bool, list[str]]:
    reasons = base_live_reasons(live)
    if live.enforce != 0:
        reasons.append(f'selinux enforce {live.enforce} != 0; '
                       'shell setter access would be denied by policy')
    if live.lk_b_sha not in (EXPECTED_STOCK_SHA, EXPECTED_B_AFTER_WRITE):
        reasons.append(f'lk_b {live.lk_b_sha} is neither stock nor candidate')
    if not live.aidl.ok:
        reasons.append('AIDL read-only gate failed')
    if live.aidl.version != EXPECTED_INTERFACE_VERSION:
        reasons.append(f'interface version {live.aidl.version} != {EXPECTED_INTERFACE_VERSION}')
    if live.aidl.iface_hash != EXPECTED_INTERFACE_HASH:
        reasons.append(f'interface hash {live.aidl.iface_hash} != {EXPECTED_INTERFACE_HASH}')
    if (live.aidl.current, live.aidl.slots) != (0, 2):
        reasons.append(f'AIDL current/slots = {live.aidl.current}/{live.aidl.slots}')
    if live.aidl.active not in (0, 1):
        reasons.append(f'AIDL active {live.aidl.active} not 0/1')
    if not live.aidl.successful_a or live.aidl.successful_b:
        reasons.append('AIDL success bits not A=1/B=0')
    if (live.aidl.suffix_a, live.aidl.suffix_b) != ('_a', '_b'):
        reasons.append(f'AIDL suffixes {live.aidl.suffix_a}/{live.aidl.suffix_b}')
    if live.aidl.merge != 0:
        reasons.append(f'VAB merge {live.aidl.merge} != 0')
    return not reasons, reasons


def postcheck_activation(live: LiveState) -> tuple[bool, list[str]]:
    reasons = base_live_reasons(live)
    if live.enforce != 0:
        reasons.append('selinux enforce != 0; AIDL/setter access not valid')
    if live.record is None or live.boot_lun is None:
        reasons.append('activation state unreadable')
    else:
        reasons.extend(model.postcheck(
            live.record, live.boot_lun, 'activation',
            a_bootable=live.aidl.bootable_a,
            b_bootable=live.aidl.bootable_b,
            merge=live.aidl.merge))
    if live.record != model.expected:
        reasons.append('raw boot-control record is not the exact expected activation record')
    if live.lk_b_sha != EXPECTED_B_AFTER_WRITE:
        reasons.append(f'lk_b {live.lk_b_sha} != expected candidate')
    if not live.aidl.ok:
        reasons.append('AIDL read failed')
    if (live.aidl.active, live.aidl.current, live.aidl.slots) != (1, 0, 2):
        reasons.append(f'AIDL active/current/slots = '
                       f'{live.aidl.active}/{live.aidl.current}/{live.aidl.slots}')
    if not live.aidl.successful_a or live.aidl.successful_b:
        reasons.append('AIDL success bits not A=1/B=0')
    if (live.aidl.suffix_a, live.aidl.suffix_b) != ('_a', '_b'):
        reasons.append('AIDL suffixes changed')
    if live.aidl.merge != 0:
        reasons.append(f'VAB merge {live.aidl.merge} != 0')
    return not reasons, reasons


def postcheck_rollback(live: LiveState) -> tuple[bool, list[str]]:
    reasons = base_live_reasons(live)
    if live.enforce != 0:
        reasons.append('selinux enforce != 0; AIDL/setter access not valid')
    if live.record is None or live.boot_lun is None:
        reasons.append('rollback state unreadable')
    else:
        reasons.extend(model.postcheck(
            live.record, live.boot_lun, 'a_active',
            a_bootable=live.aidl.bootable_a,
            merge=live.aidl.merge))
    rollback_records = {model.set_active(model.expected, 0),
                        model.set_active(model.baseline, 0)}
    if live.record not in rollback_records:
        reasons.append('raw boot-control record is not an expected A-active rollback record')
    if live.lk_b_sha not in (EXPECTED_STOCK_SHA, EXPECTED_B_AFTER_WRITE):
        reasons.append(f'lk_b {live.lk_b_sha} is neither stock nor candidate')
    if not live.aidl.ok:
        reasons.append('AIDL read failed')
    if (live.aidl.active, live.aidl.current, live.aidl.slots) != (0, 0, 2):
        reasons.append(f'AIDL active/current/slots = '
                       f'{live.aidl.active}/{live.aidl.current}/{live.aidl.slots}')
    if not live.aidl.successful_a or live.aidl.successful_b:
        reasons.append('AIDL success bits not A=1/B=0')
    if live.aidl.merge != 0:
        reasons.append(f'VAB merge {live.aidl.merge} != 0')
    return not reasons, reasons


def require_mutation(args: argparse.Namespace, confirm: str) -> bool:
    if not args.execute or not args.authorized_trial or not getattr(args, confirm):
        print('REFUSED: mutation requires --execute --authorized-trial and '
              f'--{confirm.replace("_", "-")}')
        return False
    return True


def restore_stock_b() -> int:
    restore = BACKUP_DIR / 'lk_b.bin'
    try:
        data = restore.read_bytes()
    except OSError as exc:
        print('RESTORE_SOURCE_MISSING', exc)
        print('STOP_NO_RECOVERY')
        return 2
    if hashlib.sha256(data).hexdigest() != EXPECTED_STOCK_SHA:
        print('RESTORE_SOURCE_HASH_MISMATCH')
        print('STOP_NO_RECOVERY')
        return 2
    try:
        run_cmd(['adb', 'push', str(restore), '/data/local/tmp/lk-stock-b.bin'],
                timeout=PUSH_TIMEOUT)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print('RESTORE_PUSH_FAIL', exc)
        print('STOP_NO_RECOVERY')
        return 2
    nonce = secrets.token_hex(16)
    if not run_write_with_marker(
            'dd if=/data/local/tmp/lk-stock-b.bin of=/dev/block/by-name/lk_b '
            'bs=4096 conv=sync,fsync', nonce):
        print('RESTORE_COMPLETION_UNKNOWN_STOP')
        return 4
    lk_a, lk_b = read_hashes()
    if lk_a == EXPECTED_STOCK_SHA and lk_b == EXPECTED_STOCK_SHA:
        print('RESTORED_STOCK_B')
        return 1
    print('RESTORE_VERIFICATION_FAILED', lk_a, lk_b)
    print('STOP_NO_RECOVERY')
    return 2


def write_b() -> int:
    live = read_live()
    ok, reasons = preflight(live)
    if not ok:
        print('PREFLIGHT_FAIL', *reasons, sep='\n  ')
        return 1
    try:
        run_cmd(['adb', 'push', str(CANDIDATE), '/data/local/tmp/lk-cand.img'],
                timeout=PUSH_TIMEOUT)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print('CANDIDATE_PUSH_FAIL', exc)
        return 1
    nonce = secrets.token_hex(16)
    if not run_write_with_marker(
            'dd if=/data/local/tmp/lk-cand.img of=/dev/block/by-name/lk_b '
            'bs=4096 conv=sync,fsync', nonce):
        print('WRITE_COMPLETION_UNKNOWN_STOP')
        return 4
    lk_a, lk_b = read_hashes()
    if lk_a != EXPECTED_STOCK_SHA:
        print('A_CHANGED_AFTER_B_WRITE', lk_a)
        print('STOP_NO_RECOVERY')
        return 2
    ok, reasons = check_b_write_hash(lk_b)
    if ok:
        print('WRITE_B_OK', lk_b)
        return 0
    print('WRITE_B_FAIL', *reasons, sep='\n  ')
    return restore_stock_b()


def deploy_mutation_client() -> bool:
    try:
        data = MUTATION_CLIENT.read_bytes()
    except OSError as exc:
        print('DEPLOY_FAIL host mutation-client read failed', exc)
        return False
    host_sha = hashlib.sha256(data).hexdigest()
    if host_sha != MUTATION_CLIENT_SHA:
        print('DEPLOY_REFUSED host mutation-client hash mismatch', host_sha)
        return False
    try:
        run_cmd(['adb', 'push', str(MUTATION_CLIENT), MUTATION_DEVICE],
                timeout=PUSH_TIMEOUT)
        run_cmd(['adb', 'shell', f'chmod 755 {MUTATION_DEVICE}'],
                timeout=ADB_TIMEOUT)
        deployed = adb_shell(f'sha256sum {MUTATION_DEVICE}')
        if MUTATION_CLIENT_SHA not in deployed:
            print('DEPLOY_REFUSED deployed mutation-client hash mismatch')
            return False
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print('DEPLOY_FAIL', exc)
        return False


def activate() -> int:
    live = read_live()
    ok, reasons = preflight_activation(live)
    if not ok:
        print('PREFLIGHT_ACTIVATION_FAIL', *reasons, sep='\n  ')
        return 1
    if not deploy_mutation_client():
        return 1
    # Re-read immediately before the setter: permissive state and B candidate.
    live = read_live()
    ok, reasons = preflight_activation(live)
    if not ok:
        print('PREFLIGHT_ACTIVATION_FAIL_IMMEDIATE', *reasons, sep='\n  ')
        return 1
    nonce = secrets.token_hex(16)
    clear_marker(SETTER_MARKER)
    client_rc = run_client(
        f'activate --slot 1 --execute --confirm-inactive-b --nonce {nonce}')
    marker = wait_marker(SETTER_MARKER, nonce)
    if marker is None:
        print('SETTER_COMPLETION_UNKNOWN_STOP')
        print('STOP_UNKNOWN_STATE')
        return 4
    outcome = marker_outcome(marker)
    if outcome not in ('OK', 'SERVICE_ERROR'):
        print(f'SETTER_OUTCOME_UNCERTAIN_STOP outcome={outcome}')
        print('STOP_UNKNOWN_STATE')
        return 4
    after = read_live()
    ok, reasons = postcheck_activation(after)
    if ok:
        print('ACTIVATION_POSTCHECK_OK')
        if client_rc != 0:
            print(f'CLIENT_EXIT_NONZERO_BUT_POSTCHECK_OK={client_rc}')
        return 0
    print('ACTIVATION_POSTCHECK_FAIL', *reasons, sep='\n  ')
    print('ATTEMPTING_SUPPORTED_A_ROLLBACK')
    rollback_rc = rollback()
    if rollback_rc == 0:
        print('ACTIVATION_FAILED_ROLLED_BACK')
        return 2
    if rollback_rc == 4:
        print('STOP_UNKNOWN_STATE: rollback completion unknown')
        return 4
    print('STOP_NO_RECOVERY: rollback did not verify')
    return 3


def rollback() -> int:
    live = read_live()
    ok, reasons = rollback_precheck(live)
    if not ok:
        print('ROLLBACK_PREFLIGHT_REFUSED', *reasons, sep='\n  ')
        return 5
    if not deploy_mutation_client():
        return 5
    live = read_live()
    ok, reasons = rollback_precheck(live)
    if not ok:
        print('ROLLBACK_PREFLIGHT_REFUSED_IMMEDIATE', *reasons, sep='\n  ')
        return 5
    nonce = secrets.token_hex(16)
    clear_marker(SETTER_MARKER)
    client_rc = run_client(
        f'activate --slot 0 --execute --confirm-rollback --nonce {nonce}')
    marker = wait_marker(SETTER_MARKER, nonce)
    if marker is None:
        print('ROLLBACK_COMPLETION_UNKNOWN_STOP')
        print('STOP_UNKNOWN_STATE')
        return 4
    outcome = marker_outcome(marker)
    if outcome not in ('OK', 'SERVICE_ERROR'):
        print(f'ROLLBACK_OUTCOME_UNCERTAIN_STOP outcome={outcome}')
        print('STOP_UNKNOWN_STATE')
        return 4
    after = read_live()
    ok, reasons = postcheck_rollback(after)
    if ok:
        print('ROLLBACK_POSTCHECK_OK')
        if client_rc != 0:
            print(f'CLIENT_EXIT_NONZERO_BUT_POSTCHECK_OK={client_rc}')
        return 0
    print('ROLLBACK_POSTCHECK_FAIL', *reasons, sep='\n  ')
    print('STOP_NO_RECOVERY')
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', default='preflight',
                        choices=['preflight', 'activation-preflight',
                                 'postcheck-activation', 'postcheck-rollback',
                                 'write-b', 'activate', 'rollback'])
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--authorized-trial', action='store_true')
    parser.add_argument('--confirm-write-b', action='store_true')
    parser.add_argument('--confirm-activate', action='store_true')
    parser.add_argument('--confirm-rollback', action='store_true')
    args = parser.parse_args(argv)

    live = read_live()
    if args.mode == 'preflight':
        print(f"selinux_enforce={live.enforce} "
              f"boot_lun={('0x%08x' % live.boot_lun) if live.boot_lun is not None else 'unreadable'} "
              f"active={live.aidl.active} current={live.aidl.current} "
              f"A_success={live.aidl.successful_a} B_success={live.aidl.successful_b}")
        ok, reasons = preflight(live)
        for reason in reasons:
            print('  -', reason)
        print('PREFLIGHT_OK' if ok else 'PREFLIGHT_FAIL')
        return 0 if ok else 1
    if args.mode == 'activation-preflight':
        print(f"selinux_enforce={live.enforce} "
              f"boot_lun={('0x%08x' % live.boot_lun) if live.boot_lun is not None else 'unreadable'} "
              f"active={live.aidl.active} current={live.aidl.current} "
              f"A_success={live.aidl.successful_a} B_success={live.aidl.successful_b}")
        ok, reasons = preflight_activation(live)
        for reason in reasons:
            print('  -', reason)
        print('ACTIVATION_PREFLIGHT_OK' if ok else 'ACTIVATION_PREFLIGHT_FAIL')
        return 0 if ok else 1
    if args.mode == 'postcheck-activation':
        ok, reasons = postcheck_activation(live)
        for reason in reasons:
            print('  -', reason)
        print('POSTCHECK_ACTIVATION_OK' if ok else 'POSTCHECK_ACTIVATION_FAIL')
        return 0 if ok else 1
    if args.mode == 'postcheck-rollback':
        ok, reasons = postcheck_rollback(live)
        for reason in reasons:
            print('  -', reason)
        print('POSTCHECK_ROLLBACK_OK' if ok else 'POSTCHECK_ROLLBACK_FAIL')
        return 0 if ok else 1
    if args.mode == 'write-b':
        if not require_mutation(args, 'confirm_write_b'):
            return 3
        return write_b()
    if args.mode == 'activate':
        if not require_mutation(args, 'confirm_activate'):
            return 3
        return activate()
    if args.mode == 'rollback':
        if not require_mutation(args, 'confirm_rollback'):
            return 3
        return rollback()
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
