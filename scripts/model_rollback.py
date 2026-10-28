#!/usr/bin/env python3
"""Host-only post-check and rollback decision model for the inactive-B executor.

No device access, no HAL call, no write. The metadata transformations are
derived from the reviewed HAL contract:
  - target slot: priority 15, retries 6, success bit preserved;
  - other priority-15 slots demoted to 14;
  - CRC32 over bytes 0..27 stored little-endian at 28..31.

The baseline and expected records below are the exact 32-byte BCAB records
captured on the tested LDY-AN00 at misc+0x800. They are constants so this
script can run without the original research tree; pass a different record to
the functions if you are working on another unit.

The executor imports this module for:
    baseline, expected, decode(), set_active(), postcheck()
"""

import zlib

# Captured before activation (A 15/7/1, B 15/7/0), CRC 0x6ee202d3.
baseline = bytes.fromhex(
    "5f6100004243414201020000ff007f00"
    "000000000000000000000000d302e26e")

# Expected after setActiveBootSlot(1) (A 14/7/1, B 15/6/0), CRC 0xa638af2e.
expected = bytes.fromhex(
    "5f6100004243414201020000fe006f00"
    "0000000000000000000000002eaf38a6")


def decode(rec):
    a = rec[12]
    b = rec[14]
    return {
        "magic": rec[4:8] == b"BCAB",
        "crc_ok": int.from_bytes(rec[28:32], "little")
        == (zlib.crc32(rec[:28]) & 0xffffffff),
        "a": {"priority": a & 0xf, "tries": (a >> 4) & 7, "success": (a >> 7) & 1},
        "b": {"priority": b & 0xf, "tries": (b >> 4) & 7, "success": (b >> 7) & 1},
    }


def encode_slot(priority, tries, success):
    return (priority & 0xf) | ((tries & 7) << 4) | ((success & 1) << 7)


def set_active(rec, target):
    """Model the HAL setActiveBootSlot target-slot metadata mutation."""
    r = bytearray(rec)
    a, b = r[12], r[14]
    ap, ar, as_ = a & 0xf, (a >> 4) & 7, (a >> 7) & 1
    bp, br, bs = b & 0xf, (b >> 4) & 7, (b >> 7) & 1
    if target == 0:
        ap, ar = 15, 6
        if bp == 15:
            bp = 14
    elif target == 1:
        bp, br = 15, 6
        if ap == 15:
            ap = 14
    else:
        raise ValueError("target must be 0 or 1")
    r[12] = encode_slot(ap, ar, as_)
    r[14] = encode_slot(bp, br, bs)
    r[28:32] = (zlib.crc32(r[:28]) & 0xffffffff).to_bytes(4, "little")
    return bytes(r)


def with_b_success(rec):
    r = bytearray(rec)
    r[14] |= 0x80
    r[28:32] = (zlib.crc32(r[:28]) & 0xffffffff).to_bytes(4, "little")
    return bytes(r)


def postcheck(rec, boot_lun, mode, a_bootable=True, b_bootable=True, merge=0):
    d = decode(rec)
    reasons = []
    if not d["magic"]:
        reasons.append("BCAB magic missing")
    if not d["crc_ok"]:
        reasons.append("CRC invalid")
    if mode == "activation":
        if d["a"] != {"priority": 14, "tries": 7, "success": 1}:
            reasons.append(f"A not 14/7/1: {d['a']}")
        if d["b"] != {"priority": 15, "tries": 6, "success": 0}:
            reasons.append(f"B not 15/6/0: {d['b']}")
        if boot_lun != 2:
            reasons.append(f"boot_lun {boot_lun} != 2")
    elif mode == "a_active":
        if d["a"]["priority"] != 15 or d["a"]["success"] != 1:
            reasons.append(f"A not priority15/success1: {d['a']}")
        if d["b"]["success"] != 0:
            reasons.append(f"B success not 0: {d['b']}")
        if d["b"]["priority"] >= d["a"]["priority"]:
            reasons.append(f"B priority {d['b']['priority']} not below A {d['a']['priority']}")
        if boot_lun != 1:
            reasons.append(f"boot_lun {boot_lun} != 1")
    else:
        reasons.append(f"unknown mode {mode}")
    if not a_bootable:
        reasons.append("A not bootable")
    if mode == "activation" and not b_bootable:
        reasons.append("B not bootable")
    if merge != 0:
        reasons.append(f"VAB merge {merge} != 0")
    return reasons


def _self_test():
    results = []
    results.append(("baseline+lun1", bool(postcheck(baseline, 1, "activation"))))
    results.append(("activation_ok", not postcheck(expected, 2, "activation")))
    results.append(("partial_metadata_only", bool(postcheck(expected, 1, "activation"))))
    results.append(("baseline+lun2", bool(postcheck(baseline, 2, "activation"))))
    rollback = set_active(expected, 0)
    results.append(("rollback_ok", not postcheck(rollback, 1, "a_active")))
    results.append(("rollback+lun2", bool(postcheck(rollback, 2, "a_active"))))
    bad_crc = bytearray(expected)
    bad_crc[28] ^= 0xff
    results.append(("crc_invalid", bool(postcheck(bytes(bad_crc), 2, "activation"))))
    results.append(("b_success_stop", bool(postcheck(with_b_success(expected), 2, "activation"))))
    for name, ok in results:
        print(f"{name}: {'OK' if ok else 'FAIL'}")
    assert all(ok for _, ok in results), "model self-test failed"
    print("MODEL_OK")


if __name__ == "__main__":
    _self_test()
