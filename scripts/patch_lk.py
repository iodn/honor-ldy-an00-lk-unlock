#!/usr/bin/env python3
"""
Offline LDY-AN00 (MT6993) LK patcher.

- Parses the packed LK image with liblk (the same parser used by lk-unlock).
- Applies raw byte patches (raw lk.img offset, or a Ghidra VA with --base).
- Optionally applies the lk-unlock certificate-bypass form (override or wrap)
  to every partition whose CERT2 no longer matches after patching.
- Writes the patched image and verifies it by re-parsing.

This is host-side only. It never touches the phone.

Usage:
  patch_lk.py --in lk-stock.img --out out/lk-patched.img \
      --patch 0x1234:00000000 [--patch ...] \
      --bypass override|wrap|none [--base 0x70582e00]

Patch syntax:
  0x<raw_offset>:<hex bytes>   raw lk.img file offset
  va:0x<ghidra_va>:<hex bytes> Ghidra VA; converted with raw = VA - base

Dependencies:
  pip install cryptography pyasn1 git+https://github.com/R0rt1z2/liblk
  git clone https://github.com/georgiynesterov/lk-unlock   # AGPL-3.0
  export LK_UNLOCK=/path/to/lk-unlock/lk-unlock.py         # or put it in ./lk-unlock/

The exact image used on the phone in this repository was produced with:
  patch_lk.py --in lk-stock.img --out out/lk-fbunlock-override.img \
      --patch 0x156A4:20008052 --bypass override \
      --report out/lk-fbunlock-override.json
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

from liblk.image import LkImage

HERE = Path(__file__).resolve().parent
LK_UNLOCK = Path(os.environ.get(
    "LK_UNLOCK", str(HERE.parent / "lk-unlock" / "lk-unlock.py")))


def load_lk_unlock():
    if not LK_UNLOCK.is_file():
        raise SystemExit(
            f"lk-unlock.py not found at {LK_UNLOCK}; clone "
            "https://github.com/georgiynesterov/lk-unlock and set LK_UNLOCK")
    spec = importlib.util.spec_from_file_location("lkunlock", LK_UNLOCK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_patch(spec: str, base: int):
    """Return (raw_offset, bytes). Accepts 0xOFF:HEX or va:0xVA:HEX."""
    if spec.startswith("va:"):
        va_s, hex_s = spec[3:].split(":", 1)
        va = int(va_s, 0)
        off = va - base
        if off < 0:
            raise SystemExit(f"VA {va:#x} below base {base:#x}")
    else:
        off_s, hex_s = spec.split(":", 1)
        off = int(off_s, 0)
    data = bytes.fromhex(hex_s.replace(" ", ""))
    if not data:
        raise SystemExit(f"empty patch: {spec}")
    return off, data


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--patch", action="append", default=[])
    ap.add_argument("--bypass", choices=["none", "override", "wrap"], default="none")
    ap.add_argument("--base", default="0x70582e00")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()
    base = int(args.base, 0)

    src = Path(args.inp).read_bytes()
    patched = bytearray(src)
    patches = []
    for spec in args.patch:
        off, data = parse_patch(spec, base)
        if off + len(data) > len(patched):
            raise SystemExit(f"patch out of range: {spec}")
        orig = bytes(patched[off:off + len(data)])
        patched[off:off + len(data)] = data
        patches.append({"raw_offset": off, "ghidra_va": off + base,
                        "before": orig.hex(), "after": data.hex()})

    image = LkImage(patched)
    before_parts = {}
    for name, part in image.partitions.items():
        before_parts[name] = {
            "data_size": int(part.header.data_size),
            "cert2_len": len(bytes(part.cert2.data)) if part.cert2 else None,
            "cert2_matches": (part.matches_cert2() if part.cert2 else None),
        }

    signed = []
    mode = args.bypass
    if mode != "none":
        lk = load_lk_unlock()
        m = lk.CertBypassMode(mode)
        signed = lk.apply_cert_bypass(image, m)

    out_bytes = bytes(image.contents)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(out_bytes)

    # Verify by re-parsing the generated image and the patched bytes.
    verify = LkImage(out_bytes)
    ok_patch = all(bytes(out_bytes[p["raw_offset"]:p["raw_offset"] + len(bytes.fromhex(p["after"]))])
                   == bytes.fromhex(p["after"]) for p in patches)
    parts = {}
    for name, part in verify.partitions.items():
        parts[name] = {
            "data_size": int(part.header.data_size),
            "cert2_len": len(bytes(part.cert2.data)) if part.cert2 else None,
            "cert2_matches": (part.matches_cert2() if part.cert2 else None),
        }

    report = {
        "input": str(Path(args.inp).resolve()),
        "input_sha256": sha256(src),
        "output": str(out.resolve()),
        "output_sha256": sha256(out_bytes),
        "input_size": len(src),
        "output_size": len(out_bytes),
        "bypass": mode,
        "signed_partitions": signed,
        "patches": patches,
        "patches_verified": ok_patch,
        "partitions_before": before_parts,
        "partitions_after": parts,
    }
    print(json.dumps(report, indent=2))
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    if not ok_patch:
        raise SystemExit("patch verification failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
