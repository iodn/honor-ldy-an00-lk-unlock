#!/usr/bin/env python3
"""
Offline cross-check of OUR patched LK against the BL2_EXT CERT2 Unicorn
harness from the separate lk-xiaomi-feasibility analysis.

Runs the original `emulate-bl2-cert2.py` prelude (its own stock/override/wrap/
key-substitution cases and assertions), then executes the same BL2_EXT CERT2
code on the CERT2 blob and payload of `out/lk-fbunlock-override.img`
(boot-state patch at raw 0x156A4 + override).

Host-only. No device access, no writes to any partition.

The upstream harness is not included in this repository. Point
BL2_HARNESS_DIR at the directory that contains `emulate-bl2-cert2.py`, or pass
the image path as the first argument. The tested run used the harness from the
LK research tree and returned:

    return_code=0x0
    extracted_header_hash=98360b74...
    extracted_image_hash=af541a8e...
    cert2_and_hash_checks_pass=true
    OUR IMAGE / BL2_EXT OVERRIDE EMULATION: PASS
"""
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEAS = Path(os.environ.get(
    "BL2_HARNESS_DIR", HERE.parent / "lk-xiaomi-feasibility"))
OUR_IMG = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(os.environ.get(
    "LK_CANDIDATE", HERE.parent / "out" / "lk-fbunlock-override.img"))

HARNESS = FEAS / "emulate-bl2-cert2.py"
if not HARNESS.is_file():
    raise SystemExit(
        f"BL2_EXT harness not found: {HARNESS}\n"
        "Set BL2_HARNESS_DIR to the directory containing emulate-bl2-cert2.py.")
if not OUR_IMG.is_file():
    raise SystemExit(f"candidate image not found: {OUR_IMG}")

src = HARNESS.read_text()
g = {"__name__": "bl2_emulator"}
exec(compile(src, str(HARNESS), "exec"), g)

LkImage = g["LkImage"]
v = g["v"]
run_case = g["run_case"]

our = OUR_IMG.read_bytes()
img = LkImage(our)
lk = img.partitions["lk"]
hh, ih = lk.compute_hashes()
print(f"[ours] image: {OUR_IMG}")
print(f"[ours] lk header hash: {hh.hex()}")
print(f"[ours] lk image  hash: {ih.hex()}")
print(f"[ours] lk data len: {len(lk.data)}, cert2 len: {len(lk.cert2.data)}")

entries = v.parse_part_entries(our)
target_our, cert1_our, cert2_our = v.find_targets(entries, "lk")[0]
our_cert2 = v.entry_blob(our, cert2_our)
our_payload = v.padded_image_data(our, target_our)
print(f"[ours] parsed cert2 len: {len(our_cert2)}, payload len: {len(our_payload)}")
print(f"[ours] payload sha256: {hashlib.sha256(our_payload).hexdigest()}")

res = run_case("ours_fbunlock_override", our_cert2, our_payload)
print(json.dumps(res, indent=2))

ok = (res.get("return_code") == "0x0"
      and res.get("extracted_header_hash") == hh.hex()
      and res.get("extracted_image_hash") == ih.hex())
print("OUR IMAGE / BL2_EXT OVERRIDE EMULATION:", "PASS" if ok else "FAIL")
if not ok:
    raise SystemExit(1)
