#!/usr/bin/env python3
"""Reproduce the qualified LK offline. Requires the exact stock container."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import executor

PATCHES = ['0x156A4:20008052', '0x156D8:7f0e01b9', '0x15910:14000014',
           '0x1259D0:1f810db9', '0xF0D04:81008052', '0x138E7C:e20308aa',
           '0x17D10:0d000014', '0x24D44:03008052']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock', type=Path, required=True)
    args = p.parse_args()
    source = args.stock.read_bytes()
    assert len(source) == 7976720
    assert hashlib.sha256(source).hexdigest() == '4a2758f3da93142b08059f140c02fd8c4540ff98890081d3e4475f28c9f28f67'
    with tempfile.TemporaryDirectory(prefix='lk-recipe-') as temp:
        output = Path(temp) / 'lk.img'
        command = [sys.executable, str(Path(__file__).with_name('patch_lk.py')),
                   '--in', str(args.stock), '--out', str(output), '--bypass', 'override']
        for patch in PATCHES:
            command += ['--patch', patch]
        subprocess.run(command, check=True, capture_output=True)
        image = output.read_bytes()
        assert len(image) == executor.EXPECTED_CANDIDATE_SIZE
        assert hashlib.sha256(image).hexdigest() == executor.EXPECTED_CANDIDATE_SHA
        assert hashlib.sha256(image.ljust(16777216, b'\0')).hexdigest() == executor.EXPECTED_B_AFTER_WRITE
        readme = Path(__file__).parent.parent.joinpath('README.md').read_text()
        assert all('--patch ' + patch in readme for patch in PATCHES)
        assert executor.EXPECTED_CANDIDATE_SHA in readme
        assert executor.EXPECTED_B_AFTER_WRITE in readme
    print('LK_7D_EXACT_RECIPE_EXECUTOR_README_PASS')


if __name__ == '__main__':
    main()
