#!/usr/bin/env python3
"""Read-only raw fastboot client for `oem dump-storage <partition>`.

The LDY-AN00 LK has no `fetch:` token. The only read-only partition read is
`oem dump-storage <name>`, which emits `DUMPSTART`, the raw partition bytes,
`DUMPEND`, and a final fastboot `OKAY`. The raw stream is not standard fastboot
response framing, so a pyusb client is needed. This sends the command and
captures the payload; it performs no writes.

Examples:
  python3 fastboot_dump.py --partition lk_a --expected-len 16777216 \
      --expected-sha 989e70603748b88f788e9342f0504722895b8bfd20674b33f9f30331650aecf5 \
      --out /tmp/lk_a.raw

  python3 fastboot_dump.py --partition init_boot_b --expected-len 8388608 \
      --out /tmp/init_boot_b.raw

Requires: pip install pyusb
"""
import argparse
import hashlib
import sys
import time

import usb.core
import usb.util


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--partition", required=True, help="e.g. lk_a, lk_b, init_boot_b")
    ap.add_argument("--expected-len", type=int, required=True,
                    help="exact payload length (lk partitions: 16777216)")
    ap.add_argument("--expected-sha", default=None,
                    help="optional SHA-256 of the payload")
    ap.add_argument("--out", default=None,
                    help="raw capture path (default: /tmp/<partition>.raw)")
    ap.add_argument("--serial", default=None,
                    help="USB serial; if omitted the first matching device is used")
    ap.add_argument("--vid", type=lambda x: int(x, 0), default=0x18D1)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0xD00D)
    ap.add_argument("--timeout", type=float, default=150.0)
    args = ap.parse_args()

    out = args.out or f"/tmp/{args.partition.replace('/', '_')}.raw"
    kwargs = {"idVendor": args.vid, "idProduct": args.pid}
    if args.serial:
        kwargs["serial_number"] = args.serial
    dev = usb.core.find(**kwargs)
    if dev is None and args.serial:
        # Keep the original fallback: a serial filter can fail on some hosts.
        dev = usb.core.find(idVendor=args.vid, idProduct=args.pid)
    if dev is None:
        print("DEVICE_NOT_FOUND")
        return 2
    try:
        print("serial", dev.serial_number)
    except Exception as exc:
        print("serial unavailable", exc)
    try:
        cfg = dev.get_active_configuration()
    except Exception:
        dev.set_configuration()
        cfg = dev.get_active_configuration()
    intf = None
    for it in cfg:
        print("interface", it.bInterfaceNumber, hex(it.bInterfaceClass),
              hex(it.bInterfaceSubClass), hex(it.bInterfaceProtocol))
        if (it.bInterfaceClass == 0xFF and it.bInterfaceSubClass == 0x42
                and it.bInterfaceProtocol == 0x03):
            intf = it
    if intf is None:
        print("FASTBOOT_INTERFACE_NOT_FOUND")
        return 3
    ep_in = usb.util.find_descriptor(
        intf, custom_match=lambda e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_IN)
    ep_out = usb.util.find_descriptor(
        intf, custom_match=lambda e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
    if ep_in is None or ep_out is None:
        print("ENDPOINT_NOT_FOUND", ep_in, ep_out)
        return 4
    print("ep_in", hex(ep_in.bEndpointAddress), ep_in.wMaxPacketSize,
          "ep_out", hex(ep_out.bEndpointAddress), ep_out.wMaxPacketSize)
    try:
        usb.util.claim_interface(dev, intf)
    except Exception as exc:
        print("CLAIM_FAILED", exc)
        try:
            if dev.is_kernel_driver_active(intf.bInterfaceNumber):
                dev.detach_kernel_driver(intf.bInterfaceNumber)
            usb.util.claim_interface(dev, intf)
            print("CLAIMED_AFTER_DETACH")
        except Exception as exc2:
            print("CLAIM_RETRY_FAILED", exc2)
            return 5

    cmd = f"oem dump-storage {args.partition}".encode() + b"\x00"
    print("SEND", cmd)
    try:
        ep_out.write(cmd, timeout=5000)
    except Exception as exc:
        print("WRITE_ERROR", exc)
        return 6

    data = bytearray()
    deadline = time.monotonic() + args.timeout
    start = -1
    end = -1
    last_report = 0
    while time.monotonic() < deadline:
        try:
            chunk = ep_in.read(65536, timeout=5000)
        except usb.core.USBTimeoutError:
            print("READ_TIMEOUT", len(data))
            break
        except Exception as exc:
            print("READ_ERROR", exc)
            break
        data.extend(bytes(chunk))
        if start < 0:
            start = data.find(b"DUMPSTART")
            if start >= 0:
                print("DUMPSTART_AT", start, flush=True)
                start += len(b"DUMPSTART")
        if start >= 0:
            payload_len = len(data) - start
            if payload_len - last_report >= 1024 * 1024:
                last_report = payload_len
                print("PAYLOAD", payload_len, flush=True)
            if payload_len >= args.expected_len:
                # The payload should be followed by DUMPEND.
                end = data.find(b"DUMPEND", start + args.expected_len)
                if end >= 0:
                    # Consume the final OKAY/FAIL response so the next
                    # standard fastboot command does not read a stale reply.
                    tail_deadline = time.monotonic() + 3
                    while time.monotonic() < tail_deadline:
                        try:
                            tail = ep_in.read(4096, timeout=500)
                        except usb.core.USBTimeoutError:
                            break
                        except Exception:
                            break
                        data.extend(bytes(tail))
                        if (b"OKAY" in data[end:] or b"FAIL" in data[end:]):
                            break
                    break
                # Keep reading a little to find DUMPEND.
                if payload_len >= args.expected_len + 64:
                    print("DUMPEND_NOT_FOUND", payload_len)
                    break

    print("TOTAL", len(data), "START", start, "END", end)
    with open(out, "wb") as f:
        f.write(data)
    if start < 0 or end < 0:
        print("INCOMPLETE")
        try:
            usb.util.release_interface(dev, intf)
        except Exception:
            pass
        return 7
    payload = bytes(data[start:end])
    payload_sha = hashlib.sha256(payload).hexdigest()
    print("PAYLOAD_LEN", len(payload))
    print("PAYLOAD_SHA256", payload_sha)
    if args.expected_sha:
        print("EXPECTED_SHA256", args.expected_sha)
    ok = len(payload) == args.expected_len
    if args.expected_sha:
        ok = ok and payload_sha == args.expected_sha
    print("DUMP_OK" if ok else "DUMP_MISMATCH")
    try:
        usb.util.release_interface(dev, intf)
    except Exception:
        pass
    return 0 if ok else 8


if __name__ == "__main__":
    sys.exit(main())
