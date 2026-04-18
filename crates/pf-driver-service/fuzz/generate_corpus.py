# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

"""Generate seed corpus files for the IPP parser fuzz target.

Run this script once before the first fuzzing session:

    python3 crates/pf-driver-service/fuzz/generate_corpus.py
"""

import os
import struct

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus", "ipp_parser")
os.makedirs(CORPUS_DIR, exist_ok=True)


def _ipp_attr(value_tag: int, name: bytes, value: bytes) -> bytes:
    """Encode a single IPP attribute (tag + name-length + name + value-length + value)."""
    return (
        bytes([value_tag])
        + struct.pack(">H", len(name))
        + name
        + struct.pack(">H", len(value))
        + value
    )


def build_print_job() -> bytes:
    """Minimal valid Print-Job (0x0002) request."""
    buf = bytearray()
    buf += bytes([0x02, 0x00])                  # IPP version 2.0
    buf += struct.pack(">H", 0x0002)            # Print-Job
    buf += struct.pack(">I", 1)                 # request-id = 1
    buf += bytes([0x01])                        # operation-attributes-tag
    buf += _ipp_attr(0x47, b"attributes-charset", b"utf-8")
    buf += _ipp_attr(0x48, b"attributes-natural-language", b"en-us")
    buf += _ipp_attr(0x45, b"printer-uri", b"ipp://printforge.local/ipp/print")
    buf += bytes([0x03])                        # end-of-attributes-tag
    buf += b"%PDF-1.4 test"                     # document data
    return bytes(buf)


def build_get_printer_attributes() -> bytes:
    """Minimal valid Get-Printer-Attributes (0x000B) request."""
    buf = bytearray()
    buf += bytes([0x02, 0x00])                  # IPP version 2.0
    buf += struct.pack(">H", 0x000B)            # Get-Printer-Attributes
    buf += struct.pack(">I", 2)                 # request-id = 2
    buf += bytes([0x01])                        # operation-attributes-tag
    buf += _ipp_attr(0x47, b"attributes-charset", b"utf-8")
    buf += _ipp_attr(0x48, b"attributes-natural-language", b"en-us")
    buf += _ipp_attr(0x45, b"printer-uri", b"ipp://printforge.local/ipp/print")
    buf += bytes([0x03])                        # end-of-attributes-tag
    return bytes(buf)


def main() -> None:
    seeds = {
        "print_job_minimal": build_print_job(),
        "get_printer_attrs_minimal": build_get_printer_attributes(),
    }
    for name, data in seeds.items():
        path = os.path.join(CORPUS_DIR, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  wrote {path} ({len(data)} bytes)")
    print("Seed corpus ready.")


if __name__ == "__main__":
    main()
