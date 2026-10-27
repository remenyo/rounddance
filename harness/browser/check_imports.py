#!/usr/bin/env python3
"""Fail unless the bundle is browser-shape: a wasm32 module with ZERO
imports, so WebAssembly.instantiate(bytes, {}) succeeds with no loader
shims. Parses only the import section (id 2); no external deps."""
import struct
import sys


def uleb(data, pos):
    out = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        out |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return out, pos
        shift += 7


def main(path):
    data = open(path, "rb").read()
    assert data[:4] == b"\x00asm", "not a wasm module"
    pos = 8
    imports = []
    while pos < len(data):
        sec_id = data[pos]
        pos += 1
        size, pos = uleb(data, pos)
        end = pos + size
        if sec_id == 2:
            count, pos = uleb(data, pos)
            for _ in range(count):
                mlen, pos = uleb(data, pos)
                mod_name = data[pos:pos + mlen].decode("utf-8", "replace")
                pos += mlen
                flen, pos = uleb(data, pos)
                field = data[pos:pos + flen].decode("utf-8", "replace")
                pos += flen
                kind = data[pos]
                pos += 1
                # Skip the kind payload so multi-import modules stay
                # aligned (verdict only needs the count, but names
                # should print correctly on failure).
                if kind == 0x00:  # func: type index
                    _, pos = uleb(data, pos)
                elif kind in (0x01, 0x02):  # table/memory: limits
                    flags, pos = uleb(data, pos)
                    _, pos = uleb(data, pos)  # minimum
                    if flags & 0x01:
                        _, pos = uleb(data, pos)  # maximum
                elif kind == 0x03:  # global: valtype + mutability
                    pos += 2
                else:
                    raise ValueError(f"unknown import kind {kind:#x}")
                imports.append((mod_name, field, kind))
        pos = end
    if imports:
        print(f"BROWSER-SHAPE FAIL: {len(imports)} imports:")
        for mod_name, field, kind in imports:
            print(f"  {mod_name}.{field} (kind {kind})")
        return 1
    print(f"BROWSER-SHAPE OK: {path} has zero imports")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
