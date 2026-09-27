#!/usr/bin/env python3
"""Rebuild the modded APK with a single replaced dex, preserving every other
entry byte-for-byte (compression method, order, timestamps, permissions).

The original APK Signing Block is intentionally dropped: the archive is
re-signed afterwards with apksigner.
"""
import zipfile, sys, shutil, os

src = sys.argv[1]
dst = sys.argv[2]
replacements = {}
for spec in sys.argv[3:]:
    name, path = spec.split('=', 1)
    replacements[name] = path

zin = zipfile.ZipFile(src, 'r')
existing = set(zin.namelist())
added = 0
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
    if zin.comment:
        zout.comment = zin.comment
    for item in zin.infolist():
        if item.filename in replacements:
            data = open(replacements[item.filename], 'rb').read()
            print(f"  [replace] {item.filename}: {item.file_size} -> {len(data)} bytes")
        else:
            data = zin.read(item.filename)
        zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
        zi.compress_type = item.compress_type
        zi.external_attr = item.external_attr
        zi.internal_attr = item.internal_attr
        zi.create_system = item.create_system
        # ZIP_STORED needs the CRC/sizes to be consistent; writestr handles it
        zout.writestr(zi, data)
    # add entries that do not exist in the source archive (e.g. frida gadget)
    for name, path in replacements.items():
        if name in existing:
            continue
        data = open(path, 'rb').read()
        zi = zipfile.ZipInfo(name)
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o100644 << 16
        zout.writestr(zi, data)
        added += 1
        print(f"  [add]     {name}: {len(data)} bytes")
zin.close()
print(f"[*] wrote {dst}  ({os.path.getsize(dst)} bytes)")
