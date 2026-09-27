#!/usr/bin/env python3
"""Scan AArch64 .text for ADRP(+ADD|LDR) address materialisation.

Finds code sites that reference given virtual addresses (e.g. string literals),
without relying on disassembler auto-analysis.
"""
import struct, sys

def sections(path):
    d = open(path, 'rb').read()
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i*e_shentsize
        nm, typ, fl, addr, off, size, link, info, al, ent = struct.unpack_from('<IIQQQQIIQQ', d, o)
        secs.append(dict(name_off=nm, type=typ, flags=fl, addr=addr, off=off, size=size))
    sh = secs[e_shstrndx]
    for s in secs:
        o = sh['off'] + s['name_off']
        s['name'] = d[o:d.index(b'\0', o)].decode()
    return d, secs

def get_sec(secs, name):
    for s in secs:
        if s['name'] == name: return s
    return None

def sx(v, bits=64):
    if v & (1 << (bits-1)):
        v -= (1 << bits)
    return v

def scan(path, targets):
    d, secs = sections(path)
    text = get_sec(secs, '.text')
    base = text['off']
    n = text['size'] // 4
    words = struct.unpack_from('<%dI' % n, d, base)
    addrs = set(targets)
    hits = []
    for i in range(n - 1):
        w = words[i]
        # ADRP: 1xx10000 ...
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1f
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        imm = sx(imm, 21)
        pc = text['addr'] + i*4
        page = (pc & ~0xFFF) + (imm << 12)
        # look ahead up to 4 instructions
        for k in range(1, 5):
            if i + k >= n: break
            w2 = words[i+k]
            rn = (w2 >> 5) & 0x1f
            if rn != rd:
                continue
            # ADD (immediate) 64-bit: 0x91......
            if (w2 & 0x7F800000) == 0x11000000 and ((w2 >> 31) & 1) == 1:
                sh = (w2 >> 22) & 1
                imm12 = (w2 >> 10) & 0xfff
                off = imm12 << (12 if sh else 0)
                tgt = page + off
                if tgt in addrs:
                    hits.append((text['addr'] + (i+k)*4, tgt, 'add', i))
            # LDR (immediate, unsigned offset) 64-bit: 0xF94.....
            if (w2 & 0xFFC00000) == 0xF9400000:
                imm12 = (w2 >> 10) & 0xfff
                off = imm12 * 8
                tgt = page + off
                if tgt in addrs:
                    hits.append((text['addr'] + (i+k)*4, tgt, 'ldr', i))
            # ADRP only (target is the page itself, rare)
            break
    return hits

if __name__ == '__main__':
    path = sys.argv[1]
    tgts = [int(x, 16) for x in sys.argv[2:]]
    hits = scan(path, tgts)
    print(f"[*] {len(hits)} code sites")
    for site, tgt, kind, i in hits:
        print(f"  insn@{site:#x} ({kind}) -> {tgt:#x}")
