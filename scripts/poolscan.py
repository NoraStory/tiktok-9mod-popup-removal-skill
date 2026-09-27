#!/usr/bin/env python3
"""Resolve string-pool accesses in libGoldDcc.so.

The library fetches the .data string-pool base from fcn.0002eef4 (returns 0x15e100)
and then reaches individual literals with `add xD, xBase, #imm`. This script
emulates the few instructions after every call to that getter to recover which
string each call site uses, and which function contains it.
"""
import struct, sys

POOL_GETTER = 0x2eef4
POOL_BASE = 0x15e100

def load(path):
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

def sx(v, b):
    return v - (1 << b) if v & (1 << (b-1)) else v

def main():
    path = sys.argv[1]
    needles = sys.argv[2:]
    d, secs = load(path)
    S = {s['name']: s for s in secs}
    text, data = S['.text'], S['.data']
    # locate needle strings inside .data
    db = d[data['off']:data['off']+data['size']]
    strmap = {}
    for nd in needles:
        i = db.find(nd.encode() + b'\x00')
        if i >= 0:
            strmap[data['addr'] + i] = nd
    print("[*] target strings:")
    for a, n in sorted(strmap.items()):
        print(f"    {a:#x} (pool+{a-POOL_BASE:#x})  {n!r}")

    n = text['size']//4
    words = struct.unpack_from('<%dI' % n, d, text['off'])
    def at(i):
        return text['addr'] + i*4
    def rd(w): return w & 0x1f
    def rn(w): return (w >> 5) & 0x1f

    # find BL to the pool getter
    calls = []
    for i, w in enumerate(words):
        if (w & 0xFC000000) == 0x94000000:
            tgt = at(i) + sx(w & 0x3ffffff, 26)*4
            if tgt == POOL_GETTER:
                calls.append(i)
    print(f"[*] {len(calls)} calls to pool getter")

    hits = []
    for ci in calls:
        regs = {0: POOL_BASE}
        for k in range(1, 60):
            j = ci + k
            if j >= n: break
            w = words[j]
            # ADD (imm) 64-bit
            if (w & 0x7F800000) == 0x11000000 and ((w >> 31) & 1) == 1 and ((w >> 29) & 1) == 0:
                sh = (w >> 22) & 1
                imm = ((w >> 10) & 0xfff) << (12 if sh else 0)
                src = regs.get(rn(w))
                if src is not None:
                    regs[rd(w)] = src + imm
                else:
                    regs.pop(rd(w), None)
            # MOV (reg) 64-bit: ORR Xd, XZR, Xm
            elif (w & 0xFFE0FFE0) == 0xAA0003E0:
                src = regs.get((w >> 16) & 0x1f)
                if src is not None: regs[rd(w)] = src
                else: regs.pop(rd(w), None)
            elif (w & 0x7F000000) in (0x11000000,):
                pass
            # any other instruction writing Rd invalidates it (rough)
            elif (w & 0x1f) != 31 and not (w & 0x80000000 == 0 and (w & 0x7C000000) == 0):
                if (w >> 31) & 1 or (w & 0x1F000000) == 0x10000000:
                    pass
            # check for uses of a pool-derived register in a call argument
            if (w & 0xFC000000) == 0x94000000 or (w & 0xFFFFFC1F) == 0xD63F0000:
                # BL or BLR -> argument regs are x0..x7 (or x1.. for NewStringUTF)
                for r in range(0, 8):
                    v = regs.get(r)
                    if v in strmap:
                        hits.append((at(j), r, v, strmap[v]))
            if k > 40: break
    print(f"[*] {len(hits)} string-use sites")
    seen = set()
    for site, r, v, nm in hits:
        if (site, nm) in seen: continue
        seen.add((site, nm))
        print(f"    {site:#x}  x{r} -> {nm!r}")

if __name__ == '__main__':
    main()
