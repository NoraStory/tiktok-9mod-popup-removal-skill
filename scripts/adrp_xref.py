#!/usr/bin/env python3
"""ADRP+ADD / ADRP+LDR xref scanner for AArch64 ELF.
usage: adrp_xref.py file.so [--list] [target_va ...]"""
import struct, sys
def sx(v, b=64): return v-(1<<b) if v&(1<<(b-1)) else v
path = sys.argv[1]
argv = sys.argv[2:]
list_all = '--list' in argv
targets = set(int(x,0) for x in argv if not x.startswith('--'))
d = open(path,'rb').read()
e_shoff, = struct.unpack_from('<Q', d, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x3a)
secs = [struct.unpack_from('<IIQQQQIIQQ', d, e_shoff+i*e_shentsize) for i in range(e_shnum)]
sh = secs[e_shstrndx]
def sname(nm):
    o = sh[4]+nm; return d[o:d.index(b'\0',o)].decode()
text = next(s for s in secs if sname(s[0]) == '.text')
off, size, va = text[4], text[5], text[3]
hits = []
allt = {}
for i in range(size//4):
    pc = va+i*4
    w = struct.unpack_from('<I', d, off+i*4)[0]
    if (w & 0x9F000000) != 0x90000000: continue
    rd = w & 31
    immlo = (w>>29)&3; immhi = (w>>5)&0x7ffff
    imm = (immhi<<2)|immlo
    if imm & (1<<32): imm -= (1<<33)
    page = ((pc & ~0xfff) + (imm<<12)) & 0xFFFFFFFFFFFFFFFF
    for j in range(1, 24):
        if i+j >= size//4: break
        w2 = struct.unpack_from('<I', d, off+(i+j)*4)[0]
        if (w2 & 0x9F000000) == 0x90000000: break
        if (w2 & 0xFF800000) in (0x91000000, 0x11000000) and (w2 & 31) == rd:  # ADD imm
            imm12 = (w2>>10)&0xfff; sh2 = (w2>>22)&1
            tgt = page + (imm12 << (12 if sh2 else 0))
            hits.append((pc, tgt)); allt[tgt] = pc; break
        if (w2 & 0xFFC00000) in (0xF9400000, 0xB9400000) and (w2 & 31) == rd:  # LDR imm unsigned
            imm12 = (w2>>10)&0xfff
            scale = 8 if (w2 & 0xFFC00000) == 0xF9400000 else 4
            tgt = page + imm12*scale
            hits.append((pc, tgt)); allt[tgt] = pc; break
if list_all:
    for tgt, pc in sorted(allt.items()): print(f"0x{pc:x} -> 0x{tgt:x}")
else:
    for pc, tgt in hits:
        if tgt in targets: print(f"  text_pc=0x{pc:x} -> 0x{tgt:x}")
    print(f"[*] {sum(1 for _,t in hits if t in targets)} sites")
