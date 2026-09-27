#!/usr/bin/env python3
"""Locate JNINativeMethod tables in an Android ELF .so.

Resolves R_AARCH64_RELATIVE relocations in .data.rel.ro so the {name, sig, fnPtr}
triples can be recovered even though the file stores zeroes there.
"""
import struct, sys

R_AARCH64_RELATIVE = 1027
R_AARCH64_ABS64 = 257
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026

class Elf:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        assert self.d[:4] == b'\x7fELF'
        self.is64 = self.d[4] == 2
        e_shoff = struct.unpack_from('<Q', self.d, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', self.d, 0x3a)[0]
        e_shnum = struct.unpack_from('<H', self.d, 0x3c)[0]
        e_shstrndx = struct.unpack_from('<H', self.d, 0x3e)[0]
        self.sections = []
        for i in range(e_shnum):
            off = e_shoff + i*e_shentsize
            name, typ, flags, addr, offset, size, link, info, align, entsize = \
                struct.unpack_from('<IIQQQQIIQQ', self.d, off)
            self.sections.append(dict(name_off=name, type=typ, flags=flags, addr=addr,
                                      offset=offset, size=size, link=link, info=info,
                                      align=align, entsize=entsize, idx=i))
        shstr = self.sections[e_shstrndx]
        for s in self.sections:
            s['name'] = self.cstr(shstr['offset'] + s['name_off'])
        # relocations
        self.relocs = {}   # vaddr -> addend (relative) or symbol-based
        self.reloc_list = []
        for s in self.sections:
            if s['type'] == 4:  # SHT_RELA
                n = s['size'] // 24
                for i in range(n):
                    o = s['offset'] + i*24
                    r_off, r_info, r_add = struct.unpack_from('<QQq', self.d, o)
                    rtype = r_info & 0xffffffff
                    rsym = r_info >> 32
                    self.reloc_list.append((r_off, rtype, rsym, r_add))
                    if rtype == R_AARCH64_RELATIVE:
                        self.relocs[r_off] = r_add
                    else:
                        self.relocs[r_off] = ('SYM', rsym, r_add)

    def cstr(self, off):
        end = self.d.index(b'\x00', off)
        return self.d[off:end].decode('utf-8', 'replace')

    def sec(self, name):
        for s in self.sections:
            if s['name'] == name: return s
        return None

    def sec_at(self, vaddr):
        for s in self.sections:
            if s['addr'] <= vaddr < s['addr'] + s['size'] and s['type'] != 8:
                return s
        return None

    def read(self, vaddr, n):
        s = self.sec_at(vaddr)
        if not s: return None
        off = s['offset'] + (vaddr - s['addr'])
        return self.d[off:off+n]

    def ptr(self, vaddr):
        """Read a pointer-sized value honouring relocations."""
        if vaddr in self.relocs:
            v = self.relocs[vaddr]
            if isinstance(v, tuple):
                return None, v
            return v, None
        raw = self.read(vaddr, 8)
        if raw is None: return None, None
        return struct.unpack('<Q', raw)[0], None

def find_strings(e, needles):
    """map needle -> vaddr of the string in a loaded section"""
    out = {}
    for s in e.sections:
        if not (s['flags'] & 0x2):  # SHF_ALLOC
            continue
        if s['type'] == 8:  # NOBITS
            continue
        data = e.d[s['offset']:s['offset']+s['size']]
        for nd in needles:
            b = nd.encode()
            i = data.find(b + b'\x00')
            if i >= 0 and nd not in out:
                out[nd] = s['addr'] + i
    return out

def main():
    path = sys.argv[1]
    needles = sys.argv[2:]
    e = Elf(path)
    text = e.sec('.text')
    rodata = e.sec('.rodata')
    datarel = e.sec('.data.rel.ro')
    print(f"[*] {path}")
    print(f"[*] .text      {text['addr']:#x} - {text['addr']+text['size']:#x}")
    print(f"[*] .rodata    {rodata['addr']:#x} - {rodata['addr']+rodata['size']:#x}")
    print(f"[*] .data.rel.ro {datarel['addr']:#x} - {datarel['addr']+datarel['size']:#x}")
    print(f"[*] relocs: {len(e.reloc_list)}  (relative: {sum(1 for r in e.reloc_list if r[1]==R_AARCH64_RELATIVE)})")

    sv = find_strings(e, needles) if needles else {}
    if needles:
        print("\n[*] string vaddrs:")
        for k, v in sv.items():
            print(f"    {k!r} @ {v:#x}")

    def str_at(vaddr, maxlen=256):
        s = e.sec_at(vaddr)
        if not s or s['type'] == 8: return None
        off = s['offset'] + (vaddr - s['addr'])
        chunk = e.d[off:off+maxlen]
        i = chunk.find(b'\x00')
        if i < 0: return None
        try:
            return chunk[:i].decode('utf-8')
        except Exception:
            return None

    # Enumerate JNINativeMethod triples across all writable loaded sections
    print("\n[*] JNINativeMethod candidates:")
    found = []
    for s in e.sections:
        if not (s['flags'] & 0x2) or s['type'] == 8: continue
        if s['name'] not in ('.data.rel.ro', '.data'): continue
        n = s['size'] // 8
        for i in range(n - 2):
            a = s['addr'] + i*8
            p0, _ = e.ptr(a)
            p1, _ = e.ptr(a+8)
            p2, _ = e.ptr(a+16)
            if not p0 or not p1 or not p2: continue
            if not (text['addr'] <= p2 < text['addr']+text['size']): continue
            nm = str_at(p0)
            sg = str_at(p1)
            if not nm or not sg: continue
            if not sg.startswith('('): continue
            if not all(32 <= ord(c) < 127 for c in nm): continue
            found.append((a, nm, sg, p2, s['name']))
    for a, nm, sg, p2, secname in found:
        mark = ''
        if needles and nm in sv: mark = '   <<<< MATCH'
        print(f"    {secname} @{a:#x}: {nm}{sg} -> fn {p2:#x}{mark}")
    print(f"[*] total {len(found)} native method entries")

if __name__ == '__main__':
    main()
