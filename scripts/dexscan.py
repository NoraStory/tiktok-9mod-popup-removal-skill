#!/usr/bin/env python3
"""Minimal DEX parser: find which classes/methods reference target types.

Usage:
  python3 dexscan.py <dex_dir> [prefix1 prefix2 ...] [--classes]
  python3 dexscan.py dex                       # scan all dex, report all mod refs
  python3 dexscan.py dex Lcom/aaaaaaa/         # only report refs to com.aaaaaaa.*
  python3 dexscan.py dex --classes             # list class definitions only

No hardcoded paths or version assumptions. Pure DEX format parser.
Works with any Android APK's extracted .dex files.

Known mod injection package prefixes are built-in but can be overridden.
"""
import struct, sys, os

# --- opcode sizes in 16-bit code units ---
SIZE1 = set([0x00,0x01,0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,
             0x1d,0x1e,0x21,0x27,0x28,0x3e,0x3f,0x40,0x41,0x42,0x43,0x73,0x79,0x7a])
SIZE2 = set([0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,
             0xfe,0xff])
SIZE3 = set([0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,0xfc,0xfd])
SIZE4 = set([0xfa,0xfb])
SIZE5 = set([0x18])

def op_size(op):
    if op in SIZE5: return 5
    if op in SIZE4: return 4
    if op in SIZE3: return 3
    if op in SIZE2: return 2
    if op in SIZE1: return 1
    if 0x2d <= op <= 0x31: return 2
    if 0x32 <= op <= 0x3d: return 2
    if 0x44 <= op <= 0x51: return 2
    if 0x52 <= op <= 0x5f: return 2
    if 0x60 <= op <= 0x6d: return 2
    if 0x6e <= op <= 0x72: return 3
    if 0x74 <= op <= 0x78: return 3
    if 0x7b <= op <= 0x8f: return 1
    if 0x90 <= op <= 0xaf: return 2
    if 0xb0 <= op <= 0xcf: return 1
    if 0xd0 <= op <= 0xd7: return 2
    if 0xd8 <= op <= 0xe2: return 2
    if 0xe3 <= op <= 0xf9: return 1
    return 1

class Dex:
    def __init__(self, path):
        self.path = path
        self.buf = open(path, 'rb').read()
        b = self.buf
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from('<12I', b, 56)
        self._strings = {}
        self._types = {}
        self._methods = {}
        self._fields = {}

    def uleb(self, off):
        r = 0; s = 0
        while True:
            x = self.buf[off]; off += 1
            r |= (x & 0x7f) << s
            if not (x & 0x80): break
            s += 7
        return r, off

    def string(self, idx):
        if idx in self._strings: return self._strings[idx]
        off = struct.unpack_from('<I', self.buf, self.string_ids_off + idx*4)[0]
        n, off = self.uleb(off)
        end = self.buf.index(b'\x00', off)
        s = self.buf[off:end].decode('utf-8', 'replace')
        self._strings[idx] = s
        return s

    def type_desc(self, idx):
        if idx in self._types: return self._types[idx]
        si = struct.unpack_from('<I', self.buf, self.type_ids_off + idx*4)[0]
        d = self.string(si)
        self._types[idx] = d
        return d

    def method(self, idx):
        if idx in self._methods: return self._methods[idx]
        cls, proto, name = struct.unpack_from('<HHI', self.buf, self.method_ids_off + idx*8)
        v = (self.type_desc(cls), self.string(name))
        self._methods[idx] = v
        return v

    def field(self, idx):
        if idx in self._fields: return self._fields[idx]
        cls, typ, name = struct.unpack_from('<HHI', self.buf, self.field_ids_off + idx*8)
        v = (self.type_desc(cls), self.string(name), self.type_desc(typ))
        self._fields[idx] = v
        return v

    def class_defs(self):
        out = []
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i*32
            (cls_idx, access, super_idx, ifaces, src_idx,
             anno_off, cdata_off, static_vals) = struct.unpack_from('<8I', self.buf, off)
            out.append((self.type_desc(cls_idx), cdata_off))
        return out

    def methods_of(self, cdata_off):
        """yield (method_name, code_off)"""
        if cdata_off == 0: return
        off = cdata_off
        sf, off = self.uleb(off)
        inf, off = self.uleb(off)
        dm, off = self.uleb(off)
        vm, off = self.uleb(off)
        for _ in range(sf):
            _, off = self.uleb(off); _, off = self.uleb(off)
        for _ in range(inf):
            _, off = self.uleb(off); _, off = self.uleb(off)
        midx = 0
        for _ in range(dm):
            d, off = self.uleb(off)
            midx += d
            acc, off = self.uleb(off)
            code_off, off = self.uleb(off)
            yield self.method(midx)[1], code_off
        midx = 0
        for _ in range(vm):
            d, off = self.uleb(off)
            midx += d
            acc, off = self.uleb(off)
            code_off, off = self.uleb(off)
            yield self.method(midx)[1], code_off

    def instructions(self, code_off):
        if code_off == 0: return
        b = self.buf
        insns_size = struct.unpack_from('<I', b, code_off + 12)[0]
        base = code_off + 16
        i = 0
        while i < insns_size:
            op = struct.unpack_from('<H', b, base + i*2)[0]
            if op == 0x0100:
                sz = struct.unpack_from('<H', b, base + (i+1)*2)[0]
                i += sz*2 + 4; continue
            if op == 0x0200:
                sz = struct.unpack_from('<H', b, base + (i+1)*2)[0]
                i += sz*4 + 2; continue
            if op == 0x0300:
                ew = struct.unpack_from('<H', b, base + (i+1)*2)[0]
                sz = struct.unpack_from('<I', b, base + (i+2)*2)[0]
                i += (sz*ew + 1)//2 + 4; continue
            n = op_size(op)
            ops = []
            for k in range(1, n):
                ops.append(struct.unpack_from('<H', b, base + (i+k)*2)[0])
            yield op, tuple(ops)
            i += n

# --- known mod injection package prefixes (extend as new versions are discovered) ---
KNOWN_MOD_PREFIXES = (
    'Lcom/aaaaaaa/',       # Gold / Assem / TikTok Prime
    'Lme/tiktokupdatez/',   # 9MOD / max.ru
    'L\u012bi/\u00efi/',    # 9MOD (Unicode class name obfuscation)
    'Lassem/',              # ApkSignatureKillerEx + variants
    'Lprime0/',             # Dex2C loader (v46.7.5)
    'Lprobeq0/',            # Dex2C loader (v46.3.5)
    'LGoldDcc0/',           # Dex2C loader (Gold)
    'Lieuwh0/',             # native loader (v46.7.5)
    'Lchillbro0/',          # native loader (v46.3.5)
    'Lcom/acra/',           # ACRA crash reporter
    'Lcom/tiktok/plugin/',  # TikTok mod plugin client
)

def scan(path, want_prefixes=None, list_classes_only=False):
    """Scan a single dex for references to target type prefixes."""
    d = Dex(path)
    prefixes = want_prefixes or KNOWN_MOD_PREFIXES
    if list_classes_only:
        return [(c, cdata) for c, cdata in d.class_defs()
                if any(c.startswith(p) for p in prefixes)], d
    hits = []
    for cls, cdata in d.class_defs():
        for mname, code_off in (d.methods_of(cdata) or []):
            if not code_off: continue
            for op, ops in d.instructions(code_off):
                if op == 0x1a and ops:
                    si = ops[0]
                    if si < d.string_ids_size:
                        s = d.string(si)
                        if any(s.startswith(p) for p in prefixes):
                            hits.append((cls, mname, 'const-string', s))
                elif op == 0x1b and len(ops) >= 2:
                    si = ops[0] | (ops[1] << 16)
                    if si < d.string_ids_size:
                        s = d.string(si)
                        if any(s.startswith(p) for p in prefixes):
                            hits.append((cls, mname, 'const-string/jumbo', s))
                elif op in (0x1c,0x1f,0x20,0x22,0x23,0x24,0x25,0xfe,0xff) and ops:
                    if ops[0] < d.type_ids_size:
                        t = d.type_desc(ops[0])
                        if any(t.startswith(p) for p in prefixes):
                            hits.append((cls, mname, 'type', t))
                elif (0x6e <= op <= 0x72 or 0x74 <= op <= 0x78 or op in (0xfa,0xfb)) and ops:
                    if ops[0] < d.method_ids_size:
                        tc, tn = d.method(ops[0])
                        if any(tc.startswith(p) for p in prefixes):
                            hits.append((cls, mname, 'invoke', tc + '->' + tn))
                elif 0x60 <= op <= 0x6d and ops:
                    if ops[0] < d.field_ids_size:
                        fc, fn, ft = d.field(ops[0])
                        if any(fc.startswith(p) for p in prefixes):
                            hits.append((cls, mname, 'field', fc + '->' + fn))
    return hits, d

if __name__ == '__main__':
    dexdir = sys.argv[1]
    args = sys.argv[2:]
    list_classes = '--classes' in args
    want = tuple(a for a in args if not a.startswith('--')) or None
    allhits = {}
    for f in sorted(os.listdir(dexdir)):
        if not f.endswith('.dex'): continue
        p = os.path.join(dexdir, f)
        try:
            if list_classes:
                hits, d = scan(p, want, list_classes_only=True)
                if hits:
                    print(f"===== {f} =====")
                    for c, _ in hits:
                        print(f"  {c}")
            else:
                hits, d = scan(p, want)
                if hits:
                    allhits[f] = hits
        except Exception as e:
            print(f"ERR {f}: {e}", file=sys.stderr)
    if not list_classes:
        for f, hits in allhits.items():
            print(f"===== {f} =====")
            for c, m, k, t in hits:
                print(f"  {c}::{m}  [{k}] {t}")
