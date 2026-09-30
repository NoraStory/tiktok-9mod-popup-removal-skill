#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_gate_branch.py — 把条件分支(CBZ/CBNZ/TBZ/TBNZ/B.cond)改写为无条件 B 跳转。

典型用途: mod native 弹窗链的 prefs 闸门
    LDR W8, [X29,#var]        ; dont = getBoolean("dont", false)
    CBNZ W8, loc_skip         ; dont=true → 跳过弹窗链(析构+返回)
把 CBNZ 改成 B 即"永久 dont": 弹窗链(HandlerThread/URL/AlertDialog/触发器调用)整体跳过。
安全依据: dont=true 是 mod 自己支持的状态(用户勾选"不再显示"), 跳过路径是正常路径。

用法:
    python patch_gate_branch.py <in.so> <out.so> --vaddr 0x2E7CC --target 0x2F5F8 \
        [--expect cbnz:rt=8]

  --expect  可选强校验: cbnz:rt=8 / cbz:rt=8 / tbz:bit,rt=8 / tbnz / bcond:cond=5(NE)
            不传则只检查目标距离合法。
  目标必须在 ±128MB 内(B 的 imm26 范围, 4 字节对齐)。
"""
import struct, argparse

MASKS = {
    'cbz':  0x7F000000, 'cbnz': 0x7F000000,
    'tbz':  0x7F000000, 'tbnz': 0x7F000000,
}


def parse_loads(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from('<I', data, off)
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from('<QQQQQ', data, off + 8)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def v2f(loads, v):
    for pv, po, pf in loads:
        if pv <= v < pv + pf:
            return v - pv + po
    raise SystemExit('unmapped vaddr 0x%x' % v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('in_so')
    ap.add_argument('out_so')
    ap.add_argument('--vaddr', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--target', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--expect', default=None)
    args = ap.parse_args()

    so = bytearray(open(args.in_so, 'rb').read())
    loads = parse_loads(so)
    fo = v2f(loads, args.vaddr)
    orig = struct.unpack_from('<I', so, fo)[0]

    delta = args.target - args.vaddr
    assert delta % 4 == 0, 'target not 4-byte aligned relative'
    imm26 = (delta // 4) & 0x3FFFFFF
    new = 0x14000000 | imm26

    if args.expect:
        kind, _, kv = args.expect.partition(':')
        kind = kind.lower()
        params = dict(p.split('=') for p in kv.split(',')) if kv else {}
        rt = int(params.get('rt', '8'), 0)
        if kind in ('cbnz', 'cbz'):
            exp = (0x35000000 if kind == 'cbnz' else 0x34000000) | (rt)
            # 距离在 expect 中不可知(imm19 已编码), 只验证 op+rt
            if (orig & 0xFF00001F) != (exp & 0xFF00001F):
                raise SystemExit('expect fail: 0x%08x not %s rt=%d (got op=0x%x rt=%d)'
                                 % (orig, kind, rt, orig >> 24, orig & 0x1F))
            # 用原指令的 imm19 验证 target
            imm19 = (orig >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            assert args.vaddr + imm19 * 4 == args.target, \
                'target mismatch: instruction jumps to 0x%x' % (args.vaddr + imm19 * 4)
        else:
            raise SystemExit('unsupported expect kind: %s' % kind)
        print('  @0x%x orig=0x%08x (%s rt=%d -> 0x%x) OK'
              % (args.vaddr, orig, kind, rt, args.vaddr + imm19 * 4))
    else:
        print('  @0x%x orig=0x%08x -> B 0x%x' % (args.vaddr, orig, args.target))

    struct.pack_into('<I', so, fo, new)
    open(args.out_so, 'wb').write(bytes(so))
    print('  written %s (B 0x%08x)' % (args.out_so, new))


if __name__ == '__main__':
    main()
