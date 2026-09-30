#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dump_jnitable.py — 从 .so 还原 JNINativeMethod 注册表(哪个 Java native 方法由哪个函数实现)。

为什么需要: Dex2C/加固器把 Java 方法抽成 native 后, 唯一的"方法名→实现地址"映射
就在 RegisterNatives 的 JNINativeMethod 数组 {name*, sig*, fn*} (24B/项) 里。
拿到这张表才知道该反编译哪个地址。

关键陷阱:
  * 表在 .data.rel.ro, 属 PIE 重定位区: 文件内指针槽位是链接期占位值,
    真实地址存于 .rela.dyn 的 R_AARCH64_RELATIVE(1027) 重定位 addend。
    必须用 addend 覆盖文件值, 否则全表解析为 0/乱值(本案例踩过)。
  * vaddr≠file offset: 多段 LOAD 时 vaddr = offset + 段差, 按 program header 换算。
  * 指针指向的字符串在 .rodata(通常 vaddr==file offset), 直接按偏移读 C 字符串。

用法:
    python dump_jnitable.py <lib.so> [--anchor 0x1005e0] [--span 80] [--class-str substr]

  --anchor   已知一个表项的 vaddr(例如用 IDA 找到某函数仅被一个 data xref 引用,
             该 xref 所在槽即某表项的 fn 字段, 减 16 得表项起点)。
  --span     从锚点前后各扫多少个表项。
输出: vaddr  name  signature  fn_addr
"""
import struct, argparse


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


def parse_rela_relative(data):
    """返回 {vaddr: addend} 仅 R_AARCH64_RELATIVE"""
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    shs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from('<IIQQQQ', data, off)
        shs.append((name, addr, offset, size))
    stroff = shs[e_shstrndx][2]

    def shname(n):
        j = stroff + n
        k = j
        while data[k] != 0:
            k += 1
        return data[j:k].decode()

    relmap = {}
    for name, addr, offset, size in shs:
        if shname(name) == '.rela.dyn':
            for i in range(size // 24):
                r_off, r_info, r_addend = struct.unpack_from('<QQq', data, offset + i * 24)
                if (r_info & 0xFFFFFFFF) == 1027:  # R_AARCH64_RELATIVE
                    relmap[r_off] = r_addend
    return relmap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--anchor', type=lambda x: int(x, 0), default=None,
                    help='已知表项 vaddr(该项 fn 字段) 或表项起点')
    ap.add_argument('--span', type=int, default=80)
    ap.add_argument('--filter', default='', help='只显示 name 包含该子串的表项')
    args = ap.parse_args()

    data = open(args.so, 'rb').read()
    loads = parse_loads(data)
    relmap = parse_rela_relative(data)

    def v2f(v):
        for pv, po, pf in loads:
            if pv <= v < pv + pf:
                return v - pv + po
        return None

    def cstr(v):
        if not (0 < v < len(data)):
            return None
        j = v2f(v)
        k = j
        while k < len(data) and data[k] != 0:
            k += 1
        return data[j:k].decode('utf-8', 'replace')

    # 无锚点时: 全量扫 .data.rel.ro(第一个 LOAD 结束后的段)
    if args.anchor is None:
        # 找第二段 LOAD(通常 .data.rel.ro)
        scan = [(pv, pf) for pv, po, pf in loads[1:3]]
        anchors = [pv + 8 * i for pv, pf in scan for i in range(0, pf // 8)]
    else:
        anchors = [args.anchor]

    seen = set()
    for a in anchors:
        for i in range(-args.span, args.span):
            va = a + 24 * i
            fo = v2f(va)
            if fo is None or fo < 0 or fo + 24 > len(data):
                continue
            nptr = relmap.get(va, struct.unpack_from('<Q', data, fo)[0])
            sptr = relmap.get(va + 8, struct.unpack_from('<Q', data, fo + 8)[0])
            fptr = relmap.get(va + 16, struct.unpack_from('<Q', data, fo + 16)[0])
            if not (0x10000 <= nptr < 0x400000 and 0x10000 <= sptr < 0x400000 and 0x10000 <= fptr < 0x400000):
                continue
            nm, sg = cstr(nptr), cstr(sptr)
            if not nm or not sg:
                continue
            if not (sg.startswith('(') or sg in ('I', 'J', 'Z', 'V', '[B', 'F', 'D', 'S', 'C')):
                continue
            key = (nm, sg, fptr)
            if key in seen:
                continue
            seen.add(key)
            if args.filter and args.filter not in nm:
                continue
            print('0x%06x  %-30s %-70s fn=0x%x' % (va, nm[:30], sg[:70], fptr))


if __name__ == '__main__':
    main()
