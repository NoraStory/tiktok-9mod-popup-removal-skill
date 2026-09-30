#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decode_xor_blob.py — 解密 Dex2C/加固器的 XOR-stream 加密 blob(NEON 位运算的等效化简)。

背景(46.3.5 libiam.so 0x23E64 实例):
  原生代码用 NEON(vshlq_u64/vqtbl4q)生成 keystream, 手工复刻极易出错。
  推演发现: 每轮 shift=(idx*8)&0x38, 而 idx=16r+k → (16r+k)&7 == k&7,
  即 31 轮 keystream 完全相同; vqtbl4q 索引 64-120 越界返回 0, 而 v89 只取
  tbl172/tbl173 的 lane0 → 等效 keystream = K(8B LE) 重复循环。
  验证手段: 解出的明文应为 "3字符前缀 + base64(Java序列化流, 头 ac ed 00 05)"。

用法:
    python decode_xor_blob.py <lib.so> <vaddr> <length> --key 0xDF278B5B95B52DF3 [--round8]

  --round8  keystream = K 8字节循环(默认); 不加则按 16 字节 K+K(等价)。
输出:
  明文 hex + 可打印预览; --out 可另存 .bin
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


def v2f(loads, v):
    for pv, po, pf in loads:
        if pv <= v < pv + pf:
            return v - pv + po
    raise SystemExit('unmapped vaddr 0x%x' % v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('vaddr', type=lambda x: int(x, 0))
    ap.add_argument('length', type=lambda x: int(x, 0))
    ap.add_argument('--key', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()

    data = open(args.so, 'rb').read()
    loads = parse_loads(data)
    fo = v2f(loads, args.vaddr)
    enc = data[fo: fo + args.length]
    kb = struct.pack('<Q', args.key)
    ks = (kb * ((args.length // len(kb)) + 2))[: args.length]
    pt = bytes(a ^ b for a, b in zip(enc, ks))

    print('cipher[:16]: %s' % enc[:16].hex(' '))
    print('plain  len=%d' % len(pt))
    print('plain[:48]: %s' % pt[:48].hex(' '))
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in pt)
    print('ascii: %r' % printable[:120])
    nul = pt.find(0)
    if nul > 0:
        print('NUL at %d, string=%r' % (nul, printable[:nul][:200]))
    if args.out:
        open(args.out, 'wb').write(pt)
        print('saved ->', args.out)


if __name__ == '__main__':
    main()
