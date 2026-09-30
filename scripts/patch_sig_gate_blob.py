#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_sig_gate_blob.py — 重写"双重 MD5 签名门"的期望值(46.3.5 libiam me.tigrik.a.a 实例)。

门逻辑(全解见 case-46.3.5/SIGNATURE-GATE-BREAKTHROUGH.md):
    hex1  = md5(所有 signer cert 拼接).hex()          # 32字符小写
    upper = (hex1+hex1).toUpperCase()                 # 64字符
    final = md5(upper.bytes).hex()                    # 32字符 ← 与期望值比较
    期望值藏在 506B XOR-blob 里: 明文 = 3字符前缀 + base64(Java序列化 String[])
    args[0] = 32字符 hex 期望; args[1:] = 反hook黑名单类名(Class.forName 探测, CNF被catch)

替换原理(等长差分, 完全绕开加密算法):
    新密文 = 旧密文 XOR 旧明文 XOR 新明文
    只要新明文与旧明文等长(32hex→32hex 等长替换), 无需知道 keystream 细节。

用法:
    python patch_sig_gate_blob.py <src.so> <out.so> --cert <new-cert.der> \
        [--blob-off 0x23E64 --blob-len 506 --key 0xDF278B5B95B52DF3 --prefix 3]

流程:
    1. 读 src.so 的 blob → 解密(keystream=K 8B 循环, 与 decode_xor_blob.py 一致)
    2. NUL 截断取明文字符串; 去 prefix; base64 补 padding 解码序列化流
    3. 扫描 TC_STRING(0x74) 定位 32 字符 hex 期望值; 断言 == md5((md5(旧cert).hex()*2).upper())
       (可选 --expect-old 传入旧证书以强校验)
    4. 等长替换为新证书的 final → 重编码 base64 → 断言总长不变
    5. 重加密写回 out.so; 回读解密断言新值在位
"""
import struct, base64, hashlib, argparse


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


def gate_final(cert_der):
    """门的期望值算法: md5((md5(cert).hex()*2).upper())"""
    h1 = hashlib.md5(cert_der).hexdigest()
    return hashlib.md5((h1 * 2).upper().encode()).hexdigest()


def decrypt(enc, key):
    kb = struct.pack('<Q', key)
    ks = (kb * ((len(enc) // 8) + 2))[: len(enc)]
    return bytearray(a ^ b for a, b in zip(enc, ks))


def encrypt(pt, key):
    return decrypt(pt, key)  # XOR 对称


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src_so')
    ap.add_argument('out_so')
    ap.add_argument('--cert', required=True, help='重签所用证书 DER(= PackageManager 将返回的)')
    ap.add_argument('--blob-off', type=lambda x: int(x, 0), default=0x23E64)
    ap.add_argument('--blob-len', type=lambda x: int(x, 0), default=506)
    ap.add_argument('--key', type=lambda x: int(x, 0), default=0xDF278B5B95B52DF3)
    ap.add_argument('--prefix', type=int, default=3)
    ap.add_argument('--expect-old', default=None, help='旧证书 DER, 用于强校验定位的期望值')
    args = ap.parse_args()

    so = bytearray(open(args.src_so, 'rb').read())
    loads = parse_loads(so)
    fo = v2f(loads, args.blob_off)
    enc = bytes(so[fo: fo + args.blob_len])
    pt = decrypt(enc, args.key)

    nul = pt.index(0)
    s = bytes(pt[:nul]).decode('ascii')
    b64 = s[args.prefix:]
    raw = base64.b64decode(b64 + '=' * (-len(b64) % 4))
    assert raw[:4] == b'\xac\xed\x00\x05', 'not a java serialized stream: %s' % raw[:4].hex()

    # 定位 TC_STRING 里的 32hex
    target = None
    i = 0
    while i < len(raw) - 3:
        if raw[i] == 0x74:  # TC_STRING
            ln = struct.unpack_from('>H', raw, i + 1)[0]
            if i + 3 + ln <= len(raw) and ln == 32:
                val = raw[i + 3: i + 3 + ln]
                try:
                    if all(c in b'0123456789abcdefABCDEF' for c in val):
                        target = (i + 3, val.decode())
                except Exception:
                    pass
        i += 1
    assert target, '32-hex expected-digest not found in stream'
    off, old_val = target
    print('old expected gate digest: %s @serial 0x%x' % (old_val, off))

    if args.expect_old:
        want = gate_final(open(args.expect_old, 'rb').read())
        print('  matches provided old cert:', old_val.lower() == want)
    new_final = gate_final(open(args.cert, 'rb').read())
    print('new expected gate digest: %s' % new_final)

    new_serial = bytearray(raw)
    new_serial[off: off + 32] = new_final.encode('ascii')
    new_b64 = base64.b64encode(bytes(new_serial)).decode('ascii').rstrip('=')
    new_plain = s[:args.prefix] + new_b64
    assert len(new_plain) == len(s), 'length changed! %d != %d' % (len(new_plain), len(s))

    new_pt = bytearray(new_plain, 'ascii')
    new_pt.append(0)
    while len(new_pt) < len(pt):
        new_pt.append(0)
    new_pt[len(pt) - 1] = pt[len(pt) - 1]  # 保留尾字节(原明文 505/506 布局)
    new_enc = encrypt(new_pt, args.key)
    so[fo: fo + args.blob_len] = new_enc
    open(args.out_so, 'wb').write(bytes(so))

    # 回读验证
    so2 = open(args.out_so, 'rb').read()
    chk = decrypt(so2[fo: fo + args.blob_len], args.key)
    chk_s = bytes(chk[:chk.index(0)]).decode('ascii')
    chk_raw = base64.b64decode(chk_s[args.prefix:] + '=' * (-(len(chk_s) - args.prefix) % 4))
    assert new_final.encode() in chk_raw
    diffs = sum(1 for a, b in zip(enc, new_enc) if a != b)
    print('written %s; roundtrip OK; %d cipher bytes differ' % (args.out_so, diffs))


if __name__ == '__main__':
    main()
