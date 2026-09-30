#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sigblock_extract.py — 提取 APK 签名块(v2/v3)与 v1 JAR 签名中的全部证书。

用途: 在破解"运行时签名校验门"前,必须知道原包到底有哪几张证书、
      PackageManager 实际记录的是哪一张(用 `dumpsys package <pkg>` 的
      Signatures: [SHA-256] 与本脚本输出对照,三方可互相印证)。

用法:
    python sigblock_extract.py <apk> [--outdir out_dir]

输出:
    out_dir/v2_cert_0.der / v3_cert_0.der / v1_cert_N.der
    stdout: 每张证书的 len + sha256 + md5

要点:
  * APK Signing Block 布局:
        [uint64 size][ID-value pairs...][uint64 size][16B magic "APK Sig Block 42"]
    footer 的 size 值不含 footer 自身 8 字节, block 起点 = (magic+16) - size - 8。
    pair ID: 0x7109871a=v2, 0xf05368c0=v3, 0x42726577=padding, 0x204b5041=dependency。
  * v2/v3 内层: pair → signers 序列 → signer → signed_data →
    digests(len+entries) → certificates(len+cert entries) → minSDK [v3 加 maxSDK]。
    每层都是 uint32 小端长度前缀, 容易少剥一层(本案例踩过)。
  * v1: META-INF/*.RSA 是 PKCS#7 容器; 证书在 [0] IMPLICIT(A0 82 xx xx)内,
    内部逐张 30 82 xx xx。PM 在无 v2/v3 时才回退读 v1。
"""
import struct, hashlib, os, sys, argparse


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def extract_v2v3_certs(signers_buf, label, outdir):
    """signers_buf = 签名块 pair value; 逐层剥: signers→signer→signed_data→certificates"""
    results = []
    off = 0
    seq_len = u32(signers_buf, off)          # signers 整体
    inner = off + 4
    n = 0
    while inner + 4 <= off + 4 + seq_len:
        signer_len = u32(signers_buf, inner)
        signer = signers_buf[inner + 4: inner + 4 + signer_len]
        sd_len = u32(signer, 0)
        sd = signer[4: 4 + sd_len]
        p = 4 + u32(sd, 0)                    # 跳过 digests
        certs_len = u32(sd, p)
        p += 4
        certs_end = p + certs_len
        while p + 4 <= certs_end:
            c_len = u32(sd, p)
            cert = sd[p + 4: p + 4 + c_len]
            results.append((label, n, cert))
            n += 1
            p += 4 + c_len
        inner += 4 + signer_len
        break
    return results


def extract_v1_certs(pkcs7):
    """从 PKCS#7 容器提取证书链: 找 [0] IMPLICIT (A0 82 ..) 再逐张 30 82 .."""
    out = []
    i = pkcs7.find(b'\xa0\x82')
    if i < 0:
        return out
    cl = struct.unpack_from('>H', pkcs7, i + 2)[0]
    blob = pkcs7[i + 4: i + 4 + cl]   # [0] 头 = tag(1) + 长度形式 0x82+2B = 4 字节
    j = 0
    while j + 4 <= len(blob):
        if blob[j] == 0x30 and blob[j + 1] == 0x82:
            L = struct.unpack_from('>H', blob, j + 2)[0]
            out.append(blob[j: j + 4 + L])
            j += 4 + L
        else:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('apk')
    ap.add_argument('--outdir', default='sigcerts')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    data = open(args.apk, 'rb').read()
    magic = b'APK Sig Block 42'
    mi = data.rfind(magic)
    certs = []
    if mi >= 0:
        block_size = struct.unpack_from('<Q', data, mi - 8)[0]
        end = mi + 16
        start = end - block_size - 8
        pos = start + 8
        pairs = {}
        while pos < end - 24:
            plen = struct.unpack_from('<Q', data, pos)[0]
            pid = struct.unpack_from('<I', data, pos + 8)[0]
            pairs[pid] = data[pos + 12: pos + 8 + plen]
            pos += 8 + plen
        for pid, lbl in ((0x7109871a, 'v2'), (0xf05368c0, 'v3')):
            if pid in pairs:
                certs += extract_v2v3_certs(pairs[pid], lbl, args.outdir)

    import zipfile
    z = zipfile.ZipFile(args.apk)
    for name in z.namelist():
        if name.upper().endswith('.RSA') or name.upper().endswith('.DSA'):
            for k, c in enumerate(extract_v1_certs(z.read(name))):
                certs.append(('v1', k, c))

    seen = {}
    for label, n, cert in certs:
        h = hashlib.sha256(cert).hexdigest()
        if h in seen:
            continue
        seen[h] = True
        path = os.path.join(args.outdir, '%s_cert_%d.der' % (label, len([x for x in seen]) - 1))
        open(path, 'wb').write(cert)
        print('%-4s len=%-6d sha256=%s md5=%s -> %s'
              % (label, len(cert), h, hashlib.md5(cert).hexdigest(), path))


if __name__ == '__main__':
    main()
