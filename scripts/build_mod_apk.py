#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_mod_apk.py — 组装补丁 APK: 替换 zip 内条目 → zipalign → apksigner 签名。

原则(血泪教训):
  * 优先"零 dex 改动": 只替换 .so。任何 smali 重汇编都有丢类风险
    (Windows 大小写不敏感使 X/r0N 与 X/r0n 互覆)与 dex 版本降级风险(037→035)。
  * 重签证书决定 PackageManager 返回值 → 签名门补丁的期望值必须由
    **同一张** keystore 证书计算(先用 keytool -list -v 取 SHA-256 对账)。
  * 对齐必须在签名前(zipalign 会破坏已签内容)。

用法:
    python build_mod_apk.py <src.apk> <out.apk> \
        --replace "lib/arm64-v8a/libiam.so=libiam_sigfix.so" \
        --replace "lib/arm64-v8a/libprobeq.so=libprobeq_nopop.so" \
        [--keystore USERPROFILE\\.android\\debug.keystore --ks-pass android]

keystore 缺省用 Android debug keystore(android 密码)。
build-tools 查找顺序: %ANDROID_BT% → %LOCALAPPDATA%\Android\Sdk\build-tools\* 取最大版本。
"""
import zipfile, os, sys, glob, argparse, subprocess


def find_bt():
    env = os.environ.get('ANDROID_BT')
    if env and os.path.isdir(env):
        return env
    base = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Android', 'Sdk', 'build-tools')
    if os.path.isdir(base):
        vers = sorted(os.listdir(base), reverse=True)
        if vers:
            return os.path.join(base, vers[0])
    raise SystemExit('build-tools not found; set ANDROID_BT')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src')
    ap.add_argument('out')
    ap.add_argument('--replace', action='append', default=[],
                    help='zip_entry=path/to/new/file, 可多次')
    ap.add_argument('--keystore', default=os.path.join(os.environ.get('USERPROFILE', ''),
                                                       '.android', 'debug.keystore'))
    ap.add_argument('--ks-pass', default='android')
    args = ap.parse_args()

    repl = {}
    for r in args.replace:
        k, _, v = r.partition('=')
        repl[k] = v
        assert os.path.isfile(v), 'missing replacement file: %s' % v

    unaligned = args.out + '.unaligned.tmp'
    aligned = args.out + '.aligned.tmp'

    zin = zipfile.ZipFile(args.src, 'r')
    zout = zipfile.ZipFile(unaligned, 'w', zipfile.ZIP_DEFLATED)
    n = 0
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename in repl:
            data = open(repl[item.filename], 'rb').read()
            n += 1
            print('replaced %s (%d bytes)' % (item.filename, len(data)))
        zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
        zi.compress_type = item.compress_type
        zi.external_attr = item.external_attr
        zout.writestr(zi, data)
    zout.close()
    zin.close()
    print('entries replaced: %d/%d' % (n, len(repl)))
    assert n == len(repl), 'some entries not found in src apk!'

    bt = find_bt()
    print('build-tools:', bt)
    subprocess.check_call([os.path.join(bt, 'zipalign.exe'), '-f', '4', unaligned, aligned])
    subprocess.check_call([os.path.join(bt, 'apksigner.bat'), 'sign',
                           '--ks', args.keystore, '--ks-pass', 'pass:' + args.ks_pass,
                           '--out', args.out, aligned])
    # 验证
    out = subprocess.check_output([os.path.join(bt, 'apksigner.bat'), 'verify', '--print-certs', args.out]).decode(errors='replace')
    for line in out.splitlines():
        if 'SHA-256 digest' in line:
            print('signed cert:', line.strip())
    for t in (unaligned, aligned):
        if os.path.exists(t):
            os.remove(t)
    print('OK ->', args.out, os.path.getsize(args.out))


if __name__ == '__main__':
    main()
