# 测试数据快照 — TikTok 9MOD v46.3.5 案例最终产物

> **本目录是测试数据备份,非项目代码。** 生成于 2026-09-30,对应案例 `case-46.3.5/`。
> 只保留"最终真实可用"的中间产物与逆向证据;全部安装包(APK)、IDA 数据库、
> frida-server、Python venv、smali 反汇编树均已从本仓库排除(体积原因)。
> 所有产物可由 `scripts/` 中的脚本从原始 APK 一键复现。

## 最终可用补丁产物(nopop-v3 的 4 个组件,双端验证通过)

| 文件 | 用途 |
|---|---|
| `libiam_sigfix.so` | 签名门修复:0x23E64 处 506B blob 内期望值替换为 debug 证书的双重 MD5(`patch_sig_gate_blob.py` 产物) |
| `libprobeq_nopop.so` | 弹窗①闸门:0x2E7CC `CBNZ`→`B`(`patch_gate_branch.py` 产物) |
| `libpluzneba_nopop.so` | 弹窗②触发器闸门:0x52980 `CBNZ`→`B` |
| `classes42_patched_037.dex` | 弹窗②断链:`me/tiktokupdatez/f/a.d` 改写为"写 prefs("".dont=true)+return"(baksmali→smali --api 24;类集合 7195 已校验) |

组装命令(需重签,见 `scripts/build_mod_apk.py`):

```
lib/arm64-v8a/libiam.so      = libiam_sigfix.so
lib/arm64-v8a/libprobeq.so   = libprobeq_nopop.so
lib/arm64-v8a/libpluzneba.so = libpluzneba_nopop.so
classes42.dex                = classes42_patched_037.dex
```

## 逆向基线(原版 mod 库,后续复分析用)

`libiam_orig.so` / `libprobeq.so` / `libpluzneba.so` —— 从原包
`TikTok-v46.3.5-arm8.apk` 的 `lib/arm64-v8a/` 提取,未做任何修改。

## 证据文件(签名门破解实录的原始数据)

| 文件 | 内容 |
|---|---|
| `tigrik_blob_enc.bin` | libiam 0x23E64 处 506B XOR 加密 blob(keystream = K=0xDF278B5B95B52DF3 8B 循环) |
| `tigrik_serial.bin` | blob 解密 → base64 → Java 序列化 String[](args[0]=双重MD5期望值, args[1:]=反hook黑名单 11 类名) |
| `modder_cert.der` / `modder_v2cert.der` / `modder_cert_*.bin` | 原版各签名证书与摘要(对账用) |
| `debug_cert.der` / `our_cert_sha256.bin` | 重签证书及其摘要(新期望值由 `md5((md5(cert).hex()*2).upper())` 计算 = `808478649e372c0775401adaa5c784dc`) |

完整破解过程见 `case-46.3.5/SIGNATURE-GATE-BREAKTHROUGH.md`。
