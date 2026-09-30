# 测试数据快照 — TikTok 9MOD v46.3.5 案例最终产物

> **本目录是测试数据备份,非项目代码。** 生成于 2026-09-30,对应案例文档 `case-46.3.5/`。
> 安装包(APK)、IDA 数据库(.i64)、frida-server、Python venv、smali 反汇编树均已排除(体积原因)。
> 除标注"原版基线"的文件外,所有产物均可由仓库 `scripts/` 中的脚本从原始 APK 一键复现。

---

## 一、最终补丁组件(共 4 个,即"无弹窗成品"相对原包的全部改动,双端验证通过)

### 1. `libiam_sigfix.so`(1.05MB, ARM64 ELF)

**是什么**:mod 主加载器 libiam.so 的修复版。libiam 伪装成官方加固库,实际负责
启动时的**双重 MD5 签名校验门**——校验失败会 `finish + killProcess + exit` 杀死 App。

**改了什么**:仅文件偏移 0x23E64 处 506 字节的 XOR 加密 blob。blob 解密后是
"3 字符前缀 + base64(Java 序列化数组)",数组第 0 项是签名门期望的 32 字符摘要。
我们把它从原版的 `d6c15948fd4664126f5ccf2cd3698792`(原发行者证书的双重 MD5)
等长替换为 `808478649e372c0775401adaa5c784dc`(我们重签证书的双重 MD5),
再按原 keystream(常量 0xDF278B5B95B52DF3 的 8 字节循环)写回。
其余 109 万字节与原版完全一致。

**效果**:用 debug keystore 重签后,签名门校验通过,App 不再被杀。

### 2. `libprobeq_nopop.so`(1.06MB, ARM64 ELF)

**是什么**:mod 弹窗库 libprobeq.so 的修复版,负责**英文更新弹窗**的绘制
(HandlerThread + 远程取数 + AlertDialog)。

**改了什么**:仅偏移 0x2E7CC 处 4 字节——原指令 `CBNZ W8, loc_2F5F8`(0x35007168,
prefs 开关 `getBoolean("dont")` 为真才跳过弹窗)改为无条件 `B loc_2F5F8`(0x1400038B)。
相当于永久勾选"不再显示"。

**效果**:英文弹窗链(取数/绘图)整体短路。

### 3. `libpluzneba_nopop.so`(1.06MB, ARM64 ELF)

**是什么**:mod 触发器库 libpluzneba.so 的修复版,是**俄语弹窗**的部分触发路径
(内部持有 `me/tiktokupdatez` 字符串,反射调用 Java 侧弹窗入口)。

**改了什么**:偏移 0x52980 处 4 字节,同样是 `CBNZ W8, loc_537B4`(0x350071A8)→
`B loc_537B4`(0x1400038D)。

**效果**:封掉这条触发路径。但实测俄语弹窗还有其他到达方式,所以还需要下面第 4 项。

### 4. `classes42_patched_037.dex`(4.60MB, Android DEX, 版本 037)

**是什么**:classes42.dex 的断链版。原版里 `me/tiktokupdatez/f/a.d(Context)` 是
俄语弹窗的**取数入口终点**——起线程拉远程配置并绘制弹窗。

**改了什么**:仅 `f/a.d` 一个方法体,改写为
`getSharedPreferences("", 0).edit().putBoolean("dont", true).commit(); return;`
(写"不再显示"开关后直接返回)。其余 7195 个类逐一校验与原版一致
(大小写敏感比对,防 Windows 文件系统丢类)。

**效果**:① 俄语弹窗的所有路径在入口终点被断死;② 预置的 `dont=true`
同时压制 libprobeq/libpluzneba 两个 native 闸门(双保险);③ 消除了该线程在
真机上抛未捕获异常 → 触发 `uncaughtException` 处理器杀进程的崩溃源(见 case 文档 §10)。

---

## 二、逆向基线(未修改的原版 mod 库,共 3 个)

| 文件 | 说明 |
|---|---|
| `libiam_orig.so` | 原版主加载器(1.05MB)。含:TT_S_E.onCreate 门(sub_3E954,实测放行)、me.tigrik.a.a 签名门(sub_B6B88)、MainActivity 替换实现(sub_705A8)、uncaughtException(sub_4B9D0)。后续复分析或定位新版本差异时的对照基准 |
| `libprobeq.so` | 原版弹窗库(1.06MB)。弹窗①绘制链在 sub_28AB4,prefs 闸门在 0x2E7CC |
| `libpluzneba.so` | 原版触发器库(1.06MB)。闸门在 0x52980,持有 `me/tiktokupdatez` 字符串 |

三个文件均直接来自原包 `lib/arm64-v8a/`,零字节修改,可配合仓库 `scripts/dump_jnitable.py`
等脚本复现 IDA 分析。

---

## 三、证据文件(签名门破解实录的原始数据)

| 文件 | 大小 | 说明 |
|---|---|---|
| `tigrik_blob_enc.bin` | 506B | libiam 内嵌的 XOR 加密 blob 原始字节(keystream = 0xDF278B5B95B52DF3 的 8 字节循环;明文 = "0Ah" 前缀 + base64 序列化流) |
| `tigrik_serial.bin` | 376B | 上述 blob 解密后的 Java 序列化流(`ac ed 00 05` 头)。内容 = String[]:{签名期望摘要, 反 hook 黑名单 11 个类名(SandHook / Lucky Patcher / binmt signature killer 等)} |
| `modder_v2cert.der` | 404B | 原包 v2/v3 签名块的证书(即 PackageManager 实际记录的证书) |
| `modder_cert.der` | 854B | classes41 TT_S_E blob 内嵌的另一张发行者证书 |
| `modder_cert_sha256.bin` / `modder_cert_md5.bin` | 32B/16B | 上述证书的原始摘要 |
| `debug_cert.der` | 744B | 我们重签用的 Android debug 证书(CN=Android Debug) |
| `our_cert_sha256.bin` | 32B | 重签证书的 SHA-256(`af80f4d9...`),与 keytool 输出一致 |

**期望值的推导公式**(签名门比对的核心):

```
期望 = md5( (md5(签名证书DER).hex() 重复两遍).转大写 ) 的 hex 小写
原版期望 = d6c15948fd4664126f5ccf2cd3698792   ← 对应 modder_v2cert.der
新版期望 = 808478649e372c0775401adaa5c784dc   ← 对应 debug_cert.der(已写入 libiam_sigfix.so)
```

---

## 四、如何用这份快照复现成品

```bash
python scripts/build_mod_apk.py 原包.apk 无弹窗.apk \
  --replace "lib/arm64-v8a/libiam.so=test-data-46.3.5/libiam_sigfix.so" \
  --replace "lib/arm64-v8a/libprobeq.so=test-data-46.3.5/libprobeq_nopop.so" \
  --replace "lib/arm64-v8a/libpluzneba.so=test-data-46.3.5/libpluzneba_nopop.so" \
  --replace "classes42.dex=test-data-46.3.5/classes42_patched_037.dex"
```

完整破解过程、每一步的命令与输出 → `case-46.3.5/SIGNATURE-GATE-BREAKTHROUGH.md`。
