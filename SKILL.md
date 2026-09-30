---
name: mod-apk-popup-removal-skill
description: 移除 TikTok 等魔改 APK(9MOD/max.ru/TikTok Central 等发行版)内置的更新横幅、赞助弹窗与广告弹窗,并破解其防二次打包的运行时签名校验门(Dex2C/伪装加固器/双重MD5 blob)。Use when the user says 去弹窗/移除弹窗/mod apk 弹窗/重打包闪退或被杀/签名门/me.tigrik/tiktokupdatez/probeq/pluzneba/libiam, or asks to repack a modified TikTok/9MOD APK that crashes after re-signing. Not for: official-app content issues, non-Android APKs, or root/Xposed runtime-hook approaches.
---

# SKILL — TikTok 魔改版 9MOD 弹窗移除方法论

> **前置技能**：本技能依赖 `reverse-skill`（SKILL-reverse-skill，通用逆向基础技能），使用前必须先加载。
> 本文档从真实案例（TikTok 9MOD v46.7.5 / v46.3.5）提炼，覆盖从定位到移除的全流程。
> 所有断言均附字节级出处或真机证据。
> 签名门破解的完整实录（命令级、含全部中间输出）见 `case-46.3.5/SIGNATURE-GATE-BREAKTHROUGH.md`。

---

## 0. 测试环境（本项目全部实测,版本号精确到具体值）

> 以下版本即本技能所有断言的验证环境。换用其他版本前,先按 §7 陷阱清单自查差异。

### 0.1 主机

| 项 | 值 |
|---|---|
| 操作系统 | Windows 11 25H2（内核 NT 10.0.26200, x64） |
| 命令行 | **PowerShell**（全部命令按 PS 语法给出） |
| 工作目录 | 非 C 盘（本案例 `E:\...\vmshare\`） |

### 0.2 工具与依赖清单（逐项实测版本）

| 工具 | 精确版本 | 用途 | 安装/配置关键步骤 |
|---|---|---|---|
| Python | **3.12.13** | 全部脚本（`scripts/*.py` 零第三方依赖） | python.org 安装,勾选 Add to PATH;OCR 预处理另需 `pip install Pillow` |
| JDK | **17.0.20 LTS** | `java -jar` 跑 smali/baksmali;apksigner 内部调用 | 任意 OpenJDK 17;`JAVA_HOME` 指向 JDK 根 |
| Android platform-tools | **37.0.1-15733141**（adb 1.0.41） | 设备连接/安装/logcat/screencap | SDK Manager 或 platform-tools zip 解压,加入 PATH |
| Android build-tools | **36.0.0**（apksigner **0.9**、aapt2 **2.20-13193326**、zipalign 同版本） | 对齐、签名、包信息 | `sdkmanager "build-tools;36.0.0"`;`build_mod_apk.py` 自动探测(或设 `ANDROID_BT`) |
| smali / baksmali | **2.5.2**（依赖 antlr **3.5.2**、dexlib2 **2.5.2**、guava **27.1-android**、jcommander **1.64**、stringtemplate **3.2.1**、util **2.5.2**） | dex↔smali 互转 | GitHub Releases 下载 jar,`java -jar baksmali-2.5.2.jar d` 调用;**不要用 2.5.2 以外版本**(§7.10 的 --api 行为) |
| IDA Pro | **9.4**（headless idalib + Hex-Rays） | native 静态分析、反编译 | 本技能经 ida-pro-mcp 使用;worker 会话超时后重新 `idb_open` |
| Frida | **17.18.0** + frida-tools **14.10.4** | 模拟器 Java 层诊断(可选) | PC 端 `pip install frida==17.18.0 frida-tools==14.10.4`;设备端 frida-server 需同版本;仅用于**模拟器**(真机见 §7.6) |
| tesseract-OCR | 本环境未安装 | 弹窗截图文字识别(可选) | `winget install UB-Mannheim.TesseractOCR`;未装时用人工看图替代 |
| Pillow | 随 MIMO_PYTHON 提供 | 截图像素分析/OCR 预处理 | `pip install Pillow` |

**最小可用组合**：Python 3.12.13 + JDK 17.0.20 + platform-tools 37.0.1 + build-tools 36.0.0 + smali 2.5.2 —— 即可跑通 §10 SOP 全流程;IDA 与 Frida 仅在逆向新变体时需要。

### 0.3 目标设备

| 设备 | 规格 | 角色 |
|---|---|---|
| LDPlayer 14（雷电14） | Android **14** x86_64, 已 root, ARM 翻译层可运行 arm64-only APK | 主调试环境（原版可完整运行） |
| vivo V2505A | Android **16**, **无 root**, USB 调试 | 最终验收 |
| MuMu 12 | Android **15** x86_64 | **已排除**——houdini 翻译层跑 TikTok 46.3.5 直接 SIGSEGV,原版也不行,勿浪费时间 |

### 0.4 环境注意事项与已踩坑（每条都有对应解决方法）

| # | 坑 | 现象 | 解决方法 |
|---|---|---|---|
| 1 | **MuMu 12 不兼容** | 原版 TikTok 46.3.5 直接 SIGSEGV | 换 LDPlayer 14;houdini 翻译层实现不同 |
| 2 | **Frida native hook 在 ARM 翻译层崩溃** | hook 经 houdini 翻译执行的 native 方法 → `SIGSEGV SI_KERNEL`(崩在 `tp-io-*` 线程) | 模拟器上只 hook **纯 Java 方法**;native 用 IDA 静态分析 |
| 3 | **Frida 17 无内置 Java bridge** | Python 裸 API `create_script` 里 `Java is not defined` | 用 **frida CLI**(`frida -D device -f PKG -l s.js`)或 ESM 引入 frida-java-bridge |
| 4 | **frida-gadget 在 vivo/Android 16 不可用** | dlopen 阶段 SIGSEGV(PAC 指针认证) | 真机放弃注入,走静态分析 + `adb reverse` 抓包 |
| 5 | **vivo 屏蔽第三方 App logcat** | FATAL/tombstone 看不到 | `dumpsys activity activities` + `ps -A` 判存活;杀链用 §7.12 零 frida 定位法 |
| 6 | **PowerShell 内联代码转义** | 双引号 here-string 展开 `$var`;`python -c` 内嵌引号静默失败;JSON 数组被拆散 | **一律写 `.py` 文件再执行**,不内联 |
| 7 | **Windows 大小写不敏感** | baksmali 输出 `X/r0N` 与 `X/r0n` 互相覆盖,类丢失 | 在 WSL/Linux 做全量 baksmali→smali;或用字节级 dex patch 绕过 |
| 8 | **dex 版本降级** | smali 2.5.2 默认 `--api 15` → 输出 035 → ART 拒载,开屏闪退 | `smali a --api 24`(037)/26(038)/30(039);汇编后回读 magic 断言 |
| 9 | **大 dex OOM** | 7MB dex 重汇编 JVM 需 3GB+ 堆 | `JAVA_OPTS="-Xmx3200m"` + 4GB swap |
| 10 | **无线 adb 端口漂移** | 配对窗口 30s,端口每次变 | 以手机界面当前端口为准,`pair_and_connect.sh` 重试 |
| 11 | **弹窗不在开屏时出现** | 反复盯着开屏等弹窗等不到 | 弹窗链在 **MainActivity.onCreate** 触发;开屏卡住可 `am force-stop` 后直接 `am start MainActivity` 绕过 |
| 12 | **"模拟器里装的是哪个包"拿不准** | 反复安装 340MB 包后记忆混乱,签名观感相似 | 文件级指纹一锤定音:`adb shell pm path` 拿路径 → `md5sum base.apk` 与本地各包 MD5 对比;`dumpsys package` 的 `Signatures:` 行同时看 |
| 13 | **uiautomator 读不到 mod 弹窗** | dump 只有背景文本 | mod 弹窗是自绘/AlertDialog 覆盖层,改用截屏+人工或像素 diff |
| 14 | **IDA headless worker 超时** | 会话失联 | `idb_list` 查看后重新 `idb_open`;补丁最终以 Python 脚本写文件为准(IDB 内 patch 不回写 so) |

---

## 1. 总流程

```
Triage（包信息/签名/dex 数/manifest）
  ↓
纯重签对照实验【2026-09-30 定为必做第一步, 见 §10.1】
  （原包零改动 debug 重签 → 装机 → logcat 抓真实死因/杀链,
    从源头排除"猜测性补丁", 所有后续 patch 必须能解释对照包的死亡栈）
  ↓
找注入框架（扫全部 dex 的 class defs，找非官方包名）
  ↓
弹窗文案反查（OCR 弹窗内容 → 搜 APK 找文案来源）
  ↓
区分：硬编码 vs 服务器下发
  ├─ 硬编码 → 直接在 smali/.so 里搜到
  └─ 服务器下发 → 抓包（adb reverse + logproxy + http_proxy）
  ↓
还原混淆（浮点×4 / Base64 变体 / AES-128-ECB / XOR / 倒序）
  ↓
还原 Dex2C native 调用链（.so 字符串表 → JNI 方法名 → 调用顺序）
  ↓
还原 JNINativeMethod 注册表【§10.2】（哪个 Java native 方法由哪个函数实现）
  ↓
破解签名门【§10】（期望值等长替换 > 杀点 NOP；绝不在未验证门语义前乱 NOP）
  ↓
设计 patch（优先不碰 dex/native / 利用 mod 自己的开关 / 断 Java 取数链）
  ↓
静态自检（方法签名/寄存器/try-catch 完整性）
  ↓
重打包 + 签名（scripts/build_mod_apk.py）
  ↓
真机验证（冷启动 + dumpsys + 截图 OCR + logcat 崩溃检测）
```

---

## 2. Triage（第一步）

```bash
aapt dump badging target.apk | grep -E '^package|application-label:'
aapt dump permissions target.apk
python3 -c "import zipfile; z=zipfile.ZipFile('target.apk'); print(len([n for n in z.namelist() if n.endswith('.dex')]), 'dex')"
# 提取 dex
mkdir dex && python3 -c "import zipfile; z=zipfile.ZipFile('target.apk'); [open('dex/'+n,'wb').write(z.read(n)) for n in z.namelist() if n.endswith('.dex')]"
# 签名方案
python3 -c "import struct; d=open('target.apk','rb').read(); i=d.rfind(b'APK Sig Block 42'); print('v2/v3' if i>=0 else 'no sig block')"
```

---

## 3. 找注入框架

### 3.1 扫全部 dex 的 class defs，找非官方包名

```python
# 用 scripts/dexscan.py 的 Dex 类
import sys; sys.path.insert(0, 'scripts')
from dexscan import Dex
import os
for f in sorted(os.listdir('dex')):
    if not f.endswith('.dex'): continue
    d = Dex('dex/'+f)
    for c, _ in d.class_defs():
        if any(c.startswith(p) for p in
               ['Lcom/aaaaaaa/', 'Lme/tiktokupdatez/', 'Līi/ïi/',
                'Lassem/', 'Lprime0/', 'LGoldDcc0/', 'Lchillbro0/',
                'Lprobeq0/', 'Lieuwh0/', 'Lcom/acra/']):
            print(f, c)
```

### 3.2 已知的注入框架命名模式

| 命名模式 | 来源 | 加载的 native 库 |
|---|---|---|
| `com.aaaaaaa.gold.*` | Assem / TikTok Prime / Gold | `libGoldDcc.so` |
| `assem.fix.Appnew` | ApkSignatureKillerEx | 无（纯 Java 签名绕过） |
| `com.acra.*` | ACRA 崩溃上报 | 无 |
| `me.tiktokupdatez.*` | 9MOD / max.ru | Java 实现不受 native 保护；触发器是**另一个 dex 里的 native 框架**经 `Class.forName` 反射驱动（v46.7.5: `prime0`@classes42→libprime.so；v46.3.5: `pluzneba0`@classes32→libpluzneba.so） |
| `īi/ïi/pk*` | 9MOD（Unicode 类名混淆） | `libieuwh.so`（v46.7.5，ieuwh0@classes28）/ `libprobeq.so`（v46.3.5，probeq0@classes32；**不是 libchillbro.so**） |
| `ieuwh0/*` / `probeq0/*` | native 加载器 | 对应上述 .so |
| `prime0/*` / `pluzneba0/*` | native 加载器（Dex2C） | 对应 .so |
| `chillbro0/*`（v46.3.5） | Dex2C 注册器 | libchillbro.so，只保护 4 个官方类（BackgroundAudioVM/AiMeTabFragment/X.806/X.HyI），与弹窗无关 |
| `GoldDcc0/*` | Dex2C 注册器 | `libGoldDcc.so` |

> **陷阱（核验教训）**：同一 dex 里可以有**多个** Dex2C 框架（v46.3.5 classes32 同时有 probeq0+pluzneba0）。
> 判定"哪个 .so 保护哪个类"必须看每个类 `<clinit>` 实际调用的 `registerNativesForClass` 加载器，不能按库文件名猜。

### 3.3 找弹窗的 native 库

```bash
# 扫 .so 字符串找弹窗相关（AlertDialog/setCancelable/show/dont/getSharedPreferences）
for so in lib/arm64-v8a/*.so; do
  s=$(strings -a -n 3 "$so" | grep -cE 'AlertDialog|setCancelable|dont|getSharedPreferences')
  [ "$s" != "0" ] && echo "$so: $s hits"
done
```

---

## 4. 还原混淆

### 4.1 浮点编码（char = float × 4）

魔改者用 `fill-array-data` 存浮点数组，解码：`chr(round(float × 4))`。

```python
import struct
# 从 smali 的 .array-data 提取 0xXXXXXXXX，转为 float，乘 4 得 char
floats = [0x41d00000, 0x41e80000, ...]
chars = ''.join(chr(int(round(struct.unpack('<f', struct.pack('<I', x))[0] * 4))) for x in floats)
```

已知编码值示例：`https://afmod.com/`、`LITEAPKS & 9MOD.COM`、`Update Found`、`litepaks.com`、`(.*)Url=(.*)`。

### 4.2 Base64 变体

| 方法 | 解码方式 |
|---|---|
| `a/a.a(String)` | 跳前 3 字符 → Base64.decode → UTF-8 |
| `f/a.a(String)` | 跳前 4 字符 → Base64.decode → UTF-8 |
| `f/a.byte(String)` | Base64.decode → UTF-8 |
| 倒序 | `s[::-1]` 后再 Base64 或直接用 |

### 4.3 AES-128-ECB

| 密钥（明文） | 用途 | 来源 |
|---|---|---|
| `MD5CryptoByte128`（16B） | 解 `max2.conf` URL | `me/tiktokupdatez/f/x.a(String)` |
| `MySecretKey12345`（16B） | 解 `update.json` URL / 崩溃邮箱 | `com/acra/CrashReportActivity` / `libGoldDcc.so` |

```bash
openssl enc -d -aes-128-ecb -K "$(printf '%s' 'MD5CryptoByte128' | xxd -p)" <<< "$(base64 -d <<< '密文base64')"
```

### 4.4 批量枚举解密

```python
import re, base64, subprocess
KEYS = [b'MD5CryptoByte128', b'MySecretKey12345']
# 遍历 dex/.so 里的所有 base64 候选 → 逐个 AES 解密 → 过滤可读含 URL 的
```

---

## 5. 还原 Dex2C native 调用链

Dex2C 的 Java 方法被抽成 native，实现在 .so 里。但 native 通过 JNI 按名调用 Java 方法/类，**.so 的字符串表里就有它调用的全部 Java 方法名**——这可以还原调用链。

### 5.1 提取 .so 的 JNI 方法名表

```bash
# 用真正保护弹窗类的 .so（v46.3.5 是 libprobeq.so，不是 libchillbro.so）
strings -a -n 3 libprobeq.so | grep -E '^(num|bytess|getSharedPreferences|getBoolean|dont|setCancelable|show|AlertDialog|pk\$|val\$|isClassPresent|fals|drk)' | sort -u
```

### 5.2 关键证据模式

| .so 字符串 | 含义 |
|---|---|
| `dont` + `getBoolean` + `getSharedPreferences` | native 读 pref 开关 → 预置方案可行。v46.3.5 IDA 复核：probeq（弹窗①）与 pluzneba（弹窗②触发器）**都**以 `getBoolean("dont", false)` 结果做分支，true 即跳过绘制/触发（探针地址见 §5.3）——**预置一次，多弹窗同压** |
| `num`/`num2`/.../`num6` | native 调 Java 浮点表方法 → 文案/URL 来源 |
| `pk$100000008` + 构造签名 | native 构造弹窗 Runnable |
| `setCancelable` + `show` + `AlertDialog$Builder` | native 绘制弹窗 |
| `val$sb2`..`val$sb9` | 7 个 StringBuilder 字段名 → URL 拼接 |
| 无 `afmod` / `litepaks` 等域名 | 证明域名不在 .so 里，来自浮点表 |

### 5.3 开关闸门的字节级识别法（2026-09-29 IDA 复核沉淀）

Dex2C 生成器把所有运行时字符串集中放在一个**字符串池**（`.data` 尾部，明文、`\0` 分隔），
由"池基址全局变量 + 立即数偏移"寻址，静态字符串交叉引用扫不到。识别法：

1. **找池基址**：`registerNativesForClass` 的 native 实现是一个初始化大函数，特征为成块模式
   `NewStringUTF(env, 池+off)` → `CallObjectMethod(env, s, String.intern)` → `NewGlobalRef` → 存全局。
   拿任一已知字符串的文件偏移 − 代码里的立即数即得池基址
   （v46.3.5：libprobeq 基址 0x97CD8、libpluzneba 基址 0xBDEB8）。
   枚举这些偏移即可**一次列出 native 用到的全部字符串**（类名、prefs 文件名、键名……）。
2. **JNIEnv 偏移速查**（AArch64，`LDR X8, [env, #off]`）：`0x48`=FindClass、`0xA8`=NewGlobalRef、
   `0xB8`=DeleteLocalRef、`0x108`=GetMethodID、`0x538`=NewStringUTF、`0x6B8`=RegisterNatives、`0x720`=ExceptionCheck。
3. **闸门特征**（读 prefs 开关的固定模式）：
   `GetMethodID(类, 池+off1 /*getSharedPreferences*/, 池+off2 /*签名*/)` →
   `CallObjectMethod(ctx, …)` → `GetMethodID(类, 池+off3 /*getBoolean*/, 池+off4 /*(Ljava/lang/String;Z)Z*/)` →
   CallBoolean 封装（key=缓存的全局 jstring，default=0）→ `CBNZ Wn, <skip>`；
   skip 分支是 C++ 析构 + 返回，非 skip 分支才是 HandlerThread/URL/AlertDialog。
   看到这个模式即可断言"预置开关可行"，无需读完整个巨型函数。
4. **prefs 文件名闭环**：文件名通常也在池里（v46.3.5 是**空串 ""**，对应 Java 侧
   `getSharedPreferences("",0)`），预置代码必须用同一文件名+键，否则写了个没人读的 prefs。

---

## 6. Patch 策略（按优先级）

### 策略 A：预置 mod 自己的 pref 开关（最安全）

**前提**：native 在弹窗前读 `SharedPreferences(name).getBoolean(key)`（识别法见 §5.3）。
注意 prefs 文件名可能是**空串 ""**（v46.3.5 实测），模板即按此写。

```smali
# 在 Application 启动时预置
.method public onCreate()V
    .registers 4
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    :try_start_0
    const-string v0, ""           ; pref 文件名
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    const-string v1, "dont"       ; pref key
    const/4 v2, 0x1
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->commit()Z
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0
    goto :g_done
    :catch_0
    move-exception v0
    :g_done
    return-void
.end method
```

**注入点选择**：
- 优先找 mod 自己注入的 Application 基类（如 `assem.fix.Appnew`）
- 如果 Application 被 Dex2C（native onCreate），改它的纯 Java 子类或加载器类的 `<clinit>`
- **Application 整个被官方加固成 native**（如 v46.3.5 `AwemeHostApplication` 全生命周期 native，libiam.so）时，
  借用**弹窗②触发链必经的纯 Java 入口方法**预置：native 触发器反射调用 `me/tiktokupdatez/b/a.a` →
  `f/a.d(Context)`，把 `f/a.d` 改写为"写 prefs `""`/`dont=true` + return"。该方法本身就在触发链上，
  写入必然先于后续绘制（v46.3.5 vb_signed.apk 即此做法，兼作策略 B 的断链）
- **不能改 native 方法的类**（破坏注册 → UnsatisfiedLinkError）

**同键多弹窗**：多个注入框架常共用同一 prefs 键（v46.3.5 IDA 复核：libprobeq 弹窗①闸门 0x2e7cc 与
libpluzneba 触发器闸门 0x52980 都读 `""`/`dont`）——预置一次即可同时压制多个弹窗，不必逐个框架找开关。

### 策略 B：断 Java 取数链（安全，不改 native）

将取数入口和线程体置空。v46.3.5 实操变体：取数入口 `f/a.d(Context)` 不做纯 no-op，而是
**写 `dont=true` 后 return**——断链与预置合二为一（见策略 A 注入点第三条）：

```smali
.method public static d(Landroid/content/Context;)V
    .registers 4
    ; getSharedPreferences("",0).edit().putBoolean("dont",true).commit() 后 return
    ...
    return-void
.end method
```

**注意**：用正则替换整个方法块（含 `.end method`），不要手动拼接（会粘连 `.end method`）：

```python
import re
pat = re.compile(r'\.method public static d\(Landroid/content/Context;\)V.*?\.end method', re.S)
s = pat.sub(new_body, s, count=1)
```

### 策略 C：改 run() 为 Java 空实现（有风险）

**前提**：`run()` 是 `native`，由 Java Handler/Thread 分发（非 native 直接调用）。

**必须**：
- 保留 `<clinit>` 里的 `registerNativesForClass`（否则库不加载 → `special_clinit` UnsatisfiedLinkError）
- 保留 `special_clinit_*`（库加载后才有实现）
- 只改 `run()` 本体

```smali
# 原：.method public native run()V
# 改：
.method public run()V
    .registers 1
    return-void
.end method
```

**风险（2026-09-27 核验修订）**：改 native 声明为普通方法后，`registerNativesForClass` 会把 native 实现注册到一个**非 native 方法**上 → ART 抛 NoSuchMethodError → `<clinit>` 抛 ExceptionInInitializerError → 启动崩溃（v46.3.5 实测）。这不是"完整性校验"，而是 JNI 注册路径的必然结果。

### 策略 D：改数据表（URL 无效化）

改 `num6()` 的浮点值（`afmod.com` → `afmod.inv`，同长度替换）。

**风险（核验修订）**：v46.3.5 实测此法也崩，但经 .so 逆向证明 mod 的 native 库**没有**文件 I/O 与 kill 能力（详见 7.2），此死因未定——避免依赖此法，优先用预置开关。

---

## 7. 陷阱清单（必读）

### 7.1 Dex2C 注册陷阱
- `registerNativesForClass(int, Class)` 同时触发 `System.loadLibrary()`（在加载器类的 `<clinit>` 里）
- **删了 registerNativesForClass → 库不加载 → `special_clinit_*`（native）无实现 → UnsatisfiedLinkError**
- 正确做法：保留完整 `<clinit>`，只改 `run()` 本体

### 7.2 "Native 完整性校验"误区（2026-09-27 核验修订）
- **初版结论"mod native 对 dex 有完整性校验"经逆向证伪**：v46.3.5 的三个 mod .so（libprobeq/libpluzneba/libchillbro）
  导入表无任何文件 I/O（无 open/read/mmap/fstat/openat）、无 kill/exit/fork、.text 无内联 syscall——
  它们**既不可能读 dex 文件，也不可能发 SIGKILL**；唯一致命导入是 C++ 运行时 `abort`。
- 真实死因（按证据）：① 删 registerNativesForClass → UnsatisfiedLinkError（可完整解释）；
  ② native 方法改成 Java 体 → RegisterNatives 注册到非 native 方法 → NoSuchMethodError →
  ExceptionInInitializerError → 启动崩溃（Java 异常路径，非杀进程）；
  ③ 纯 Java 浮点表改动导致崩溃的死因未定（baksmali→smali 往返会重排整个 dex，疑似构建副作用）。
- **通用排查法**：拿到 .so 先查 `rabin2 -i xxx.so`（导入表）+ svc 扫描——无文件 I/O 就不可能有 dex 校验。
- **稳妥策略不变**：不碰 native 保护的 dex，用其他 dex 预置 `dont` 开关 + 断链。
- vivo/Android 16 上 logcat 部分被屏蔽，历史测试缺 logcat 佐证是误判根源——**重打包失败必留 logcat 证据**

### 7.3 smali 替换粘连
- 手动拼接 smali 方法体时，`.end method` 容易粘连（`.end method.end method`）
- **对策**：用 Python 正则替换整个方法块（`re.compile(r'\.method ... \.end method', re.S)`）

### 7.4 大 dex 重汇编 OOM
- 7.6MB dex 的 smali（81MB）重汇编时 JVM 需要 3GB+ 堆
- 1.9GB RAM 的虚拟机会 OOM
- **对策**：`JAVA_OPTS="-Xmx3200m"` + 添加 4GB swap（`fallocate -l 4G /swap2 && mkswap /swap2 && swapon /swap2`）

### 7.5 apksigner 大 APK OOM
- 385MB APK 签名时 apksigner 需要 1GB+ 堆
- **对策**：同上，加 swap

### 7.6 Frida Gadget 在 vivo/Android 16 不可用
- `libfrida-gadget.so` 在 dlopen 阶段 SIGSEGV（null deref @ 0x38）
- PAC（指针认证）开启导致兼容性问题
- 两个注入点（`Appnew.<clinit>` / `prime0/gold.<clinit>`）均崩
- **对策**：放弃 Frida，用静态分析 + `adb reverse` 代理抓包

### 7.7 无线 adb 端口漂移
- 无线调试端口每次连接后可能变化
- **对策**：每次以手机「无线调试」界面当前显示为准；用 `pair_and_connect.sh` 重试

### 7.8 OCR 识别率低
- 弹窗文案可能烤在图片里（服务器下发的 banner）→ OCR 难识别
- **对策**：PIL 放大裁剪 + tesseract 多 psm 模式 + 多次截取

### 7.9 vivo 屏蔽 logcat
- vivo 对第三方 app 的 logcat 做了屏蔽
- App 的 FATAL 异常可能不出现在 `adb logcat` 里
- **对策**：用 `dumpsys activity activities` 跟踪 Activity + `ps -A | grep` 判断进程存活

### 7.10 smali 重汇编默认把 dex 版本降级（037→035 → 开屏闪退）【2026-09-29 真机实锤】
- smali 2.5.2 默认 `--api 15`，输出 dex 版本标记 **035**；而 TikTok 官方 42 个 dex 全部是 **037**
  （magic 在 dex 头 0x00–0x07）。classes42 就含 4 个接口 `<clinit>`（037 特性：接口静态初始化器）。
- **症状**：装上后"打开即闪退"——版本标记 035 + 037 特性结构，ART 校验拒绝，dex 加载失败。
- **对策（必须做）**：
  1. 重汇编前读原 dex magic，用 `--api` 匹配版本：037→`--api 24`（或 25）、038→`--api 26..29`、039→`--api 30+`
  2. 汇编后回读 magic 断言 `dex\n037\x00`（与原版一致）再打包
- 此机制大概率就是 case-46.3.5 里 `fix3`（classes32 纯 Java 改动）"死因未定"的真凶——
  同为 baksmali→smali 往返、同样被降级到 035，与所谓 native 校验无关。
  对照实验可用 `--api 24` 重汇编 fix3 的 smali 源验证。
- 同时注意：baksmali 默认 `--api 15` 只影响解析宽松度，反汇编一般无碍；**关键在 smali 侧**。

### 7.11 伪装成官方加固库的 mod 主加载器 + 动态定义类【2026-09-29 真机剖析 / 09-30 修正】
部分发行版（46.3.5 arm8）把整个 mod 做成**伪装成官方加固库的主加载器**：
- `TT_J/TT_S_E`（ContentProvider）里 `System.loadLibrary("iam")`——先于 Application 加载；
  libiam.so 实为 mod 主加载器，运行时 DefineClass 创建 **dex 中不存在**的类（`me/tigrik1`、
  `kotlin/jvm/internal/AFpS124S0000000_3` 等），并向 Application(11)/MainActivity(117)/mod 插件
  注册 native；dex 静态分析对动态类内的逻辑完全不可见
- **防二次打包的真相【09-30 纯重签对照实验修正】**：看似"多层签名门散布各处"，实际**唯一
  主动校验签名的是 `me/tigrik.a.a`（native，sub_B6B88）的双重 MD5 门**（破解见 §10.3）。
  其余疑似门均为"异常兜底杀"：
  - `TT_S_E.onCreate`（sub_3E954）：`String.equals(期望摘要, 实际摘要)` 的 CallBooleanMethod
    **返回值被忽略**——流程不抛异常就 return 1（provider 正常创建）。只有 PM 查询链抛异常
    （签名数组空等）才走 ThrowNew NPE → printStackTrace → kill。给它改期望摘要常量
    （XOR base64）是**无效功**
  - MainActivity.onCreate（sub_705A8，2301 行）：是 mod 的完整替换实现而非门，NOP 其 NPE
    守卫反而让 null 流转到下游崩（历史 expH 教训）
- **动手前先确认原包能不能用**：此类 mod 常依赖远程配置（gist/自建站）。46.3.5 的 gist 已 404，
  但【09-30 修正】**原包在真机/模拟器上仍可完整运行**（开屏动画、引导页、弹窗全部正常）——
  远程配置死亡≠mod 整体死亡，只是更新/远控功能失效。判定标准：冷启动后 `topResumedActivity`
  是否推进到引导页/主界面 + 弹窗是否出现,而不是"有没有网络请求失败"

### 7.12 静默自杀（无 FATAL/无 tombstone）的识别与杀点定位
- 症状：启动后数秒死、三处无痕迹 → Java 层 `Process.killProcess` 自杀
- 定位：`logcat -b events` 量 am_proc_start→am_proc_died 间隔；主日志搜
  `Process: Sending signal. PID: <pid> SIG: 9`（自杀标记，出现即 Java 自杀而非系统杀）
- **零 frida 杀链定位法【2026-09-30, 雷电14 实战】**：root 模拟器上若 rom/框架给
  `Process.killProcess` 打了 `System.err` 诊断栈（"call killProcess callstack!"）,
  `logcat -d | grep -A 25 'call killProcess callstack'` 直接给出**完整 Java 调用链**
  （本案例: killProcess ← me.tigrik.a.a(Native Method) ← MainActivity.onCreate(Native Method)）,
  一条日志顶数天静态分析。没有该诊断时: 纯重签对照包 + `logcat -d -b crash` +
  `dumpsys activity activities` 也能定位（对照包能走到哪, 门就在哪之后被调）
- 杀点三连（native）：`GetStaticMethodID(Process,"myPid")` → CallStaticInt →
  `GetStaticMethodID(Process,"killProcess")` → CallStaticVoid → `System.exit`；
  .so 内 grep "killProcess" 字符串 → xref 所在函数 → **先读懂门语义再决定** NOP 还是改期望值
  （§10.3 的教训: 无脑 NOP 返回值路径会引发 NPE, 改期望值才是正解）
- JNI 偏移速查：env+0x418=CallStaticIntMethod、env+0x478=CallStaticVoidMethodV、
  env+0x340=CallVoidMethod、env+0x720=ExceptionCheck、env+0x108=GetMethodID、
  env+0x538=NewStringUTF、env+0x6B8=RegisterNatives、env+0xC8/0x120=Get*Class 系、
  env+0x120(288/8=36)=CallObjectMethodV 系、env+0x550(1368/8=171)=GetArrayLength、
  env+0x568(1384/8=173)=GetObjectArrayElement、env+0x640(1600/8=200)=GetByteArrayRegion
- RegisterNatives 表在 .data.rel.ro，文件内槽位为 0，须解析 .rela.dyn（R_AARCH64_RELATIVE=1027）
  取 addend 还原 {name,sig,fn} 三元组，才能反查"哪个类的方法由哪个函数实现"
  （一键脚本 `scripts/dump_jnitable.py`）

---

## 8. 真机验证方法

```bash
# 配对 + 连接
adb connect <IP:PORT>

# 卸载旧版（签名已变）
adb uninstall com.zhiliaoapp.musically

# 安装
adb install output.apk

# 冷启动
adb shell monkey -p com.zhiliaoapp.musically -c android.intent.category.LAUNCHER 1

# 跟踪 Activity（每 8 秒）
for i in 1 2 3 4 5 6; do
  sleep 8
  adb shell "dumpsys activity activities | grep -m1 topResumedActivity"
  adb shell "ps -A | grep -c zhiliaoapp"
done

# 截图 + OCR
adb exec-out screencap -p > s.png
tesseract s.png stdout --psm 6

# 弹窗文案检测
tesseract s.png stdout --psm 6 | grep -icE '9mod|liteapks|download now|telegram|max\.ru|блокир|подпиш'

# 崩溃检测
adb logcat -d | grep -cE 'FATAL|System.exit'
```

---

## 9. 抓包方法（adb reverse + 日志代理）

```bash
# 1. 起代理（在 Kali 上）
python3 scripts/logproxy.py 8888 proxy.log &

# 2. adb 反向端口
adb reverse tcp:8888 tcp:8888

# 3. 设全局代理
adb shell settings put global http_proxy 127.0.0.1:8888

# 4. 冷启动 App
adb shell monkey -p com.zhiliaoapp.musically -c android.intent.category.LAUNCHER 1

# 5. 读日志
cat proxy.log | grep -E 'CONNECT|SNI'

# 6. 清理
adb shell settings put global http_proxy :0
adb reverse --remove-all
```

代理会记录所有 CONNECT 目标（域名）和 TLS ClientHello SNI（即使直连 IP 也能拿到 SNI）。

---

## 10. 签名门破解方法论【2026-09-30 实战沉淀, 46.3.5 全程验证】

> 完整实录（每一步的命令、地址、字节、预期输出）: `case-46.3.5/SIGNATURE-GATE-BREAKTHROUGH.md`

### 10.1 纯重签对照实验（必做第一步, 最高性价比）

**做法**：原包**零改动**，仅用 debug keystore 重签（`scripts/build_mod_apk.py` 不带
`--replace` 即可），装入模拟器/真机，观察死亡方式。

**它能一次性回答三个问题**：
1. 门到底存不存在（不死 = 无签名门，直接做 dex 补丁收工）
2. 门在哪个 Java 帧触发（logcat 栈直接给出 `at xxx(Native Method)` 调用链）
3. 原包本身是否健康（对照死亡时间线：Splash → 引导 → 主界面，死在哪一步）

**46.3.5 实证**：diagld（纯重签）一路跑到 NewUserJourney 窗口后 ~40s 自杀，
栈顶 `at me.tigrik.a.a(Native Method) ← at MainActivity.onCreate(Native Method)`——
这一条日志纠正了此前数天"多层签名门"的错误攻坚方向。

**纪律**：此后做的每一个 patch，都必须能解释"对照包为什么死、自己的包为什么活"。

### 10.2 JNINativeMethod 注册表还原（定位门函数的唯一手段）

native 化的方法在 dex 里只剩 `native` 声明，唯一映射在 RegisterNatives 的
`{name*, sig*, fn*}` 24B 三元组数组里。三个坑：

1. 表在 `.data.rel.ro`（PIE 重定位区），文件内指针是链接期占位值，
   必须用 `.rela.dyn` 的 `R_AARCH64_RELATIVE(1027)` addend 覆盖——否则全表解析为 0；
2. vaddr≠file offset（多段 LOAD 差 0x1000/0x2000），按 program header 换算；
3. 锚点找法：在 IDA 里对疑似门函数（如含 killProcess 字符串 xref 的函数）查
   data xref，唯一引用处即表内 fn 槽位，槽位地址 −16 = 表项起点。

```bash
python scripts/dump_jnitable.py libiam.so --anchor 0x1005e0 --span 80
# 输出: 0x1005e0  onCreate  ()Z  fn=0x3e954   ← TT_S_E.onCreate
#       0x100e38  onCreate  (Landroid/os/Bundle;)V  fn=0x705a8  ← MainActivity.onCreate(mod替换)
```

### 10.3 门语义判定 → 期望值替换（先读懂, 再动手）

对每个疑似门函数反编译, 按此清单分类：

| 特征 | 真门 | 兜底/非门 |
|---|---|---|
| equals/比较的**返回值参与分支**（CBZ/CBNZ W0 后走 kill） | ✅ | |
| equals 返回值被忽略（强转 void, 无异常即 return 成功） | | ✅ 异常兜底杀 |
| 摘要输入 = Signature.toByteArray() 且**逐 signer update** | ✅（看清楚 digest 调用次数!） | |
| 摘要后还有二次 update/digest（双哈希!） | ✅ 复现算法时必须完整还原 | |
| Class.forName(...) + ClassNotFoundException 被 catch 后 continue | 反 hook 黑名单探测（不杀） | |
| Activity.finish + killProcess + System.exit 连环 | kill 路径终点（定位用） | |

**46.3.5 的真门算法**（me.tigrik.a.a = sub_B6B88, 1538 行伪代码）：

```
certs  = SDK<=27 ? signatures[i].toByteArray() : signingInfo.getApkContentsSigners()[i]
hex1   = md5(所有certs拼接).hex()                       # Integer.toString(b|0x100,16).substring(1)
upper  = (hex1 + hex1).toUpperCase()                    # StringBuffer append 两次
final  = md5(upper.getBytes()).hex()                    # ← 双重 MD5, 32字符小写
期望值 = 解密 506B blob → "0Ah"前缀 + base64(Java序列化String[]) → args[0]
final == args[0].toLowerCase() ? 校验黑名单类后返回"TRUE" : throw → finish+kill+exit
```

验证公式：`md5((md5(modder_cert_der).hex()*2).upper()) == "d6c15948fd4664126f5ccf2cd3698792"` ✓

**修复 = 期望值等长替换**（不是 NOP！）：

```bash
# 用将要重签的同一张证书算新期望值并重写 blob（脚本自动完成 解密→定位→替换→重加密→回读断言）
python scripts/patch_sig_gate_blob.py libiam_orig.so libiam_sigfix.so --cert debug_cert.der
# libprobeq/pluzneba 的 prefs 闸门(dont)改无条件跳过:
python scripts/patch_gate_branch.py libprobeq.so  libprobeq_nopop.so  --vaddr 0x2E7CC --target 0x2F5F8 --expect cbnz:rt=8
python scripts/patch_gate_branch.py libpluzneba.so libpluzneba_nopop.so --vaddr 0x52980 --target 0x537B4 --expect cbnz:rt=8
python scripts/build_mod_apk.py 原包.apk 成品.apk \
  --replace "lib/arm64-v8a/libiam.so=libiam_sigfix.so" \
  --replace "lib/arm64-v8a/libprobeq.so=libprobeq_nopop.so" \
  --replace "lib/arm64-v8a/libpluzneba.so=libpluzneba_nopop.so"
```

期望值替换优于杀点 NOP 的原因：返回值语义（"TRUE"）被调用方（MainActivity 替换实现）依赖，
粗暴 NOP 会返回 null/错误状态 → 下游 NPE（expH 系列全部失败的根因）。

**46.3.5 最终成品补丁清单（nopop-v3, 模拟器+真机双验证通过）**：

| 文件 | 改动 | 拦截目标 |
|---|---|---|
| lib/arm64-v8a/libiam.so | 506B blob 期望值等长替换 | 签名门(me.tigrik.a.a 双重MD5) |
| lib/arm64-v8a/libprobeq.so | 0x2E7CC CBNZ→B | 弹窗①(英文)绘制链 |
| lib/arm64-v8a/libpluzneba.so | 0x52980 CBNZ→B | 弹窗②触发器部分路径 |
| classes42.dex | f/a.d 改写为"写 prefs("".dont=true)+return"（baksmali→smali --api 24 往返） | **弹窗②(俄语)全部路径** + 预置 dont 双保险 |

**教训：native 闸门 patch 不一定能拦住全部弹窗路径。** 46.3.5 实测：probeq B-patch
杀掉了英文弹窗，但俄语弹窗仍然出现——多个 native 库/多条路径触发**同一个 dex 入口**
（`me/tiktokupdatez/b.a → f/a.d`）。当弹窗绘制入口是**纯 Java 类**时，直接把入口终点
方法改写为"写 prefs + return"是最彻底的断链（顺带预置 dont 闸门，双保险）；这比追
补每一条 native 调用路径更快更稳。

### 10.7 真机闪退但模拟器正常——mod 残留网络链路陷阱【2026-09-30 真机实锤】

**现象**：nopop-v2（只改 3 个 so）在模拟器存活 100s+，真机（vivo, Android 16）闪退。

**根因**：只 patch native 门、不动 dex 时，**mod 的远程取数链路仍然活着**——
`f/a.d` 起线程拉远程配置（gist 404）。模拟器上该请求**静默失败**（吞异常）；
真机 Android 16 上链路抛出未捕获异常 → 进入 mod 的 `uncaughtException` 处理器
（sub_4B9D0，同样有杀点与跳转 CrashReportActivity 逻辑）→ kill。

**解决**：v3 用 dex 断链（f/a.d 写 prefs + return）**同时消灭了弹窗与异常源**，
真机随即不再闪退。

**方法论**：
1. 模拟器验证通过 ≠ 真机可用。**同一包两台设备的行为差异 = 环境依赖路径的差异**
   （网络栈/时区/locale/厂商 ROM），优先审查"网络请求+异常处理"类代码。
2. `uncaughtException` 处理器是常被忽视的杀点——任何未捕获异常都会进入它，
   它内部还做设备信息采集（TreeMap + versionCode/versionName + 反射字段）并
   `startActivity(CrashReportActivity) + killProcess + exit`。真机闪退而模拟器正常时，
   先怀疑这条路径。
3. 复现/消除实验顺序：先全新安装（清数据）排除残留 prefs；再对比"只断 native"与
   "native+dex 断链"两个版本。

### 10.8 "装的到底是哪个包"——MD5 文件指纹核验法【2026-09-30】

反复装卸 340MB 包后，"模拟器/真机里现在是什么版本"极易记混，且**签名观感不可靠**
（用户与 Agent 各执一词）。一锤定音：

```bash
adb shell pm path com.zhiliaoapp.musically
# package:/data/app/~~xxxx/base.apk
adb shell md5sum /data/app/~~xxxx/base.apk
# 与本地各候选 APK 的 MD5 逐一对比 —— MD5 一致 = 同一个文件,无争论空间
```

签名（`dumpsys package` 的 `Signatures:` 行）作为第二佐证（modder=原版 / debug=重签版）。
注意 `pm install` 的 Incremental/Streamed Install 输出 "Success" 不代表装的是你以为的文件——
**以 MD5 为准**。

### 10.4 XOR-blob 加密：等效化简 + 差分重加密

mod 用 NEON（`vshlq_u64` 移位表 + `vqtbl4q` 查表 + `veorq`）生成 keystream。
**不要手工复刻 NEON**，两条捷径：

1. **等效化简**：每轮 shift=(idx*8)&0x38，而 idx=16r+k ⇒ (16r+k)&7==k&7，
   所有轮次 keystream 恒同；vqtbl4q 索引 64-120 越界返回 0，v89 只取 lane0 ⇒
   keystream = K（8 字节小端）重复循环。解出明文验证：应为 `3字符前缀 + base64(序列化流, 头 ac ed 00 05)`。
   （46.3.5: K=0xDF278B5B95B52DF3, blob@0x23E64, 506B, 脚本 `scripts/decode_xor_blob.py`）
2. **差分重加密**：XOR 流密码下 `新密文 = 旧密文 ⊕ 旧明文 ⊕ 新明文`。
   只要做**等长替换**（32hex→32hex），连 keystream 都不用完全理解。

坑位记录：Java 序列化流的 String = `0x74 + u2 len + modified-UTF8`（等长 ASCII 替换安全）；
Android `Base64.decode(str, 0)` 容忍缺 padding，Python 侧需手动补 `=` 再解码。

### 10.5 反 hook 黑名单（Class.forName 探测）

blob 序列化数组 args[1:] 存的是 hook 框架类名，native 逐个 `Class.forName` 探测，
**ClassNotFoundException 被 catch 后 continue（不杀）**——只有 args[0]（签名期望值）
不匹配才杀。46.3.5 黑名单：`com.swift.sandhook.SandHook`、`sharkfall.inc.signkiller.SignKillerApp`、
`org.EirvAppComponentFactoryStub`、`np.manager.FuckSign`、`np.App`、`lucky.patcher.sign.hook`、
`yazdan.SignHook`、`arm.StubApp`、`cnfix.FuckSign`、`cc.binmt.signature.PmsHookApplication`、
`org.lsposed.hiddenapibypass.HiddenApiBypass`。
**含义**：任何基于这些框架的"运行时签名伪装"方案会被 native 探测并 kill；
静态等长替换期望值不在黑名单之列，是唯一穿门路径。

### 10.6 标准作业流程（SOP 汇总）

```
1. python scripts/sigblock_extract.py 原包.apk              # 全部证书 + 哈希
2. adb shell dumpsys package <pkg> | grep -A2 Signatures    # PM 实际记录哪张(三方对账)
3. build_mod_apk.py 原包.apk 对照.apk                        # 纯重签对照包 → 装机 → 抓杀链(§10.1)
4. IDA: 对照包死点函数反编译 → 门语义分类(§10.3 表格)
5. dump_jnitable.py 还原注册表 → 确认"死点帧"对应的 native fn
6. 按门类型修复: 期望值等长替换(patch_sig_gate_blob) / 闸门改跳(patch_gate_branch)
7. 弹窗入口若为纯 Java 类 → dex 断链(写 prefs+return, §10.3 末尾), 消灭弹窗+异常源
8. build_mod_apk.py 组包重签 → 模拟器验证存活 + topResumedActivity 推进
9. 真机验证（§8）: 存活 + 弹窗消失双确认; 模拟器/真机行为不一致时按 §10.7 排查
```
