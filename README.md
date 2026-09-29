# tiktok-9mod-popup-removal-skill

> 针对 **TikTok 魔改版 9MOD** APK 的逆向工程技能：定位并移除强制弹窗的可复用方法论与工具集。
> 基于两个真实案例（v46.7.5 / v46.3.5）提炼，所有结论均附字节级出处或真机证据。

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/target-Android%20arm64-green)
![License](https://img.shields.io/badge/license-EDU%20%2F%20research-orange)

---

## 前置技能（必须先加载）

本技能是专项技能，**依赖前置技能 `reverse-skill`（SKILL-reverse-skill，通用逆向基础技能）**。

- 使用本技能前，请确认 `reverse-skill` 已安装并加载；它提供通用的 APK 反编译、smali 阅读、native 分析等基础能力。
- 本技能只覆盖 **TikTok 9MOD 魔改包弹窗移除** 的专项流程与已知陷阱，不重复前置技能中的通用内容。
- 若环境中没有 `reverse-skill`，请先获取并加载它，再回到本技能。

## 为什么做这个

魔改 TikTok 包普遍注入多层强制弹窗（更新提示、Telegram 导流、广告），且常用 **Dex2C native 保护 + 浮点编码 / AES 混淆 + 多套独立注入框架**，定位成本高。本项目把一次完整的移除过程沉淀成：

1. **定位** — 在注入代码中找出弹窗实现（即使被 Dex2C 抽到 native、字符串被加密）
2. **还原** — 完整调用链：触发 → 取数 → 解码 → 绘制 → 按钮回调
3. **Patch** — 最小化修改：不改 native、不破坏注册路径、不触发崩溃
4. **验证** — 无线 adb + 截图 OCR + 崩溃检测的闭环流程

## 目录结构

```
├── SKILL.md               完整方法论（流程、命令、陷阱清单）
├── scripts/               11 个工具脚本（除 Frida 外均为纯 Python 标准库 / bash）
│   ├── version_detect.py  版本探测器：自动发现 mod 布局、native 库、AES 密钥、推荐策略
│   ├── dexscan.py         轻量 DEX 解析器：按包前缀找引用 / 调用点
│   ├── adrpscan.py        AArch64 ADRP+ADD/LDR 扫描：定位字符串引用
│   ├── adrp_xref.py       ADRP 交叉引用分析
│   ├── jninative.py       ELF JNI 方法表解析（含 R_AARCH64_RELATIVE 重定位还原）
│   ├── poolscan.py        Dex2C 字符串池基址 + 偏移还原
│   ├── logproxy.py        adb reverse 日志代理：抓 CONNECT / SNI / HTTP
│   ├── rebuild_apk.py     定点替换 / 新增 zip 条目重建 APK
│   ├── pair_and_connect.sh  adb 无线配对重试（对付 30 秒配对窗口）
│   ├── popup_watch.sh     弹窗监控（dumpsys window + uiautomator dump）
│   └── java_trace.js      Frida Java-bridge 追踪脚本
├── case-46.7.5/           v46.7.5 案例：链路、patch 方案、验证结果（已通过）
├── case-46.3.5/           v46.3.5 案例：差异分析、陷阱、核验修订记录
└── SHA256SUMS.txt         全部案例与脚本文件的完整性校验
```

## 快速开始

```bash
# 0. 版本探测（推荐第一步，自动发现 mod 布局）
python3 scripts/version_detect.py target.apk

# 1. 提取并反编译 dex
mkdir -p work/dex
python3 -c "import zipfile; z=zipfile.ZipFile('target.apk'); \
  [open('work/dex/'+n,'wb').write(z.read(n)) for n in z.namelist() if n.endswith('.dex')]"
baksmali d work/dex/classes33.dex -o work/smali33   # 具体 dex 以 version_detect 输出为准

# 2. 扫注入包
python3 scripts/dexscan.py work/dex

# 3. 还原混淆（浮点×4 / Base64 变体 / AES）— 见 SKILL.md §4

# 4. patch smali — 见 SKILL.md §5（精确到方法签名）

# 5. 重打包（--api 必须匹配原 dex 版本：037→24、038→26、039→30；否则开屏闪退，见 SKILL.md §7.10）
smali a --api 24 work/smali_patch -o patched.dex
python3 scripts/rebuild_apk.py original.apk output.apk "classes33.dex=patched.dex"
zipalign -f -p 4 output.apk aligned.apk
apksigner sign --ks key.keystore aligned.apk

# 6. 真机验证
python3 scripts/pair_and_connect.sh IP:PORT CODE
adb install output.apk
adb shell monkey -p com.xxx -c android.intent.category.LAUNCHER 1
adb exec-out screencap -p > s.png && tesseract s.png stdout --psm 6
```

## 环境安装

### 脚本依赖一览

| 脚本 | 依赖 |
|---|---|
| version_detect.py | Python 3 + aapt（分析 APK 时） |
| dexscan / adrpscan / adrp_xref / jninative / poolscan / logproxy / rebuild_apk | Python 3 纯标准库 |
| pair_and_connect.sh / popup_watch.sh | bash + adb |
| java_trace.js | Frida（gadget 或 frida-server） |

### 必装工具

| 工具 | 用途 | 安装 |
|---|---|---|
| **Python 3.8+** | 运行全部 Python 脚本（零第三方包） | python.org 安装并勾选 Add to PATH |
| **Java JDK 8+** | 运行 baksmali / smali / apksigner | 任意 OpenJDK；大 dex 重汇编需 `JAVA_OPTS="-Xmx3200m"`（SKILL.md §7.4） |
| **Android Platform-Tools** | `adb`：无线连真机、安装、截图、logcat | https://developer.android.com/tools/releases/platform-tools |
| **Android Build-Tools** | `aapt`/`aapt2`、`zipalign`、`apksigner` | SDK Manager 或 `sdkmanager "build-tools;34.0.0"` |
| **baksmali / smali 2.5.2+** | dex ↔ smali 互转 | https://github.com/baksmali/smali Releases，`java -jar` 调用 |

**最小可用组合 = 以上 5 项**，即可跑通 README 快速开始的完整流程。

### 按需安装

| 工具 | 用途 | 安装 |
|---|---|---|
| **tesseract-ocr** | 弹窗截图文字识别 | Windows：`winget install UB-Mannheim.TesseractOCR`；Linux：`apt install tesseract-ocr` |
| **Pillow** | 截图放大裁剪（OCR 预处理，SKILL.md §7.8）——**唯一需要的 pip 包** | `pip install Pillow` |
| **openssl** | AES-128-ECB 解密混淆字符串（SKILL.md §4.3） | Git Bash 自带，或 `winget install openssl` |
| **bash**（Git Bash / WSL） | 运行两个 `.sh` 脚本 | Windows 装 Git for Windows 即可 |
| **rabin2 / radare2** | 查 .so 导入表，核验有无 native 校验能力（SKILL.md §7.2 通用排查法） | https://rada.re |
| **apktool** | 资源层面反编译（可选） | https://apktool.org |
| **Frida** | 运行 `java_trace.js` 动态追踪 | `pip install frida-tools` + 真机 frida-server / gadget；注意 vivo / Android 16 上 Gadget 因 PAC 崩溃不可用（SKILL.md §7.6） |

### 真机要求

一台开启**无线调试**的 Android 手机（开发者选项 → 无线调试），与电脑同一局域网。无线调试端口会漂移（SKILL.md §7.7），每次以手机界面当前显示为准，配合 `pair_and_connect.sh` 自动重试。

## 核心方法论摘要

**Patch 策略优先级**（详见 SKILL.md §6）：

- **A. 预置 mod 自己的 pref 开关**（最安全）—— native 弹窗前读 `getSharedPreferences("").getBoolean("dont")` 时，直接在 Application `onCreate` 预置 `dont=true`
- **B. 断 Java 取数链** —— 将取数入口方法体置空，不碰 native
- **C. 改 native `run()` 为 Java 空实现** —— 高风险：`RegisterNatives` 注册到非 native 方法会抛 `NoSuchMethodError` → `ExceptionInInitializerError` 启动崩溃
- **D. 改数据表（URL 无效化）** —— 死因未定，避免依赖

**已证伪的误区**（2026-09-27 核验修订）：所谓 "native 对 dex 做完整性校验" 不存在——mod 的 .so 导入表无文件 I/O、无 kill 能力。真实崩溃源于 JNI 注册路径。排查通用法：`rabin2 -i xxx.so` 查导入表 + svc 扫描。

## 案例速览

| 版本 | 弹窗①（英文） | 弹窗②（俄文） | 状态 |
|---|---|---|---|
| v46.7.5 | classes28 + `libieuwh.so`，预置 `dont=true` | classes33 断取数链，触发器 `prime0`@classes42 | 真机验证通过 |
| v46.3.5 | classes32 + `libprobeq.so`，预置 `dont=true`（libprobeq/libpluzneba 均读该开关） | classes42 断链（同 v46.7.5 方法） | **补丁链已真机验证到第 4 层**：dex 版本门/杀点/PM 摘要门均已破解，但该发行版为多层签名门 + 动态定义类 + 远程配置依赖（gist 已 404，原包本身已坏），见 `case-46.3.5/DEVICE-DEBUG-LOG.md`。建议使用 v46.7.5 线 |

不同版本的注入布局完全不同，**不能用固定 dex 编号**——先跑 `version_detect.py`。

## 免责声明

本项目仅用于安全研究与学习目的。逆向修改后的 APK 不得用于分发或任何侵犯原软件权利的行为。使用者需自行承担相关法律与设备风险。

## License

Educational / research use only. 参见免责声明。
