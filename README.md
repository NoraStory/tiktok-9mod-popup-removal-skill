# TikTok 9MOD 弹窗移除技能

一份教 Agent(和你)把 TikTok 魔改版里的强制弹窗干净移除的完整方法论与工具集。
来自两个真实案例的实战沉淀:**TikTok v46.3.5(arm8, 9MOD 发行版)** 与 **TikTok v46.7.5(arm8, 9MOD 发行版)**,
每个结论都有字节级出处或真机证据。

> **重要声明:本项目分析的全部 APK 均为第三方魔改发行版(9MOD 等社区修改版),
> 不是 TikTok 官方版本。** 相关原生库(libiam/libprobeq/libpluzneba 等)也是魔改发行版
> 自带的注入组件,与 ByteDance/TikTok 官方无关。**请勿对本技能所述方法用于逆向
> TikTok 官方版本或任何官方组件。**

---

## 它解决什么问题

魔改版 TikTok(9MOD / max.ru / TikTok Central 等发行版)有三个让人头疼的东西:

1. **强制弹窗** —— 更新提示、Telegram 导流、赞助广告,启动就弹
2. **多层混淆** —— 弹窗代码被抽成 native(Dex2C)、字符串加密、Unicode 类名
3. **防二次打包** —— 重签,App 启动几秒后直接自杀(killProcess)

这个项目把整套破解流程拆成 **5 步**,每步都有现成脚本:

| 步骤 | 做什么 | 用什么 |
|---|---|---|
| ① 侦察 | 探测 mod 发行版、注入布局、保护库 | `version_detect.py` |
| ② 还原 | 反编译、扫注入框架、解密字符串 | `dexscan.py` / `poolscan.py` |
| ③ 定位门 | 还原 JNI 注册表、找真正的签名校验函数 | `dump_jnitable.py` |
| ④ 破门 | 重写签名期望值 / 关掉弹窗闸门 | `patch_sig_gate_blob.py` / `patch_gate_branch.py` |
| ⑤ 成品 | 替换 .so → 对齐 → 重签 → 装机验证 | `build_mod_apk.py` |

---

## 适配的 TikTok 版本

| TikTok 版本 | 发行版 | 测试状态 |
|---|---|---|
| **v46.3.5** (arm8) | 9MOD | **完整破解并通过双端验证**:签名门(双重 MD5 blob)+ 弹窗闸门 + dex 断链,模拟器与真机(vivo, Android 16)均确认弹窗消失、App 正常运行 |
| **v46.7.5** | 9MOD / TikTok Central | 去弹窗补丁真机验证通过 |

> 其他版本?注入布局完全不同,**不要按固定 dex 编号套**——先跑
> `python scripts/version_detect.py 目标.apk`,它会告诉你该怎么走。

---

## 三分钟了解核心思路

**为什么重打包后 App 会死?**
魔改版里藏着一个"授权校验器"(藏在伪装成官方加固库的 `libiam.so` 里)。它在启动时:

1. 读取你 APK 的签名证书
2. 算一个双重 MD5
3. 和它自己内置的加密常量比对
4. 不一致 → `finish + killProcess + exit`,App 秒死

**怎么破?**
不需要伪造签名(那需要别人私钥)。它把"期望值"存在一个 XOR 加密的 blob 里——
我们把里面的 32 字符摘要**等长替换成你自己签名证书的对应值**,再用同样的 XOR 方式写回去。
App 启动时一算:一致,放行。

**弹窗呢?**
两个弹窗库(probeq/pluzneba)在画弹窗前都会读一个开关:`getBoolean("dont", false)`。
把这条判断从"有条件跳过"改成"无条件跳过",弹窗链整体短路——等于永久勾选"不再显示"。

最终成品:**只替换 3 个 `.so` 文件,DEX 一个字节不动**,风险最小。

---

## 快速开始

```powershell
# 0. 环境自检(需先按下文《测试环境》装好工具)
python --version        # 3.12.x
java -version           # 17.x
adb version             # platform-tools 37.x

# 1. 侦察
python scripts/version_detect.py TikTok-v46.3.5-arm8.apk

# 2. 提取全部证书,和真机/模拟器 dumpsys 的签名对账
python scripts/sigblock_extract.py TikTok-v46.3.5-arm8.apk --outdir sigcerts
adb shell "dumpsys package com.zhiliaoapp.musically" | findstr Signatures

# 3. 纯重签对照实验(最重要的一步!先看 App 死在哪,再谈 patch)
python scripts/build_mod_apk.py TikTok-v46.3.5-arm8.apk control.apk
adb install control.apk   # 装机观察 logcat 死亡栈

# 4. 按死亡栈破门(详见 SKILL.md §10)
python scripts/dump_jnitable.py libiam.so --anchor 0x1005e0
python scripts/decode_xor_blob.py libiam.so 0x23E64 506 --key 0xDF278B5B95B52DF3
python scripts/patch_sig_gate_blob.py libiam.so libiam_sigfix.so --cert debug_cert.der
python scripts/patch_gate_branch.py libprobeq.so libprobeq_nopop.so --vaddr 0x2E7CC --target 0x2F5F8 --expect cbnz:rt=8

# 5. 成品
python scripts/build_mod_apk.py TikTok-v46.3.5-arm8.apk 无弹窗.apk `
  --replace "lib/arm64-v8a/libiam.so=libiam_sigfix.so" `
  --replace "lib/arm64-v8a/libprobeq.so=libprobeq_nopop.so"
```

---

## 目录与文档导航

**本项目每个路径是什么、干什么用的:**

### 根目录

| 路径 | 说明 |
|---|---|
| `SKILL.md` | **核心方法论主文档**(Agent 加载的技能正文)。含:测试环境与工具版本、五步总流程、混淆还原、Dex2C 调用链还原、Patch 策略、陷阱清单(14 条)、签名门破解方法论(§10,含纯重签对照实验/JNI 注册表还原/双重 MD5 门/SOP) |
| `README.md` | 本文件。项目介绍、适配版本、快速开始、导航 |
| `LICENSE` | AGPL-3.0 协议全文 |
| `SHA256SUMS.txt` | 全部文档与脚本的完整性校验和 |

### `scripts/` — 17 个工具脚本

**核心流水线(按 §10 SOP 的使用顺序):**

| 脚本 | 用途 |
|---|---|
| `version_detect.py` | 第一步:探测 mod 发行版布局、注入框架、native 库,输出推荐策略 |
| `sigblock_extract.py` | 提取 APK 的 v1/v2/v3 全部签名证书并计算哈希(与 dumpsys 三方对账) |
| `dump_jnitable.py` | 还原 .so 里的 JNINativeMethod 注册表(哪个 Java native 方法由哪个函数实现,含 RELATIVE 重定位解析) |
| `decode_xor_blob.py` | 解密 NEON XOR 加密 blob(等效 keystream 化简,用于读取签名门期望值) |
| `patch_sig_gate_blob.py` | 重写签名门期望值:等长替换 + 差分重加密 + 回读断言 |
| `patch_gate_branch.py` | 把 prefs 闸门的条件分支(CBNZ)改写为无条件跳转(弹窗闸门关闭) |
| `build_mod_apk.py` | 组包:替换 zip 条目 → zipalign → apksigner 签名;不带 --replace 即"纯重签对照包" |

**辅助脚本:**

| 脚本 | 用途 |
|---|---|
| `dexscan.py` | 轻量 DEX 解析:按包前缀找注入类/调用点 |
| `adrpscan.py` / `adrp_xref.py` | AArch64 ADRP+ADD/LDR 扫描与交叉引用(定位字符串引用) |
| `jninative.py` | ELF JNI 方法表解析(早期版本,`dump_jnitable.py` 为其增强) |
| `poolscan.py` | Dex2C 字符串池基址与偏移还原 |
| `rebuild_apk.py` | 定点替换 zip 条目重组 APK(早期版本,`build_mod_apk.py` 为其增强) |
| `logproxy.py` | adb reverse 日志代理:抓 CONNECT 域名 / TLS SNI |
| `pair_and_connect.sh` | adb 无线配对重试(30 秒窗口) |
| `popup_watch.sh` | 弹窗监控(dumpsys window + uiautomator dump) |
| `java_trace.js` | Frida Java-bridge 追踪脚本(可选,仅模拟器) |

### `case-46.3.5/` — v46.3.5 案例档案(主案例,签名门破解)

| 文档 | 内容 |
|---|---|
| `SIGNATURE-GATE-BREAKTHROUGH.md` | **签名门破解完整实录**(命令级):纯重签对照实验、双重 MD5 门全解、blob 差分重加密、最终成品 nopop-v3 与双端验证 |
| `DEVICE-DEBUG-LOG.md` | 真机调试日志:杀点定位、JNI 表、动态定义类、frida 各轮实验记录 |
| `NOTES.md` | 中间分析笔记:dex 版本门、构建链、早期误区与证伪 |
| `VERIFICATION.md` | 各轮验证包的结果矩阵 |
| `../test-data-46.3.5/` | (相邻目录)该案例的最终产物与证据备份,见下 |

### `case-46.7.5/` — v46.7.5 案例档案

| 文档 | 内容 |
|---|---|
| `NOTES.md` | 去弹窗补丁方案与真机验证记录(该版本无签名门) |

### `test-data-46.3.5/` — 测试数据备份(非代码,9.8MB)

**存的是什么**:v46.3.5 案例最终真实可用的产物与逆向证据,未上传任何 APK/IDA 库/大二进制。

| 文件组 | 内容 |
|---|---|
| `libiam_sigfix.so` + `libprobeq_nopop.so` + `libpluzneba_nopop.so` + `classes42_patched_037.dex` | 无弹窗成品的**全部 4 处改动**(签名门 blob / 两个弹窗闸门 / dex 断链),附逐文件说明 |
| `libiam_orig.so` / `libprobeq.so` / `libpluzneba.so` | 原版基线(零修改,供复分析) |
| `tigrik_blob_enc.bin` / `tigrik_serial.bin` | 签名门加密 blob 与解密后的序列化流(期望值 + 反 hook 黑名单证据) |
| `modder_*.der` / `modder_cert_*.bin` / `debug_cert.der` / `our_cert_sha256.bin` | 原版与重签证书及摘要(哈希对账) |

每个文件的字节级说明见 `test-data-46.3.5/README.md`。

---

## 测试环境(本项目实测版本)

| 组件 | 版本 | 说明 |
|---|---|---|
| Windows 11 | Build 26200 (25H2) x64 | 全部命令在 PowerShell 运行 |
| Python | 3.12.13 | 零第三方依赖(仅 OCR 预处理需 Pillow) |
| JDK | 17.0.20 LTS | 跑 smali/baksmali/apksigner |
| Android platform-tools | 37.0.1-15733141 | adb 1.0.41 |
| Android build-tools | 36.0.0 | zipalign / apksigner 0.9 / aapt2 2.20-13193326 |
| smali / baksmali | 2.5.2 | GitHub Releases |
| IDA Pro | 9.4 (headless idalib) | native 静态分析 |
| Frida | 17.18.0 + frida-tools 14.10.4 | 可选,仅限模拟器 Java 层诊断 |
| 模拟器 | LDPlayer 14(雷电14), Android 14 x86_64, 已 root | MuMu 12 实测不兼容,勿用 |
| 真机 | vivo V2505A, Android 16, 无 root | 最终验收设备 |

完整安装步骤、每项工具的用途和踩坑说明 → **SKILL.md「测试环境」章节**。

---

## 新手最容易踩的 5 个坑

1. **改完 dex 重打包必死,以为有"全套完整性校验"** → 其实只有一个签名门,
   先做"纯重签对照实验"定位真凶(README 上面的第 3 步)
2. **smali 重汇编后开屏闪退** → dex 版本被降级(037→035),`smali a --api 24` 补回
3. **在 killProcess 上无脑 NOP** → 返回值被下游依赖,换来 NPE;要先读懂门逻辑
4. **用 logcat 判断真机死因** → vivo 屏蔽第三方 App 日志,改用 `dumpsys` + 进程存活
5. **相信"最新版"工具就能跑** → 版本差异是真坑(smali 2.5.2 的 `--api` 默认值、
   Frida 17 的 Java bridge 变化都是本案例实际踩过的)

---

## 免责声明

- 本项目分析的**全部 APK 均为第三方魔改发行版**(9MOD 等社区修改版),**非官方版本**;
  文中提到的 libiam / libprobeq / libpluzneba 等库均为魔改发行版自带的注入组件,并非官方代码。
- **请勿使用本项目的方法对 TikTok 官方版本或任何官方组件进行逆向、修改或重打包。**
- 逆向修改后的 APK 不得用于分发或任何侵犯原软件权利的行为。
- 使用者自行承担相关法律与设备风险。

## 贡献者

| 贡献人 | 角色 |
|---|---|
| **NoraStory** | 项目发起、案例提供、真机验证 |
| **MiMo** | AI 助手(小米 MiMo):逆向分析、签名门破解、方法论沉淀与全部脚本/文档编写 |

> 本项目由 **AI 辅助完成**:逆向分析、调用链还原、补丁设计与全部文档/脚本均由
> MiMo 在人类指导下产出;方向决策、设备操作与真机验证由人类完成。
> 我们认为公开 AI 参与方式有助于读者评估内容可信度,故在此如实注明。

## License

本项目以 **GNU Affero General Public License v3.0(AGPL-3.0)** 发布,完整协议文本见 [LICENSE](LICENSE)。

- 任何对本项目代码的修改与网络提供服务,均须以 AGPL-3.0 开放源码
- 衍生作品须保留同样的 AGPL-3.0 协议与版权声明
