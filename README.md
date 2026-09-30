# TikTok 9MOD 弹窗移除技能

一份教 Agent(和你)把 TikTok 魔改版里的强制弹窗干净移除的完整方法论与工具集。
来自两个真实案例的实战沉淀:**TikTok v46.3.5(arm8, 9MOD 发行版)** 与 **TikTok v46.7.5**,
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

## 目录结构

```
├── SKILL.md                 完整方法论(测试环境/流程/签名门破解/陷阱清单)
├── scripts/                 17 个工具脚本(核心 6 个 + 辅助 11 个)
│   ├── version_detect.py    版本探测:自动发现 mod 布局与推荐策略
│   ├── sigblock_extract.py  提取 APK v1/v2/v3 全部签名证书
│   ├── dump_jnitable.py     还原 JNINativeMethod 注册表(含重定位解析)
│   ├── decode_xor_blob.py   解密 NEON XOR 加密 blob(等效 keystream)
│   ├── patch_sig_gate_blob.py  重写双重 MD5 签名门期望值(差分重加密)
│   ├── patch_gate_branch.py    条件分支改无条件跳转(弹窗闸门)
│   ├── build_mod_apk.py     组包+对齐+签名一条龙
│   ├── dexscan.py / adrpscan.py / adrp_xref.py / jninative.py / poolscan.py
│   ├── logproxy.py / rebuild_apk.py / pair_and_connect.sh / popup_watch.sh
│   └── java_trace.js        Frida 追踪脚本(可选)
├── case-46.3.5/             v46.3.5 案例:签名门破解完整实录 + 踩坑记录
├── case-46.7.5/             v46.7.5 案例:去弹窗补丁与验证
└── SHA256SUMS.txt           文件完整性校验
```

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

## License

本项目以 **GNU Affero General Public License v3.0(AGPL-3.0)** 发布,完整协议文本见 [LICENSE](LICENSE)。

- 任何对本项目代码的修改与网络提供服务,均须以 AGPL-3.0 开放源码
- 衍生作品须保留同样的 AGPL-3.0 协议与版权声明
