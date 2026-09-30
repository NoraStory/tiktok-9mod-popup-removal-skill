# v46.3.5 案例记录

> **2026-09-27 静态核验修订版**。本版修正了初版的三个错误结论（加载器映射、"native 完整性校验"、dont 开关不可用），
> 完整证据链见 `VERIFICATION.md`。
>
> **⚠️ 2026-09-30 进一步修正**:下表中"Application 全生命周期 native(**官方 libiam.so 加固,非 mod**)"
> 已被推翻——libiam.so 实为 **mod 的主加载器**(伪装官方加固名),负责签名门/动态类定义/全量 native 注册,
> 见 `SIGNATURE-GATE-BREAKTHROUGH.md`。本文件其余结构分析(注入框架映射/prefs 机制/断链点)仍有效。
> 当年引用的 `work/...` 路径为本地临时目录,已清理;产物与证据备份在仓库 `test-data-46.3.5/`。

## APK 信息
- 包名：`com.zhiliaoapp.musically`
- versionName/Code：`46.3.5` / `2024603050`
- 42 个 dex，238 个 arm64 .so
- 签名：v2+v3

## 与 v46.7.5 的关键差异（核验后修正）

| 项 | v46.7.5 | v46.3.5 |
|---|---|---|
| mod 形态 | 4 个小 overlay dex（33/40/41/42） | 合并进现有大 dex（32/42） |
| 弹窗① 类 `īi/ïi/pk*` | classes28 | **classes32** |
| 弹窗① 保护框架 | `ieuwh0`（classes28）→ libieuwh.so | **`probeq0`（classes32）→ libprobeq.so** |
| 弹窗② 触发器（native） | `prime0` 在 **classes42** → libprime.so | `pluzneba0` 在 **classes32** → libpluzneba.so |
| 弹窗② Java 实现 | classes33 | **classes42** |
| 第三框架（与弹窗无关） | GoldDcc0（classes41）→ libGoldDcc.so | `chillbro0`（classes42）→ libchillbro.so（保护 4 个官方类） |
| Application | AwemeHostApplication extends Appnew（纯 Java，可注入） | 全生命周期 native（官方 libiam.so 加固，非 mod） |
| native 读 `dont` prefs | libieuwh.so ✓ | **libprobeq.so 与 libpluzneba.so 均读** `getSharedPreferences("",0).getBoolean("dont",false)` |

> 初版错误：把弹窗①的保护库写成 libchillbro.so。实际 `chillbro0/berusz` 在 classes42，
> 只保护 `BackgroundAudioVM`/`AiMeTabFragment`/`X/806`/`X/HyI`，与弹窗无关。

## 弹窗①（英文横幅）链路（核验确认）

- 类在 classes32，`<clinit>` → `probeq0/neonlia.registerNativesForClass(I,Class)` → libprobeq.so。
- native 完整实现弹窗：HandlerThread+Looper+Handler、URL 拉取（openConnection/getInputStream/readLine）、
  AlertDialog/CheckBox UI、prefs 检查。字符串全部走"池基址+offset"运行时寻址（静态 ADRP 扫不到）。
- **native 读 prefs `""` + 键 `dont`**。证据：Java 侧勾选框 `pk$100000008$100000007.onClick`
  写 `getSharedPreferences("",0).putBoolean("dont",true)`；native 必须读同一文件+键，
  且 libprobeq 池含 `dont`/`getSharedPreferences`/`getBoolean` 且代码确有引用（0x2fd94/0x2e5a4）。

## 弹窗②（俄文赞助）链路（核验确认）

- native 触发：libpluzneba.so 在 0x48f24 `NewStringUTF("me.tiktokupdatez.b.a")` → Class.forName 反射加载
  → `b/a.a(Context)` → … → `f/a.d(Context)`（此处起线程）→ `f/e.run()`（拉 URL）→ `f/f.run()`/`f/g.run()`（绘制）。
- Java 实现在 classes42，无 native 保护。断链（no-op 三个 runner + f/a.d 不起线程）即死，与 46.7.5 同法。

## 关于"改 classes32 被杀"（核验后推翻原结论）

原结论"native 完整性校验"**不成立**：
- 三个 mod .so 导入表无任何文件 I/O（open/read/mmap/fstat 全无）、无 kill/exit，.text 无内联 syscall
  —— **既不可能读 dex，也不可能发 SIGKILL**。
- registerNativesForClass 实现（probeq 0x30460）不检查 RegisterNatives 返回值，注册失败静默。

历史尝试的真实死因：
| 产物 | 实际改动 | 死因（核验后） |
|---|---|---|
| classes32_fix.dex | clinit 去 registerNativesForClass + run() 转普通 | **UnsatisfiedLinkError**：special_clinit_0_20 已调用但未注册（可完整解释） |
| classes32_fix2.dex | clinit 全清空 + run() 转普通 | run() 注册到非 native 方法 → NoSuchMethodError → ExceptionInInitializerError（Java 崩溃路径） |
| classes32_fix4.dex | 仅 run() 转普通（clinit 保留） | 同上（注册失败 → 异常 → 启动崩溃），非哈希校验 |
| classes32_fix3.dex | 仅 num6() 浮点表 com→inv（纯 Java，native 不涉及） | **无法归因**于任何 mod native 机制；baksmali 往返会重排整个 dex（±12 字节），疑似构建副作用或环境因素，需 logcat 定论 |

稳妥策略不变：**不碰 classes32**，用预置 `dont` + classes42 断链绕开。

## 方案 D（vb_signed.apk）静态核验结果

- 与原版逐条目 diff：仅 classes42.dex 变化，其余 19,832 条目零改动。
- `f/a.d(Context)` → `getSharedPreferences("",0).edit().putBoolean("dont",true).commit()`（try/catch，寄存器正确）；
  `f/e.run`/`f/f.run`/`f/g.run` → no-op。chillbro 保护的 4 个官方类与 AwemeHostApplication 未动。
- prefs 文件名/键与 native 读取端完全匹配 ✓；b/a.a→f/a.d 调用路径保留，预置可执行 ✓。
- **静态核验全部通过，待上机验证**（需先卸载原包：签名不同）。

## 结论（修订版）

- 弹窗②：classes42 断链关闭 ✓（与 46.7.5 同法，机制同构）。
- 弹窗①：**预置 `dont=true` 方案（方案 D）在静态上是正确路径** —— 修正初版"libchillbro 无 dont 开关、无法预置"的错误判断。
  初版建议的"逆向 patch libchillbro.so"方向作废（chillbro 与弹窗无关；真正要动也是 probeq/pluzneba，且无必要）。
- "native 完整性校验"条目从陷阱清单中降级：mod 三 .so 无校验能力；classes32 重建失败另有原因（Java 异常路径/构建副作用）。

## 2026-09-29 IDA 原生层复核（ida-pro-mcp，样本 SHA-256 d5138080… 一致）

用 IDA 9.4 无头模式反编译 libprobeq.so / libpluzneba.so，把"两弹窗共用 dont 开关"从推断升级为字节级证据：

| 证据 | libprobeq.so（弹窗①） | libpluzneba.so（弹窗②触发器） |
|---|---|---|
| 字符串池基址 | 0x97CD8 | 0xBDEB8 |
| prefs 文件名 | 池+3519 = **空串 ""**（0x98A97），intern 后缓存为全局 jstring | 同布局（Dex2C 同代码生成器） |
| prefs 键 | 池+5608 = **"dont"**（0x992C0） | 池内明文（闸门函数用同一键） |
| getSharedPreferences 方法 ID | GetMethodID @0x2e5a4（名=池+0x13BD，签名=池+0x13D2），调用 @0x2e5f0 | GetMethodID @0x5275c（名=池+0x31CE），调用 @0x527a8 |
| getBoolean 方法 ID | GetMethodID @0x2e734（名=池+0x140B="getBoolean"，签名=池+0x1416） | GetMethodID @0x528ec（名=池+0x321C="getBoolean"） |
| 读取 + 默认值 | CallBoolean 封装 @0x2e780，key="dont"（全局 jstring），default=false | CallBoolean 封装 @0x52938，default=false |
| **闸门** | **0x2e7cc `CBNZ W8, loc_2F5F8`**：dont=true → 析构+返回，弹窗代码不执行；false 才建 HandlerThread/拉 URL/AlertDialog | **0x52980 `CBNZ W8, loc_537B4`**：dont=true → 跳过后继逻辑 |
| 反射触发 | —（弹窗①全 native） | sub_47B10 @0x48f24 `NewStringUTF(池+0x1F6B)` = "me.tiktokupdatez.b.a" → CallObjectMethod 辅助加载 → NewGlobalRef 缓存；JNI_OnLoad 经注册表登记该 native |

辅助识别（沉淀进 SKILL.md §5.3）：registerNativesForClass 的 native 实现（probeq sub_2FA78）以
`NewStringUTF(池+off)→intern→NewGlobalRef` 成块缓存全部运行时字符串；JNIEnv 偏移 0x48=FindClass、
0xA8=NewGlobalRef、0x108=GetMethodID、0x538=NewStringUTF、0x6B8=RegisterNatives、0x720=ExceptionCheck。

复核结论：方案 D（预置 `""`/`dont=true` + classes42 断链）在原生层完全成立——预置同时压制弹窗①绘制与
弹窗②触发器的 native 闸门；断链再兜底弹窗② Java 实现。首次启动的时序竞态（native 检查早于预置，最多弹一次）不变。

## 2026-09-29 成品构建（Windows 本机复现 vb_signed 补丁）

- 样本：`TikTok-v46.3.5-arm8.apk`（SHA-256 d5138080…），仅替换 classes42.dex（4,822,076 → 4,821,492 字节，与 vb_signed 尺寸一致）。
- 工具：Java 17 + Maven Central 组件拼装 baksmali/smali 2.5.2（thin jar + dexlib2/util/guava/jcommander/antlr），
  build-tools 36.0.0 的 zipalign/apksigner，debug.keystore 签名；条目级 diff：19,832 共同条目仅 classes42.dex 变化。
- 修改内容与 VERIFICATION §三 完全一致：`f/a.d` 预置 `""`/`dont=true` 后 return；`f/e/f/g.run()` no-op。
  全树重反汇编比对：7195 个类仅 4 个目标文件有内容差异（`X/r0N` vs `X/r0n` 的文件名 `.1` 互换是 Windows 大小写不敏感 FS 假象，类声明均完整）。
- 成品：`TikTok-v46.3.5-nopopup.apk`，SHA-256 `330f53c6340a8d7f97ed33b0a7478e13d7056a7613c5d90b2e095909f0607a68`，345,872,968 字节。
- 陷阱记录：① GitHub Releases 的 `releases/download` 直链 404（返回 HTML 页），fat jar 需绕道 Maven Central 依赖拼装；
  ② PowerShell 双引号 here-string 会展开 `$Editor`/保留 `\"`，smali 生成务必用单引号 here-string 或外部脚本文件。

## 2026-09-29 真机闪退 → 根因：smali 把 dex 版本 037 降级成 035

- 现象：首版成品（`330f53c6…`）安装后打开即闪退。
- 结构级 diff（dex header + map_list，非 smali 层）：
  - **magic：原版 `dex\n037` → 重汇编 `dex\n035`**（smali 2.5.2 默认 `--api 15`）；
  - method_ids 38868→38867（无引用条目被裁，良性）、annotations_directory 3506→3504（去掉的两处 @Override，良性）；
  - 其余全部类型计数一致。smali 层全树比对仅 4 个目标文件有差异。
- classes42 含 4 个接口 `<clinit>`（037 特性），035 版本标记下 ART 校验拒绝 → 开屏闪退。
  这也统一解释了 `fix3`（classes32 往返重建）的"死因未定"——同是 035 降级，与"native 校验"无关。
- 修复：`smali a --api 24`（→037）重汇编重建。成品 `e5af1e75…`（4,821,488 字节 dex，条目 diff 仅 classes42.dex 变化）。
- 流程教训：**重汇编后必须回读 dex magic 断言与原版一致**——静态"smali 层全绿"骗不过 ART 的版本特性校验。
