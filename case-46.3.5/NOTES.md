# v46.3.5 案例记录

> **2026-09-27 静态核验修订版**。本版修正了初版的三个错误结论（加载器映射、"native 完整性校验"、dont 开关不可用），
> 完整证据链见 `work/20260927-062910-tiktok-v46-3-5-mod-apk-patch/VERIFICATION.md`。

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
