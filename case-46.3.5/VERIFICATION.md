# TikTok v46.3.5 差异核验与去弹窗过程正确性 — 核验报告

日期：2026-09-27　方法：全静态（baksmali 2.5.2 / r2 6.0.5 / 自研 ADRP xref 扫描 / zip 逐条目 diff）
样本：`/home/kali/Desktop/Tiktok/TikTok-v46.3.5-arm8.apk`（原版 MOD，SHA-256 d5138080…）
对照：`TikTok_Central_v46.7.5_(MOD).apk` 与已验证成品 `_no-popup.apk`（SHA-256 89218273…）

---

## 一、v46.3.5 结构差异（对照 v46.7.5）

| 项 | v46.7.5（已验证） | v46.3.5（本次核验） |
|---|---|---|
| dex 总数 | 45 | 42 |
| mod 代码形态 | 4 个**小 overlay dex**（classes33=35KB, 40=18KB, 41=38KB, 42=6KB） | **合并进现有大 dex**（32/42 均为 4.8MB 级） |
| 弹窗① Java/native 混合类 `īi/ïi/pk*` | classes28 | **classes32** |
| 弹窗① 保护框架 | `ieuwh0`（classes28）→ libieuwh.so | **`probeq0`（classes32）→ libprobeq.so** |
| 弹窗② 触发器（native） | **`prime0` 在 classes42** → libprime.so | **`pluzneba0` 在 classes32** → libpluzneba.so |
| 弹窗② Java 实现（me/tiktokupdatez/*） | classes33 | **classes42** |
| 第三框架（与弹窗无关） | `GoldDcc0`（classes41）→ libGoldDcc.so | `chillbro0`（classes42）→ libchillbro.so，保护 4 个官方类 |
| Application | `AwemeHostApplication` extends `assem.fix.Appnew`（classes17，纯 Java，可注入） | `AwemeHostApplication` 直接 extends Application，**全部生命周期方法 native**（官方 libiam.so 加固，非 mod 所为，不可注入） |
| prefs 预置开关 `dont` | libieuwh.so 有 `getSharedPreferences/getBoolean/dont` | **libprobeq.so 与 libpluzneba.so 都有**（此前误判为没有） |

两版共同规律：**弹窗②的 native 触发器与 Java 实现分居两个 dex**；Java 实现不受 native 保护，断链安全。

## 二、关键错误结论的推翻（附证据）

### 1. "弹窗① 由 libchillbro.so 保护" — 错
- libchillbro.so 的加载器 `chillbro0/berusz` 在 **classes42**（原 case 笔记误写为弹窗①加载器）。
- classes32 内真正的弹窗①注册链：`īi/ïi/pk`、`pk$ctr`、`pk$100000008` 的 `<clinit>` → `probeq0/neonlia;->registerNativesForClass(I,Class)` → libprobeq.so。
- libchillbro.so 只保护 `BackgroundAudioVM`、`AiMeTabFragment`、`X/806`、`X/HyI` 四个官方类，与弹窗无关。

### 2. "libchillbro 没有 dont/getSharedPreferences，所以 native 可能不读 dont" — 前提错，结论反
- libprobeq.so 的 `.data` 字符串池含完整 prefs 词汇：`getSharedPreferences` / `(Ljava/lang/String;I)…` / `getBoolean` / `(Ljava/lang/String;Z)Z` / **`dont`**。
- 且代码引用证实（非死字符串）：`mov w10,#0x15e8; add x1,x9,x10`（=池基址+0x15e8 → "dont"）后接 `[env+0x538]`=NewStringUTF，位于 0x2fd94；getSharedPreferences 的 GetMethodID 位于 0x2e5a4（name=池+0x13bd）。libpluzneba.so 同样三处全中（0x5275c/0x528ec/0x53e20）。
- **prefs 文件名闭环**：弹窗① Java 侧勾选框 `pk$100000008$100000007.onClick` 写 `getSharedPreferences("",0).putBoolean("dont",true)`；native 必须读同一文件+键（否则 mod 自带"不再显示"功能失效），故 **libprobeq 读 prefs `""` + 键 `dont`** —— 与 v46.7.5 真机验证过的预置写法完全一致。

### 3. "改 classes32 被杀 = native 完整性校验" — 无证据支撑，机制不成立
- 三个 mod .so 的导入表**没有任何文件 I/O**（无 open/read/mmap/fstat/openat），**没有 kill/exit/fork/dlopen**，.text 无内联 syscall（svc#0 扫描 0 命中）。它们**既不可能读 dex 文件，也不可能发 SIGKILL**；唯一致命导入是 C++ 运行时的 `abort`。
- registerNativesForClass 实现（probeq 0x30460）：`cbz x20`（class 为空即跳过）且**不检查 RegisterNatives 返回值** —— 注册失败是静默的。
- 4 个历史尝试产物的实际内容（反汇编比对）：
  - `classes32_fix.dex` = 去掉 `<clinit>` 中 `registerNativesForClass` 调用 + run() 转普通方法 → **UnsatisfiedLinkError 可完整解释**：special_clinit_0_20 已调用但从未注册。
  - `fix2` = clinit 全清空 + run() 转普通；`fix4` = 仅 run() 转普通（clinit 完整保留）。两者中 run() 由 native 声明改为 Java 体后，clinit 里 registerNativesForClass 注册到非 native 方法 → ART 抛 NoSuchMethodError（pending）→ ExceptionInInitializerError → 启动崩溃。这是 **Java 异常路径**，不是哈希校验。
  - `fix3` = 仅改 pk$100000005.num6() 浮点表（com→inv，纯 Java 方法，native 不涉及）→ 死因**无法归因于上述任何机制**，"完整性校验"说法对它完全失效。因 baksmali→smali 往返会重排整个 dex（4 个产物体积均 ±4~20 字节），死因更可能是构建过程副作用或当时设备/环境因素；**需 logcat 才能定论**。
- 46.3.5 无第 4 个 mod native 库（全量 238 个 arm64 lib 排查，mod 相关仅 chillbro/probeq/pluzneba）。

### 4. 弹窗②触发链（此前未查清）
- libpluzneba.so 在 0x48f24 运行时构造 `"me.tiktokupdatez.b.a"`（NewStringUTF，池+0x1f6b）→ 辅助函数 0x277a4（结合池中 `java.lang.Class`+`forName`+`(Ljava/lang/String;)Ljava/lang/Class;`）**反射加载并驱动弹窗②**。
- 46.7.5 侧 libprime.so 池中同样有 `me.tiktokupdatez.f.a` 与 `me.tiktokupdatez.b.a`；其加载器 `prime0/` 在 **classes42**（原笔记的"弹窗② dex=classes33"只对 Java 实现成立）。

## 三、vb_signed.apk 补丁内容逐项核验（此前未测的最后一版）

与原版 APK 逐条目 diff：**仅 classes42.dex 一个条目变化**（4,822,076 → 4,821,492 字节），其余 19,832 个条目（含全部 41 个其他 dex、全部 .so）零改动 ✓。

classes42 内 4 处 smali 修改（baksmali 后语义比对）：
1. `me/tiktokupdatez/f/a.d(Context)`：原"建 Handler+Thread(f/e)" → 改为 `getSharedPreferences("",0).edit().putBoolean("dont",true).commit()`，try/catch 包裹，寄存器 4→3 正确 ✓
2. `f/e.run()`、`f/f.run()`、`f/g.run()` → `return-void` no-op（registers=1）✓
3. `chillbro0` 保护的 4 个官方类、`AwemeHostApplication`、其余全部类**未动** ✓

语义判定：
- **弹窗②**：三个 Runnable 全断 + f/a.d 不再起线程 → 绘制链死。触发器（libpluzneba native）仍会调用 b/a.a → f/a.d，但那只会执行预置写 pref 然后 return。**有效** ✓
- **弹窗①**：libprobeq/pluzneba native 读 prefs `""`+`dont`（已证实）→ 预置写入正确的文件与键。b/a.a→f/a.d 的调用路径未改动，预置可执行。时序上若某次启动 native 检查先于预置，最多弹一次，之后 prefs 持久化即永久抑制。**静态上成立** ✓
- **不碰 classes32** → 与历史死亡案例的死因路径（无论其真实机制为何）无交集 ✓

## 四、结论

1. **v46.3.5 与 v46.7.5 的真正差异**是 mod 注入形态（overlay dex vs 合并）与框架命名（probeq/pluzneba/chillbro vs ieuwh/prime/GoldDcc），**机制完全同构**：弹窗① native 读 prefs `""`+`dont` 开关；弹窗② native 触发 + Java 实现，断链即可。
2. **"native 完整性校验"结论错误**：mod 的三个 .so 无文件 I/O、无 kill 能力，不可能校验 dex；历史失败各有更平凡的解释（UnsatisfiedLinkError / NoSuchMethodError 崩溃路径 / 未定）。
3. **vb_signed.apk 是当前已知最优解**，静态核验全部通过，从未上机测试（此前 adb 掉线）。安装验证时注意：签名不同需先卸载原包。
4. 若 vb 上机后弹窗①仍首次出现，属预期时序；只要第二次启动起消失即证明预置生效。

## 五、下一步建议（按优先级）
1. 安装 `vb_signed.apk` 实测（先卸载原包），`adb logcat` 全程记录 —— 验证两弹窗状态与是否有崩溃。
2. 若弹窗①首次仍弹：把预置点提前（如 classes42 中更早被调用的 me/tiktokupdatez 入口，或 b/a.a 入口首行）。
3. 若仍想彻底断根弹窗① 的 URL 拉取：可 patch libprobeq.so/libpluzneba.so 内联浮点表（需先解其 bytess 编码）——但这是可选项，非必需。
