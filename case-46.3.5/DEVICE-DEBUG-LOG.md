# 2026-09-29 真机调试全记录：46.3.5 防二次打包架构剖析（最终状态：未破解，结论明确）

## 实验矩阵（vivo V2505A / Android 16 / arm64，全部 adb 实测）

| 构建产物 | dex | libiam | 签名 | 结果 |
|---|---|---|---|---|
| 原版 46.3.5 (d5138080) | 原版 | 原版 | modder | 启动 → **mod 自带 CrashActivity**（不是正常主界面！），✕ 后回桌面 |
| expA | 原版 | 原版 | debug | **120-280ms 静默死亡**（无 FATAL/无 tombstone/无 dropbox） |
| expB | 原版 | 杀点 NOP | debug | 活到 NewUserJourney，进 MainActivity 时 NPE → CrashActivity |
| diag3 | classes42 补丁 + classes41(换证书) | 杀点 NOP | debug | 同 expB |
| expF | 原版 | 杀点 NOP + **摘要常量改为 debug 证书** | debug | 活更久（1.8s），仍被下一层杀 |
| expG | 原版 | 杀点 NOP + 摘要补丁 | debug | 同 expB，MainActivity NPE → CrashActivity |
| expH | 原版 | expG + MainActivity 内 5 个 NPE 守卫 NOP | debug | 依旧 NPE（守卫/抛出点 > 5 个） |

## libiam.so 的真实身份（IDA 反编译实锤）

**它不是 ByteDance 官方加固，是 mod 的主加载器**，伪装成官方 lib 名：
- 入口：classes41 的 `TT_J/TT_S_E`（ContentProvider，`System.loadLibrary("iam")`，先于 Application 初始化）
- `sub_3C764`：运行时向大量类注册 native——AwemeHostApplication(11 个)、MainActivity(117 个！)、
  `com/tiktok/plugin/client/*`（I-am-Jaggu 插件套件）、`me/tigrik/*`、`i/am/jaggu/dialog` 等
- **动态定义类**：`me/tigrik1`、`kotlin/jvm/internal/AFpS124S0000000_3` 等在全部 42 个 dex 中**无 class_def**，
  由 libiam 运行时 DefineClass 创建，方法体即 so 内 native——dex 里根本看不到这些逻辑

## 四个杀点（killProcess+exit 经 JNI，全 NOP 后仍不够）

| 函数 | 身份 | 杀点 BLR |
|---|---|---|
| sub_3E954 | 某 native（PM 摘要 vs XOR 加密常量 `Aioe2f6w...`=TikTok 官方证书摘要） | 0x3ed88 / 0x3edf4 |
| sub_4B9D0 | **AwemeHostApplication.uncaughtException**（全局崩溃处理器：吞异常→收集签名→杀） | 0x4f9a4 / 0x4fa14 |
| sub_B6B88 | **me/tigrik/a.a（钩子分发器）**，含 finish+kill 关停例程 | 0xb6f18 / 0xb6f8c |
| sub_705A8 | **MainActivity.onCreate**（内含 ≥9 处 NPE 守卫 + 杀块） | 0x717e8 / 0x7185c |

## 已破解的层

1. **dex 版本门**：smali 默认 --api15 把 037 降 035 → ART 拒载（SKILL §7.10）
2. **PM 摘要门**：sub_3E954 的 XOR 加密常量（key `C7638BDDCFBD2BAF`，45B：44 字符 b64+NUL，
   常量位于文件偏移 0x21C48[16]+0x21C58[29]）→ 原位改为 debug 证书摘要 b64 即可通过
3. **4 个杀点** → 全部 NOP 后不再被杀

## 仍未破解的层（停止原因）

- MainActivity.onCreate 的空守卫链：X/1NB.LIZ()（X/90f 单例）、X/HLw.LIZIZ（native SetObjectField 填充，无任何
  Java 写入者）等返回 null。X/90f 的构造 lambda（AFpS124 id1876 `new X/90f()`）本身无门，
  **但 AFpS124S0000000_3 是动态定义类**——其 get$arr$/invoke 分发在 sub_59AF8（0x5560B），
  无立即数比较（跳转表分发），门藏在动态类方法体内
- 层数未知：每剥一层暴露新的一层，且门可藏在任何动态定义类中（dex 静态分析不可见）
- sub_4A514（Application.startActivity native）里还发现：解密 Intent 启动 + `X/SxS` 构造器强制
  `LIZ=false`（`const p2,0x0` 覆盖入参）等人为逻辑

## 最终结论：46.3.5 这个 mod 本身已死

- mod 的远程配置 `https://gist.githubusercontent.com/tigr1234566/e9bf...`（me/tigrik/g/a.CheckUrl）
  **已 404**。原版启动 → 更新/配置检查失败 → 崩进自带 CrashActivity（✕ 只能退出）
- 即：**modder 签名的原包在今天也无法正常使用**，与我们的补丁无关
- 46.3.5 的去弹窗 = 需要（a）破解全部未知层数的签名门 +（b）重建死掉的远程配置系统——
  属于重写 mod 级别的工程，投入产出比远低于使用 46.7.5 线（TikTok Central 发行版无此依赖，去弹窗构建已真机验证）

## 方法论沉淀（可复用）

1. **静默死亡诊断法**：无 FATAL/无 tombstone/dropbox 无条目 = 自杀；查 `logcat -b events` 的
   am_proc_start→am_proc_died 间隔定位死亡时机；`Process: Sending signal. PID: self SIG: 9` =
   Java 层 Process.killProcess 自杀标记
2. **杀点定位法**：lib 里 grep "killProcess" 字符串 → xref 到引用函数 → 函数尾部 `GetStaticMethodID
   (myPid/killProcess/exit)` + `BLR X8`（env+0x418=CallStaticIntMethod、env+0x478=CallStaticVoidMethodV）
   三连即杀点，NOP BLR 即废武功
3. **JNI 注册表解析**：RegisterNatives 表在 .data.rel.ro，文件内槽位为 0，须解析 .rela.dyn
   （R_AARCH64_RELATIVE=1027）取 addend 还原 {name, sig, fn} 三元组
4. **动态类识别**：dex 引用但全 dex 无 class_def 的类 = 运行时 DefineClass；其方法实现在
   提供 DefineClass/RegisterNatives 的 native 库内
5. **XOR 字符串常量扫描**：45 字节窗（44 字符+NUL）按 8 字节循环 key 异密后为合法 base64+padding
   的，即为签名摘要常量；vaddr==file offset 时可直接文件内定位
6. **v1/v2 对照实验定生死**：原 dex + 换签名若死 → 签名门；原签名 + 换 dex 若死 → 内容门

## 模拟器动态调试路线（2026-09-30 追加）

- **MuMu 12（x86_64, Android 15, 伪装 OPPO）**：frida-server 17.18 x86_64 以 root 运行成功
  （MuMu 无 su，但 `adb root` 直接给 root adbd）；**Java 层 frida 钩子全部安装成功**
  （killProcess/exit/getPackageInfo/Signature）——诊断能力已验证
- **但 TikTok 46.3.5 在 MuMu 上无法运行**：arm64-only 的 libiam.so 在 AwemeHostApplication.<init>
  的 System.loadLibrary 阶段即触发 libhoudini SIGSEGV（trying to execute non-executable memory，
  solist_get_headv + libhoudini 翻译栈）。**原版未补丁 APK 同样崩** → 与补丁无关，纯属
  MuMu 翻译层与该 TikTok 的 arm64 库不兼容
- 结论：x86 模拟器路线需换翻译层实现（雷电 9 / Genymotion+旧版 houdini），
  或回到真机（root/gadget）。frida 17.18 PC 端须与 gadget/server 版本严格一致，
  且 Python 裸 create_script 无 Java bridge（frida 17 起），须用 frida CLI 或自带 bridge
- RegisterNatives 数量门：把 native 表绑到 Java 方法上时 ART 直接 SIGABRT
  （"no pending exception expected: NoSuchMethodError"），不是静默失败——
  把 Java 方法改回 native 或将注册计数减一（如 11→10）即可绕过
