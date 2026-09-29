# SKILL — TikTok 魔改版 9MOD 弹窗移除方法论

> **前置技能**：本技能依赖 `reverse-skill`（SKILL-reverse-skill，通用逆向基础技能），使用前必须先加载。
> 本文档从真实案例（TikTok 9MOD v46.7.5 / v46.3.5）提炼，覆盖从定位到移除的全流程。
> 所有断言均附字节级出处或真机证据。

---

## 1. 总流程

```
Triage（包信息/签名/dex 数/manifest）
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
设计 patch（优先不碰 native / 利用 mod 自己的开关 / 断 Java 取数链）
  ↓
静态自检（方法签名/寄存器/try-catch 完整性）
  ↓
重打包 + 签名
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
