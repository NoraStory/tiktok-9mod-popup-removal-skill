# 46.3.5 签名门突破记录 (2026-09-30)

## 结论

重打包必死的根因**不是** TT_S_E.onCreate 的签名比较,而是 `me.tigrik.a.a`(libiam native,
sub_B6B88)里的**双重 MD5 签名校验**。修一个 506 字节 blob 即可让 debug 签名放行。

## 证据链

1. **diagld(纯重签+原dex+原so)在雷电14 的完整死亡栈**(logcat System.err):
   ```
   at android.os.Process.killProcess
   at me.tigrik.a.a(Native Method)                  ← 杀手
   at com.ss.android.ugc.aweme.main.MainActivity.onCreate(Native Method)
   ```
   死前已显示 NewUserJourney 窗口 → Splash/引导正常,杀点在 MainActivity.onCreate。

2. **TT_S_E.onCreate native (sub_3E954) 不是门**:
   - `String.equals(期望摘要, 实际摘要)` 的 **CallBooleanMethod 返回值被忽略**
   - 流程正常走完(不管匹配与否)→ return 1
   - 仅当流程抛异常(签名数组空/getInstance失败等)→ ThrowNew NPE → printStackTrace → kill
   - 摘要常量 `Aioe2f6w5smCbfmcWDULd4mnGtUfFC9ARJ+R1YwCeME=`(022a1ed9...)身份成谜但无关紧要

3. **JNI 注册表**(libiam .data.rel.ro, 需 R_AARCH64_RELATIVE 重定位解析):
   - TT_S_E.onCreate()Z → 0x3e954
   - TT_S_E.run()V → 0x3fc24(纯透传)
   - MainActivity.onCreate(Bundle)V → 0x705a8(mod 完整替换实现,2301 行)
   - me.tigrik.a.a 是 native(注册在 tigrik 相关表段)→ sub_B6B88

4. **me.tigrik.a.a (sub_B6B88) 授权校验器全解**:
   ```
   算法名 = 解密4B TLS blob (key D3 1F 7D A3) = "MD5"
   certs  = SDK<=27 ? signatures[0..].toByteArray() : signingInfo.getApkContentsSigners()[0..]
   hex1   = md5(所有cert拼接).hex()              // 32字符小写
   upper  = (hex1 + hex1).toUpperCase()           // append两次, 64字符大写
   final  = md5(upper.bytes).hex()                // 32字符小写 ← 双重MD5
   期望值 = 解密506B blob → "0Ah"前缀 + base64(Java序列化String[])
            args[0] = "d6c15948fd4664126f5ccf2cd3698792"
   final == args[0].toLowerCase() ? 继续 : throw → Activity.finish + killProcess + exit(1)
   之后: for each args[i]: Class.forName(i)     // 反hook黑名单, CNF被catch继续
        黑名单: SandHook / SignKillerApp / EirvAppComponentFactoryStub / np.manager.FuckSign
                np.App / lucky.patcher.sign.hook / yazdan.SignHook / arm.StubApp
                cnfix.FuckSign / cc.binmt.signature.PmsHookApplication / lsposed.HiddenApiBypass
   返回 String.valueOf(!hex.equals(blob明文)).toUpperCase() = "TRUE"(正常路径恒返回TRUE)
   ```
   验证: md5((md5(modder404cert).hex()*2).upper()) == d6c15948fd4664126f5ccf2cd3698792 ✓

5. **506B blob 加密** = XOR keystream `K(8B LE)+K(8B LE)` 循环,
   K = 0xDF278B5B95B52DF3(vshlq_u64 + vqtbl4q 组合的等效化简,
   每轮 shift=(idx*8)&0x38 对 idx=16r+k 恒为 0/8 循环 → 31轮 keystream 恒同)。
   期望 hex 为 32 字符**等长替换** → 序列化流/base64/明文全长不变 →
   新密文 = 旧密文 ⊕ 旧明文 ⊕ 新明文(无需复刻 NEON)。

6. **两个弹窗库的 prefs 闸门**(dont boolean):
   - libprobeq  0x2e7cc: `CBNZ W8, loc_2F5F8` → 改 `B loc_2F5F8`(0x1400038b)
   - libpluzneba 0x52980: `CBNZ W8, loc_537B4` → 改 `B loc_537B4`(0x1400038d)
   - pluzneba 持有 `me/tiktokupdatez` 字符串 → 弹窗②(me.tiktokupdatez.b.a)由它 native 调用;
     probeq 持有 AlertDialog/HandlerThread → 弹窗①链在闸门函数 sub_28AB4 内
   - dont=true 时原包本来就走同一条跳过路径 → patch 后行为 = "永久 dont"

## 补丁清单(nopop-v2,相对原包仅 3 个 so,DEX 零改动)

| 文件 | 偏移 | 原 | 新 |
|---|---|---|---|
| lib/arm64-v8a/libiam.so | 0x23E64 (506B) | 期望 d6c15948... | 期望 808478649e372c0775401adaa5c784dc (debug双MD5) |
| lib/arm64-v8a/libprobeq.so | 0x2E7CC | 0x35007168 CBNZ | 0x1400038B B |
| lib/arm64-v8a/libpluzneba.so | 0x52980 | 0x350071A8 CBNZ | 0x1400038D B |

debug 证书: ~/.android/debug.keystore (CN=Android Debug),
sha256 = af80f4d9cd9e42526cd612de21c0a2d7087e44aadaa5ca793c550333034873d9

## 模拟器验证(雷电14, 无frida)

- diagld(纯重签): NewUserJourney 出现后 ~40s killProcess(见栈)
- sigfix(仅libiam): 存活 70s+, 过 MainActivity.onCreate(即 a.a 门)
- nopop-v2(3so): 存活 75s+, NewUserJourney 正常, 零 kill/FATAL/SIGSEGV

## 工具脚本

- dump_jnitable.py   — 解析 RELATIVE 重定位后的 JNINativeMethod 表
- decrypt_blob.py    — 506B blob 解密(neon keystream 等效)
- make_libiam_sigfix.py — 等长替换期望MD5并重加密
- make_nopop_libs.py — 两个 CBNZ→B patch
- build_nopop.py     — 组包
