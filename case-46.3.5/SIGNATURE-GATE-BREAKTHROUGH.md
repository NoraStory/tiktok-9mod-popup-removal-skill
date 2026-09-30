# 46.3.5 签名门破解完整实录（2026-09-30）

> 配套方法论: `../SKILL.md` §10。本文是命令级实录, 每一步含真实输出与踩坑。
> 环境: Windows PowerShell + MIMO_PYTHON; 设备: 雷电14 (Android 14, root, 无 frida)。
> 目标产物: `TikTok-46.3.5-nopop-v2.apk`（原包仅替换 3 个 .so, DEX 零改动, debug 重签）。

## 0. 起点状态（历史包袱）

此前数天的错误结论（已被本实录推翻）:
- 以为 TT_S_E.onCreate(sub_3E954) 是"PM 摘要门", 改其 XOR 摘要常量（libiam_ourdigest.so）无效;
- 以为存在"多层签名门"（Application/MainActivity/B6B88/uncaughtException 各一套）, 逐层 NOP kill
  导致 NPE（expH~expQ 全军覆没）;
- 以为 gist 404 = "原包已坏"（实际原包真机/模拟器均可完整运行, 含开屏动画与弹窗）。

## 1. 决定性实验: 纯重签对照包（零 frida）

```powershell
# 纯重签 = build_mod_apk.py 不带 --replace（或历史上的 diagld 包）
adb -s emulator-5554 install -r TikTok-4635-diagld.apk     # Success
adb shell logcat -c; adb shell am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity
Start-Sleep 18
adb shell "logcat -d | grep -A 25 'call killProcess callstack'"
```

真实输出（决定性证据）:

```
java.lang.Exception: call killProcess callstack! pid=6664
    at android.os.Process.killProcess(Process.java:1318)
    at me.tigrik.a.a(Native Method)                          ← 杀手
    at com.ss.android.ugc.aweme.main.MainActivity.onCreate(Native Method)
    at android.app.Activity.performCreate(Activity.java:8627)
    ...
09-30 11:59:44.933 I Process : Sending signal. PID: 6664 SIG: 9
```

三个结论:
1. 死点唯一: `me.tigrik.a.a`（native）在 `MainActivity.onCreate` 里被调;
2. 纯重签包能跑到 NewUserJourney → Splash/引导/provider 链全部正常;
   **TT_S_E.onCreate 根本没有拦截**（后续反编译证实它忽略 equals 结果）;
3. `dumpsys package` 显示 PM 记录的签名 = v2/v3 的 404B 证书
   `3b61c2a82aff9f76...` —— 门比较对象就是它。

## 2. 证书全景对账（scripts/sigblock_extract.py）

```powershell
& $env:MIMO_PYTHON scripts\sigblock_extract.py C:\Users\story\Downloads\TikTok-v46.3.5-arm8.apk --outdir sigcerts
& 'E:\JAVA\JDK\bin\keytool.exe' -list -v -keystore "$env:USERPROFILE\.android\debug.keystore" -storepass android | Select-String SHA256
```

对账表:

| 证书 | 长度 | sha256 前 16 | 来源 |
|---|---|---|---|
| v2=v3 signer | 404B | 3b61c2a82aff9f76 | 签名块（PM 实际记录的就是它）|
| v1 BNDLTOOL.RSA 内层 | 907B | 9041803e... | PKCS#7 |
| classes41 TT_S_E blob 内嵌 | 854B | 2509dde1335913f2 | mod 自带 |
| debug keystore | 744B | af80f4d9cd9e4252 | 我们重签用的, keytool 对账一致 |

> 坑: TT_S_E 的 `onCreate` 是 native, Java 侧只是存了一个证书 blob 字符串;
> smali41 里的 blob 已是历史实验换成 debug 证书的版本, 看原始内容要回原包 dex。

## 3. JNI 注册表还原（scripts/dump_jnitable.py）

锚点: IDA 中 sub_3E954 仅有一个 data xref @0x1005f0 → 表项起点 0x1005e0。

```powershell
& $env:MIMO_PYTHON scripts\dump_jnitable.py libiam_orig.so --anchor 0x1005e0 --span 90
```

关键输出（节选, 全表 ~117 项见 case 附件脚本输出）:

```
0x1005e0  onCreate   ()Z                                  fn=0x3e954    ← TT_S_E.onCreate
0x100610  run        ()V                                  fn=0x3fc24    ← TT_S_E.run(纯透传)
0x100730  uncaughtException (Thread,Throwable)V              fn=0x4b9d0
0x100e38  onCreate   (Landroid/os/Bundle;)V                fn=0x705a8    ← MainActivity.onCreate(mod替换实现)
```

踩坑记录（脚本已内置修复）:
- 文件内槽位全 0 → 必须 `.rela.dyn` R_AARCH64_RELATIVE addend 覆盖;
- 第二段 LOAD `vaddr=0x100530 offset=0xff530` → vaddr = fileoff + 0x1000;
- 字符串指针（如 0x1ff6b='onCreate'）在第一段 LOAD, vaddr==fileoff。

## 4. TT_S_E.onCreate 证伪（不是门）

sub_3E954 全文 547 行, 控制流:
```
getContext → getPackageManager → getPackageInfo(pkg, SDK>=28 ? 0x8000000 : 64)
→ versionName equals(结果被忽略, 死代码)
→ SDK>=28 ? signingInfo.getApkContentsSigners()[0] : signatures[0]
→ MessageDigest("SHA-256").digest(cert)
→ Base64.encodeToString(digest, 0).trim()
→ equals(解密常量 "Aioe2f6w5smCbfmcWDULd4mnGtUfFC9ARJ+R1YwCeME=", 实际b64)
   → CallBooleanMethod 返回值【被忽略】→ 无异常即 return 1
   → 只有流程抛异常(数组空/getInstance失败)才 LABEL_19: killProcess+exit
```
其期望摘要 `Aioe...` 解码 = `022a1ed9fe...` 与任何已知证书的 sha256 都不匹配 —— 无所谓,
反正是"恒放行"逻辑。**结论: 给这个门改常量（历史 libiam_ourdigest.so）是无用功。**

## 5. 真门 me.tigrik.a.a（sub_B6B88）全解

1538 行伪代码, 完整算法:

```
alg   = 解密 4B TLS blob(unk_10C250, key D3 1F 7D A3) = "MD5"
certs = SDK<=27: signatures[i].toByteArray() 逐个 update
        SDK>27 : signingInfo.getApkContentsSigners() 遍历逐个 update
hex1  = 逐字节 Integer.toString(b|0x100, 16).substring(1) 拼 StringBuffer   ← 小写 hex
sb.append(hex1); sb.append(hex1)            ← 同一 hex1 append 两次
upper = sb.toString().toUpperCase()
md.update(upper.getBytes()); final = md5 → 又一轮 hex1 算法        ← 双重 MD5
blob  = 解密 506B(unk_23E64) → NewStringUTF → substring(3)
        → Base64.decode → ObjectInputStream.readObject → String[] args
args[0].toLowerCase().equals(final) ?
    true : Class.forName(args[i]) 逐个探测(CNF被catch, continue) → 返回 "TRUE"
    false: throw Exception → Activity.finish() → killProcess(myPid) → System.exit(1)
           (kill @0xb6f18, exit @0xb6f8c)
```

期望值验证:

```powershell
& $env:MIMO_PYTHON -c "import hashlib; c=open('sigcerts\v2_cert_0.der','rb').read(); h=hashlib.md5(c).hexdigest(); print(hashlib.md5((h*2).upper().encode()).hexdigest())"
# d6c15948fd4664126f5ccf2cd3698792  ← 与 blob 序列化流里的 args[0] 逐字符一致
```

blob 明文（解密后 505 字符, 头部）:

```
'0AhrO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAx0ACBkNmMxNTk0OGZkN...'
  ^^^prefix                              base64("...Ljava/lang/String;...") …
```

序列化 String[] 内容（scripts/decode_xor_blob.py + 手工解析）:
- `[0] d6c15948fd4664126f5ccf2cd3698792`（32hex = 双重MD5 期望值, @serial 0x2f）
- `[1..11] 反hook黑名单`: SandHook / SignKillerApp / EirvAppComponentFactoryStub /
  np.manager.FuckSign / np.App / lucky.patcher.sign.hook / yazdan.SignHook /
  arm.StubApp / cnfix.FuckSign / cc.binmt.signature.PmsHookApplication /
  org.lsposed.hiddenapibypass.HiddenApiBypass

## 6. blob 加密的等效化简（避免复刻 NEON）

原始 NEON（0xb8d88-0xb8ed8）: 8 个索引 xmmword(0x20A50/0x20B60/0x210F0/0x20A90/
0x21360/0x20DE0/0x21030/0x20720 = 索引 14,15/10,11/12,13/8,9/6,7/2,3/4,5/0,1),
每轮 +0x10; `vshlq_u64(K, -(vshlq_n(idx,3) & 0x38))` 造表 → `vqtbl4q` 按
perm=xmmword_21320(=[0,8,...,120]) 取 16B → veor。

推演结论（逐条在实录中验证）:
- shift=(idx*8)&0x38; idx=16r+k ⇒ (16r+k)&7==k&7 ⇒ **31 轮 keystream 恒同**;
- `vqtbl4q` 索引 64-120 越界返回 0, 而 `v89.n128_u64[0/1]` 各只取 tbl172/tbl173
  结果的 lane0 ⇒ 等效 keystream = `K(8B LE) 重复`, K=0xDF278B5B95B52DF3;
- 尾部 8B veor K + b[504]^=0xF3, b[505]^=0x2D 恰与 16B 循环一致（496%16==0）。

验证: `decrypt_blob.py libiam_orig.so 0x23E64 506 --key 0xDF278B5B95B52DF3`
→ 明文 = `'0Ah' + base64(ac ed 00 05...)` ✓

## 7. 差分重加密（patch_sig_gate_blob.py）

等长替换原则: 32hex→32hex ⇒ 序列化流长度不变 ⇒ base64 不变 ⇒ 明文不变长 ⇒
`新密文 = 旧密文 ⊕ 旧明文 ⊕ 新明文`。新期望值:

```
md5(debug_cert) = c17a6a6803d22869ed10553a7c1dfda9
final_debug     = md5(("c17a6a68...da9"*2).upper()) = 808478649e372c0775401adaa5c784dc
```

```powershell
& $env:MIMO_PYTHON scripts\patch_sig_gate_blob.py work-4635-build\libiam_orig.so work-4635-build\libiam_sigfix.so --cert work-4635-build\debug_cert.der
# old expected gate digest: d6c15948fd4664126f5ccf2cd3698792 @serial 0x2f
# new expected gate digest: 808478649e372c0775401adaa5c784dc
# written libiam_sigfix.so; roundtrip OK; 40 cipher bytes differ
```

## 8. 弹窗闸门 patch（patch_gate_branch.py）

libprobeq 0x2e7cc（弹窗①绘制链 sub_28AB4 内, AlertDialog/HandlerThread 所在）:

```
0x2e7c8  LDUR W8, [X29,#var_48]     ; dont = getBoolean("", "dont", false)
0x2e7cc  CBNZ W8, loc_2F5F8          ; 0x35007168 → B 0x1400038B (imm26=(0x2F5F8-0x2E7CC)/4=907)
```

libpluzneba 0x52980（弹窗②触发器 sub_4CAB8, 持有 "me/tiktokupdatez" 字符串@0xbde26,
即调 me.tiktokupdatez.b.a 的 native）:

```
0x52980  CBNZ W8, loc_537B4          ; 0x350071A8 → B 0x1400038D (imm26=909)
```

安全依据: dont=true 是 mod 自身支持的"不再显示"状态, 跳过分支=正常路径。

## 9. 组包 + 签名 + 模拟器验证

```powershell
& $env:MIMO_PYTHON scripts\build_mod_apk.py 原包.apk TikTok-4635-nopop-v2.apk `
  --replace "lib/arm64-v8a/libiam.so=libiam_sigfix.so" `
  --replace "lib/arm64-v8a/libprobeq.so=libprobeq_nopop.so" `
  --replace "lib/arm64-v8a/libpluzneba.so=libpluzneba_nopop.so"
adb install -r TikTok-4635-nopop-v2.apk; adb shell am start ...
```

对照时间线（全部无 frida, 同一模拟器）:

| 包 | 结果 |
|---|---|
| diagld 纯重签 | NewUserJourney 后 ~40s killProcess（栈见 §1）|
| sigfix 仅 libiam | 存活 70s+, 越过 MainActivity.onCreate（门已放行）|
| nopop-v2 三 so | 存活 75s+, NewUserJourney 正常, 零 kill/FATAL/SIGSEGV |

## 10. 遗留与真机清单

- 真机 vivo V2505A（Android 16）: 安装前必须卸载原包（签名不同）, 会清登录态, 需用户确认;
- libchillbro.so 只保护 4 个官方类, 与弹窗/签名门无关（历史结论维持）;
- mod 远控（gist 404）失效不影响本地运行（09-30 修正）;
- 成品: 桌面 `TikTok-46.3.5-无弹窗-修复版.apk` = nopop-v2。
