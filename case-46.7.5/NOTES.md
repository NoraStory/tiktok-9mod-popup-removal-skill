# v46.7.5 案例记录

## APK 信息
- 包名：`com.zhiliaoapp.musically`
- versionName/Code：`46.7.5` / `2024607050`
- 45 个 dex、455 个 .so
- 签名：v2+v3（无 v1）

## 注入框架（4 套）

| # | 框架 | dex | native | 作用 |
|---|---|---|---|---|
| 1 | `com.aaaaaaa.*`（Gold/Assem） | classes41 | libGoldDcc.so | 去水印等 + "New Update Available" 更新弹窗（另一套） |
| 2 | `assem.fix.Appnew` + `com.acra.*` | classes40 | 无 | ApkSignatureKillerEx + ACRA |
| 3 | `me.tiktokupdatez.*` | classes33 | libprime.so | 俄文弹窗 |
| 4 | `īi/ïi/pk` + `ieuwh0/*` | classes28 | libieuwh.so | 英文横幅弹窗 |

## 弹窗①（英文横幅）链路

```
native (libieuwh.so) → pk.process(Context)
  → pk$100000008(Context, 7×StringBuilder)
    → run()（native）:
        getSharedPreferences("").getBoolean("dont")  ← 开关
        pk$num*() → 浮点表解码（char=float×4）→ URL+文案
        HttpURLConnection → 服务器取数
        正则 (.*)Url=(.*) / (.*)Version=(.*) / (.*)Code=(.*) 解析
        AlertDialog$Builder.setView().setCancelable(false).show()
按钮:
  $100000006.onClick → dialog.dismiss() + startActivity(下载链接)
  $100000007.onClick → dialog.dismiss() + prefs("").putBoolean("dont", true)
```

URL 基址：`https://afmod.com/`（来自 `pk$100000005.num6()` 浮点表）
镜像：`a.tiktokmod.pro/banner30.conf`、`a.tiktokmod.pro/max2.conf`（AES 密钥 `MD5CryptoByte128`）、`tigr1234566.github.io/banner.conf`、`rezvorck.github.io/pub.conf`

## 弹窗②（俄文赞助）链路

```
f/a.d(Context) → new Thread(f/e).start()
  f/e.run():
    StringBuffer(f/a.d() + f/a.e()) → 解码 ×2 → URL
    HttpURLConnection(60s) → readLine → f/a.b()(ArrayList)
    成功 → Handler.post(f/g) → 触发绘制
    失败 → Handler.post(f/f) → if(a()>=2) d(Context) 重试
b/a.a(Context):
    prefs("key"/"act") 判断激活 → 按语言取 d/a.* 文案 → Html.fromHtml
    → AlertDialog$Builder.setCancelable(false).show()
```

文案来源：`d/a.<clinit>` 5 个 Base64 编码的多语言 HTML（ru/zh/en）。
解码链：`a/a.a()`（skip3+Base64）、`a/a.b()`（XOR+Base64）、`f/x.a()`（AES-128-ECB，密钥 `MD5CryptoByte128`）。

## 修复方案（已验证通过）

| dex | 改动 | 目标 |
|---|---|---|
| classes40.dex | `Appnew.onCreate()` 预置 `prefs("").dont=true` | 弹窗①（native 读 dont → 不弹） |
| classes33.dex | `f/a.d(Context)` + `f/e.run()` + `f/f.run()` + `f/g.run()` → 空实现 | 弹窗②（断取数链） |
| classes28.dex | **未修改** | — |
| classes41.dex | **未修改** | — |

产物 SHA-256：`892182738f6c29ef7ba346cce420d3bd2d887552a42639a5b8df81294e43041a`

## 验证结果

- 弹窗①（9MOD.COM/DOWNLOAD NOW）：**不出现**（OCR 0 命中）
- 弹窗②（Telegram/MAX/俄文）：**不出现**（OCR 0 命中）
- FATAL 崩溃：0
- App 能走到 `NewUserJourneyActivity`（首次引导页）

## 关键证据

libieuwh.so 字符串偏移：
- `dont` @ 0xf2b2d
- `getSharedPreferences` @ 0xf285b
- `getBoolean` @ 0xef9be
- `num6` @ 0xf2856
- `pk$100000008` @ 0xf210d
- `setCancelable` @ 0xf20f5
- `val$sb2` @ 0xf1e8c
- `afmod` / `litepaks`：**未找到**（证明域名来自浮点表而非 .so 硬编码）
