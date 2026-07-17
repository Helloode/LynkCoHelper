# 领克 App 原生签名密钥（AppKey / AppSecret）逆向提取记录

本文档记录 `lynkco_common.py` 中 `NATIVE_APP_KEY` / `NATIVE_APP_SECRET`
两个常量的来源、提取方法与验证过程，供密钥失效后重新提取时参考。

> 密钥明文不在本文档展示（用 `<REDACTED_APP_KEY>` / `<REDACTED_APP_SECRET>`
> 占位），实际值在 `lynkco_common.py` 的默认常量中（支持环境变量
> `LYNKCO_NATIVE_APP_KEY` / `LYNKCO_NATIVE_APP_SECRET` 覆盖，详见该文件顶部
> 注释与 `readme.md`）。

用途：为 App 原生 SDK 访问 `app-services.lynkco.com.cn` 网关（阿里云 API 网关）
的 `/auth/login/refresh`（refreshToken 换取新 token）接口生成
`x-ca-signature` 签名，实现自动续期，见 `lynkco_common.py` 的
`build_native_signature()` 和 `lynkco_login.py` 的 `refresh_token()`。

---

## 1. 背景：为什么不能靠静态反编译直接拿到明文

App 包名 `com.lynkco.customer`，代码中密钥调用链如下：

```
LynkCoModuleInitializer.initInProcess()
  -> SWXKitCore.setAliCloudAppKey(str2, str3)      // str2 = g.b, str3 = g.c
  -> SWFramworkKitCore.setAliCloudGateWay(str2, str3)

com.safe.cons.LynkCoConstants$g   (静态初始化块)
  static { b = v(); c = w(); d = H(); e = I(); ... }
  v() -> release 分支: com.safe.cons.b.w().l()   // -> b 字段 = APP_KEY  (x-ca-key)
  w() -> release 分支: com.safe.cons.b.w().p()   // -> c 字段 = APP_SECRET

com.safe.cons.b（com/safe/cons/b.java）全部方法均标注 @LDPProtect、均为
native 方法，无 Java 实现：
  public native String l();   // APP_KEY
  public native String p();   // APP_SECRET
```

`@LDPProtect` 由白盒加密/VMP 壳 SDK 在运行时动态实现，**密钥明文只在这些
native 方法被调用执行的运行时瞬间存在于内存中**，无法通过反编译 dex、扫描
字符串常量池等静态手段获取，必须走动态调试路线截获返回值。

## 2. 尝试过但失败/放弃的路线

| 方案 | 结果 |
|---|---|
| Frida hook `com.safe.cons.b.l()/p()` | App 检测到 frida-server 进程存在（即使未 attach）就会自杀退出 |
| IDA Pro `android_server` native attach 直接下断点 | 连接稳定建立后几秒内即被反调试逻辑发现并自杀；精细控制挂起时机仍未能抢在检测窗口之前 |
| 对 native 方法本体直接下断点（JDWP / jdb） | JDI 报错 `"Cannot set breakpoints on native methods"`——ART/JVM 硬限制，非权限问题 |

关键教训：**只要 App 有机会跑完自己的反调试/自杀检测逻辑，进程就会被杀掉**，
必须在检测逻辑执行之前完成挂起/拦截。

## 3. 前置条件：系统镜像必须是 `userdebug`/`eng`（与 root、App 自身 debuggable 无关）

```bash
adb shell dumpsys package com.lynkco.customer | grep -i pkgFlags
# 没有 DEBUGGABLE 标志，说明 App 本身不是 debuggable 构建

adb shell run-as com.lynkco.customer id
# run-as: package not debuggable      <- 进一步印证 App 级 debuggable=false

adb shell getprop ro.debuggable   # 1
adb shell getprop ro.build.type   # userdebug
```

- App 级 `android:debuggable`：领克 App 官方正式包是 `false`（Release 构建），
  `run-as` 直接拒绝，这条路走不通。
- 系统级 `ro.debuggable` 才是关键：只要系统固件是 `userdebug`/`eng`（AVD 模拟器、
  部分厂商工程机默认如此），`adbd` 就能无视 App 自身 debuggable 标志，允许
  `am start -D` 强制让任意 App 进程挂起等待调试器、并开放 JDWP 端口。
- 零售版真机（`ro.build.type=user`）：**无论是否 root 都无法使用**本方案（`am
  start -D` 后 JDWP 端口不会开放）。若确需重新提取密钥，可选 AVD 模拟器（本文档
  采用的方式）或 `userdebug`/`eng` 固件的工程机。

### 3.1 本文档实测使用的具体环境版本

以下版本组合已验证可稳定复现（并非唯一可行版本，仅供参考对齐；核心要求
仍是第 3 节所述的 `userdebug`/`eng` 固件）：

| 组件 | 版本 |
|---|---|
| 宿主机 OS | macOS 26.5.1（arm64） |
| Android Emulator | 36.6.11.0 |
| AVD 镜像 | `android-33`（Android 13 / API 33），`google_apis`，`arm64-v8a` |
| 领克 App 安装包 | `com.lynkco.customer`（Release 正式包，`debuggable=false`） |
| Python | 3.9.6 |
| pexpect | 4.9.0（`pip install pexpect`） |
| JDK（提供 `jdb`） | OpenJDK 1.8.0（Corretto 8），`jdb` 协议版本 1.8 |
| Android SDK 位置 | `$HOME/Library/Android/sdk`（`platform-tools`/`emulator` 需在 `PATH` 中） |

## 4. 最终成功路线：`am start -D` + `jdb`（JDWP）在 Java 层断点静态初始化块

### 4.1 思路

1. 用 `adb shell am start -D -n <component>` 以"等待调试器"状态启动 App，此时
   进程会阻塞在等待 JDWP 客户端连接这一步，App 自身代码（包括反调试检测逻辑）
   尚未开始执行，是一个天然的早期挂起点。
2. 用 JDK 自带的 `jdb` 通过 `adb forward tcp:8700 jdwp:<pid>` 建立端口转发后
   连接。JDWP 是 Java 标准协议，可直接对 Java 方法下断点、查看局部变量/静态
   字段，无需涉及 native 层的 ArtMethod 内存结构。
3. 因 native 方法本体不能下断点，改为在**调用方**——
   `com.safe.cons.LynkCoConstants$g` 类的静态初始化块 `<clinit>`——下断点
   （`stop in com.safe.cons.LynkCoConstants$g.<clinit>`），命中后单步执行完
   `static { b = v(); c = w(); ... }`，再 `print` 打印静态字段 `b`/`c`/`d`/`e`。

### 4.2 关键坑与规避方式

- `adb jdwp` 命令会一直阻塞，需后台短暂运行再杀掉获取一次输出（`(adb jdwp
  &) ; sleep 1.5; pkill -f "adb jdwp"`），不能直接阻塞式调用。
- **jdb 必须交互式驱动**：非交互模式（`jdb -attach 8700 < commands.txt`）stdin
  关闭会导致 jdb 直接退出、等不到断点命中，必须用 `expect`/Python `pexpect`
  逐条发送命令并等待响应后再发下一条（一次性批量 `send()` 多条命令也不可靠，
  目标线程还未恢复到挂起态时发送的命令会被丢弃并回显"未挂起任何对象"）。
- `<clinit>` 断点只能命中一次：静态初始化块只执行一次，若连接晚了（类已
  初始化完）只能重启 App（`am force-stop` + `am start -D`）重新来过。
- **不能发送 `quit` 让 jdb 正常断开**：jdb 走正常 "VM Dispose" 流程会让 App 检测到
  调试器连接状态变化并触发自杀重启。**正确做法：直接 `kill -9` 强杀本地 jdb
  客户端进程**，让 TCP 连接异常中断，App 端无感知，进程可继续存活。
- **单步次数越多耗时越长，越容易触发自杀重启**：实测 30 次 `next` 逐条发送（每步
  `sleep 0.2s`）执行到第 14 步左右即触发自杀断开重连。**规避方式：每单步一次即立
  `print` 探测目标字段是否已赋值，命中立即停止**，无需固定次数跑完整个初始化
  块。实测仅需 2 次 `next` 即可命中，大幅压缩暴露在调试状态下的时间窗口。
- jdb 的断点命中提示可能是中文"断点命中"也可能是英文 `"Breakpoint hit"`，驱动
  脚本的匹配逻辑需同时兼容两种输出。

### 4.3 实际操作步骤（可复现）

```bash
# 0. 环境准备（若无现成设备，先启动 AVD 模拟器，天然 userdebug）
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
emulator -avd <avd_name> -no-snapshot-load &
adb wait-for-device

# 1. 以等待调试器状态启动 App
adb shell "am force-stop com.lynkco.customer"
adb shell "am start -D -n com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
NEWPID=$(adb shell "pidof com.lynkco.customer")

# 2. 建立 JDWP 端口转发
adb forward tcp:8700 jdwp:$NEWPID

# 3. 用 pexpect 驱动 jdb：连接 -> 下断点 -> run -> 命中后逐步 next
#    （每步探测字段是否已赋值，命中即停）-> 打印 b/c/d/e -> kill -9 本地 jdb
python3 drive_jdb.py
adb forward --remove tcp:8700
```

对应的 `jdb` 交互命令序列（注意每条命令都要等上一条的提示符返回后再发送）：

```
jdb -attach 8700
stop in com.safe.cons.LynkCoConstants$g.<clinit>
run
# ... 等待 "Breakpoint hit" / "断点命中" ...
next                                          # 单步一次
print com.safe.cons.LynkCoConstants$g.c       # 探测 c 是否已赋值，仍为空值则继续 next
# ... 重复 next + print 探测，直到 c 不再是"空值" ...
print com.safe.cons.LynkCoConstants$g.b
print com.safe.cons.LynkCoConstants$g.c
print com.safe.cons.LynkCoConstants$g.d
print com.safe.cons.LynkCoConstants$g.e
# 不发 quit！直接在本地 kill -9 这个 jdb 进程
```

`drive_jdb.py`（`pexpect`）实现思路：连接后下断点并 `run`，匹配中英文两种
断点提示；循环执行 `next` + `print com...c` 探测，一旦返回值不再是空值就
`break` 跳出循环；最后依次打印 b/c/d/e 四个字段，并用 `child.kill(9)`（而非
发送 `quit`）结束本地 jdb 进程。

完整可复现代码如下（**注意**：`EMPTY_VALUES` 必须包含中文 `"空值"`——jdb 在
字段尚未赋值时会打印 `= 空值` 而非英文 `null`，漏判会导致探测循环提前误判
为"已赋值"而过早退出，实测因这个坑多走了一轮完整流程才定位到）：

```python
#!/usr/bin/env python3
"""
按照 docs/AppSecret_逆向分析记录.md 第4节流程，
通过 jdb (JDWP) 在 com.safe.cons.LynkCoConstants$g.<clinit> 下断点，
单步执行后提取 b/c/d/e 四个静态字段明文值。

用法: python3 drive_jdb.py [jdb端口，默认8700]

注意：
- 本脚本仅在本地临时使用，提取完成后应删除，密钥不应写入代码仓库。
- 结束时必须 kill -9 本地 jdb 进程，不能发送 quit（会触发 App 自杀重启）。
"""
import sys
import time

import pexpect

PORT = sys.argv[1] if len(sys.argv) > 1 else "8700"
CLASS = "com.safe.cons.LynkCoConstants$g"

BREAKPOINT_PATTERNS = [
    "Breakpoint hit",
    "断点命中",
]

# jdb 在字段未赋值时可能打印中文"空值"或英文 null，两者都要识别为"未就绪"
EMPTY_VALUES = {"null", '""', "", "= null", "空值"}


def send_cmd(child, cmd, timeout=15):
    child.sendline(cmd)
    time.sleep(0.3)
    try:
        child.expect(["> ", pexpect.TIMEOUT], timeout=timeout)
    except Exception:
        pass
    return child.before


def main():
    print(f"[*] Connecting jdb -attach {PORT} ...")
    child = pexpect.spawn(f"jdb -attach {PORT}", timeout=30, encoding="utf-8")
    child.logfile = sys.stdout  # 实时打印交互过程，便于观察

    child.expect(["> ", pexpect.EOF, pexpect.TIMEOUT], timeout=30)

    print(f"\n[*] Setting breakpoint at {CLASS}.<clinit> ...")
    send_cmd(child, f"stop in {CLASS}.<clinit>")

    print("\n[*] run")
    child.sendline("run")

    idx = child.expect(BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT], timeout=60)
    if idx >= len(BREAKPOINT_PATTERNS):
        print("[!] 未命中断点（超时/EOF），退出")
        child.kill(9)
        return
    print("\n[+] Breakpoint hit!")
    time.sleep(0.2)
    try:
        child.expect(["> ", pexpect.TIMEOUT], timeout=5)
    except Exception:
        pass

    max_steps = 15
    hit = False
    for i in range(max_steps):
        print(f"\n[*] next (step {i + 1})")
        send_cmd(child, "next", timeout=15)

        out = send_cmd(child, f"print {CLASS}.c", timeout=10)
        val_line = [l for l in out.splitlines() if "=" in l]
        val = val_line[-1].split("=", 1)[-1].strip() if val_line else ""
        print(f"    -> c probe: {val!r}")
        if val and val not in EMPTY_VALUES:
            hit = True
            break

    if not hit:
        print("[!] 单步次数用尽仍未探测到 c 字段赋值，可能命中太晚或结构变化")

    print("\n[*] Dumping fields b/c/d/e ...")
    results = {}
    for field in ["b", "c", "d", "e"]:
        out = send_cmd(child, f"print {CLASS}.{field}", timeout=10)
        results[field] = out

    print("\n" + "=" * 60)
    print("[RESULT]")
    for field, out in results.items():
        print(f"--- {field} raw output ---")
        print(out)
    print("=" * 60)

    print("\n[*] Done. Killing local jdb process with SIGKILL (NOT quit) ...")
    child.kill(9)


if __name__ == "__main__":
    main()
```

运行方式（承接 4.3 节第 2 步已建立的端口转发）：

```bash
pip install pexpect   # 若未安装
python3 drive_jdb.py 8700
```

实测：仅 2 次 `next` 即探测到 `c` 字段非空，`b`/`c` 两个字段打印结果与
`env.json` 中已保存的 `nativeAppKey`/`nativeAppSecret` **完全一致**，全程未
触发反调试自杀，再次验证了方法与脚本的可复现性。

### 4.4 捕获结果

单步执行 `<clinit>` 过程中完整捕获到四个静态字段的明文值：

```
b = "<REDACTED_APP_KEY>"      <- v() 结果 = APP_KEY (x-ca-key)
c = "<REDACTED_APP_SECRET>"   <- w() 结果 = APP_SECRET
d/e                          <- 另一套日志上报用的 APP_KEY/APP_SECRET，非本次目标
```

`b` 字段的值与此前长时间真实抓包记录中观察到的 `x-ca-key` 请求头值**完全一致**，
从未变化过，证明断点位置正确，`c` 字段就是目标 `appSecret` 明文。

> **多次复现验证**：按上述流程在同一台 AVD 上重新跑过多遍，仅需 2 次
> `next` 即命中 `b`/`c` 赋值，全程未触发自杀。每次提取到的值均与当时 `env.json`
> 中已保存的 `nativeAppKey`/`nativeAppSecret` **完全一致**，交叉验证了本文档方法
> 的可复现性与准确性。

## 5. 验证：确认 AppSecret 与签名算法均正确

拿到候选 `appSecret` 后，用真实抓包样本反向验证签名算法。

### 5.1 第一轮验证：失败

最初按猜测的签名格式（分隔符 `#`、无 `Date` 头参与）构造 `string-to-sign`
计算签名，与真实抓包的 `x-ca-signature` 逐一比对，所有组合均不匹配，
说明问题在于签名格式而非密钥本身。

### 5.2 定位官方签名算法

参考阿里云 API 网关官方 SDK（`SignUtil`/`SdkConstant`）的公开实现，确认：

- 分隔符为换行符 `"\n"`，而非之前猜测的 `"#"`；
- `Date` 请求头需要参与签名运算；
- 参与签名的头仅限 `x-ca-` 前缀，按 key 字典序排序，格式为每行 `"key:value\n"`；
- 待签名字符串结构（`buildStringToSign`）为：

  ```
  METHOD\n
  Accept\n
  Content-MD5(固定为空)\n
  Content-Type\n
  Date\n
  (排序后的 x-ca- 头，每行 "key:value\n")
  path(?按 key 排序的 query，格式 "k1=v1&k2=v2")
  ```

- 签名 = `Base64(HMAC-SHA256(string-to-sign, appSecret))`。

### 5.3 第二轮验证：完全匹配

严格按上述算法重建 `string-to-sign`（使用真实抓包的 `nonce`/`timestamp`/
`date`/`path`/`query`），用候选 secret 计算签名，与两组独立的真实抓包样本中的
`x-ca-signature` 逐字节完全一致。至此，`NATIVE_APP_KEY` / `NATIVE_APP_SECRET`
与签名算法均得到验证，`lynkco_common.py` 据此完成 `build_native_signature()`
的实现。

## 6. 结论 & 后续维护提示

- `NATIVE_APP_KEY` / `NATIVE_APP_SECRET` 是领克 App **应用级别**共用的密钥（不区分
  用户、不随登录状态变化），可在脚本里长期复用。
- 若未来领克升级 App 并更换密钥（常见于大版本更新或更换加固方案时），签名会
  重新返回 403，需重新执行第 4 节的流程提取，并按第 5 节验证。重新提取前请先
  确认第 3 节的前置条件（设备系统固件为 `userdebug`/`eng`）仍满足，否则需先
  换用模拟器或工程机。
- 若某个 App 版本调整了密钥调用链（类名/方法名/字段名混淆变化），需先重新做静态
  分析定位新的调用路径（参考第 1 节的分析思路）。
- **环境要求小结**：本方法不依赖 root，也不依赖 App 自身的
  `android:debuggable`，真正的前提是设备/模拟器系统固件为 `userdebug`/`eng`
  （详见第 3 节）。零售版真机（`user` 固件）无论是否 root 均无法直接使用本文档
  的方法，需改用 AVD 模拟器或对应固件的工程机。
