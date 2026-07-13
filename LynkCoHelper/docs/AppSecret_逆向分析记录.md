# 领克 App 原生签名密钥（AppKey / AppSecret）逆向提取记录

本文档完整记录 `lynkco_common.py` 中 `NATIVE_APP_KEY` / `NATIVE_APP_SECRET`
两个常量的来源、提取方法与验证过程，供后续维护者（或密钥失效后需要重新提取时）参考。

> **密钥明文说明**：出于安全加固考虑，本文档不再直接展示 AppKey/AppSecret
> 的明文值（用 `<REDACTED_APP_KEY>` / `<REDACTED_APP_SECRET>` 占位），实际值
> 已迁移到 `lynkco_common.py` 的默认常量中（并支持通过环境变量
> `LYNKCO_NATIVE_APP_KEY` / `LYNKCO_NATIVE_APP_SECRET` 覆盖，详见该文件顶部
> 注释与 `readme.md` 的 GitHub Actions Secrets 配置说明）。需要查看真实值时
> 请直接查阅 `lynkco_common.py` 源码。

- **NATIVE_APP_KEY** = `<REDACTED_APP_KEY>`
- **NATIVE_APP_SECRET** = `<REDACTED_APP_SECRET>`

用途：为 App 原生 SDK 访问 `app-services.lynkco.com.cn` 网关（阿里云 API 网关）
的 `/auth/login/refresh`（refreshToken 换取新 token）接口生成
`x-ca-signature` 签名，实现自动续期，见 `lynkco_common.py` 中的
`build_native_signature()` 和 `lynkco_login.py` 中的 `refresh_token()`。

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

com.safe.cons.b   (com/safe/cons/b.java)
  全部方法 a()~z(), A()~I() 均标注 @LDPProtect，均为 native 方法，无 Java 实现
  public native String l();   // APP_KEY
  public native String p();   // APP_SECRET
```

`@LDPProtect` 注解（`com.geely.core.common.protect.LDPProtect`）由
`libKwProtectSDK.so` / `libwhite-box.so` 等白盒加密/VMP 壳 SDK 在运行时动态实现，
**密钥明文只在这些 native 方法被调用执行的运行时瞬间存在于寄存器/内存中**，
无法通过反编译 dex、扫描字符串常量池等任何静态手段获取。因此必须走**动态调试**路线，
在运行时截获这两个 native 方法的返回值。

## 2. 尝试过但失败/放弃的路线

| 方案 | 结果 |
|---|---|
| Frida hook `com.safe.cons.b.l()/p()` | App 检测到 frida-server 进程存在（即使未 attach）就会自杀退出，放弃 |
| IDA Pro `android_server` native attach，直接下断点 | `attach_process` 本身能连上，但只要连接稳定建立、进程继续跑，几秒内反调试逻辑就会发现 tracer 并自杀；即使用 `wait_for_next_event` 精细控制事件循环并第一时间 `suspend_process`，耗时仍然超过了反调试检测的时间窗口 |
| 对 native 方法本体直接下断点（JDWP / jdb） | JDI 明确报错 `"Cannot set breakpoints on native methods"`——JDWP 协议层面根本不允许对 native 方法本体下断点，这是 ART/JVM 的硬限制，并非权限问题 |

关键教训：**只要 App 有机会跑完自己的反调试/自杀检测逻辑，进程就会被杀掉**；
必须在其检测逻辑执行之前就完成挂起/拦截。

## 3. 最终成功路线：`am start -D` + `jdb`（JDWP）在 Java 层断点静态初始化块

### 3.1 思路

1. 用 `adb shell am start -D -n <component>` 以"等待调试器"（`waiting-for-debugger`）
   状态启动 App。此时 zygote 已 fork 出新进程，但**进程会阻塞在等待 JDWP 客户端连接
   这一步，App 自身的 Java 代码（包括反调试检测逻辑）完全还没开始执行**，天然获得了一个
   干净的、早于任何检测代码的挂起点。
2. 用标准 JDK 自带的 `jdb`（Java Debugger）通过 `adb forward tcp:8700 jdwp:<pid>`
   建立端口转发后连接上去。**JDWP 是 Java 标准协议，直接在 Java 方法上下断点、
   查看局部变量/静态字段，完全不需要碰 native 层的 ArtMethod 内存结构**，比手写
   IDAPython 解析 ART 内部结构简单得多，且天然契合 `-D` 参数的设计目的。
3. 因为 native 方法本体不能下断点，改为**在调用方**——即
   `com.safe.cons.LynkCoConstants$g` 类的静态初始化块 `<clinit>`——下断点：

   ```
   stop in com.safe.cons.LynkCoConstants$g.<clinit>
   ```

   命中后单步执行完 `static { b = v(); c = w(); d = H(); e = I(); ... }`，
   直接用 `print` 打印类的静态字段 `b`/`c`/`d`/`e`，无需处理"返回值断点"的时序问题。

### 3.2 关键坑与规避方式

- **`adb jdwp` 命令会一直阻塞**：需要用 `(adb jdwp &) ; sleep 1.5; pkill -f "adb jdwp"`
  这种后台短暂运行再杀掉的方式获取一次输出，不能直接阻塞式调用。
- **jdb 非交互模式（`jdb -attach 8700 < commands.txt`）不可靠**：`run` 命令后
  没有更多命令，stdin 关闭会导致 jdb 直接退出，根本等不到断点命中。必须用交互式
  方式（`expect` 或 Python `pexpect`）持续喂命令、等待特定输出后再发下一条命令。
- **不能对已下过一次的 `<clinit>` 断点重复命中**：静态初始化块只会执行一次，
  一旦类已经被初始化过，之后断点不会再触发；如果连接晚了（类已经初始化完），
  只能重启 App（`am force-stop` + `am start -D`）重新来过。
- **绝对不能主动发送 `quit` 让 jdb 正常断开连接**：实测只要 jdb 走了 JDWP 的
  正常 "VM Dispose" 断开流程，App 就会检测到"调试器连接状态发生变化
  （已连接 → 已断开）"并触发自杀重启（这是一种常见反调试策略，用来清除调试痕迹、
  防御"打断点看完就脱离"的攻击手法）。
  **正确做法：直接用 `kill -9` 强制杀掉本地 jdb 客户端进程**，不发送任何
  JDWP dispose/断开信号，TCP 连接异常中断，App 端不会感知到"调试器已断开"，
  进程可以继续正常存活运行。经实测验证：`kill -9` jdb 后目标进程依然存活。

### 3.3 实际操作步骤（可复现）

```bash
# 0. 环境准备
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/platform-tools:$PATH"

# 1. 以等待调试器状态启动 App
adb shell "am force-stop com.lynkco.customer"
adb shell "am start -D -n com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
NEWPID=$(adb shell "pidof com.lynkco.customer")

# 2. 建立 JDWP 端口转发
adb forward tcp:8700 jdwp:$NEWPID

# 3. 用 pexpect 驱动 jdb：连接 -> 下断点 -> run -> 命中后单步执行 <clinit> ->
#    打印 b/c/d/e 字段 -> 全程不发送 quit，操作完直接 kill -9 本地 jdb 进程
```

对应的 `jdb` 交互命令序列（核心部分）：

```
jdb -attach 8700
stop in com.safe.cons.LynkCoConstants$g.<clinit>
run
# ... 等待 "Breakpoint hit" ...
next   # 单步执行，直到 static 块里 b/c/d/e 都被赋值
print com.safe.cons.LynkCoConstants$g.b
print com.safe.cons.LynkCoConstants$g.c
print com.safe.cons.LynkCoConstants$g.d
print com.safe.cons.LynkCoConstants$g.e
# 不发 quit！直接在本地 kill -9 这个 jdb 进程
```

### 3.4 捕获结果

单步执行 `<clinit>` 过程中完整捕获到四个静态字段的明文值：

```
b = "<REDACTED_APP_KEY>"      <- v() 结果 = APP_KEY (x-ca-key)
c = "<REDACTED_APP_SECRET>"   <- w() 结果 = APP_SECRET
d = "<REDACTED_LOG_APP_KEY>"    <- H() 结果（另一套日志上报用的 APP_KEY，非本次目标）
e = "<REDACTED_LOG_APP_SECRET>" <- I() 结果（另一套日志上报用的 APP_SECRET，非本次目标）
```

`b` 字段的值与此前长达约 18 小时、跨越多次 App 生命周期/refreshToken
使用的真实抓包记录（`/tmp/refresh_flow_output.txt`）中观察到的
`x-ca-key` 请求头值 **完全一致**，从未变化过，这直接证明了断点位置正确，
`c` 字段就是我们要找的 `appSecret` 明文。

## 4. 验证：确认 AppSecret 与签名算法均正确

拿到候选 `appSecret` 后，用真实抓包样本反向验证签名算法，确认密钥真实有效。

### 4.1 第一轮验证：失败（算法猜测有误）

最初按照分析笔记里对 H5 端签名算法的猜测（分隔符 `#`、无 `Date` 头参与），
构造 `string-to-sign` 后用候选 secret 计算 HMAC-SHA256，与真实抓包的
`x-ca-signature` 逐一比对，**所有 accept/content-type 组合均不匹配**。
说明问题不在 secret 本身，而在 string-to-sign 的构造格式。

### 4.2 定位官方权威算法

从运行时脱壳的完整 dex 集合反编译出阿里云官方 SDK 源码：
`com.alibaba.cloudapi.sdk.util.SignUtil`（`buildStringToSign` 方法）以及
`com.alibaba.cloudapi.sdk.constant.SdkConstant` / `HttpConstant`，确认：

- 分隔符 `CLOUDAPI_LF` 实际值是 `"\n"`（换行符），**不是**之前猜测的 `"#"`；
- `Date` 请求头必须参与签名运算（此前的实现遗漏了这一项）；
- 参与签名的头仅限 `x-ca-` 前缀（`x-ca-key` / `x-ca-nonce` / `x-ca-timestamp`），
  用 `TreeMap` 按 key 字典序自动排序，格式为每行 `"key:value\n"`；
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

### 4.3 第二轮验证：完全匹配

严格按上述官方算法重建 `string-to-sign`（使用真实抓包的 `nonce`、
`timestamp`、`date`、`path`、`query`），用候选 secret（即上文提取到的
`<REDACTED_APP_SECRET>`）计算签名，**与两组独立的真实抓包样本中的
`x-ca-signature` 逐字节完全一致**。至此，`NATIVE_APP_KEY` /
`NATIVE_APP_SECRET` 以及签名算法均得到确凿验证，`lynkco_common.py` 据此完成
`build_native_signature()` 的最终实现。

## 5. 结论 & 后续维护提示

- `NATIVE_APP_KEY` / `NATIVE_APP_SECRET` 是领克官方 App **应用级别**共用的密钥
  （不区分用户、不随用户登录状态变化），可以在脚本里长期硬编码使用。
- 若未来领克升级 App 版本并更换了这一对密钥（一般发生在 App 大版本更新、更换加固/
  白盒方案时），签名会重新开始返回 403，需要重新执行本文档第 3 节的动态调试流程
  （`am start -D` + `jdb` 断点 `com.safe.cons.LynkCoConstants$g.<clinit>`）
  重新提取，并按第 4 节的方法重新验证。
- 若某个 App 版本把密钥调用链（类名/方法名/字段名）做了混淆调整，需要先重新
  静态分析定位新的调用链路径（参考第 1 节的分析方法：从
  `LynkCoModuleInitializer.initInProcess()` 或
  `SWXKitCore.setAliCloudAppKey()` 的调用点反向追踪其参数来源）。
