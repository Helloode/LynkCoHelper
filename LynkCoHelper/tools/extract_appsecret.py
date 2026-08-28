#!/usr/bin/env python3
"""
extract_appsecret.py —— 一键自动提取领克 App 的 nativeAppKey / nativeAppSecret。
（原 drive_jdb_proxy.py，更名并移入 tools/ 子目录）

原理（详见 docs/AppSecret_逆向分析记录.md 4.5 节）：
  App 进入 waitForDebugger 阻塞态后，adbd 的 jdwp 转发握手会永久挂死；
  只有在进程 fork 后约 0.5s 的早期窗口内完成 JDWP 握手才能成功，而 jdb
  （JVM）冷启动需 1-3s 赶不上。故由本脚本的本地 TCP 代理抢先完成握手，
  再把字节流双向转发给 jdb 下断点提取。

用法（在仓库根目录执行，详见文档第 7 节）：
  python3 LynkCoHelper/tools/extract_appsecret.py            # 无设备时自动冷启动 AVD
  python3 LynkCoHelper/tools/extract_appsecret.py <AVD名字>  # 指定要冷启动的 AVD

自动化内容：
  1. 前置环境自动探测与下载：
     - pexpect 缺失 -> 自动 pip 安装
     - adb (platform-tools ~10MB) / jdb (Amazon Corretto 8 ~110MB) 缺失 ->
       确认后自动下载官方公开源包到 ~/.lynkco-helper-tools/（无需许可协议）
     - 模拟器/AVD 需一次性手动安装（emulator + 系统镜像约 1.5GB 且需接受
       许可协议，Android Studio 图形界面三步更可靠，见文档 7.1 节）
  2. 无在线设备时自动冷启动 AVD（-no-snapshot-load，规避快照导致的握手挂死）
  3. 代理抢握手 -> jdb 断点单步 -> 提取 b/c 字段
  4. 提取成功后交互确认，可自动写入 env.json 的 secrets 段
  5. 连接中断（App 反调试自杀/平台不稳）或提取值格式异常时自动重试，最多 3 次

注意：密钥不应写入代码仓库（env.json 已被 gitignore）。
"""
import glob
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zipfile

try:
    import pexpect
except ImportError:
    pexpect = None

APP = "com.lynkco.customer"
ACTIVITY = "com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
CLASS = "com.safe.cons.LynkCoConstants$g"

PROXY_PORT = 8700      # jdb -> 代理
UPSTREAM_PORT = 8701   # 代理 -> adb forward -> jdwp:<pid>

BREAKPOINT_PATTERNS = ["Breakpoint hit", "断点命中"]
EMPTY_VALUES = {"null", '""', "", "= null", "空值"}
# jdb 提示符两种形态：主提示符 "> "、断点命中后的线程提示符 "main[1] "。
# 只匹配 "> " 会在断点命中后失同步，导致命令输出错位（上一条命令的残留
# 被当成下一条的结果）。
PROMPTS = ["> ", r"main\[\d+\] "]
# 提取值应为纯字母数字串（实测 key 为 9 位数字、secret 为 32 位小写字母数字）
VALUE_RE = re.compile(r"[0-9A-Za-z]{6,64}")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 脚本位于 tools/ 子目录，env.json 在上一级业务目录
ENV_JSON = os.path.join(SCRIPT_DIR, "..", "env.json")
ENV_EXAMPLE = os.path.join(SCRIPT_DIR, "..", "env.json.example")

# 自动下载的前置工具安装位置（不污染项目目录；二次运行可直接复用）
TOOLS_DIR = os.path.expanduser("~/.lynkco-helper-tools")

ADB = None  # main() 中动态探测后赋值
JDB = None


def find_adb():
    """探测 adb：PATH -> ANDROID_HOME/SDK_ROOT -> 常见默认位置 -> 本脚本工具目录。"""
    p = shutil.which("adb")
    if p:
        return p
    bases = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             "~/Library/Android/sdk",   # macOS + Android Studio 默认
             "~/Android/Sdk"]           # Linux + Android Studio 默认
    for base in bases:
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "platform-tools", "adb")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(TOOLS_DIR, "platform-tools", "adb")
    return cand if os.path.exists(cand) else None


def find_jdb():
    """探测 jdb：java_home(-v 1.8) -> 已安装 JVM 目录 -> PATH（排除 macOS 桩）
    -> 本脚本工具目录（自动下载的 Corretto 8）。"""
    try:
        home = subprocess.run(["/usr/libexec/java_home", "-v", "1.8"],
                              capture_output=True, text=True).stdout.strip()
        if home:
            cand = os.path.join(home, "bin", "jdb")
            if os.path.exists(cand):
                return cand
    except Exception:
        pass
    for base in ("~/Library/Java/JavaVirtualMachines",   # macOS 用户级
                 "/Library/Java/JavaVirtualMachines"):   # macOS 系统级
        hits = sorted(glob.glob(os.path.expanduser(base) + "/*/Contents/Home/bin/jdb"))
        if hits:
            return hits[0]
    p = shutil.which("jdb")
    if p and p != "/usr/bin/jdb":   # macOS 的 /usr/bin/jdb 是无 JDK 时的桩
        return p
    hits = sorted(glob.glob(os.path.join(TOOLS_DIR, "jdk8", "**", "bin", "jdb"),
                            recursive=True))
    return hits[0] if hits else None


def find_emulator():
    p = shutil.which("emulator")
    if p:
        return p
    for base in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                 "~/Library/Android/sdk", "~/Android/Sdk"):
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "emulator", "emulator")
        if os.path.exists(cand):
            return cand
    return None


def ensure_pexpect():
    """pexpect 缺失时自动 pip 安装（仅本脚本进程内生效）。"""
    global pexpect
    if pexpect is not None:
        return
    print("[*] 缺少依赖 pexpect，自动安装中（pip install pexpect）...")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "pexpect"])
    if r.returncode != 0:
        sys.exit("[!] pexpect 自动安装失败，请手动执行: "
                 f"{sys.executable} -m pip install pexpect")
    import importlib
    pexpect = importlib.import_module("pexpect")


def _download(url, dest_file, size_mb):
    """下载文件并显示粗略进度。"""
    print(f"[*] 下载 {url}（约 {size_mb}MB，视网络可能需数分钟）")
    state = {"last": -1}

    def hook(count, block, total):
        pct = int(count * block * 100 / total) if total > 0 else 0
        if pct != state["last"] and pct % 5 == 0:
            state["last"] = pct
            print(f"    {pct}%", end="\r")

    try:
        urllib.request.urlretrieve(url, dest_file, reporthook=hook)
    except Exception as e:
        if os.path.exists(dest_file):
            os.remove(dest_file)
        sys.exit(f"[!] 下载失败：{e}\n    可手动下载 {url} 解压到 {TOOLS_DIR} 后重跑")
    print("    100% - 完成          ")


def _confirm_download(kind, size_mb, dest):
    try:
        ans = input(f"[*] 未找到 {kind}，是否自动下载（约 {size_mb}MB -> {dest}）？[Y/n]: ")
    except EOFError:
        ans = "y"
    return ans.strip().lower() != "n"


def ensure_adb():
    """探测 adb；缺失时经确认自动下载 Android platform-tools（官方公开源，
    ~10MB，解压即用，无需许可协议）。"""
    p = find_adb()
    if p:
        return p
    dest = os.path.join(TOOLS_DIR, "platform-tools")
    if not _confirm_download("adb (Android platform-tools)", 10, dest):
        sys.exit("[!] 未找到 adb 且跳过下载。请安装 Android Studio（文档 7.1 节）"
                 "或设置 ANDROID_HOME 后重试。")
    os.makedirs(TOOLS_DIR, exist_ok=True)
    zip_name = ("platform-tools-latest-darwin.zip" if sys.platform == "darwin"
                else "platform-tools-latest-linux.zip")
    arc = os.path.join(TOOLS_DIR, zip_name)
    _download("https://dl.google.com/android/repository/" + zip_name, arc, 10)
    with zipfile.ZipFile(arc) as z:
        z.extractall(TOOLS_DIR)
    os.remove(arc)
    cand = os.path.join(TOOLS_DIR, "platform-tools", "adb")
    if not os.path.exists(cand):
        sys.exit(f"[!] 解压后未找到 adb，请检查 {TOOLS_DIR}")
    return cand


def ensure_jdb():
    """探测 jdb；缺失时经确认自动下载 Amazon Corretto 8 / JDK 8（官方公开源，
    ~110MB，解压即用，无需许可协议）。"""
    p = find_jdb()
    if p:
        return p
    dest = os.path.join(TOOLS_DIR, "jdk8")
    if not _confirm_download("jdb (Amazon Corretto 8 / JDK 8)", 110, dest):
        sys.exit("[!] 未找到 jdb 且跳过下载。请安装 JDK 8"
                 "（macOS: brew install --cask corretto8）后重试。")
    os.makedirs(TOOLS_DIR, exist_ok=True)
    if sys.platform == "darwin":
        arch = "aarch64" if platform.machine() == "arm64" else "x64"
        pkg_name = f"amazon-corretto-8-{arch}-macos-jdk.tar.gz"
    else:
        pkg_name = "amazon-corretto-8-x64-linux-jdk.tar.gz"
    arc = os.path.join(TOOLS_DIR, pkg_name)
    _download("https://corretto.aws/downloads/latest/" + pkg_name, arc, 110)
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(arc) as t:
        t.extractall(dest)
    os.remove(arc)
    hits = sorted(glob.glob(os.path.join(dest, "**", "bin", "jdb"), recursive=True))
    if not hits:
        sys.exit(f"[!] 解压后未找到 jdb，请检查 {dest}")
    return hits[0]


def ensure_device(wanted_avd=None):
    """有在线设备直接用；否则冷启动 AVD（-no-snapshot-load 是硬性前提，见 4.5 坑 1）。"""
    out = adb("devices")
    online = [ln.split()[0] for ln in out.splitlines()
              if ln.strip().endswith("\tdevice")]
    if online:
        print(f"[*] 检测到在线设备：{online[0]}"
              "（若此前是快照方式启动且稍后握手挂死，请改用冷启动后重试，见文档 4.5 坑 1）")
        return
    emu = find_emulator()
    if not emu:
        sys.exit("[!] 无在线设备且未找到 emulator。模拟器/AVD 需一次性手动安装："
                 "Android Studio -> Device Manager 创建（系统镜像选 Google APIs，"
                 "勿选 Google Play），步骤见文档 7.1 节。本脚本不自动下载它"
                 "（emulator + 系统镜像约 1.5GB 且需接受许可协议，手动装一次"
                 "更可靠）。")
    avds = sh([emu, "-list-avds"]).split()
    if not avds:
        sys.exit("[!] 无在线设备，也未找到任何 AVD。请先在 Android Studio 创建模拟器"
                 "（系统镜像必须选 Google APIs，不要选 Google Play）。")
    if wanted_avd:
        if wanted_avd not in avds:
            sys.exit(f"[!] 未找到 AVD \"{wanted_avd}\"，可用：{', '.join(avds)}")
        avd = wanted_avd
    elif len(avds) == 1:
        avd = avds[0]
    else:
        print("[*] 检测到多个 AVD：")
        for i, name in enumerate(avds, 1):
            print(f"    {i}. {name}")
        try:
            idx = int(input("选择要启动的编号 [1]: ").strip() or "1") - 1
            avd = avds[idx]
        except (ValueError, IndexError, EOFError):
            avd = avds[0]
    print(f"[*] 冷启动模拟器 {avd}（-no-snapshot-load，约需 1~2 分钟）...")
    subprocess.Popen([emu, "-avd", avd, "-no-snapshot-load"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    adb("wait-for-device")
    for _ in range(120):   # 最多等 4 分钟
        if adb("shell", "getprop", "sys.boot_completed").strip() == "1":
            print("[+] 模拟器启动完成")
            time.sleep(5)  # 等 adbd / am 就绪，避免首轮 am start 拿不到 PID
            return
        time.sleep(2)
    sys.exit("[!] 模拟器启动超时，请手动冷启动后重试。")


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def adb(*args):
    return subprocess.run([ADB, *args], capture_output=True, text=True).stdout.strip()


class Proxy:
    """jdb 先连上并挂起在握手阶段；等上游就绪后抢先握手并双向转发。"""

    def __init__(self):
        self.upstream_ready = threading.Event()
        self.handshake_done = threading.Event()
        self.status = "init"
        self.aborted = False

    def start_and_serve(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", PROXY_PORT))
        srv.listen(1)
        # 1. 接受 jdb 连接，读取其握手请求并挂起
        self.jdb_sock, _ = srv.accept()
        self.jdb_sock.settimeout(None)
        hs = b""
        while len(hs) < 14:
            chunk = self.jdb_sock.recv(14 - len(hs))
            if not chunk:
                raise RuntimeError("jdb 在握手前断开")
            hs += chunk
        assert hs == b"JDWP-Handshake", hs
        self.status = "jdb_connected"
        srv.close()

        # 2. 等主流程通知上游就绪
        self.upstream_ready.wait(timeout=30)
        if self.aborted:
            return
        # 3. 抢先连接上游（命中早期窗口）并完成握手
        try:
            up = socket.socket()
            up.settimeout(10)
            up.connect(("127.0.0.1", UPSTREAM_PORT))
            up.sendall(b"JDWP-Handshake")
            echo = b""
            while len(echo) < 14:
                c = up.recv(14 - len(echo))
                if not c:
                    raise RuntimeError("上游握手被关闭")
                echo += c
            assert echo == b"JDWP-Handshake"
        except (OSError, RuntimeError, AssertionError):
            return   # 已中止/上游异常：静默退出线程，由主流程重试
        up.settimeout(None)
        self.up_sock = up
        self.jdb_sock.sendall(echo)  # 把握手回显交给 jdb
        self.handshake_done.set()
        self.status = "relaying"

        # 4. 双向转发
        def pump(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        t1 = threading.Thread(target=pump, args=(self.jdb_sock, up), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, self.jdb_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        self.status = "closed"

    def close(self):
        """中止代理线程并释放套接字（重试前清理旧代理）。"""
        self.aborted = True
        self.upstream_ready.set()
        for s in (getattr(self, "jdb_sock", None), getattr(self, "up_sock", None)):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        self.status = "closed"


class Disconnected(Exception):
    """jdb 与目标 VM 的连接中断（App 反调试自杀或平台连接不稳），可重试。"""


def send_cmd(child, cmd, timeout=15):
    """向 jdb 发送命令并收集本条命令的输出。

    同步策略（修复命令输出错位）：
    1. 回显锚点——先等到本条命令的回显出现，天然跳过缓冲区里上一条
       命令的残留输出；
    2. 静默等待——jdb 会异步输出事件（典型：next 的"已完成的步骤"出现在
       早期 "> " 提示符之后），只等第一个提示符会提前返回、把事件文本
       留给下一条命令误捕获，造成整体错位一条。故持续消费到 1 秒无新
       输出为止。
    连接中断时抛 Disconnected，由 main 统一重试。
    """
    try:
        child.sendline(cmd)
        child.expect(re.escape(cmd), timeout=timeout)   # 锚点：本条回显
    except pexpect.EOF:
        raise Disconnected("jdb 已退出（EOF）")
    except (pexpect.TIMEOUT, OSError) as e:
        raise Disconnected(f"等待命令回显失败（{cmd!r}）：{e}")

    parts = []
    first = True
    while True:
        try:
            idx = child.expect(PROMPTS + [pexpect.EOF, pexpect.TIMEOUT],
                               timeout=timeout if first else 1)
        except OSError as e:
            raise Disconnected(f"读取 jdb 输出失败（{e}）")
        if idx == len(PROMPTS):            # EOF：jdb 退出
            raise Disconnected("jdb 已退出（EOF）")
        if idx == len(PROMPTS) + 1:        # 静默：本条命令输出结束
            break
        parts.append(child.before or "")
        first = False
    out = "\n".join(p for p in parts if p.strip())
    if "已断开连接" in out or "disconnected" in out.lower():
        raise Disconnected("目标 VM 断开（App 反调试自杀或平台连接中断）")
    return out


def parse_field(out):
    """从 jdb print 输出中解析字段值；未赋值/失败返回 None。

    只接受行尾 `= "..."` 形式的带引号字符串值：jdb 未赋值时打印 `空值`/
    `null`（无引号）；`next` 的"已完成的步骤: \"线程=main\", ..."等行
    虽含 "=" 但值不带引号，均会被正确排除。
    """
    for line in out.splitlines():
        m = re.search(r'=\s*"([^"]+)"\s*$', line.strip())
        if m and m.group(1) not in EMPTY_VALUES:
            return m.group(1)
    return None


def looks_valid(v):
    """提取值格式校验：纯字母数字串（key=9 位数字，secret=32 位字母数字）。"""
    return bool(v) and VALUE_RE.fullmatch(v) is not None


def maybe_write_env(key, secret):
    """交互确认后，把提取结果写入 env.json 的 secrets 段。"""
    try:
        ans = input("\n是否把上述两个值自动写入 env.json？[y/N]: ").strip().lower()
    except EOFError:
        ans = ""
    if ans != "y":
        print("[*] 未写入，请自行保存。")
        return
    if not os.path.exists(ENV_JSON):
        hint = (f"请先复制 {ENV_EXAMPLE} 为 env.json 并填入账号后重跑"
                if os.path.exists(ENV_EXAMPLE) else "请手动创建该文件")
        print(f"[!] {ENV_JSON} 不存在：{hint}，或手动填入上述值。")
        return
    with open(ENV_JSON, encoding="utf-8") as f:
        env = json.load(f)
    env.setdefault("secrets", {})
    env["secrets"]["nativeAppKey"] = key
    env["secrets"]["nativeAppSecret"] = secret
    with open(ENV_JSON, "w", encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[+] 已写入 {ENV_JSON}（该文件已被 gitignore，不会入库）")


MAX_ATTEMPTS = 3


def run_once():
    """单次完整提取；连接类故障抛 Disconnected 交由 main 重试。返回 (key, secret)。"""
    proxy = Proxy()
    threading.Thread(target=proxy.start_and_serve, daemon=True).start()
    time.sleep(0.3)  # 等代理开始监听
    child = None
    try:
        print(f"[*] Using jdb: {JDB}")
        child = pexpect.spawn(f"{shlex.quote(JDB)} -attach {PROXY_PORT}",
                              timeout=60, encoding="utf-8")
        child.logfile = sys.stdout

        # 等 jdb 完成与代理的 TCP 连接（握手暂时挂起）
        for _ in range(50):
            if proxy.status in ("jdb_connected", "upstream_ready", "relaying"):
                break
            time.sleep(0.1)
        print("\n[*] jdb 已连上代理（阻塞在握手），现在启动 App ...")

        # 启动 App（等待调试器状态），进程一出现立刻建立 forward 并放行代理
        adb("shell", "am", "force-stop", APP)
        time.sleep(0.5)
        adb("shell", "am", "start", "-D", "-n", ACTIVITY)
        t0 = time.time()
        pid = None
        for _ in range(300):   # 约 9s，冷启动后 App 起得慢也等得到
            out = adb("shell", f"pidof {APP}")
            out = out.strip()
            if out and out.split()[0].isdigit():
                pid = out.split()[0]
                break
            time.sleep(0.03)
        if not pid:
            raise Disconnected("未取到 App PID：请确认模拟器已安装领克 App"
                               "（adb shell pm list packages | grep lynkco）")
        print(f"[*] PID={pid} (t={time.time()-t0:.2f}s)，立即建立转发 ...")
        adb("forward", f"tcp:{UPSTREAM_PORT}", f"jdwp:{pid}")
        proxy.upstream_ready.set()

        if not proxy.handshake_done.wait(timeout=15):
            raise Disconnected("上游握手失败（可能错过早期窗口）。"
                               "若模拟器非冷启动，请按文档 4.5 节坑 1 冷启动后重试")
        print("[+] JDWP 握手完成（命中早期窗口）！\n")

        # 等 jdb 初始化完成出现提示符（两种形态："> " / "main[1] "）
        try:
            child.expect(PROMPTS + [pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        except Exception:
            pass

        # 尽快冻结 VM，最大限度赢得与 clinit 的竞速
        print("\n[*] suspend")
        send_cmd(child, "suspend", timeout=10)

        print("\n[*] Setting breakpoint ...")
        send_cmd(child, f"stop in {CLASS}.<clinit>")

        print("\n[*] resume")
        try:
            child.sendline("resume")
        except OSError as e:
            raise Disconnected(f"jdb 进程已退出（{e}）")
        # resume 后断点事件（"设置延迟的断点/断点命中"）会异步到达，这里
        # 不能用 send_cmd（其静默等待可能提前吞掉断点事件），直接等断点文本。
        idx = child.expect(BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT],
                           timeout=90)
        if idx == len(BREAKPOINT_PATTERNS):
            raise Disconnected("等待断点期间 jdb 已退出（EOF）")
        if idx < len(BREAKPOINT_PATTERNS):
            print("\n[+] Breakpoint hit!")
            time.sleep(0.2)
            try:
                child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=5)
            except Exception:
                pass
            for i in range(15):
                print(f"\n[*] next (step {i + 1})")
                send_cmd(child, "next", timeout=15)
                out = send_cmd(child, f"print {CLASS}.c", timeout=10)
                val = parse_field(out)
                print(f"    -> c probe: {val!r}")
                if val:
                    break
        else:
            print("\n[!] 未命中断点（clinit 可能已提前执行），直接尝试打印字段 ...")

        print("\n[*] Dumping fields b/c/d/e ...")
        results = {}
        for field in ["b", "c", "d", "e"]:
            results[field] = send_cmd(child, f"print {CLASS}.{field}", timeout=10)

        print("\n" + "=" * 60)
        print("[RESULT]")
        for field, out in results.items():
            print(f"--- {field} raw output ---")
            print(out)
        print("=" * 60)

        return parse_field(results.get("b", "")), parse_field(results.get("c", ""))
    finally:
        print("\n[*] Killing local jdb with SIGKILL (NOT quit) ...")
        if child is not None:
            try:
                child.kill(9)
            except Exception:
                pass
        proxy.close()
        try:
            adb("forward", "--remove", f"tcp:{UPSTREAM_PORT}")
        except Exception:
            pass


def main():
    global ADB, JDB
    ensure_pexpect()
    ADB = ensure_adb()
    JDB = ensure_jdb()
    print(f"[*] adb: {ADB}")
    print(f"[*] jdb: {JDB}")
    ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    if not adb("shell", "pm", "path", APP).strip():
        sys.exit(f"[!] 设备上未安装 {APP}（领克 App），请先把 APK 拖入模拟器安装")

    key = secret = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            print(f"\n========== 第 {attempt}/{MAX_ATTEMPTS} 次尝试 ==========")
            key, secret = run_once()
            if looks_valid(key) and looks_valid(secret):
                break
            # 解析出了值但格式异常（含空格/中文/引号等）——多为 jdb 输出错位
            print(f"\n[!] 第 {attempt} 次提取的值格式异常（疑似 jdb 输出不同步）：")
            print(f"    nativeAppKey    = {key!r}")
            print(f"    nativeAppSecret = {secret!r}")
            key = secret = None
            if attempt < MAX_ATTEMPTS:
                print("[*] 3 秒后自动重试（将重新 force-stop 并启动 App）...")
                time.sleep(3)
        except Disconnected as e:
            print(f"\n[!] 第 {attempt} 次尝试失败：{e}")
            if attempt < MAX_ATTEMPTS:
                print("[*] 3 秒后自动重试（将重新 force-stop 并启动 App）...")
                time.sleep(3)

    if key and secret:
        print(f"\n[+] 提取成功！nativeAppKey    = {key}")
        print(f"           nativeAppSecret = {secret}")
        maybe_write_env(key, secret)
    else:
        print("\n[!] 多次尝试均未提取到 b/c 字段值。排查建议：")
        print("    1. 反复在 suspend/断点阶段断开 → 多为模拟器非冷启动或平台连接"
              "不稳，请冷启动模拟器（文档 4.5 坑 1/坑 2）后重跑")
        print("    2. 反复未命中断点/字段为空 → App 可能更新了混淆类名，"
              "需按文档第 1 节思路重新静态分析")
        print("    3. 逐段排查可参考文档 4.3 节的 jdb 命令序列；速查表见 7.4 节")
        sys.exit(1)


if __name__ == "__main__":
    main()
