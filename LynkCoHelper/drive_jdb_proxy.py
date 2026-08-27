#!/usr/bin/env python3
"""
drive_jdb_proxy.py —— 在 drive_jdb.py 基础上增加本地 TCP 代理层。

背景：本环境实测发现，App 进入 waitForDebugger 阻塞状态后，adbd 的
jdwp 转发握手会永久挂死（Settings 等系统应用同样如此）；只有在 App
进程刚 fork、尚未执行到 waitForDebugger 的窗口期（约 0.5s 内）完成
JDWP 握手才能成功。而 jdb 自身是 JVM，冷启动需要 1-3 秒，来不及。

方案：先启动本地代理监听 8700，让 jdb 先连上代理并阻塞在握手阶段；
随后启动 App（am start -D），进程 PID 一出现立刻建立 adb forward 并由
代理抢先与上游完成握手（命中早期窗口），再双向转发字节。

流程：
  代理监听 8700 -> jdb 连接代理（握手挂起）-> am start -D -> 轮询 PID
  -> adb forward 8701 -> 代理连上游 8701 完成握手 -> jdb 就绪
  -> suspend（尽快冻结 VM）-> stop in <clinit> -> resume -> 断点命中
  -> next + print 探测 -> 打印 b/c/d/e -> kill -9 jdb
"""
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

import pexpect

ADB = os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
CORRETTO8_JDB = os.path.expanduser(
    "~/Library/Java/JavaVirtualMachines/amazon-corretto-8.jdk/Contents/Home/bin/jdb")
JDB = "jdb" if shutil.which("jdb") and shutil.which("jdb") != "/usr/bin/jdb" else CORRETTO8_JDB

APP = "com.lynkco.customer"
ACTIVITY = "com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
CLASS = "com.safe.cons.LynkCoConstants$g"

PROXY_PORT = 8700      # jdb -> 代理
UPSTREAM_PORT = 8701   # 代理 -> adb forward -> jdwp:<pid>

BREAKPOINT_PATTERNS = ["Breakpoint hit", "断点命中"]
EMPTY_VALUES = {"null", '""', "", "= null", "空值"}


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
        # 3. 抢先连接上游（命中早期窗口）并完成握手
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


def send_cmd(child, cmd, timeout=15):
    child.sendline(cmd)
    time.sleep(0.3)
    try:
        child.expect(["> ", pexpect.TIMEOUT], timeout=timeout)
    except Exception:
        pass
    return child.before


def main():
    proxy = Proxy()
    threading.Thread(target=proxy.start_and_serve, daemon=True).start()
    time.sleep(0.3)  # 等代理开始监听

    print(f"[*] Using jdb: {JDB}")
    child = pexpect.spawn(f"{JDB} -attach {str(PROXY_PORT)}", timeout=60, encoding="utf-8")
    child.logfile = sys.stdout

    # 等 jdb 完成与代理的 TCP 连接（握手暂时挂起）
    for _ in range(50):
        if proxy.status in ("jdb_connected", "upstream_ready", "relaying"):
            break
        time.sleep(0.1)
    print("\n[*] jdb 已连上代理（阻塞在握手），现在启动 App ...")

    # 启动 App（等待调试器状态），进程一出现立刻建立 forward 并放行代理
    adb("shell", f"am force-stop {APP}")
    time.sleep(0.5)
    adb("shell", "am", "start", "-D", "-n", ACTIVITY)
    t0 = time.time()
    pid = None
    for _ in range(200):
        out = adb("shell", f"pidof {APP}")
        out = out.strip()
        if out and out.split()[0].isdigit():
            pid = out.split()[0]
            break
        time.sleep(0.03)
    if not pid:
        print("[!] 未取到 App PID")
        child.kill(9)
        return
    print(f"[*] PID={pid} (t={time.time()-t0:.2f}s)，立即建立转发 ...")
    adb("forward", f"tcp:{UPSTREAM_PORT}", f"jdwp:{pid}")
    proxy.upstream_ready.set()

    if not proxy.handshake_done.wait(timeout=15):
        print("[!] 上游握手失败（可能错过早期窗口）")
        child.kill(9)
        return
    print("[+] JDWP 握手完成（命中早期窗口）！\n")

    # 等 jdb 初始化完成出现提示符
    try:
        child.expect(["> ", pexpect.EOF, pexpect.TIMEOUT], timeout=30)
    except Exception:
        pass

    # 尽快冻结 VM，最大限度赢得与 clinit 的竞速
    print("\n[*] suspend")
    send_cmd(child, "suspend", timeout=10)

    print("\n[*] Setting breakpoint ...")
    send_cmd(child, f"stop in {CLASS}.<clinit>")

    print("\n[*] resume")
    send_cmd(child, "resume", timeout=10)

    idx = child.expect(BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT], timeout=90)
    if idx < len(BREAKPOINT_PATTERNS):
        print("\n[+] Breakpoint hit!")
        time.sleep(0.2)
        try:
            child.expect(["> ", pexpect.TIMEOUT], timeout=5)
        except Exception:
            pass
        max_steps = 15
        for i in range(max_steps):
            print(f"\n[*] next (step {i + 1})")
            send_cmd(child, "next", timeout=15)
            out = send_cmd(child, f"print {CLASS}.c", timeout=10)
            val_line = [l for l in out.splitlines() if "=" in l]
            val = val_line[-1].split("=", 1)[-1].strip() if val_line else ""
            print(f"    -> c probe: {val!r}")
            if val and val not in EMPTY_VALUES:
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

    print("\n[*] Done. Killing local jdb with SIGKILL (NOT quit) ...")
    child.kill(9)
    adb("forward", "--remove", f"tcp:{UPSTREAM_PORT}")


if __name__ == "__main__":
    main()
