#!/usr/bin/env python3
"""
extract_appsecret_auto.py —— 全自动版（CI / 无本地 Android 环境的机器）：
从零自动提取领克 App 的 nativeAppKey / nativeAppSecret。

支持平台：仅 macOS Apple Silicon（arm64）——这是唯一可行的自动化路线。
领克 APK 仅含 arm64-v8a 原生库，x86_64 模拟器靠 libndk 翻译执行 ARM
代码时其加固壳必崩（SIGSEGV，2026-08-31 ubuntu runner 三次实测），
Linux x86_64 路线已废弃（对领克 App 必败，维护无意义）。GitHub Actions
macos-latest runner 实测路径：复用 runner 预装的 adb/JDK，但其预装
emulator 是 x86_64 包（无法承载 arm64 guest），需自下载
emulator-darwin_aarch64 + arm64-v8a API34 系统镜像（约 1.2GB）与 APK。

用法（在仓库根目录执行，详见文档第 7 节）：
  python3 LynkCoHelper/tools/extract_appsecret_auto.py            # 全自动
  python3 LynkCoHelper/tools/extract_appsecret_auto.py <AVD名字>  # 指定 AVD

全自动内容（核心流程与 macOS 版共用 appsecret_core.py）：
  1. 前置环境自动探测与下载（存 ~/.lynkco-helper-tools/，二次运行复用）：
     - pexpect 缺失 -> 自动 pip 安装
     - adb / jdb 缺失 -> 多镜像源自动下载官方公开源包
     - emulator：本地已有的（含 arm64 qemu 后端）直接用；否则自下载
       darwin_aarch64 原生包（GitHub macos runner 预装的是 x86_64 包，
       启动 arm64 AVD 即失败，不能用）
     - arm64-v8a API34 Google APIs 系统镜像缺失 -> 下载（约 1.2GB）、
       手工创建 AVD（无需 cmdline-tools）
     - 硬件加速检测（下载前做，避免白下镜像才发现起不来）：有 HVF 用
       HVF；无 HVF（如 GitHub macos arm runner 是 VM）自动降级 qemu TCG
       软件模拟（-accel off），boot 超时同步放宽
  2. 无在线设备时自动冷启动 AVD（-no-snapshot-load，规避快照导致的握手
     挂死；设 EMU_HEADLESS=1 切无头模式，适配 CI）
  3. 设备未装领克 App 时 -> 从领克官方 CDN 下载最新版 APK（约 285MB）
     自动安装（与 macOS 版共用 core.ensure_apk）
  4. 代理抢握手 -> jdb 断点单步 -> 提取 b/c 字段
  5. 提取成功后交互确认，可自动写入 env.json 的 secrets 段
     （CI 场景设 LYNKCO_AUTO_WRITE=1 免确认，env.json 缺失时自动创建）
  6. 连接中断（App 反调试自杀/平台不稳）或提取值格式异常时自动重试，
     最多 3 次；失败时 dump 设备侧诊断（进程/ABI/logcat 崩溃缓冲）

注意：密钥不应写入代码仓库（env.json 已被 gitignore）。
本地 macOS 已有 Android Studio 环境时，交互友好的入口是
tools/extract_appsecret.py。
"""
import os
import platform
import re
import sys
import zipfile
import urllib.request

import appsecret_core as core

# 下载镜像源：官方源优先（海外快），腾讯云镜像回退（国内快，包同步自 Google）
_PKG_MIRRORS = [
    "https://dl.google.com/android/repository/",
    "https://mirrors.cloud.tencent.com/AndroidSDK/",
]

_AVD_NAME = "lynkco_helper_avd"

# 平台参数（仅 macOS Apple Silicon 一条路，原因见文件头）
_ABI = "arm64-v8a"
_EMU_PKG_RE = r"(emulator-darwin_aarch64-\d+\.zip)"
_SYSIMG_PKG_RE = r"(arm64-v8a-34_r\d+\.zip)"
_SYSIMG_FALLBACK = "sys-img/google_apis/arm64-v8a-34_r14.zip"
_PT_ZIP = "platform-tools-latest-darwin.zip"
_CORRETTO_PKG = "amazon-corretto-8-aarch64-macos-jdk.tar.gz"
_SYSIMG_MB = 1200


def ensure_adb():
    """探测 adb；缺失时自动下载 Android platform-tools（官方公开源，
    ~10MB，解压即用，无需许可协议）。CI 的 macOS runner 已预装，直接复用。"""
    p = core.find_adb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "platform-tools")
    if not core._confirm_download("adb (Android platform-tools)", 10, dest):
        sys.exit("[!] 未找到 adb 且跳过下载。请安装 Android Studio"
                 "（文档 7.1 节）或 brew install android-platform-tools 后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arc = os.path.join(core.TOOLS_DIR, _PT_ZIP)
    core._download("https://dl.google.com/android/repository/" + _PT_ZIP, arc, 10)
    with zipfile.ZipFile(arc) as z:
        z.extractall(core.TOOLS_DIR)
    os.remove(arc)
    cand = os.path.join(core.TOOLS_DIR, "platform-tools", "adb")
    if not os.path.exists(cand):
        sys.exit(f"[!] 解压后未找到 adb，请检查 {core.TOOLS_DIR}")
    os.chmod(cand, 0o755)   # zipfile 解压不保留可执行位
    return cand


def ensure_jdb():
    """探测 jdb（任意版本 JDK 均可）；缺失时经确认自动下载 Amazon Corretto 8
    （官方公开源，~110MB，解压即用，无需许可协议）。"""
    p = core.find_jdb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "jdk8")
    if not core._confirm_download("jdb (Amazon Corretto 8 / JDK 8)", 110, dest):
        sys.exit("[!] 未找到 jdb 且跳过下载。请安装任意版本 JDK 后重试"
                 "（如 brew install --cask corretto8；jdb 走 JDWP 协议，"
                 "任意版本均可）。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arc = os.path.join(core.TOOLS_DIR, _CORRETTO_PKG)
    core._download("https://corretto.aws/downloads/latest/" + _CORRETTO_PKG,
                   arc, 110)
    return core._extract_jdk_and_find_jdb(arc, dest)


# ---------------------------------------------------------------------------
# 模拟器 / 系统镜像 / AVD / APK 自动安装
# ---------------------------------------------------------------------------

def _fetch_latest_pkg_names():
    """从 Google repository XML 获取最新的 emulator 与 google_apis 系统镜像
    包名，返回 (emulator_pkg, sysimg_pkg)。两者分属不同 XML：emulator 在
    repository2-3.xml，系统镜像在 sys-img/google_apis/sys-img2-3.xml
    （只在主 XML 里找镜像永远找不到）。单项失败不影响另一项。
    同一包在 XML 中有多个通道（stable/beta/canary）各一块，只取 stable
    （channel-0）——beta 包捆绑 android-sdk-preview-license，行为不可预期。"""
    def _grep(url, pattern):
        try:
            text = urllib.request.urlopen(url, timeout=30).read().decode("utf-8", "replace")
        except Exception:
            return None
        for block in re.findall(r"<remotePackage[^>]*>.*?</remotePackage>", text, re.S):
            if 'ref="channel-0"' not in block:
                continue
            hits = re.findall(pattern, block)
            if hits:
                return hits[-1]
        hits = re.findall(pattern, text)   # 无 stable 块时回退全文匹配
        return hits[-1] if hits else None

    emu_pkg = _grep("https://dl.google.com/android/repository/repository2-3.xml",
                    _EMU_PKG_RE)
    sysimg = _grep("https://dl.google.com/android/repository/"
                   "sys-img/google_apis/sys-img2-3.xml",
                   _SYSIMG_PKG_RE)
    return emu_pkg, (f"sys-img/google_apis/{sysimg}" if sysimg else None)


def _download_and_extract(pkg_name, dest_dir, size_mb):
    """多镜像源下载 zip 并解压到指定目录，成功返回 True。"""
    arc = os.path.join(core.TOOLS_DIR, os.path.basename(pkg_name))
    for base in _PKG_MIRRORS:
        if core._try_download(base + pkg_name, arc, size_mb):
            print(f"[*] 解压 {os.path.basename(pkg_name)} 到 {dest_dir}"
                  f"（约 {size_mb}MB，可能需 1~3 分钟）...")
            os.makedirs(dest_dir, exist_ok=True)
            with zipfile.ZipFile(arc) as z:
                z.extractall(dest_dir)
            os.remove(arc)
            return True
    return False


def _make_executable(bin_dir):
    """zipfile 解压不保留可执行位，对无后缀二进制补 chmod +x。"""
    for root, _dirs, files in os.walk(bin_dir):
        for f in files:
            if os.path.splitext(f)[1] == "" or f.startswith("qemu-"):
                try:
                    os.chmod(os.path.join(root, f), 0o755)
                except OSError:
                    pass


def _create_avd_manual(avd_name):
    """手工创建 AVD 配置（无需 cmdline-tools/avdmanager）。
    AVD 本质就是 ~/.android/avd/<name>.ini + <name>.avd/config.ini。"""
    avd_home = os.environ.get("ANDROID_AVD_HOME",
                              os.path.join(os.path.expanduser("~"), ".android", "avd"))
    os.makedirs(avd_home, exist_ok=True)
    avd_dir = os.path.join(avd_home, f"{avd_name}.avd")
    os.makedirs(avd_dir, exist_ok=True)
    with open(os.path.join(avd_home, f"{avd_name}.ini"), "w", encoding="utf-8") as f:
        f.write("avd.ini.encoding=UTF-8\n")
        f.write(f"path={avd_dir}\n")
        f.write(f"path.rel=avd/{avd_name}.avd\n")
        f.write("target=android-34\n")
    with open(os.path.join(avd_dir, "config.ini"), "w", encoding="utf-8") as f:
        f.write("avd.ini.encoding=UTF-8\n")
        f.write(f"image.sysdir.1=system-images/android-34/google_apis/{_ABI}/\n")
        f.write("tag.id=google_apis\n")
        f.write("tag.display=Google APIs\n")
        f.write(f"abi.type={_ABI}\n")
        f.write("hw.cpu.arch=arm64\n")
        f.write("hw.cpu.ncore=4\n")
        f.write("hw.ramSize=2048\n")
        f.write("hw.lcd.width=1080\n")
        f.write("hw.lcd.height=1920\n")
        f.write("hw.lcd.density=440\n")
        f.write("hw.keyboard=yes\n")
        f.write("hw.gpu.enabled=yes\n")
        f.write("hw.gpu.mode=auto\n")
        f.write("disk.dataPartition.size=6442450944\n")
    print(f"[+] 已创建 AVD: {avd_name}")


def _ensure_acceleration():
    """硬件加速检测：有 Hypervisor.framework 用 HVF（默认，不改环境）；
    没有则降级 qemu TCG 纯软件模拟（设 EMU_ACCEL=off，由 core 的
    cold_start_and_wait 转成 -accel off，boot 超时同步放宽）。

    GitHub macOS arm64 runner 是 VM，guest 内无 HVF（官方确认短期无解，
    actions/runner-images#13505），故 CI 上实际就是走 TCG——本机
    emulator 36.6.11（与 runner 预装同版）实测 arm64 镜像 -accel off
    冷启动 53s，完全可用，仅全程更慢。"""
    try:
        out = core.sh(["sysctl", "-n", "kern.hv_support"]).strip()
    except Exception:
        out = ""
    hvf = out == "1"
    if os.environ.get("EMU_ACCEL", "").lower() == "off":
        return   # 已降级或用户已强制（ensure_device/ensure_emulator 各调一次，幂等）
    if hvf:
        return   # HVF 可用（物理 Mac 默认路径）
    print("[*] 无 Hypervisor.framework（VM 内？），降级 qemu TCG 软件模拟"
          "（启动与运行更慢，属预期）")
    os.environ["EMU_ACCEL"] = "off"


def _emu_supports_arm64_guests(emu):
    """检查 emulator 能否承载 arm64 guest：qemu 后端目录需存在
    qemu/darwin-aarch64/qemu-system-aarch64。
    GitHub macos runner 预装的是 x86_64 包（launcher 在 Rosetta 下运行），
    启动 arm64 AVD 即报 "Could not launch .../qemu/darwin-x86_64/
    qemu-system-aarch64: No such file or directory"（run 33359423830
    实测），必须改用自下载的 darwin_aarch64 原生包。"""
    qemu = os.path.join(os.path.dirname(emu), "qemu", "darwin-aarch64",
                        "qemu-system-aarch64")
    return os.path.exists(qemu)


def ensure_emulator(existing_emu=None):
    """自动下载 emulator + 系统镜像并创建 AVD（镜像约 1.2GB）。
    返回 (emulator_path, avd_name)。下载前先做硬件加速预检。
    现有 emulator 缺 arm64 qemu 后端时（如 GitHub macos runner 预装的
    x86_64 包）不用它，改用自下载的 darwin_aarch64 原生包。"""
    sdk_root = os.path.join(core.TOOLS_DIR, "sdk")
    emu = os.path.join(sdk_root, "emulator", "emulator")
    if existing_emu and _emu_supports_arm64_guests(existing_emu):
        emu = existing_emu
        sdk_root = os.path.dirname(os.path.dirname(emu))
    elif existing_emu:
        print("[*] 现有 emulator 缺 arm64 qemu 后端（GitHub macos runner 预装的"
              "是 x86_64 包），改用自下载的 darwin_aarch64 原生 emulator ...")
    else:
        print("[*] 未找到 emulator，开始自动安装 ...")
    os.makedirs(sdk_root, exist_ok=True)

    _ensure_acceleration()

    sysimg_dir = os.path.join(sdk_root, "system-images", "android-34",
                              "google_apis", _ABI)
    emu_pkg, sysimg_pkg = None, None
    if not os.path.exists(emu) or not os.path.exists(sysimg_dir):
        emu_pkg, sysimg_pkg = _fetch_latest_pkg_names()

    # 1. emulator（约 350MB）
    if not os.path.exists(emu):
        if not emu_pkg:
            sys.exit("[!] 无法获取 emulator 包名（repository XML 不可达），"
                     "请手动安装 Android SDK 后重试。")
        print(f"[*] 下载 emulator ({emu_pkg}, 约 350MB)...")
        if not _download_and_extract(emu_pkg, sdk_root, 350):
            sys.exit(f"[!] emulator 下载失败，可手动下载解压到 {sdk_root}/")
        _make_executable(os.path.join(sdk_root, "emulator"))
    if not os.path.exists(emu):
        sys.exit(f"[!] 安装后未找到 emulator：{emu}")

    # 2. sdk_root 下必须有 platform-tools 子目录，否则 emulator 启动即
    #    FATAL "Broken AVD system path"
    pt_dir = os.path.join(sdk_root, "platform-tools")
    if not os.path.exists(pt_dir):
        print("[*] 下载 platform-tools 到 SDK 目录 (~10MB)...")
        arc = os.path.join(core.TOOLS_DIR, "platform-tools-sdk.zip")
        core._download("https://dl.google.com/android/repository/" + _PT_ZIP, arc, 10)
        with zipfile.ZipFile(arc) as z:
            z.extractall(sdk_root)
        os.remove(arc)

    # 3. 系统镜像（API 34 Google APIs，ABI 见 _ABI）
    if not os.path.exists(sysimg_dir):
        # 上次运行可能解压到错误位置（sdk_root/<ABI>），先归位
        wrong_dir = os.path.join(sdk_root, _ABI)
        if os.path.isdir(wrong_dir):
            os.makedirs(os.path.dirname(sysimg_dir), exist_ok=True)
            os.rename(wrong_dir, sysimg_dir)
            print(f"[+] 系统镜像已移到正确位置: {sysimg_dir}")
        else:
            if not sysimg_pkg:
                sysimg_pkg = _SYSIMG_FALLBACK
                print(f"[*] 未从 XML 取到镜像包名，使用已验证版本: {sysimg_pkg}")
            print(f"[*] 下载系统镜像 ({sysimg_pkg}, 约 {_SYSIMG_MB}MB)...")
            # zip 内顶层是 <ABI>/，解压到 google_apis/ 即得 google_apis/<ABI>/
            if not _download_and_extract(sysimg_pkg, os.path.dirname(sysimg_dir),
                                         _SYSIMG_MB):
                sys.exit("[!] 系统镜像下载失败，可手动下载解压到 "
                         f"{os.path.dirname(sysimg_dir)}/")

    _create_avd_manual(_AVD_NAME)
    return emu, _AVD_NAME


def ensure_apk():
    """已收敛至共享核心（appsecret_core.ensure_apk），两平台行为一致。"""
    core.ensure_apk()


def ensure_device(wanted_avd=None):
    """有在线设备直接用；否则冷启动 AVD（-no-snapshot-load 是硬性前提，见 4.5 坑 1）。"""
    out = core.adb("devices")
    online = [ln.split()[0] for ln in out.splitlines()
              if ln.strip().endswith("\tdevice")]
    if online:
        print(f"[*] 检测到在线设备：{online[0]}"
              "（若此前是快照方式启动且稍后握手挂死，请改用冷启动后重试，见文档 4.5 坑 1）")
        return
    emu = core.find_emulator()
    if not emu:
        # 硬件加速预检 + 自动下载 emulator/镜像 + 建 AVD
        emu, avd = ensure_emulator()
        core.cold_start_and_wait(emu, avd)
        return
    _ensure_acceleration()   # 有 emulator 也先检测加速：无 HVF 则降级 TCG，别白等超时
    avds = core.sh([emu, "-list-avds"]).split()
    if not avds:
        # 复用已有 emulator，补齐镜像并创建 AVD
        _, avd = ensure_emulator(emu)
        core.cold_start_and_wait(emu, avd)
        return
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
    core.cold_start_and_wait(emu, avd)


def main():
    if sys.platform != "darwin" or platform.machine() != "arm64":
        sys.exit("[!] 本自动版仅支持 macOS Apple Silicon（arm64）：领克 App 原生库"
                 "仅 arm64-v8a，x86_64 模拟器的 ARM 翻译层（libndk）下其加固壳必崩"
                 "（2026-08-31 ubuntu runner 实测），Linux/Intel mac 路线均已废弃。"
                 "其他平台请改用 arm64 真机（adb 连接后跑本地版 "
                 "tools/extract_appsecret.py）。")
    core.ensure_pexpect()
    core.setup(ensure_adb(), ensure_jdb())
    print(f"[*] adb: {core.ADB}")
    print(f"[*] jdb: {core.JDB}")
    ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    ensure_apk()
    core.extract_main_loop()


if __name__ == "__main__":
    main()
