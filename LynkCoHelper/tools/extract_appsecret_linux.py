#!/usr/bin/env python3
"""
extract_appsecret_linux.py —— Linux / CI 版：从零全自动提取领克 App 的
nativeAppKey / nativeAppSecret（平台共享核心见 appsecret_core.py）。

与 macOS 版（extract_appsecret.py）的差异：Linux 上一切皆自动，包括
模拟器和领克 App 本体，适合无人值守环境（GitHub Actions ubuntu runner
即开箱即用，见 .github/workflows/extract-appsecret.yml）。

用法（在仓库根目录执行，详见文档第 7 节）：
  python3 LynkCoHelper/tools/extract_appsecret_linux.py            # 全自动
  python3 LynkCoHelper/tools/extract_appsecret_linux.py <AVD名字>  # 指定 AVD

Linux 全自动内容（核心流程与 macOS 版共用 appsecret_core.py）：
  1. 前置环境自动探测与下载（存 ~/.lynkco-helper-tools/，二次运行复用）：
     - pexpect 缺失 -> 自动 pip 安装（Ubuntu 24.04 自动加 --break-system-packages）
     - adb (platform-tools ~10MB) / jdb (Corretto 8 ~110MB) 缺失 ->
       确认后自动下载官方公开源包（无需许可协议）
     - emulator（~350MB）+ API34 Google APIs x86_64 系统镜像（~1.5GB）缺失 ->
       多镜像源自动下载（dl.google.com 优先，腾讯云回退）、手工创建 AVD
       （下载前先做 KVM 预检，/dev/kvm 缺失直接退出并给指引——这是 Linux
       模拟器起不来的最常见原因）
- 设备未装领克 App 时 -> 从领克官方 CDN 下载最新版 APK（约 285MB）
  自动安装（与 macOS 版共用 core.ensure_apk）
  2. 无在线设备时自动冷启动 AVD（-no-snapshot-load，规避快照导致的握手
     挂死；设 EMU_HEADLESS=1 或无 DISPLAY 时自动切无头模式，适配 CI）
  3. 代理抢握手 -> jdb 断点单步 -> 提取 b/c 字段
  4. 提取成功后交互确认，可自动写入 env.json 的 secrets 段
     （CI 场景设 LYNKCO_AUTO_WRITE=1 免确认，env.json 缺失时自动创建）
  5. 连接中断（App 反调试自杀/平台不稳）或提取值格式异常时自动重试，最多 3 次

注意：密钥不应写入代码仓库（env.json 已被 gitignore）。
架构限制：x86_64 专用（Google 未提供 Linux ARM64 的 emulator/系统镜像，
Apple Silicon 容器内因无嵌套虚拟化也跑不了模拟器——Mac 上请用
tools/extract_appsecret.py，模拟器跑宿主机、脚本可远程 adb connect）。
"""
import glob
import os
import platform
import re
import shutil
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


def find_adb():
    """探测 adb：PATH -> ANDROID_HOME/SDK_ROOT -> Linux 默认位置 -> 工具目录。"""
    p = shutil.which("adb")
    if p:
        return p
    bases = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             "~/Android/Sdk"]           # Linux + Android Studio 默认
    for base in bases:
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "platform-tools", "adb")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(core.TOOLS_DIR, "platform-tools", "adb")
    return cand if os.path.exists(cand) else None


def find_jdb():
    """探测 jdb：JAVA_HOME -> PATH -> /usr/lib/jvm 等 Linux 常见路径
    -> 本脚本工具目录（自动下载的 Corretto 8）。任意版本 JDK 均可
    （jdb 走 JDWP 协议，与目标 JVM 版本无关）。"""
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cand = os.path.join(jh, "bin", "jdb")
        if os.path.exists(cand):
            return cand
    p = shutil.which("jdb")
    if p:   # Linux 的 /usr/bin/jdb 是 alternatives 真实链接，无需排除
        return p
    for pat in ("/usr/lib/jvm/*/bin/jdb",                      # Debian/Ubuntu/Fedora
                os.path.expanduser("~/.jdks/*/bin/jdb"),       # IntelliJ IDEA
                os.path.expanduser("~/.sdkman/candidates/java/*/bin/jdb")):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    hits = sorted(glob.glob(os.path.join(core.TOOLS_DIR, "jdk8", "**", "bin", "jdb"),
                            recursive=True))
    return hits[0] if hits else None


def find_emulator():
    p = shutil.which("emulator")
    if p:
        return p
    for base in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                 "~/Android/Sdk"):          # Linux + Android Studio 默认
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "emulator", "emulator")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(core.TOOLS_DIR, "sdk", "emulator", "emulator")
    return cand if os.path.exists(cand) else None


def ensure_adb():
    """探测 adb；缺失时经确认自动下载 Android platform-tools（官方公开源，
    ~10MB，解压即用，无需许可协议）。"""
    p = find_adb()
    if p:
        return p
    if platform.machine() == "aarch64":
        # Google 未提供 Linux ARM64 的 platform-tools 包（本分支仅 x86_64）
        sys.exit("[!] Linux ARM64 无官方 platform-tools 包，请先安装系统 adb："
                 "Ubuntu/Debian: sudo apt install adb；然后重试。")
    dest = os.path.join(core.TOOLS_DIR, "platform-tools")
    if not core._confirm_download("adb (Android platform-tools)", 10, dest):
        sys.exit("[!] 未找到 adb 且跳过下载。请设置 ANDROID_HOME 或 "
                 "sudo apt install adb 后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    zip_name = "platform-tools-latest-linux.zip"
    arc = os.path.join(core.TOOLS_DIR, zip_name)
    core._download("https://dl.google.com/android/repository/" + zip_name, arc, 10)
    with zipfile.ZipFile(arc) as z:
        z.extractall(core.TOOLS_DIR)
    os.remove(arc)
    cand = os.path.join(core.TOOLS_DIR, "platform-tools", "adb")
    if not os.path.exists(cand):
        sys.exit(f"[!] 解压后未找到 adb，请检查 {core.TOOLS_DIR}")
    os.chmod(cand, 0o755)   # zipfile 解压不保留可执行位
    return cand


def ensure_jdb():
    """探测 jdb；缺失时经确认自动下载 Amazon Corretto 8（官方公开源，
    ~110MB，解压即用，无需许可协议）。"""
    p = find_jdb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "jdk8")
    if not core._confirm_download("jdb (Amazon Corretto 8 / JDK 8)", 110, dest):
        sys.exit("[!] 未找到 jdb 且跳过下载。请安装 JDK（sudo apt install "
                 "default-jdk 或设 JAVA_HOME）后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arch = "aarch64" if platform.machine() == "aarch64" else "x64"
    pkg_name = f"amazon-corretto-8-{arch}-linux-jdk.tar.gz"
    arc = os.path.join(core.TOOLS_DIR, pkg_name)
    core._download("https://corretto.aws/downloads/latest/" + pkg_name, arc, 110)
    return core._extract_jdk_and_find_jdb(arc, dest)


# ---------------------------------------------------------------------------
# 模拟器 / 系统镜像 / AVD / APK 自动安装
# ---------------------------------------------------------------------------

def _fetch_latest_pkg_names():
    """从 Google repository XML 获取最新的 emulator 与 google_apis 系统镜像
    包名，返回 (emulator_pkg, sysimg_pkg)。两者分属不同 XML：emulator 在
    repository2-3.xml，系统镜像在 sys-img/google_apis/sys-img2-3.xml
    （只在主 XML 里找镜像永远找不到）。单项失败不影响另一项。"""
    def _grep(url, pattern):
        try:
            text = urllib.request.urlopen(url, timeout=30).read().decode("utf-8", "replace")
            m = re.findall(pattern, text)
            return m[-1] if m else None
        except Exception:
            return None

    emu_pkg = _grep("https://dl.google.com/android/repository/repository2-3.xml",
                    r"(emulator-linux_x64-\d+\.zip)")
    sysimg = _grep("https://dl.google.com/android/repository/"
                   "sys-img/google_apis/sys-img2-3.xml",
                   r"(x86_64-34_r\d+\.zip)")
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
        f.write("image.sysdir.1=system-images/android-34/google_apis/x86_64/\n")
        f.write("tag.id=google_apis\n")
        f.write("tag.display=Google APIs\n")
        f.write("abi.type=x86_64\n")
        f.write("hw.cpu.arch=x86_64\n")
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


def _ensure_kvm():
    """Linux 上 x86_64 模拟器硬性依赖 KVM（同 Windows 必须 WHPX/AEHD）；
    缺失时给出开启指引后退出，避免下载 1.9GB 后才发现起不来。"""
    if os.path.exists("/dev/kvm"):
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            return
        sys.exit("[!] /dev/kvm 存在但当前用户无权限。执行：\n"
                 "    sudo usermod -aG kvm $USER  然后重新登录\n"
                 "    （CI/容器可临时 sudo chmod 666 /dev/kvm）")
    sys.exit("[!] 未找到 /dev/kvm：x86_64 模拟器必须 KVM 硬件加速。\n"
             "    Ubuntu/Debian: sudo apt install qemu-kvm && sudo usermod -aG kvm $USER\n"
             "    云主机/虚拟机需开启嵌套虚拟化；Docker 需启动参数 --device /dev/kvm")


def ensure_emulator(existing_emu=None):
    """自动下载 emulator + 系统镜像并创建 AVD（约 1.9GB）。
    返回 (emulator_path, avd_name)。下载前先做 KVM 预检。"""
    if existing_emu:
        emu = existing_emu
        sdk_root = os.path.dirname(os.path.dirname(emu))
    else:
        print("[*] 未找到 emulator，开始自动安装 ...")
        sdk_root = os.path.join(core.TOOLS_DIR, "sdk")
        os.makedirs(sdk_root, exist_ok=True)
        emu = os.path.join(sdk_root, "emulator", "emulator")

    _ensure_kvm()

    sysimg_dir = os.path.join(sdk_root, "system-images", "android-34",
                              "google_apis", "x86_64")
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
        core._download("https://dl.google.com/android/repository/"
                       "platform-tools-latest-linux.zip", arc, 10)
        with zipfile.ZipFile(arc) as z:
            z.extractall(sdk_root)
        os.remove(arc)

    # 3. 系统镜像（约 1.5GB，API 34 Google APIs x86_64）
    if not os.path.exists(sysimg_dir):
        # 上次运行可能解压到错误位置（sdk_root/x86_64），先归位
        wrong_dir = os.path.join(sdk_root, "x86_64")
        if os.path.isdir(wrong_dir):
            os.makedirs(os.path.dirname(sysimg_dir), exist_ok=True)
            os.rename(wrong_dir, sysimg_dir)
            print(f"[+] 系统镜像已移到正确位置: {sysimg_dir}")
        else:
            if not sysimg_pkg:
                sysimg_pkg = "sys-img/google_apis/x86_64-34_r14.zip"
                print(f"[*] 未从 XML 取到镜像包名，使用已验证版本: {sysimg_pkg}")
            print(f"[*] 下载系统镜像 ({sysimg_pkg}, 约 1.5GB)...")
            # zip 内顶层是 x86_64/，解压到 google_apis/ 即得 google_apis/x86_64/
            if not _download_and_extract(sysimg_pkg, os.path.dirname(sysimg_dir), 1500):
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
    emu = find_emulator()
    if not emu:
        # KVM 预检 + 自动下载 emulator/镜像 + 建 AVD
        emu, avd = ensure_emulator()
        core.cold_start_and_wait(emu, avd)
        return
    _ensure_kvm()   # 有 emulator 也先查 KVM，缺了别白白等 8 分钟超时
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
    if sys.platform == "darwin":
        sys.exit("[!] 本脚本是 Linux/CI 版，macOS 请用: "
                 "LynkCoHelper/tools/extract_appsecret.py")
    if sys.platform == "win32":
        sys.exit("[!] 本脚本不支持 Windows（pexpect 依赖 POSIX 伪终端）。")
    if platform.machine() == "aarch64":
        sys.exit("[!] Linux ARM64 无官方 x86_64 模拟器镜像，且通常无嵌套虚拟化。"
                 "请在 x86_64 Linux（物理机/CI runner）上运行。")
    core.ensure_pexpect()
    core.setup(ensure_adb(), ensure_jdb())
    print(f"[*] adb: {core.ADB}")
    print(f"[*] jdb: {core.JDB}")
    ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    ensure_apk()
    core.extract_main_loop()


if __name__ == "__main__":
    main()
