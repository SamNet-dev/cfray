#!/usr/bin/env python3
#
# ┌─────────────────────────────────────────────────────────────────┐
# │                                                                 │
# │   ⚡  CF CONFIG SCANNER v1.1                                    │
# │                                                                 │
# │   Test VLESS/VMess proxy configs for latency + download speed   │
# │                                                                 │
# │   • Latency test (TCP + TLS) all IPs in seconds                 │
# │   • Download speed test via progressive funnel                  │
# │   • Live TUI dashboard with real-time results                   │
# │   • Smart rate limiting with CDN fallback                       │
# │   • Clean IP Finder — scan all Cloudflare ranges (up to 3M)     │
# │   • Multi-port scanning (443, 8443) for maximum coverage        │
# │   • Zero dependencies — Python 3.8+ stdlib only                 │
# │   • Xray Pipeline Test — smart probe → expand → speed test      │
# │   • Deploy Xray Server — full VPS setup with systemd + certs    │
# │   • Worker Proxy — fresh workers.dev SNI for any VLESS config   │
# │                                                                 │
# │   GitHub: https://github.com/SamNet-dev/cfray                   │
# │                                                                 │
# └─────────────────────────────────────────────────────────────────┘
#
# Usage:
#   python3 scanner.py                              Interactive TUI
#   python3 scanner.py -i configs.txt               Normal mode
#   python3 scanner.py --sub https://example.com/sub Fetch from subscription
#   python3 scanner.py --template "vless://..." -i addrs.json  Generate + test
#   python3 scanner.py --find-clean --no-tui --clean-mode mega  Clean IP scan
#

import asyncio
import argparse
import base64
import copy
import csv
import glob as globmod
import http.client
import ipaddress
import json
import os
import platform as _platform
import random
import re
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


VERSION = "1.1"
SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down"
DEBUG_LOG = os.path.join("results", "debug.log")
LOG_MAX_BYTES = 5 * 1024 * 1024

LATENCY_WORKERS = 50
SPEED_WORKERS = 10
LATENCY_TIMEOUT = 5.0
SPEED_TIMEOUT = 30.0

CDN_FALLBACK = ("cloudflaremirrors.com", "/archlinux/iso/latest/archlinux-x86_64.iso")

# Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips-v4/)
CF_SUBNETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13",
]

CF_HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

CLEAN_MODES = {
    "quick":  {"label": "Quick",  "sample": 1, "workers": 500,  "validate": False,
               "ports": [443], "desc": "1 random IP per /24 (~4K IPs, ~30s)"},
    "normal": {"label": "Normal", "sample": 3, "workers": 500,  "validate": True,
               "ports": [443], "desc": "3 IPs per /24 + CF verify (~12K IPs, ~2 min)"},
    "full":   {"label": "Full",   "sample": 0, "workers": 1000, "validate": True,
               "ports": [443], "desc": "All IPs + CF verify (~1.5M IPs, 20+ min)"},
    "mega":   {"label": "Mega",   "sample": 0, "workers": 1500, "validate": True,
               "ports": [443, 8443], "desc": "All IPs × 2 ports (~3M probes, 30-60 min)"},
}

# ─── Xray Proxy Testing Constants ────────────────────────────────────────────

XRAY_HOME = os.path.join(os.path.expanduser("~"), ".cfray")
XRAY_BIN_DIR = os.path.join(XRAY_HOME, "bin")
XRAY_TMP_DIR = os.path.join(XRAY_HOME, "tmp")
XRAY_BASE_PORT = 10900
XRAY_CONNECT_TIMEOUT = 8.0
XRAY_QUICK_TIMEOUT = 10.0
XRAY_QUICK_SIZE = 100_000
XRAY_SPEED_TIMEOUT = 20.0
XRAY_SPEED_SIZE = 5_000_000
XRAY_PROFILES_DIR = os.path.join(XRAY_HOME, "profiles")
RESULTS_DIR = "results"

_CF_PREFLIGHT_IPS = ["104.16.128.1", "198.41.192.1", "172.67.128.1"]


def _generate_random_cf_ips(count: int = 100) -> List[str]:
    """Pick *count* random IPs, one per /24, spread across all CF ranges."""
    blocks = []
    for sub in CF_SUBNETS:
        try:
            net = ipaddress.IPv4Network(sub.strip(), strict=False)
            if net.prefixlen <= 24:
                blocks.extend(net.subnets(new_prefix=24))
            else:
                blocks.append(net)
        except (ValueError, TypeError):
            continue
    random.shuffle(blocks)
    ips: List[str] = []
    for blk in blocks[:count]:
        hosts = list(blk.hosts())
        ips.append(str(random.choice(hosts)))
    return ips


CF_TEST_IPS = _generate_random_cf_ips(6666)
_CF_NETS = [ipaddress.IPv4Network(s, strict=False) for s in CF_SUBNETS]


def _is_cf_address(addr: str) -> bool:
    """Check if an address falls within known Cloudflare IP ranges."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _CF_NETS)
    except (ValueError, TypeError):
        return False


def _resolve_is_cf(addr: str) -> bool:
    """Check if an address is behind Cloudflare."""
    if _is_cf_address(addr):
        return True
    try:
        infos = socket.getaddrinfo(addr, None, socket.AF_INET, socket.SOCK_STREAM)
        for _, _, _, _, (ip_str, _) in infos:
            if _is_cf_address(ip_str):
                return True
    except (socket.gaierror, OSError):
        pass
    return False


XRAY_FRAG_PRESETS = {
    "none": [None],
    "light": [
        {"packets": "tlshello", "length": "100-200", "interval": "10-20"},
    ],
    "medium": [
        {"packets": "tlshello", "length": "50-100", "interval": "10-20"},
        {"packets": "tlshello", "length": "100-200", "interval": "20-40"},
    ],
    "heavy": [
        {"packets": "tlshello", "length": "10-50", "interval": "5-10"},
        {"packets": "tlshello", "length": "50-100", "interval": "10-30"},
        {"packets": "tlshello", "length": "100-300", "interval": "20-50"},
    ],
    "all": [
        None,
        {"packets": "tlshello", "length": "100-200", "interval": "10-20"},
        {"packets": "tlshello", "length": "50-100", "interval": "10-30"},
        {"packets": "tlshello", "length": "10-50", "interval": "5-10"},
    ],
}

XRAY_CONFIG_TEMPLATE = {
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "tag": "socks", "port": XRAY_BASE_PORT, "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }],
    "outbounds": [{
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "", "port": 443, "users": []}]},
        "streamSettings": {},
    }],
}

# ─── Deploy Constants ────────────────────────────────────────────────────────

DEPLOY_XRAY_BIN = "/usr/local/bin/xray"
DEPLOY_XRAY_CONFIG = "/usr/local/etc/xray/config.json"
DEPLOY_XRAY_CONFIG_DIR = "/usr/local/etc/xray"
DEPLOY_XRAY_SHARE = "/usr/local/share/xray"
DEPLOY_XRAY_SERVICE = "/etc/systemd/system/xray.service"
DEPLOY_XRAY_BACKUP_DIR = "/usr/local/etc/xray/backups"

DEPLOY_SYSTEMD_UNIT = """\
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
"""

PRESETS = {
    "quick": {
        "label": "Quick",
        "desc": "Latency sort -> 1MB top 100 -> 5MB top 20",
        "dynamic": True,
        "latency_cut": 50,
        "round_sizes": [1_000_000, 5_000_000],
        "round_pcts": [100, 20],
        "round_min": [50, 10],
        "round_max": [100, 20],
        "data": "~200 MB",
        "time": "~2-3 min",
    },
    "normal": {
        "label": "Normal",
        "desc": "Latency sort -> 1MB top 200 -> 5MB top 50 -> 20MB top 20",
        "dynamic": True,
        "latency_cut": 40,
        "round_sizes": [1_000_000, 5_000_000, 20_000_000],
        "round_pcts": [100, 25, 10],
        "round_min": [50, 20, 10],
        "round_max": [200, 50, 20],
        "data": "~850 MB",
        "time": "~5-10 min",
    },
    "thorough": {
        "label": "Thorough",
        "desc": "Deep funnel: 5MB / 25MB / 50MB",
        "dynamic": True,
        "latency_cut": 15,
        "round_sizes": [5_000_000, 25_000_000, 50_000_000],
        "round_pcts": [100, 25, 10],
        "round_min": [0, 30, 15],
        "round_max": [0, 150, 50],
        "data": "~5-10 GB",
        "time": "~20-45 min",
    },
}


class A:
    RST = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITAL = "\033[3m"
    ULINE = "\033[4m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    WHT = "\033[97m"
    BGBL = "\033[44m"
    BGDG = "\033[100m"
    HOME = "\033[H"
    CLR = "\033[H\033[J"
    EL = "\033[2K"
    HIDE = "\033[?25l"
    SHOW = "\033[?25h"


_ansi_re = re.compile(r"\033\[[^m]*m")


def _dbg(msg: str):
    """Append a debug line to results/debug.log with rotation."""
    try:
        os.makedirs("results", exist_ok=True)
        if os.path.exists(DEBUG_LOG):
            try:
                sz = os.path.getsize(DEBUG_LOG)
                if sz > LOG_MAX_BYTES:
                    bak = DEBUG_LOG + ".1"
                    if os.path.exists(bak):
                        os.remove(bak)
                    os.rename(DEBUG_LOG, bak)
            except Exception:
                pass
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _char_width(c: str) -> int:
    """Return terminal column width of a single character (1 or 2)."""
    o = ord(c)
    # Common wide ranges: CJK, emojis, dingbats, symbols, etc.
    if (
        0x1100 <= o <= 0x115F      # Hangul Jamo
        or 0x2329 <= o <= 0x232A   # angle brackets
        or 0x2E80 <= o <= 0x303E   # CJK radicals / ideographic
        or 0x3040 <= o <= 0x33BF   # Hiragana / Katakana / CJK compat
        or 0x3400 <= o <= 0x4DBF   # CJK Unified Extension A
        or 0x4E00 <= o <= 0xA4CF   # CJK Unified / Yi
        or 0xA960 <= o <= 0xA97C   # Hangul Jamo Extended-A
        or 0xAC00 <= o <= 0xD7A3   # Hangul Syllables
        or 0xF900 <= o <= 0xFAFF   # CJK Compatibility Ideographs
        or 0xFE10 <= o <= 0xFE6F   # CJK compat forms / small forms
        or 0xFF01 <= o <= 0xFF60   # Fullwidth forms
        or 0xFFE0 <= o <= 0xFFE6   # Fullwidth signs
        or 0x1F000 <= o <= 0x1FAFF # Mahjong, Domino, Playing Cards, Emojis, Symbols
        or 0x20000 <= o <= 0x2FA1F # CJK Unified Extension B-F
        or 0x2600 <= o <= 0x27BF   # Misc symbols, Dingbats
        or 0x2700 <= o <= 0x27BF   # Dingbats
        or 0xFE00 <= o <= 0xFE0F   # Variation selectors (zero-width but paired with emoji)
        or 0x200D == o             # ZWJ (zero-width joiner)
        or 0x231A <= o <= 0x231B   # Watch, Hourglass
        or 0x23E9 <= o <= 0x23F3   # Various symbols
        or 0x23F8 <= o <= 0x23FA   # Various symbols
        or 0x25AA <= o <= 0x25AB   # Small squares
        or 0x25B6 == o or 0x25C0 == o  # Play buttons
        or 0x25FB <= o <= 0x25FE   # Medium squares
        or 0x2614 <= o <= 0x2615   # Umbrella, Hot beverage
        or 0x2648 <= o <= 0x2653   # Zodiac signs
        or 0x267F == o             # Wheelchair
        or 0x2693 == o             # Anchor
        or 0x26A1 == o             # High voltage (⚡)
        or 0x26AA <= o <= 0x26AB   # Circles
        or 0x26BD <= o <= 0x26BE   # Soccer, Baseball
        or 0x26C4 <= o <= 0x26C5   # Snowman, Sun behind cloud
        or 0x26D4 == o             # No entry
        or 0x26EA == o             # Church
        or 0x26F2 <= o <= 0x26F3   # Fountain, Golf
        or 0x26F5 == o             # Sailboat
        or 0x26FA == o             # Tent
        or 0x26FD == o             # Fuel pump
        or 0x2702 == o             # Scissors
        or 0x2705 == o             # Check mark
        or 0x2708 <= o <= 0x270D   # Various
        or 0x270F == o             # Pencil
        or 0x2753 <= o <= 0x2755   # Question marks (❓❔❕)
        or 0x2757 == o             # Exclamation
        or 0x2795 <= o <= 0x2797   # Plus, Minus, Divide
        or 0x27B0 == o or 0x27BF == o  # Curly loop
    ):
        return 2
    # Zero-width characters
    if o in (0xFE0F, 0xFE0E, 0x200D, 0x200B, 0x200C, 0x200E, 0x200F):
        return 0
    return 1


def _vl(s: str) -> int:
    """Visible length of a string, accounting for ANSI codes and wide chars."""
    clean = _ansi_re.sub("", s)
    return sum(_char_width(c) for c in clean)


def _w(text: str):
    sys.stdout.write(text)


def _fl():
    sys.stdout.flush()


def enable_ansi():
    if sys.platform == "win32":
        os.system("")
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_ulong()
            k.GetConsoleMode(h, ctypes.byref(m))
            k.SetConsoleMode(h, m.value | 0x0004)
        except Exception:
            pass


def term_size() -> Tuple[int, int]:
    try:
        c, r = os.get_terminal_size()
        return max(c, 60), max(r, 20)
    except Exception:
        return 80, 24


def _read_key_blocking() -> str:
    """Read a single key press (blocking). Returns key name."""
    if sys.platform == "win32":
        import msvcrt
        k = msvcrt.getch()
        if k in (b"\x00", b"\xe0"):
            k2 = msvcrt.getch()
            return {b"H": "up", b"P": "down", b"K": "left", b"M": "right"}.get(k2, "")
        if k == b"\r":
            return "enter"
        if k == b"\x03":
            return "ctrl-c"
        if k == b"\x1b":
            return "esc"
        return k.decode("latin-1", errors="replace")
    else:
        import select as _sel
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                rdy, _, _ = _sel.select([sys.stdin], [], [], 0.2)
                if rdy:
                    ch2 = sys.stdin.read(1)
                    if ch2 == "[":
                        rdy2, _, _ = _sel.select([sys.stdin], [], [], 0.2)
                        if rdy2:
                            ch3 = sys.stdin.read(1)
                            return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(ch3, "esc")
                    return "esc"
                return "esc"
            if ch == "\r" or ch == "\n":
                return "enter"
            if ch == "\x03":
                return "ctrl-c"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _read_key_nb(timeout: float = 0.05) -> Optional[str]:
    """Non-blocking key read. Returns None if no key."""
    if sys.platform == "win32":
        import msvcrt
        if msvcrt.kbhit():
            return _read_key_blocking()
        time.sleep(timeout)
        return None
    else:
        import select
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            rdy, _, _ = select.select([sys.stdin], [], [], timeout)
            if rdy:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    # Wait for escape sequence bytes (longer timeout for SSH)
                    rdy2, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if rdy2:
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            rdy3, _, _ = select.select([sys.stdin], [], [], 0.2)
                            if rdy3:
                                ch3 = sys.stdin.read(1)
                                return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(ch3, "")
                        return ""
                    return "esc"  # bare Esc key
                if ch in ("\r", "\n"):
                    return "enter"
                if ch == "\x03":
                    return "ctrl-c"
                return ch
            return None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _wait_any_key():
    """Simple blocking wait for any keypress. More robust than _read_key_blocking for popups."""
    if sys.platform == "win32":
        import msvcrt
        msvcrt.getch()
    else:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _prompt_number(prompt: str, max_val: int) -> Optional[int]:
    """Show prompt, read a number from user. Returns None if cancelled."""
    _w(A.SHOW)
    _w(f"\n {prompt}")
    _fl()
    buf = ""
    if sys.platform == "win32":
        import msvcrt
        while True:
            k = msvcrt.getch()
            if k == b"\r":
                break
            if k == b"\x1b" or k == b"\x03":
                _w("\n")
                return None
            if k == b"\x08" and buf:
                buf = buf[:-1]
                _w("\b \b")
                _fl()
                continue
            ch = k.decode("latin-1", errors="replace")
            if ch.isdigit():
                buf += ch
                _w(ch)
                _fl()
    else:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                if ch == "\x1b" or ch == "\x03":
                    _w("\n")
                    return None
                if ch == "\x7f" and buf:  # backspace
                    buf = buf[:-1]
                    _w("\b \b")
                    _fl()
                    continue
                if ch.isdigit():
                    buf += ch
                    _w(ch)
                    _fl()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    _w(A.HIDE)
    if buf and buf.isdigit():
        n = int(buf)
        if 1 <= n <= max_val:
            return n
    return None


def _fmt_elapsed(secs: float) -> str:
    m, s = divmod(int(secs), 60)
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


@dataclass
class ConfigEntry:
    address: str
    name: str = ""
    original_uri: str = ""
    ip: str = ""


@dataclass
class RoundCfg:
    size: int
    keep: int

    @property
    def label(self) -> str:
        if self.size >= 1_000_000:
            return f"{self.size // 1_000_000}MB"
        return f"{self.size // 1000}KB"


@dataclass
class Result:
    ip: str
    domains: List[str] = field(default_factory=list)
    uris: List[str] = field(default_factory=list)
    tcp_ms: float = -1
    tls_ms: float = -1
    ttfb_ms: float = -1
    speeds: List[float] = field(default_factory=list)
    best_mbps: float = -1
    colo: str = ""
    score: float = 0
    error: str = ""
    alive: bool = False


class State:
    def __init__(self):
        self.input_file = ""
        self.configs: List[ConfigEntry] = []
        self.ip_map: Dict[str, List[ConfigEntry]] = defaultdict(list)
        self.ips: List[str] = []
        self.res: Dict[str, Result] = {}
        self.rounds: List[RoundCfg] = []
        self.mode = "normal"

        self.phase = "init"
        self.phase_label = ""
        self.cur_round = 0
        self.total = 0
        self.done_count = 0
        self.alive_n = 0
        self.dead_n = 0
        self.best_speed = 0.0
        self.start_time = 0.0
        self.notify = ""  # notification message shown in footer
        self.notify_until = 0.0

        self.top = 50  # export top N (0 = all)
        self.finished = False
        self.interrupted = False
        self.saved = False
        self.latency_cut_n = 0  # how many IPs were cut after latency phase


@dataclass
class XrayVariation:
    """One test variation = specific SNI + fragment combo."""
    tag: str
    sni: str
    fragment: Optional[dict]
    config_json: dict
    source_uri: str
    alive: bool = False
    connect_ms: float = -1
    ttfb_ms: float = -1
    speed_mbps: float = -1
    error: str = ""
    score: float = 0
    result_uri: str = ""
    native_tested: bool = False


class XrayTestState:
    """State for xray proxy testing progress."""
    def __init__(self):
        self.variations: List[XrayVariation] = []
        self.phase = "init"
        self.phase_label = ""
        self.total = 0
        self.done_count = 0
        self.alive_count = 0
        self.dead_count = 0
        self.best_speed = 0.0
        self.start_time = 0.0
        self.finished = False
        self.interrupted = False
        self.source_uri = ""
        self.xray_bin = ""
        self.export_error = ""
        self.quick_passed = 0
        # Pipeline stage tracking
        self.pipeline_mode = False
        self.pipeline_stage = 0
        self.pipeline_stages = [
            {"name": "ip_scan",    "label": "IP Scan",           "status": "pending"},
            {"name": "base_test",  "label": "Base Connectivity",  "status": "pending"},
            {"name": "expansion",  "label": "Expansion",          "status": "pending"},
        ]
        self.live_ips: List[Tuple[str, float]] = []
        self.live_ip_ports: dict = {}  # {ip: [port1, port2, ...]}
        self.working_ips: List[str] = []
        self.preflight_is_cf: Optional[bool] = None
        self.preflight_warning: str = ""
        self.cf_origin_errors: int = 0


@dataclass
class PipelineConfig:
    """Configuration for the progressive xray pipeline."""
    uri: str
    parsed: dict
    sni_pool: List[str] = field(default_factory=list)
    frag_preset: str = "all"
    transport_variants: List[str] = field(default_factory=list)
    max_stage2_ips: int = 120
    max_expansion: int = 1000
    max_snis_per_ip: int = 20
    configless: bool = False
    base_uris: List[Tuple[str, dict]] = field(default_factory=list)
    custom_ips: List[str] = field(default_factory=list)
    probe_ports: List[int] = field(default_factory=lambda: [443])


class DeployState:
    """State for Xray server deployment (Linux only)."""
    def __init__(self):
        self.source_uris: List[str] = []
        self.parsed_configs: List[dict] = []
        self.fresh_mode = False

        self.server_config: dict = {}
        self.client_uris: List[str] = []

        self.server_ip = ""
        self.listen_port = 443

        self.reality_private_key = ""
        self.reality_public_key = ""
        self.reality_short_id = ""
        self.tls_cert_path = ""
        self.tls_key_path = ""
        self.tls_domain = ""

        self.phase = "init"
        self.steps_done: List[str] = []
        self.error = ""


class CFRateLimiter:
    """Respects Cloudflare's per-IP rate limit window.

    CF allows ~600 requests per 10-minute window to speed.cloudflare.com.
    When 429 is received, retry-after header tells us exactly when the
    window resets.  We track request count and pause when budget runs out
    or when CF explicitly tells us to wait.
    """
    BUDGET = 550          # conservative limit (CF allows ~600)
    WINDOW = 600          # 10-minute window in seconds

    def __init__(self):
        self.count = 0
        self.window_start = 0.0
        self.blocked_until = 0.0
        self._lock = asyncio.Lock()

    async def _wait_blocked(self, st: Optional["State"]):
        """Wait out a 429 block period (called outside lock)."""
        while time.monotonic() < self.blocked_until:
            if st and st.interrupted:
                return
            left = int(self.blocked_until - time.monotonic())
            if st:
                st.phase_label = f"CF rate limit — resuming in {left}s"
            await asyncio.sleep(1)

    async def _wait_budget(self, wait_until: float, st: Optional["State"]):
        """Wait for window reset when budget exhausted (called outside lock)."""
        while time.monotonic() < wait_until:
            if st and st.interrupted:
                return
            left = int(wait_until - time.monotonic())
            if st:
                st.phase_label = f"Rate limit ({self.count} reqs) — next window in {left}s"
            await asyncio.sleep(1)

    async def acquire(self, st: Optional["State"] = None):
        """Wait if we're rate-limited, then count a request."""
        # Wait out any 429 block first (outside lock so others can also wait)
        if self.blocked_until > 0 and time.monotonic() < self.blocked_until:
            _dbg(f"RATE: waiting {self.blocked_until - time.monotonic():.0f}s for CF window reset")
            await self._wait_blocked(st)

        await self._lock.acquire()
        try:
            # Re-check after acquiring lock
            if self.blocked_until > 0 and time.monotonic() >= self.blocked_until:
                self.count = 0
                self.window_start = time.monotonic()
                self.blocked_until = 0.0

            now = time.monotonic()
            if self.window_start == 0.0:
                self.window_start = now

            if now - self.window_start >= self.WINDOW:
                self.count = 0
                self.window_start = now

            if self.count >= self.BUDGET:
                remaining = self.WINDOW - (now - self.window_start)
                if remaining > 0:
                    _dbg(f"RATE: budget exhausted ({self.count} reqs), waiting {remaining:.0f}s")
                    wait_until = self.window_start + self.WINDOW
                    saved_window = self.window_start
                    self._lock.release()
                    try:
                        await self._wait_budget(wait_until, st)
                    finally:
                        await self._lock.acquire()
                    # Only reset if no other coroutine already did
                    if self.window_start == saved_window:
                        self.count = 0
                        self.window_start = time.monotonic()
                else:
                    self.count = 0
                    self.window_start = time.monotonic()

            self.count += 1
        finally:
            self._lock.release()

    def would_block(self) -> bool:
        """Check if speed.cloudflare.com is currently rate-limited."""
        now = time.monotonic()
        if self.blocked_until > 0 and now < self.blocked_until:
            return True
        if self.window_start > 0 and now - self.window_start < self.WINDOW:
            if self.count >= self.BUDGET:
                return True
        return False

    def report_429(self, retry_after: int):
        """CF told us to wait.  Set blocked_until so all workers pause.
        Cap at 600s (10 min) — CF's actual window is 10 min but it sends
        punitive retry-after (3600+) after repeated violations."""
        capped = min(max(retry_after, 30), 600)
        until = time.monotonic() + capped
        if until > self.blocked_until:
            self.blocked_until = until
            _dbg(f"RATE: 429 received (retry-after={retry_after}s, capped={capped}s)")


def build_dynamic_rounds(mode: str, alive_count: int) -> List[RoundCfg]:
    """Build round configs dynamically based on mode and alive IP count."""
    preset = PRESETS.get(mode, PRESETS["normal"])

    if not preset.get("dynamic"):
        return [RoundCfg(1_000_000, alive_count)]

    sizes = preset["round_sizes"]
    pcts = preset["round_pcts"]
    mins = preset["round_min"]
    maxs = preset["round_max"]

    # Small sets (<50 IPs): test ALL in every round — no funnel needed
    small_set = alive_count <= 50

    rounds = []
    for size, pct, mn, mx in zip(sizes, pcts, mins, maxs):
        if small_set:
            keep = alive_count
        else:
            keep = int(alive_count * pct / 100) if pct < 100 else alive_count
            if mn > 0:
                keep = max(mn, keep)
            if mx > 0:
                keep = min(mx, keep)
        keep = min(keep, alive_count)
        if keep > 0:
            rounds.append(RoundCfg(size, keep))

    return rounds


def parse_vless(uri: str) -> Optional[ConfigEntry]:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    rest = uri[8:]
    name = ""
    if "#" in rest:
        rest, name = rest.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    if "?" in rest:
        rest = rest.split("?", 1)[0]
    if "@" not in rest:
        return None
    _, addr = rest.split("@", 1)
    if addr.startswith("["):
        if "]" not in addr:
            return None
        address = addr[1 : addr.index("]")]
    else:
        address = addr.rsplit(":", 1)[0]
    return ConfigEntry(address=address, name=name, original_uri=uri.strip())


def parse_vmess(uri: str) -> Optional[ConfigEntry]:
    uri = uri.strip()
    if not uri.startswith("vmess://"):
        return None
    b64 = uri[8:]
    if "#" in b64:
        b64 = b64.split("#", 1)[0]
    b64 += "=" * (-len(b64) % 4)
    try:
        try:
            raw = base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:
            raw = base64.urlsafe_b64decode(b64).decode("utf-8", errors="replace")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
    except Exception:
        return None
    address = str(obj.get("add", ""))
    if not address:
        return None
    name = str(obj.get("ps", ""))
    return ConfigEntry(address=address, name=name, original_uri=uri.strip())


def parse_config(uri: str) -> Optional[ConfigEntry]:
    """Try parsing as VLESS or VMess."""
    return parse_vless(uri) or parse_vmess(uri)


def _infer_orig_sni(parsed: dict) -> str:
    """Infer the original TLS SNI from a parsed config.

    Priority: explicit sni > address domain > host > address.
    When no explicit sni is set, xray-core uses the vnext address as
    serverName.  If the address is a domain (not an IP), that domain IS the
    TLS SNI.  This matters for CDN domain-fronting configs where the address
    domain (front) differs from the host domain (real origin).
    When the address is an IP, fall back to host (most clients infer SNI
    from the host field in that case).
    """
    if parsed.get("sni"):
        return parsed["sni"]
    addr = parsed.get("address", "")
    # If address is a domain (not an IP), it's the actual TLS SNI
    try:
        ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        if addr:
            return addr
    # Address is an IP — fall back to host
    return parsed.get("host") or addr


def parse_vless_full(uri: str) -> Optional[dict]:
    """Parse VLESS URI into all component fields for Xray config generation."""
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    rest = uri[8:]
    name = ""
    if "#" in rest:
        rest, name = rest.split("#", 1)
        name = urllib.parse.unquote(name)
    params_str = ""
    if "?" in rest:
        rest, params_str = rest.split("?", 1)
    if "@" not in rest:
        return None
    uuid_part, addr_part = rest.split("@", 1)
    if not uuid_part or len(uuid_part) < 8:
        return None
    if addr_part.startswith("["):
        if "]" not in addr_part:
            return None
        bracket_end = addr_part.index("]")
        address = addr_part[1:bracket_end]
        port_str = addr_part[bracket_end + 2:] if len(addr_part) > bracket_end + 1 and addr_part[bracket_end + 1] == ":" else "443"
    else:
        parts = addr_part.rsplit(":", 1)
        address = parts[0]
        port_str = parts[1] if len(parts) > 1 and parts[1].isdigit() else "443"
    if not address:
        return None
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            port = 443
    except ValueError:
        port = 443
    params = dict(urllib.parse.parse_qsl(params_str, keep_blank_values=True))
    security = params.get("security") or "none"
    return {
        "protocol": "vless",
        "uuid": uuid_part,
        "address": address,
        "port": port,
        "name": name,
        "type": params.get("type") or "tcp",
        "security": security,
        "sni": params.get("sni") or "",
        "host": params.get("host") or "",
        "path": params.get("path") or "/",
        "fp": params.get("fp") or "",
        "flow": params.get("flow") or "",
        "alpn": params.get("alpn") or "",
        "encryption": params.get("encryption") or "none",
        "serviceName": params.get("serviceName", ""),
        "headerType": params.get("headerType", ""),
        "pbk": params.get("pbk", ""),
        "sid": params.get("sid", ""),
        "spx": params.get("spx", ""),
        "mode": params.get("mode") or "auto",
    }


def parse_vmess_full(uri: str) -> Optional[dict]:
    """Parse VMess base64 URI into all component fields for Xray config generation."""
    uri = uri.strip()
    if not uri.startswith("vmess://"):
        return None
    b64 = uri[8:]
    if "#" in b64:
        b64 = b64.split("#", 1)[0]
    b64 += "=" * (-len(b64) % 4)
    try:
        try:
            raw = base64.b64decode(b64).decode("utf-8", errors="replace")
        except ValueError:
            raw = base64.urlsafe_b64decode(b64).decode("utf-8", errors="replace")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
    except (ValueError, TypeError):
        return None
    address = str(obj.get("add", ""))
    if not address:
        return None
    try:
        port = int(obj.get("port", 443))
        if not (1 <= port <= 65535):
            port = 443
    except (ValueError, TypeError):
        port = 443
    try:
        aid = int(obj.get("aid", 0))
    except (ValueError, TypeError):
        aid = 0
    uuid_val = str(obj.get("id", ""))
    if not uuid_val or len(uuid_val) < 8:
        return None
    tls_val = str(obj.get("tls") or "")
    return {
        "protocol": "vmess",
        "uuid": uuid_val,
        "address": address,
        "port": port,
        "name": str(obj.get("ps") or ""),
        "type": str(obj.get("net") or "tcp"),
        "security": "tls" if tls_val.lower() == "tls" else "none",
        "sni": str(obj.get("sni") or ""),
        "host": str(obj.get("host") or ""),
        "path": str(obj.get("path") or "/"),
        "fp": str(obj.get("fp") or ""),
        "aid": aid,
        "scy": str(obj.get("scy") or "auto"),
        "alpn": str(obj.get("alpn") or ""),
        "headerType": str(obj.get("type") or ""),
        "mode": str(obj.get("mode") or "auto"),
    }


def build_xray_config(parsed: dict, sni: str, fragment: Optional[dict], port: int,
                      address_override: str = "") -> dict:
    """Build a complete Xray JSON config from parsed URI fields."""
    cfg = copy.deepcopy(XRAY_CONFIG_TEMPLATE)
    cfg["inbounds"][0]["port"] = port

    is_vmess = parsed.get("protocol") == "vmess"
    protocol = "vmess" if is_vmess else "vless"
    _addr = address_override or parsed["address"]

    outbound = cfg["outbounds"][0]
    outbound["protocol"] = protocol

    if is_vmess:
        outbound["settings"] = {"vnext": [{
            "address": _addr,
            "port": parsed["port"],
            "users": [{
                "id": parsed["uuid"],
                "alterId": parsed.get("aid", 0),
                "security": parsed.get("scy", "auto"),
            }],
        }]}
    else:
        user = {
            "id": parsed["uuid"],
            "encryption": parsed.get("encryption", "none"),
        }
        flow = parsed.get("flow", "")
        if flow:
            user["flow"] = flow
        outbound["settings"] = {"vnext": [{
            "address": _addr,
            "port": parsed["port"],
            "users": [user],
        }]}

    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "tls")
    host = parsed.get("host") or sni

    stream: dict = {"network": net, "security": sec}

    if sec == "tls":
        tls_cfg: dict = {
            "serverName": sni,
            "allowInsecure": False,
        }
        _fp = parsed.get("fp", "")
        if _fp:
            tls_cfg["fingerprint"] = _fp
        if parsed.get("alpn"):
            tls_cfg["alpn"] = parsed["alpn"].split(",")
        stream["tlsSettings"] = tls_cfg
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": parsed.get("fp", "chrome"),
            "publicKey": parsed.get("pbk", ""),
            "shortId": parsed.get("sid", ""),
            "spiderX": parsed.get("spx", ""),
        }

    if net == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("path", "/"),
            "host": host,
            "headers": {"Host": host},
        }
    elif net == "grpc":
        grpc_cfg: dict = {
            "serviceName": parsed.get("serviceName") or (parsed.get("path", "") if parsed.get("path", "") != "/" else ""),
        }
        if host:
            grpc_cfg["authority"] = host
        stream["grpcSettings"] = grpc_cfg
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "host": [host],
            "path": parsed.get("path", "/"),
        }
    elif net == "tcp":
        htype = parsed.get("headerType", "")
        if htype == "http":
            stream["tcpSettings"] = {"header": {
                "type": "http",
                "request": {
                    "path": [parsed.get("path", "/")],
                    "headers": {"Host": [host]},
                },
            }}
    elif net in ("xhttp", "splithttp"):
        xhttp_cfg = {"path": parsed.get("path", "/xhttp")}
        if host:
            xhttp_cfg["host"] = host
        mode = parsed.get("mode", "auto")
        if mode and mode != "auto":
            xhttp_cfg["mode"] = mode
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = xhttp_cfg

    if fragment:
        sockopt: dict = {
            "dialerProxy": "fragment",
            "tcpKeepAliveIdle": 300,
        }
        if sys.platform == "linux":
            sockopt["mark"] = 255
        stream["sockopt"] = sockopt
        cfg["outbounds"].append({
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {"fragment": fragment},
        })

    outbound["streamSettings"] = stream
    return cfg


def build_vless_uri(parsed: dict, sni: str, tag: str) -> str:
    """Reconstruct a VLESS URI with a specific SNI domain."""
    security = parsed.get("security", "tls")
    params = {
        "type": parsed.get("type", "tcp"),
        "security": security,
        "sni": sni,
    }
    _fp = parsed.get("fp", "")
    if _fp:
        params["fp"] = _fp
    if (parsed.get("type") in ("ws", "h2", "http", "xhttp", "splithttp", "grpc")
            or (parsed.get("type") == "tcp" and parsed.get("headerType") == "http")
            or parsed.get("host")):
        params["host"] = parsed.get("host") or sni
    if parsed.get("path") and parsed["path"] != "/":
        params["path"] = parsed["path"]
    if parsed.get("flow"):
        params["flow"] = parsed["flow"]
    if parsed.get("alpn"):
        params["alpn"] = parsed["alpn"]
    if parsed.get("encryption") and parsed["encryption"] != "none":
        params["encryption"] = parsed["encryption"]
    if parsed.get("pbk"):
        params["pbk"] = parsed["pbk"]
    if parsed.get("sid"):
        params["sid"] = parsed["sid"]
    if parsed.get("spx"):
        params["spx"] = parsed["spx"]
    sn = parsed.get("serviceName") or ""
    if not sn and parsed.get("type") == "grpc":
        sn = parsed.get("path", "")
        if sn == "/":
            sn = ""
    if sn:
        params["serviceName"] = sn
    if parsed.get("headerType") and parsed["headerType"] != "none":
        params["headerType"] = parsed["headerType"]
    if parsed.get("mode") and parsed["mode"] != "auto":
        params["mode"] = parsed["mode"]
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    name = urllib.parse.quote(tag)
    addr = parsed["address"]
    if ":" in addr:
        addr = f"[{addr}]"
    return f"vless://{parsed['uuid']}@{addr}:{parsed['port']}?{qs}#{name}"


def build_vmess_uri(parsed: dict, sni: str, tag: str) -> str:
    """Reconstruct a VMess base64 URI with a specific SNI domain."""
    obj = {
        "v": "2",
        "ps": tag,
        "add": parsed["address"],
        "port": str(parsed["port"]),
        "id": parsed["uuid"],
        "aid": str(parsed.get("aid", 0)),
        "scy": parsed.get("scy", "auto"),
        "net": parsed.get("type", "tcp"),
        "type": parsed.get("headerType") or "none",
        "host": parsed.get("host") or sni,
        "path": parsed.get("path", "/"),
        "tls": "tls" if parsed.get("security", "") == "tls" else "",
        "sni": sni,
        "alpn": parsed.get("alpn", ""),
        "fp": parsed.get("fp", ""),
    }
    if parsed.get("type") in ("xhttp", "splithttp"):
        obj["mode"] = parsed.get("mode", "auto")
    if parsed.get("type") == "grpc":
        obj["path"] = parsed.get("serviceName") or parsed.get("path", "grpc")
    raw = json.dumps(obj, separators=(",", ":"))
    b64 = base64.b64encode(raw.encode()).decode()
    return f"vmess://{b64}"


def _build_uri(parsed: dict, sni: str, tag: str) -> str:
    """Build VLESS or VMess URI based on the protocol field in parsed dict."""
    if parsed.get("protocol") == "vmess":
        return build_vmess_uri(parsed, sni, tag)
    return build_vless_uri(parsed, sni, tag)


def switch_transport(parsed: dict, new_transport: str, path: str = "") -> dict:
    """Clone parsed config and change its transport type."""
    new = copy.deepcopy(parsed)

    # Only carry over path if it looks custom (not a transport default)
    _default_paths = {"/", "/ws", "/xhttp", "/h2", "/grpc", "grpc"}
    old_path = parsed.get("path", "/")
    carry_path = old_path if old_path not in _default_paths else ""

    # XTLS flow (e.g. xtls-rprx-vision) only works with TCP — clear for others
    if new_transport != "tcp" and new.get("flow"):
        new["flow"] = ""

    if new_transport == "ws":
        new["type"] = "ws"
        new["path"] = path or carry_path or "/ws"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
    elif new_transport in ("xhttp", "splithttp"):
        new["type"] = "xhttp"
        new["path"] = path or carry_path or "/xhttp"
        new["mode"] = parsed.get("mode", "auto")
        new["headerType"] = ""
        new.pop("serviceName", None)
    elif new_transport == "grpc":
        new["type"] = "grpc"
        svc = path or parsed.get("serviceName") or "grpc"
        if svc.startswith("/"):
            svc = svc[1:]
        new["serviceName"] = svc
        new["path"] = ""
        new["headerType"] = ""
        new.pop("mode", None)
    elif new_transport in ("h2", "http"):
        new["type"] = "h2"
        new["path"] = path or carry_path or "/h2"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
    elif new_transport == "tcp":
        new["type"] = "tcp"
        new["path"] = "/"
        new["headerType"] = ""
        new.pop("mode", None)
        new.pop("serviceName", None)
        # VLESS+REALITY+TCP requires XTLS flow
        if (new.get("security") == "reality"
                and new.get("protocol", "vless") == "vless"
                and not new.get("flow")):
            new["flow"] = "xtls-rprx-vision"
    else:
        return new

    return new


# ─── Input Helpers ────────────────────────────────────────────────────────


def _flush_stdin():
    """Drain any stale bytes from stdin (e.g. leftover from multi-line paste)."""
    if sys.platform == "win32":
        import msvcrt
        time.sleep(0.05)  # let paste buffer settle
        while msvcrt.kbhit():
            msvcrt.getwch()  # getwch avoids echo
    else:
        import select
        fd = sys.stdin.fileno()
        while select.select([sys.stdin], [], [], 0.0)[0]:
            os.read(fd, 4096)


def _restore_console_input():
    """Restore Windows console input mode for proper input() line editing.

    After TUI raw-key reads (msvcrt.getch), the console input mode flags
    may be stripped.  Re-enable ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
    ENABLE_PROCESSED_INPUT so that input() works with arrow keys, backspace,
    etc.  No-op on non-Windows.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)  # STD_INPUT_HANDLE
        m = ctypes.c_ulong()
        k.GetConsoleMode(h, ctypes.byref(m))
        # ENABLE_LINE_INPUT=0x2 | ENABLE_ECHO_INPUT=0x4 | ENABLE_PROCESSED_INPUT=0x1
        need = 0x0007
        if (m.value & need) != need:
            k.SetConsoleMode(h, m.value | need)
    except (OSError, ValueError):
        pass


# ─── Xray Binary & Process Management ────────────────────────────────────


def xray_find_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """Find xray binary. Search order: custom_path > PATH > ~/.cfray/bin/xray."""
    if custom_path and os.path.isfile(custom_path):
        return os.path.abspath(custom_path)
    xray_name = "xray.exe" if sys.platform == "win32" else "xray"
    found = shutil.which(xray_name)
    if found:
        return found
    local_bin = os.path.join(XRAY_BIN_DIR, xray_name)
    if os.path.isfile(local_bin):
        return local_bin
    return None


def xray_install() -> Optional[str]:
    """Download xray-core to ~/.cfray/bin/. Returns binary path or None."""
    os.makedirs(XRAY_BIN_DIR, exist_ok=True)
    machine = _platform.machine().lower()
    if sys.platform == "win32":
        if "aarch64" in machine or "arm64" in machine:
            asset_name = "Xray-windows-arm64-v8a.zip"
        elif "64" in machine or "amd64" in machine:
            asset_name = "Xray-windows-64.zip"
        else:
            asset_name = "Xray-windows-32.zip"
    elif sys.platform == "darwin":
        if "arm" in machine or "aarch64" in machine:
            asset_name = "Xray-macos-arm64-v8a.zip"
        else:
            asset_name = "Xray-macos-64.zip"
    else:
        if "aarch64" in machine or "arm64" in machine:
            asset_name = "Xray-linux-arm64-v8a.zip"
        elif "arm" in machine:
            asset_name = "Xray-linux-arm32-v7a.zip"
        else:
            asset_name = "Xray-linux-64.zip"

    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset_name}"
    zip_path = os.path.join(XRAY_BIN_DIR, asset_name)

    print(f"  Downloading {asset_name}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except (OSError, ValueError, http.client.HTTPException) as e:
        print(f"  Download failed: {e}")
        try:
            os.remove(zip_path)
        except OSError:
            pass
        return None

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            real_base = os.path.realpath(XRAY_BIN_DIR)
            for info in zf.infolist():
                target = os.path.realpath(os.path.join(XRAY_BIN_DIR, info.filename))
                if target != real_base and not target.startswith(real_base + os.sep):
                    print(f"  Bad zip entry (path traversal): {info.filename}")
                    return None
            zf.extractall(XRAY_BIN_DIR)
    except (zipfile.BadZipFile, OSError) as e:
        print(f"  Extract failed: {e}")
        return None
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass

    xray_name = "xray.exe" if sys.platform == "win32" else "xray"
    bin_path = os.path.join(XRAY_BIN_DIR, xray_name)
    if sys.platform != "win32":
        try:
            os.chmod(bin_path, 0o755)
        except OSError:
            pass
    if os.path.isfile(bin_path):
        print(f"  Installed to {bin_path}")
        return bin_path
    return None


def _find_free_ports(base: int, count: int) -> List[int]:
    """Find `count` free TCP ports starting from `base`."""
    ports: List[int] = []
    port = base
    while len(ports) < count and port <= 65535:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            ports.append(port)
        except OSError:
            pass
        finally:
            s.close()
        port += 1
    return ports


class XrayProcess:
    """Manages a single xray-core subprocess."""

    def __init__(self, binary: str, config_path: str, socks_port: int):
        self.binary = binary
        self.config_path = config_path
        self.socks_port = socks_port
        self.proc: Optional[subprocess.Popen] = None
        self.last_error: str = ""

    def _read_stderr_file(self):
        """Read last error from stderr temp file (tail)."""
        try:
            p = self.config_path + ".err"
            if not os.path.isfile(p):
                self.last_error = "no-stderr-file"
                return
            sz = os.path.getsize(p)
            if sz == 0:
                self.last_error = "xray-stderr-empty"
                return
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                # Read last 32KB to capture debug-level output
                if sz > 32768:
                    f.seek(sz - 32768)
                    f.readline()  # skip partial first line
                lines = f.read().strip().splitlines()
            if not lines:
                self.last_error = f"xray-stderr-{sz}B-no-lines"
                return
            # Search backward for meaningful error lines
            for line in reversed(lines):
                lo = line.lower()
                if any(kw in lo for kw in (
                    "error", "fail", "reject", "refused", "timeout",
                    "closed", "reset", "eof", "tls:", "dial",
                    "handshake", "certificate", "invalid")):
                    self.last_error = line.strip()[-120:]
                    return
            # No keyword match — show last non-empty line + file stats
            self.last_error = f"[{sz}B/{len(lines)}L] {lines[-1].strip()[-80:]}"
        except OSError:
            pass

    def start(self) -> bool:
        """Start xray process. Returns True if SOCKS5 port becomes reachable."""
        err_path = self.config_path + ".err"
        try:
            err_fd = os.open(err_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            kwargs: dict = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": err_fd,
            }
            if sys.platform == "win32":
                kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
            self.proc = subprocess.Popen(
                [self.binary, "run", "-c", self.config_path],
                **kwargs,
            )
            os.close(err_fd)
        except (OSError, ValueError, subprocess.SubprocessError):
            try:
                os.close(err_fd)
            except (OSError, UnboundLocalError):
                pass
            return False

        deadline = time.monotonic() + XRAY_CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self._read_stderr_file()
                return False
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(0.5)
                s.connect(("127.0.0.1", self.socks_port))
                s.close()
                return True
            except (ConnectionRefusedError, socket.timeout, OSError):
                s.close()
                time.sleep(0.3)
        self._read_stderr_file()
        self.stop()
        return False

    def stop(self):
        """Terminate xray process and cleanup."""
        if self.proc:
            self._read_stderr_file()
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            self.proc = None

    def cleanup(self):
        """Remove temp config and stderr files."""
        for p in (self.config_path, self.config_path + ".err"):
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass


# ─── SOCKS5 Speed Test (stdlib only) ───────────────────────────────────────


def _xray_speed_test_blocking(
    socks_port: int, size: int, timeout: float,
) -> Tuple[float, float, float, str]:
    """Blocking SOCKS5 + TLS + HTTP download. Returns (connect_ms, ttfb_ms, speed_mbps, error)."""
    sock = None
    tls_sock = None
    try:
        t0 = time.monotonic()

        # 1) Connect to SOCKS5 proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", socks_port))

        def _recv_exact(s, n):
            """Receive exactly n bytes from socket."""
            buf = bytearray()
            while len(buf) < n:
                chunk = s.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("connection closed during recv")
                buf.extend(chunk)
            return bytes(buf)

        # SOCKS5 handshake (no auth)
        sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp != b"\x05\x00":
            return -1, -1, 0, f"socks5-auth:{resp.hex()}"

        # SOCKS5 CONNECT to speed.cloudflare.com:443
        host = SPEED_HOST.encode("ascii")
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big")
        sock.sendall(req)
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            return -1, -1, 0, f"socks5-connect:{head[1]}"
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            dlen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, dlen + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return -1, -1, 0, f"socks5-bad-atyp:{atyp}"

        # 2) TLS upgrade
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=SPEED_HOST)
        sock = None  # tls_sock now owns the socket
        connect_ms = (time.monotonic() - t0) * 1000

        # 3) HTTP request
        http_req = (
            f"GET {SPEED_PATH}?bytes={size} HTTP/1.0\r\n"
            f"Host: {SPEED_HOST}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode()
        tls_sock.sendall(http_req)

        # Read headers
        hbuf = b""
        hdr_deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in hbuf:
            if time.monotonic() > hdr_deadline:
                return connect_ms, -1, 0, "hdr-timeout"
            ch = tls_sock.recv(4096)
            if not ch:
                return connect_ms, -1, 0, "empty-headers"
            hbuf += ch
            if len(hbuf) > 65536:
                return connect_ms, -1, 0, "hdr-too-big"

        sep_idx = hbuf.index(b"\r\n\r\n") + 4
        htxt = hbuf[:sep_idx].decode("latin-1", errors="replace")
        body0 = hbuf[sep_idx:]

        status_parts = htxt.split("\r\n")[0].split(None, 2)
        status_code = status_parts[1] if len(status_parts) >= 2 else ""
        if status_code not in ("200", "206"):
            return connect_ms, -1, 0, f"http:{status_code}"

        ttfb_ms = (time.monotonic() - t0) * 1000 - connect_ms

        # 4) Download body (seed with body bytes already in header buffer)
        dl_start = time.monotonic()
        dl_deadline = dl_start + timeout
        total = len(body0)
        while True:
            try:
                if time.monotonic() > dl_deadline:
                    break
                ch = tls_sock.recv(65536)
                if not ch:
                    break
                total += len(ch)
            except socket.timeout:
                break
            except ssl.SSLWantReadError:
                continue
            except (OSError, ssl.SSLError):
                break

        dl_t = time.monotonic() - dl_start
        if total < min(size * 0.05, 4096):
            return connect_ms, ttfb_ms, 0, f"incomplete:{total}"
        mbps = (total / 1_000_000) / dl_t if dl_t > 0.001 else 0
        return connect_ms, ttfb_ms, mbps, ""

    except socket.timeout:
        return -1, -1, 0, "timeout"
    except (OSError, ssl.SSLError) as e:
        return -1, -1, 0, str(e)[:60]
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except OSError:
                pass
        if sock:
            try:
                sock.close()
            except OSError:
                pass


async def xray_speed_test(
    socks_port: int, size: int, timeout: float,
) -> Tuple[float, float, float, str]:
    """Async wrapper: runs blocking SOCKS5 speed test in executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _xray_speed_test_blocking, socks_port, size, timeout,
    )


# ─── Python-native VLESS-over-WS speed test ───────────────────────────────


def _ws_frame_encode(data: bytes, opcode: int = 0x02) -> bytes:
    """Encode a masked WebSocket binary frame (client->server)."""
    import secrets as _sec
    mask = _sec.token_bytes(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    length = len(data)
    if length <= 125:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length <= 65535:
        header = bytes([0x80 | opcode, 0xFE]) + length.to_bytes(2, 'big')
    else:
        header = bytes([0x80 | opcode, 0xFF]) + length.to_bytes(8, 'big')
    return header + mask + masked


class _WsFrameParser:
    """Incremental WebSocket frame parser for server->client (unmasked) frames."""
    __slots__ = ('_buf',)

    def __init__(self, initial: bytes = b""):
        self._buf = bytearray(initial)

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)

    def next_frame(self) -> Optional[Tuple[int, bytes]]:
        """Extract next complete frame. Returns (opcode, payload) or None."""
        buf = self._buf
        if len(buf) < 2:
            return None
        opcode = buf[0] & 0x0F
        masked = bool(buf[1] & 0x80)
        plen = buf[1] & 0x7F
        off = 2
        if plen == 126:
            if len(buf) < 4:
                return None
            plen = int.from_bytes(buf[2:4], 'big')
            off = 4
        elif plen == 127:
            if len(buf) < 10:
                return None
            plen = int.from_bytes(buf[2:10], 'big')
            off = 10
        if masked:
            if len(buf) < off + 4:
                return None
            off += 4
        if len(buf) < off + plen:
            return None
        payload = bytes(buf[off:off + plen])
        if masked:
            mask_key = bytes(buf[off - 4:off])
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        del self._buf[:off + plen]
        return (opcode, payload)

    @property
    def buffered(self) -> int:
        return len(self._buf)


def _extract_vless_ws_params(config_json: dict) -> Optional[dict]:
    """Extract VLESS-over-WS params from xray config JSON.

    Returns dict with ip, port, uuid, sni, host, path, security -- or None
    if this config is not a VLESS+WS combination.
    """
    outbounds = config_json.get("outbounds", [])
    if not outbounds:
        return None
    out = outbounds[0]
    if out.get("protocol") != "vless":
        return None
    stream = out.get("streamSettings", {})
    if stream.get("network") not in ("ws", "websocket"):
        return None
    vnext = out.get("settings", {}).get("vnext", [{}])
    if not vnext:
        return None
    vnext0 = vnext[0]
    users = vnext0.get("users", [{}])
    if not users:
        return None
    ws = stream.get("wsSettings", {})
    tls = stream.get("tlsSettings", {})
    security = stream.get("security", "none")
    return {
        "ip": vnext0.get("address", ""),
        "port": int(vnext0.get("port", 443)),
        "uuid": users[0].get("id", ""),
        "sni": tls.get("serverName", ""),
        "host": ws.get("headers", {}).get("Host", "") or ws.get("host", ""),
        "path": ws.get("path", "/"),
        "security": security,
    }


async def _vless_ws_read_tunnel(
    reader: asyncio.StreamReader, wsp: _WsFrameParser,
    vless_hdr_done: bool, timeout: float = 5.0,
) -> Tuple[bytes, bool, bool, str]:
    """Read next non-empty data chunk from VLESS tunnel.

    Strips WS framing and VLESS response header automatically.
    Loops internally until real data arrives or the connection closes.

    Returns (data, vless_hdr_done, closed, reason).
    - data: decapsulated tunnel bytes (non-empty unless closed)
    - vless_hdr_done: updated flag
    - closed: True if connection ended
    - reason: error description when closed (empty string otherwise)
    """
    while True:
        frame = wsp.next_frame()
        if frame is not None:
            op, payload = frame
            if op == 8:
                cc = int.from_bytes(payload[:2], 'big') \
                    if len(payload) >= 2 else 0
                return b"", vless_hdr_done, True, f"ws-close:{cc}"
            if op not in (0, 2):
                continue
            # Strip VLESS v0 response header from first data frame
            if not vless_hdr_done:
                if len(payload) >= 2 and payload[0] == 0x00:
                    addon_len = payload[1]
                    payload = payload[2 + addon_len:]
                    vless_hdr_done = True
                elif payload:
                    return (b"", vless_hdr_done, True,
                            f"vless-bad:{payload[:6].hex()}")
                else:
                    continue  # empty frame, keep reading
            # Skip empty payloads (e.g. VLESS header was in its own frame)
            if not payload:
                continue
            return payload, vless_hdr_done, False, ""

        # Need more data from network
        try:
            chunk = await asyncio.wait_for(
                reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError:
            return b"", vless_hdr_done, True, "tunnel-timeout"
        except (OSError, ssl.SSLError) as e:
            return b"", vless_hdr_done, True, f"tunnel:{str(e)[:30]}"
        if not chunk:
            return b"", vless_hdr_done, True, "tunnel-eof"
        wsp.feed(chunk)


async def _vless_ws_speed_test(
    ip: str, port: int, sni: str, host: str, ws_path: str,
    uuid_str: str, size: int, timeout: float,
    security: str = "tls",
) -> Tuple[float, float, float, str]:
    """Python-native VLESS-over-WS speed test -- no xray binary needed.

    Two modes based on download size:
    - Quick probe (<=200KB): HTTP to cp.cloudflare.com:80 through tunnel.
      No inner TLS. Proves tunnel works and measures latency.
    - Speed test (>200KB): HTTPS to speed.cloudflare.com:443 with
      inner TLS via ssl.MemoryBIO. Full throughput measurement.

    Returns (connect_ms, ttfb_ms, speed_mbps, error).
    """
    import secrets as _sec
    import uuid as _uuid_mod
    writer = None
    try:
        t0 = time.monotonic()

        # -- 1. Outer connection (TLS or plain) --
        if security == "tls":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx,
                                        server_hostname=sni),
                timeout=6.0)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=6.0)

        # -- 2. WebSocket upgrade --
        ws_key = base64.b64encode(_sec.token_bytes(16)).decode()
        ws_req = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        writer.write(ws_req)
        await writer.drain()

        # Read HTTP 101 response
        hdr_buf = b""
        hdr_end = time.monotonic() + 6.0
        while b"\r\n\r\n" not in hdr_buf:
            if time.monotonic() > hdr_end:
                return -1, -1, 0, "ws-hdr-timeout"
            chunk = await asyncio.wait_for(reader.read(4096), timeout=4.0)
            if not chunk:
                return -1, -1, 0, "ws-eof"
            hdr_buf += chunk
            if len(hdr_buf) > 16384:
                return -1, -1, 0, "ws-hdr-overflow"

        sep = hdr_buf.index(b"\r\n\r\n") + 4
        hdr_txt = hdr_buf[:sep].decode("latin-1", errors="replace")
        m = re.search(r'HTTP/\S+\s+(\d{3})', hdr_txt)
        ws_status = m.group(1) if m else ""
        if ws_status != "101":
            return -1, -1, 0, f"ws-{ws_status or 'no-resp'}"

        extra = hdr_buf[sep:]
        connect_ms = (time.monotonic() - t0) * 1000
        uuid_bytes = _uuid_mod.UUID(uuid_str).bytes

        # -- HTTP probe to cp.cloudflare.com:80 (no inner TLS) --
        # Always use cp.cloudflare.com -- speed.cloudflare.com is commonly
        # blocked by VLESS server routing rules.
        dest = b"cp.cloudflare.com"
        http_req = (
            b"GET /cdn-cgi/trace HTTP/1.1\r\n"
            b"Host: cp.cloudflare.com\r\n"
            b"Connection: close\r\n\r\n"
        )
        vless_payload = (
            b'\x00' + uuid_bytes + b'\x00'
            + b'\x01' + (80).to_bytes(2, 'big')
            + b'\x02' + bytes([len(dest)]) + dest
            + http_req
        )
        writer.write(_ws_frame_encode(vless_payload))
        await writer.drain()

        # Read VLESS response + HTTP data directly from WS frames
        wsp = _WsFrameParser(extra)
        vless_hdr_done = False
        http_hdr_done = False
        http_buf = b""
        body_total = 0
        ttfb_ms = -1.0
        dl_deadline = time.monotonic() + timeout + 3.0

        while time.monotonic() < dl_deadline:
            tun_data, vless_hdr_done, closed, _reason = \
                await _vless_ws_read_tunnel(
                    reader, wsp, vless_hdr_done, timeout=6.0)
            if closed:
                if not http_hdr_done:
                    return connect_ms, -1, 0, _reason or "probe-closed"
                break
            if not tun_data:
                continue

            if not http_hdr_done:
                http_buf += tun_data
                if b"\r\n\r\n" in http_buf:
                    h_sep = http_buf.index(b"\r\n\r\n") + 4
                    h_line = http_buf[:h_sep].decode(
                        "latin-1", errors="replace")
                    h_parts = h_line.split("\r\n")[0].split(None, 2)
                    h_code = h_parts[1] if len(h_parts) >= 2 else ""
                    if h_code not in ("200", "204"):
                        return connect_ms, -1, 0, f"probe-http:{h_code}"
                    ttfb_ms = ((time.monotonic() - t0) * 1000
                               - connect_ms)
                    body_total = len(http_buf) - h_sep
                    http_hdr_done = True
            else:
                body_total += len(tun_data)
                # /cdn-cgi/trace is small (~300B) -- done once we have it
                if body_total > 50:
                    break

        if not http_hdr_done:
            return connect_ms, -1, 0, "probe-no-response"

        dl_t = (time.monotonic() - t0) - (connect_ms / 1000)
        mbps = (body_total / 1_000_000) / dl_t if dl_t > 0.001 else 0.01
        # Ensure non-zero speed so config is marked alive
        return connect_ms, ttfb_ms, max(mbps, 0.001), ""

    except asyncio.TimeoutError:
        return -1, -1, 0, "timeout"
    except asyncio.CancelledError:
        return -1, -1, 0, "cancelled"
    except (OSError, ssl.SSLError) as e:
        return -1, -1, 0, str(e)[:60]
    except Exception as e:
        return -1, -1, 0, f"{type(e).__name__}:{str(e)[:40]}"
    finally:
        if writer:
            try:
                writer.close()
            except OSError:
                pass


# ─── Variation Generation ─────────────────────────────────────────────────


def generate_xray_variations(
    uri: str,
    snis: Optional[List[str]],
    frag_preset: str,
    base_port: int,
    clean_ips: Optional[List[str]] = None,
) -> List[XrayVariation]:
    """Generate IP x SNI x fragment combinations from a single URI.

    When clean_ips is provided, each IP is tested with each SNI/fragment combo.
    The original config IP is always tested first.
    """
    parsed = None
    if uri.strip().startswith("vless://"):
        parsed = parse_vless_full(uri)
    elif uri.strip().startswith("vmess://"):
        parsed = parse_vmess_full(uri)
    if not parsed:
        return []

    if not snis:
        snis = [_infer_orig_sni(parsed) or parsed.get("address", "")]

    fragments = XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS["all"])
    orig_addr = parsed["address"]

    # Always prepend the original SNI/host so the base config is tested first
    orig_sni = _infer_orig_sni(parsed)
    # Ensure host is set so SNI rotation doesn't change the WS Host header
    if not parsed.get("host") and orig_sni:
        parsed["host"] = orig_sni
    if orig_sni and parsed.get("security") not in ("none", "", "reality"):
        snis = [s for s in snis if s != orig_sni]
        snis.insert(0, orig_sni)

    # REALITY: SNI is cryptographically bound to public key, don't rotate
    if parsed.get("security") == "reality":
        snis = [parsed.get("sni") or (snis[0] if snis else "")]

    # No TLS / REALITY: SNI is meaningless or crypto-bound -- don't rotate
    # Also nothing to fragment (tlshello fragmentation is meaningless or breaks REALITY)
    # XTLS-Vision manages its own packet flow -- fragments break it
    if parsed.get("security") in ("none", "", "reality"):
        if parsed.get("security") != "reality":
            snis = [_infer_orig_sni(parsed) or parsed.get("address", "")]
        fragments = [None]
    elif parsed.get("flow", "").startswith("xtls-rprx-vision"):
        fragments = [None]

    # Build list of IPs to test: original first, then clean IPs
    ips_to_test = [orig_addr]
    if clean_ips:
        for ip in clean_ips:
            if ip != orig_addr and ip not in ips_to_test:
                ips_to_test.append(ip)

    # When testing multiple IPs, limit SNIs/frags to keep total manageable
    if len(ips_to_test) > 1:
        # For multi-IP: top 8 SNIs x 2 frags x N IPs
        snis = snis[:8]
        if len(fragments) > 2:
            fragments = [fragments[0], fragments[-1]]  # none + heaviest

    # Guard: cap variations so base_port + idx stays in valid port range
    max_variations = max(1, 65535 - base_port)
    total_combos = len(ips_to_test) * len(snis) * len(fragments)
    if total_combos > max_variations:
        per_ip = max(1, max_variations // len(ips_to_test))
        snis = snis[:max(1, per_ip // max(1, len(fragments)))]

    variations: List[XrayVariation] = []
    idx = 0
    for ip in ips_to_test:
        for sni in snis:
            for fi, frag in enumerate(fragments):
                if base_port + idx > 65535:
                    break
                frag_label = "none" if frag is None else f"{frag.get('length', '?')}"
                ip_short = ip if ip == orig_addr else ip
                tag = f"{ip_short}|{sni}|{frag_label}"
                config_json = build_xray_config(
                    parsed, sni, frag, base_port + idx,
                    address_override=ip,
                )
                # Build result URI with the tested IP as address
                _p = copy.copy(parsed)
                _p["address"] = ip
                result_uri = _build_uri(_p, sni, tag)
                variations.append(XrayVariation(
                    tag=tag,
                    sni=sni,
                    fragment=frag,
                    config_json=config_json,
                    source_uri=uri,
                    result_uri=result_uri,
                ))
                idx += 1

    return variations


def generate_pipeline_variations(
    parsed: dict,
    source_uri: str,
    working_ips: List[str],
    sni_pool: List[str],
    frag_preset: str,
    transport_variants: List[str],
    base_port: int,
    max_total: int = 200,
    max_snis_per_ip: int = 10,
    ip_ports: Optional[dict] = None,
) -> List[XrayVariation]:
    """Generate xray variations for proven working IPs with budget control.

    Budget math distributes max_total across IPs x ports x transports x SNIs x frags.
    ip_ports: optional {ip: [port1, port2, ...]} for multi-port variations.
    Reuses build_xray_config(), switch_transport(), and URI builders.
    """
    if not working_ips or not parsed:
        return []

    _sec = parsed.get("security") or "none"
    _flow = parsed.get("flow") or ""
    _no_tls = _sec in ("none", "")
    _is_reality = _sec == "reality"
    _is_vision = _flow.startswith("xtls-rprx-vision")
    _orig_port = int(parsed.get("port", 443))

    # Ensure host is set before SNI rotation -- if empty, rotating SNIs
    # would change the WS/HTTP Host header (build_xray_config falls back
    # to sni when host is empty).  Set it to the original SNI so the
    # Host stays constant regardless of which SNI is being tested.
    orig_sni = _infer_orig_sni(parsed)
    if not parsed.get("host") and orig_sni:
        parsed = dict(parsed)  # don't mutate caller's dict
        parsed["host"] = orig_sni

    # Build SNI list -- use helper that handles CDN fronting correctly
    # CF enforces zone matching: SNI must be in the same CF zone as the
    # Host header.  The host domain is therefore ALWAYS a valid SNI and
    # should appear first.  orig_sni (address domain) may be a *different*
    # zone (domain-fronting configs), so it goes second.
    if _is_reality:
        effective_snis = [parsed.get("sni") or orig_sni or ""]
    elif _no_tls:
        effective_snis = [orig_sni or parsed.get("address", "")]
    else:
        effective_snis = []
        # Host domain first -- guaranteed same-zone as what CF routes by
        _host = parsed.get("host", "")
        if _host:
            try:
                ipaddress.ip_address(_host)
            except (ValueError, TypeError):
                # host is a domain (not IP) -> include it
                effective_snis.append(_host)
        # Original SNI second (may be different zone -- works for base config)
        if orig_sni and orig_sni not in effective_snis:
            effective_snis.append(orig_sni)
        for s in sni_pool:
            if s not in effective_snis:
                effective_snis.append(s)

    # Build fragment list
    if _no_tls or _is_reality or _is_vision:
        fragments = [None]
    else:
        fragments = XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS["all"])

    # Build transport list: original + variants
    transport_configs = [("orig", parsed)]
    if not _is_reality and not _no_tls:
        for tv in transport_variants:
            orig_type = parsed.get("type") or parsed.get("net") or "tcp"
            if tv != orig_type:
                switched = switch_transport(parsed, tv)
                if switched:
                    transport_configs.append((tv, switched))

    # xhttp mode variations: test different modes for xhttp/splithttp configs
    _orig_net = parsed.get("type") or parsed.get("net") or "tcp"
    _xhttp_modes: List[str] = []
    if _orig_net in ("xhttp", "splithttp"):
        _orig_mode = parsed.get("mode", "auto") or "auto"
        for _m in ["auto", "packet-up", "stream-up", "stream-down"]:
            if _m != _orig_mode:
                _xhttp_modes.append(_m)

    # Budget: distribute max_total across IPs x ports x SNIs x frags x transports
    # With empty sni_pool, effective_snis has just host + orig_sni (1-2 entries).
    # Budget goes mostly to IPs x fragments.
    n_ips = len(working_ips)
    n_transports = len(transport_configs)
    n_frags = len(fragments)
    # Count total port variants per IP
    _avg_ports = 1
    if ip_ports:
        _total_ports = sum(len(ip_ports.get(ip, [_orig_port])) for ip in working_ips)
        _avg_ports = max(1, _total_ports // n_ips)
    per_ip = max(1, max_total // n_ips)
    per_port = max(1, per_ip // _avg_ports)
    # SNIs get the full per-port budget -- fragments divide what's left per SNI
    snis_budget = max(1, min(max_snis_per_ip, per_port,
                             len(effective_snis)))
    n_frags_eff = max(1, per_port // max(1, snis_budget))
    fragments = fragments[:n_frags_eff]
    # Cap transports to fit remaining budget
    _t_budget = max(1, per_port // max(1, snis_budget * n_frags_eff))
    transport_configs = transport_configs[:_t_budget]
    effective_snis = effective_snis[:snis_budget]

    _dbg(f"[gen_vars] n_ips={n_ips} max_total={max_total} per_ip={per_ip} "
         f"per_port={per_port} snis_budget={snis_budget} n_frags={n_frags_eff} "
         f"transports={len(transport_configs)} effective_snis={len(effective_snis)} "
         f"expected={n_ips * snis_budget * n_frags_eff * len(transport_configs)}")

    variations: List[XrayVariation] = []
    idx = 0

    def _add_variation(ip: str, srv_port: int, t_name: str, t_parsed: dict,
                       sni: str, frag, mode_label: str = "") -> bool:
        """Add one variation. Returns False if budget exhausted."""
        nonlocal idx
        if base_port + idx > 65535 or len(variations) >= max_total:
            return False
        t_type = t_parsed.get("type") or t_parsed.get("net") or "tcp"
        frag_label = "none" if frag is None else f"{frag.get('length', '?')}"
        t_label = t_type if t_name != "orig" else ""
        port_label = f":{srv_port}" if srv_port != 443 else ""
        tag = f"{ip}{port_label}|{sni}|{frag_label}"
        if t_label:
            tag += f"|{t_label}"
        if mode_label:
            tag += f"|{mode_label}"

        _p = copy.copy(t_parsed)
        _p["address"] = ip
        _p["port"] = srv_port

        config_json = build_xray_config(
            _p, sni, frag, base_port + idx,
            address_override=ip,
        )
        result_uri = _build_uri(_p, sni, tag)

        variations.append(XrayVariation(
            tag=tag, sni=sni, fragment=frag,
            config_json=config_json,
            source_uri=source_uri,
            result_uri=result_uri,
        ))
        idx += 1
        return True

    for ip in working_ips:
        ports = ip_ports.get(ip, [_orig_port]) if ip_ports else [_orig_port]
        for srv_port in ports:
            for t_name, t_parsed in transport_configs:
                for sni in effective_snis:
                    for frag in fragments:
                        if not _add_variation(ip, srv_port, t_name, t_parsed,
                                              sni, frag):
                            break
                        # xhttp mode variations: test other modes on first frag only
                        if _xhttp_modes and frag is None:
                            t_type = t_parsed.get("type") or t_parsed.get("net") or "tcp"
                            if t_type in ("xhttp", "splithttp"):
                                for _m in _xhttp_modes:
                                    _mp = copy.copy(t_parsed)
                                    _mp["mode"] = _m
                                    if not _add_variation(ip, srv_port, t_name, _mp,
                                                          sni, frag, _m):
                                        break
                    if len(variations) >= max_total:
                        break
                if len(variations) >= max_total:
                    break
            if len(variations) >= max_total:
                break
        if len(variations) >= max_total:
            break

    return variations


def expand_custom_ips(raw_input: str) -> List[str]:
    """Expand user input (IPs, CIDRs, or file path) into a list of individual IPs.

    Accepts:
      - Single IPs: "1.2.3.4"
      - CIDR notation: "104.16.0.0/24"
      - Comma-separated mix: "1.2.3.4, 10.0.0.0/30"
      - File path (one IP/CIDR per line)
    Returns deduplicated list of IPs (max 6666 to avoid memory issues).
    """
    MAX_IPS = 6666
    entries: List[str] = []

    # Check if input is a file path
    raw = raw_input.strip()
    if os.path.isfile(raw):
        try:
            with open(raw, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(line)
        except OSError:
            pass
    else:
        # Comma or newline separated
        for part in raw.replace("\n", ",").split(","):
            part = part.strip()
            if part:
                entries.append(part)

    seen: set = set()
    result: List[str] = []
    for entry in entries:
        try:
            # Try as single IP first
            ip = ipaddress.IPv4Address(entry)
            if str(ip) not in seen:
                seen.add(str(ip))
                result.append(str(ip))
        except ValueError:
            try:
                # Try as CIDR
                net = ipaddress.IPv4Network(entry, strict=False)
                for host in net.hosts():
                    if len(result) >= MAX_IPS:
                        break
                    s = str(host)
                    if s not in seen:
                        seen.add(s)
                        result.append(s)
            except ValueError:
                continue
        if len(result) >= MAX_IPS:
            break
    return result


# ─── Xray Testing & Pipeline ─────────────────────────────────────────────


def _xray_calc_scores(xst: XrayTestState):
    """Calculate scores for xray variations."""
    for v in xst.variations:
        if not v.alive:
            v.score = 0
            continue
        cms = v.connect_ms if v.connect_ms >= 0 else 1000
        tms = v.ttfb_ms if v.ttfb_ms >= 0 else 1000
        lat = max(0.0, 100.0 - cms / 10.0)
        ttfb = max(0.0, 100.0 - tms / 5.0)
        if v.native_tested or v.speed_mbps < 0.01:
            # Native VLESS test: no real speed data, score on latency only
            v.score = round(lat * 0.55 + ttfb * 0.45, 1)
        else:
            spd = min(100.0, v.speed_mbps * 20.0)
            v.score = round(lat * 0.35 + spd * 0.50 + ttfb * 0.15, 1)


async def _test_single_variation(
    var: XrayVariation, xray_bin: str, size: int, timeout: float,
) -> bool:
    """Test one XrayVariation via Python-native VLESS or xray SOCKS5.

    For VLESS+WS configs without fragments, uses a direct Python tunnel
    (TLS->WS->VLESS->HTTP) which avoids xray binary issues.
    Falls back to xray SOCKS5 proxy for all other protocols.

    Mutates var in place (alive, connect_ms, ttfb_ms, speed_mbps, error).
    Returns True if alive (mbps > 0).
    """
    # -- Try Python-native VLESS test for ALL VLESS+WS configs --
    # Even for fragment variations: if the SNI/IP doesn't work without
    # fragments (e.g. CF returns 403), it won't work with fragments either
    # (fragments only affect DPI, not CF routing). This avoids falling
    # through to the xray binary which has SSL issues.
    params = _extract_vless_ws_params(var.config_json)
    if params and params["uuid"]:
        connect_ms, ttfb_ms, mbps, err = await _vless_ws_speed_test(
            ip=params["ip"], port=params["port"],
            sni=params["sni"] or params["host"],
            host=params["host"] or params["sni"],
            ws_path=params["path"],
            uuid_str=params["uuid"],
            size=size, timeout=timeout,
            security=params["security"],
        )
        var.connect_ms = connect_ms
        if mbps > 0:
            var.alive = True
            var.native_tested = True
            var.ttfb_ms = ttfb_ms
            var.speed_mbps = mbps
            return True
        else:
            # For fragment variations: native test proves connectivity.
            # If it fails, no point trying xray binary (same CF routing).
            var.error = err or "no-data"
            return False

    # -- Fallback: xray SOCKS5 proxy test --
    loop = asyncio.get_running_loop()
    os.makedirs(XRAY_TMP_DIR, exist_ok=True)

    ports = _find_free_ports(XRAY_BASE_PORT, 1)
    if not ports:
        var.error = "no-free-port"
        return False
    port = ports[0]

    test_cfg = copy.deepcopy(var.config_json)
    test_cfg["inbounds"][0]["port"] = port

    config_path = os.path.join(XRAY_TMP_DIR, f"xray_{port}.json")
    try:
        _fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            json.dump(test_cfg, f)
    except OSError as e:
        var.error = f"write-cfg:{str(e)[:30]}"
        try:
            os.remove(config_path)
        except OSError:
            pass
        return False

    xp = XrayProcess(xray_bin, config_path, port)
    try:
        if not await loop.run_in_executor(None, xp.start):
            var.error = xp.last_error[:40] if xp.last_error else "xray-start-fail"
            return False

        connect_ms, ttfb_ms, mbps, err = await xray_speed_test(
            port, size, timeout,
        )
        var.connect_ms = connect_ms
        if mbps > 0:
            var.alive = True
            var.ttfb_ms = ttfb_ms
            var.speed_mbps = mbps
            return True
        else:
            _py_err = err or "no-data"
            # Stop xray FIRST so it flushes all output to .err file
            xp.stop()
            xp._read_stderr_file()
            if xp.last_error:
                var.error = xp.last_error[:60]
            else:
                var.error = _py_err
            return False
    finally:
        xp.stop()  # safe to call twice
        xp.cleanup()


async def xray_pipeline_test(xst: XrayTestState, pcfg: PipelineConfig):
    """Progressive 3-stage pipeline for xray proxy testing.

    Stage 1: IP Scan       -- TLS probe CF_TEST_IPS + original IP (~10s)
    Stage 2: Base Test     -- Real xray test with original config on live IPs (~30-60s)
    Stage 3: Expansion     -- SNI + fragment + transport variations on working IPs (~2-3 min)
    """
    xst.pipeline_mode = True
    xst.start_time = time.monotonic()
    os.makedirs(XRAY_TMP_DIR, exist_ok=True)
    # Clean stale temp configs
    for stale in globmod.glob(os.path.join(XRAY_TMP_DIR, "xray_*.json")):
        try:
            os.remove(stale)
        except OSError:
            pass

    orig_addr = pcfg.parsed.get("address", "")
    orig_sni = _infer_orig_sni(pcfg.parsed) or "speed.cloudflare.com"
    orig_port = int(pcfg.parsed.get("port", 443))
    _sec = pcfg.parsed.get("security") or "none"
    _is_reality = _sec == "reality"
    _no_tls = _sec in ("none", "")
    _is_cf = _is_cf_address(orig_addr)
    if not _is_cf and not _is_reality and not _no_tls:
        _is_cf = _resolve_is_cf(orig_addr)

    # Auto-detect: find alternative SNI to try if primary fails
    # With new _infer_orig_sni, orig_sni is the address domain for CDN
    # fronting configs; the host domain becomes the fallback (and vice versa).
    _alt_sni = ""
    if not _is_reality and not _no_tls:
        _host = pcfg.parsed.get("host", "")
        _av = pcfg.parsed.get("address", "")
        _addr_is_domain = False
        try:
            ipaddress.ip_address(_av)
        except (ValueError, TypeError):
            _addr_is_domain = bool(_av)
        # Pick an alternative that differs from orig_sni
        if _host and _host != orig_sni:
            _alt_sni = _host
        elif _addr_is_domain and _av != orig_sni:
            _alt_sni = _av

    # -- Pre-flight: verify server and auto-detect SNI mode --
    if not _is_reality and not _no_tls and orig_addr:
        _pf_addr = orig_addr
        try:
            ipaddress.ip_address(orig_addr)
        except (ValueError, TypeError):
            if _CF_PREFLIGHT_IPS:
                _pf_addr = _CF_PREFLIGHT_IPS[0]

        xst.phase_label = f"Pre-flight: checking {orig_sni}:{orig_port}..."
        pf_lat, pf_is_cf, pf_err = await _tls_probe(
            _pf_addr, orig_sni, timeout=5.0, validate=True, port=orig_port)
        xst.preflight_is_cf = pf_is_cf if pf_lat > 0 else None

        # Only switch SNI if the TLS connection itself completely failed.
        if _alt_sni and pf_lat <= 0:
            xst.phase_label = f"Pre-flight: trying {_alt_sni}..."
            pf2_lat, pf2_is_cf, pf2_err = await _tls_probe(
                _pf_addr, _alt_sni, timeout=5.0, validate=True,
                port=orig_port)
            if pf2_lat > 0 and pf2_is_cf and not pf2_err.startswith(
                    "cf-origin-"):
                # Alternative SNI works -- switch
                orig_sni = _alt_sni
                _alt_sni = ""
                xst.preflight_is_cf = True
                pf_lat, pf_is_cf, pf_err = pf2_lat, pf2_is_cf, pf2_err

        # Set warnings based on final pre-flight result
        if pf_lat <= 0:
            xst.preflight_warning = (
                f"Server {orig_sni}:{orig_port} unreachable")
        elif not pf_is_cf:
            xst.preflight_warning = (
                f"TLS OK but HTTP validation inconclusive for {orig_sni} "
                f"(origin may only accept WebSocket)")
        elif pf_err.startswith("cf-origin-"):
            _pf_code = pf_err.split('-')[-1]
            if _pf_code == "403":
                _pf_hint = "domain may not be on Cloudflare"
            elif _pf_code in ("521", "522", "523"):
                _pf_hint = "origin server is down or unreachable"
            elif _pf_code in ("502", "520", "530"):
                _pf_hint = "origin DNS or routing error"
            else:
                _pf_hint = "server may be down or misconfigured"
            xst.preflight_warning = (
                f"CF edge OK but HTTP {_pf_code} -- {_pf_hint}")

        # -- VLESS tunnel probe: test WS upgrade + VLESS handshake --
        _ws_net = pcfg.parsed.get("type") or pcfg.parsed.get("net") or "tcp"
        _ws_host = pcfg.parsed.get("host") or orig_sni
        _ws_path = pcfg.parsed.get("path") or "/"
        _uuid_str = pcfg.parsed.get("uuid", "")
        if pf_lat > 0 and _ws_net in ("ws", "websocket") and _uuid_str:
            xst.phase_label = f"Pre-flight: testing VLESS tunnel..."
            _vless_diag = ""
            try:
                _ws_ip = _pf_addr
                _ws_ctx = ssl.create_default_context()
                _ws_ctx.check_hostname = False
                _ws_ctx.verify_mode = ssl.CERT_NONE
                _ws_r, _ws_w = await asyncio.wait_for(
                    asyncio.open_connection(
                        _ws_ip, orig_port, ssl=_ws_ctx,
                        server_hostname=orig_sni),
                    timeout=5.0)
                # Step 1: WebSocket upgrade
                import secrets as _secrets
                _ws_key = base64.b64encode(_secrets.token_bytes(16)).decode()
                _ws_req = (
                    f"GET {_ws_path} HTTP/1.1\r\n"
                    f"Host: {_ws_host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {_ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                _ws_w.write(_ws_req.encode())
                await _ws_w.drain()

                # Read HTTP response -- must find \r\n\r\n boundary
                _hdr_buf = b""
                _hdr_deadline = time.monotonic() + 5.0
                while b"\r\n\r\n" not in _hdr_buf:
                    if time.monotonic() > _hdr_deadline:
                        break
                    _chunk = await asyncio.wait_for(
                        _ws_r.read(4096), timeout=3.0)
                    if not _chunk:
                        break
                    _hdr_buf += _chunk
                    if len(_hdr_buf) > 8192:
                        break

                _ws_txt = _hdr_buf.decode("latin-1", errors="replace")
                _ws_status = ""
                _ws_m = re.search(r'HTTP/\S+\s+(\d{3})', _ws_txt)
                if _ws_m:
                    _ws_status = _ws_m.group(1)

                # Extract any WS data after the HTTP headers
                _ws_extra = b""
                if b"\r\n\r\n" in _hdr_buf:
                    _ws_extra = _hdr_buf[_hdr_buf.index(b"\r\n\r\n") + 4:]

                if _ws_status != "101":
                    _ws_first_line = _ws_txt.split("\r\n", 1)[0]
                    _vless_diag = f"WS {_ws_status or 'no-resp'}: {_ws_first_line[:40]}"
                else:
                    # Step 2: Build VLESS header + HTTP request payload
                    import uuid as _uuid_mod
                    _uuid_bytes = _uuid_mod.UUID(_uuid_str).bytes
                    _dest = b"cp.cloudflare.com"
                    _http_req = (
                        b"GET /cdn-cgi/trace HTTP/1.1\r\n"
                        b"Host: cp.cloudflare.com\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    _vless_payload = (
                        b'\x00'                      # version
                        + _uuid_bytes                 # UUID (16 bytes)
                        + b'\x00'                     # addon length
                        + b'\x01'                     # command: TCP
                        + (80).to_bytes(2, 'big')     # port 80 (HTTP)
                        + b'\x02'                     # addr type: domain
                        + bytes([len(_dest)])          # domain length
                        + _dest                        # domain
                        + _http_req                    # first data chunk
                    )
                    # Wrap in WS binary frame (client must mask)
                    _mask = _secrets.token_bytes(4)
                    _masked = bytes(
                        b ^ _mask[i % 4] for i, b in enumerate(_vless_payload))
                    _frame_len = len(_vless_payload)
                    if _frame_len <= 125:
                        _ws_frame = (bytes([0x82, 0x80 | _frame_len])
                                     + _mask + _masked)
                    else:
                        _ws_frame = (bytes([0x82, 0xFE])
                                     + _frame_len.to_bytes(2, 'big')
                                     + _mask + _masked)
                    _ws_w.write(_ws_frame)
                    await _ws_w.drain()

                    # Step 3: Read VLESS response + HTTP data (over WS)
                    try:
                        _vr = _ws_extra  # include any data from HTTP read
                        _vr += await asyncio.wait_for(
                            _ws_r.read(2048), timeout=8.0)
                        if len(_vr) >= 4:
                            # Parse WS frame
                            _op = _vr[0] & 0x0F
                            _plen = _vr[1] & 0x7F
                            _pstart = 2
                            if _plen == 126:
                                _plen = int.from_bytes(_vr[2:4], 'big')
                                _pstart = 4
                            elif _plen == 127:
                                _pstart = 10
                            _payload = _vr[_pstart:_pstart + _plen]

                            if _op == 8:
                                # WS close frame
                                _close_code = int.from_bytes(
                                    _payload[:2], 'big') if len(_payload) >= 2 else 0
                                _close_reason = _payload[2:].decode(
                                    'utf-8', errors='replace') if len(_payload) > 2 else ""
                                _vless_diag = (
                                    f"VLESS rejected: WS close {_close_code}"
                                    f"{' ' + _close_reason[:30] if _close_reason else ''}"
                                    f" (UUID may be wrong/expired)")
                            elif len(_payload) >= 2 and _payload[0] == 0x00:
                                # VLESS v0 response header (2+ bytes)
                                _addon_len = _payload[1]
                                _data_after = _payload[2 + _addon_len:]
                                # Check if HTTP response follows
                                if b"HTTP" in _data_after[:20]:
                                    _vless_diag = "VLESS tunnel OK -- proxy works!"
                                else:
                                    _vless_diag = (
                                        f"VLESS tunnel OK (v0) "
                                        f"data={_data_after[:16].hex()}")
                            else:
                                _vless_diag = (
                                    f"VLESS unexpected: op={_op} len={_plen} "
                                    f"hex={_payload[:12].hex() if _payload else 'empty'}")
                        elif len(_vr) > 0:
                            _vless_diag = (
                                f"VLESS short: {len(_vr)}B "
                                f"{_vr[:20].hex()}")
                        else:
                            _vless_diag = "VLESS: empty response"
                    except asyncio.TimeoutError:
                        _vless_diag = "VLESS: timeout (origin can't reach destination?)"

                _ws_w.close()
                try:
                    await _ws_w.wait_closed()
                except OSError:
                    pass
            except asyncio.TimeoutError:
                _vless_diag = "TLS/WS timeout"
            except OSError as _ws_e:
                _vless_diag = f"connect: {str(_ws_e)[:40]}"

            if _vless_diag:
                xst.preflight_warning = (
                    (xst.preflight_warning + " | " if xst.preflight_warning else "")
                    + _vless_diag)

    # -- Stage 1: IP Scan --
    xst.pipeline_stage = 0
    xst.pipeline_stages[0]["status"] = "active"
    xst.phase = "ip_scan"

    if _is_reality:
        # REALITY: only probe the original server IP on its port/SNI
        xst.phase_label = f"Probing {orig_addr}:{orig_port}..."
        probe_ips = [orig_addr] if orig_addr else []
        probe_sni = orig_sni
        probe_ports = [orig_port]
    else:
        # Cloudflare-fronted: probe CF IPs on configured ports
        probe_ips = list(pcfg.custom_ips) if pcfg.custom_ips else list(CF_TEST_IPS)
        if orig_addr and orig_addr not in probe_ips:
            probe_ips.insert(0, orig_addr)
        probe_sni = "speed.cloudflare.com"
        probe_ports = pcfg.probe_ports if pcfg.probe_ports else [orig_port]
        n_ports = len(probe_ports)
        port_label = f" x {n_ports} ports ({','.join(str(p) for p in probe_ports)})" if n_ports > 1 else f" on port {probe_ports[0]}"
        if pcfg.custom_ips:
            _cf_range_count = sum(1 for ip in probe_ips if _is_cf_address(ip))
            _non_cf = len(probe_ips) - _cf_range_count
            if _non_cf > len(probe_ips) * 0.5:
                xst.preflight_warning = (
                    (xst.preflight_warning + " | " if xst.preflight_warning else "")
                    + f"{_non_cf}/{len(probe_ips)} custom IPs outside known CF ranges")
            xst.phase_label = (
                f"Scanning {len(probe_ips)} IPs "
                f"({_cf_range_count} in CF ranges){port_label}...")
        else:
            xst.phase_label = f"Scanning {len(probe_ips)} IPs{port_label}..."

    # Build (ip, port) probe pairs
    probe_pairs: List[Tuple[str, int]] = []
    for ip in probe_ips:
        for port in probe_ports:
            probe_pairs.append((ip, port))

    # Scale concurrency: 50 for default CF_TEST_IPS, up to 200 for large custom sets
    _sem_count = min(200, max(50, len(probe_pairs) // 20))
    sem = asyncio.Semaphore(_sem_count)
    xst.total = len(probe_pairs)
    xst.done_count = 0

    async def _probe_one(ip: str, port: int) -> Optional[Tuple[str, int, float]]:
        async with sem:
            if xst.interrupted:
                return None
            try:
                lat, is_cf, err = await _tls_probe(ip, probe_sni, timeout=4.0,
                                                    validate=True, port=port)
                xst.done_count += 1
                if lat > 0 and is_cf:
                    if err.startswith("cf-origin-"):
                        xst.cf_origin_errors += 1
                    return (ip, port, lat)
            except Exception:
                xst.done_count += 1
            return None

    results = await asyncio.gather(*[_probe_one(ip, port) for ip, port in probe_pairs])
    # Deduplicate IPs -- keep best latency per IP; track all working ports
    _ip_best: dict = {}  # ip -> best latency
    xst.live_ip_ports = {}
    for r in results:
        if r is not None:
            ip, port, lat = r
            if ip not in _ip_best or lat < _ip_best[ip]:
                _ip_best[ip] = lat
            if ip not in xst.live_ip_ports:
                xst.live_ip_ports[ip] = []
            if port not in xst.live_ip_ports[ip]:
                xst.live_ip_ports[ip].append(port)
    xst.live_ips = sorted([(ip, lat) for ip, lat in _ip_best.items()], key=lambda x: x[1])

    xst.pipeline_stages[0]["status"] = "done"
    _cf_count = len(xst.live_ips)
    _origin_warn = f" ({xst.cf_origin_errors} with origin errors)" if xst.cf_origin_errors else ""
    _port_info = f" on port {probe_ports[0]}" if len(probe_ports) == 1 else f" on ports {','.join(str(p) for p in probe_ports)}"
    xst.phase_label = f"IP Scan: {_cf_count} CF confirmed{_port_info}{_origin_warn}"

    if not xst.live_ips or xst.interrupted:
        xst.pipeline_stages[0]["status"] = "interrupted"
        xst.finished = True
        if _is_cf:
            if xst.preflight_warning:
                xst.phase_label = "No Cloudflare IPs found -- server may not be behind CF CDN"
            else:
                xst.phase_label = "No Cloudflare IPs found -- check your network or IP list"
        else:
            xst.phase_label = f"Server {orig_addr}:{orig_port} unreachable -- check address/port"
        _xray_calc_scores(xst)
        return

    # -- Stage 2: Base Connectivity --
    xst.pipeline_stage = 1
    xst.pipeline_stages[1]["status"] = "active"
    xst.phase = "base_test"

    # For config-less mode: test each base URI on original IP first
    if pcfg.configless and pcfg.base_uris:
        xst.phase_label = f"Testing {len(pcfg.base_uris)} base configs..."
        xst.total = len(pcfg.base_uris)
        xst.done_count = 0

        working_uri = None
        working_parsed = None
        for uri, parsed in pcfg.base_uris:
            if xst.interrupted:
                break
            _sni = _infer_orig_sni(parsed) or "speed.cloudflare.com"
            cfg_json = build_xray_config(parsed, _sni, None, XRAY_BASE_PORT,
                                         address_override=orig_addr)
            var = XrayVariation(
                tag=f"{orig_addr}|{_sni}|none",
                sni=_sni, fragment=None,
                config_json=cfg_json,
                source_uri=uri, result_uri=uri,
            )
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            if alive:
                working_uri = uri
                working_parsed = parsed
                xst.working_ips.append(orig_addr)
                xst.variations.append(var)
                xst.alive_count += 1
                break
            else:
                xst.dead_count += 1

        if not working_uri:
            xst.pipeline_stages[1]["status"] = "done"
            xst.finished = True
            xst.phase_label = "No base config could connect -- server may not support ws/xhttp"
            _xray_calc_scores(xst)
            return

        # Use the working config for remaining stages
        pcfg.uri = working_uri
        pcfg.parsed = working_parsed
        orig_sni = _infer_orig_sni(working_parsed)

    # Test live IPs with the base config
    test_ips = [ip for ip, _ in xst.live_ips[:pcfg.max_stage2_ips]]
    # Ensure original IP is always tested
    if orig_addr and orig_addr not in test_ips:
        test_ips.insert(0, orig_addr)

    xst.total = len(test_ips)
    xst.done_count = 0
    xst.phase_label = f"Base test: 0/{len(test_ips)} IPs..."

    # Build all base variations upfront
    _base_vars: List[Tuple[str, XrayVariation]] = []
    for ip in test_ips:
        _test_port = (xst.live_ip_ports.get(ip, []) or [orig_port])[0]
        _p = copy.copy(pcfg.parsed)
        _p["address"] = ip
        _p["port"] = _test_port
        cfg_json = build_xray_config(_p, orig_sni, None,
                                     XRAY_BASE_PORT + len(_base_vars),
                                     address_override=ip)
        r_uri = _build_uri(_p, orig_sni, f"{ip}|{orig_sni}|none")
        var = XrayVariation(
            tag=f"{ip}|{orig_sni}|none",
            sni=orig_sni, fragment=None,
            config_json=cfg_json,
            source_uri=pcfg.uri, result_uri=r_uri,
        )
        _base_vars.append((ip, var))

    # Run Stage 2 in parallel batches
    _base_sem = asyncio.Semaphore(10)

    async def _test_base(ip: str, var: XrayVariation) -> None:
        async with _base_sem:
            if xst.interrupted:
                return
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            xst.variations.append(var)
            if alive:
                if ip not in xst.working_ips:
                    xst.working_ips.append(ip)
                xst.alive_count += 1
            else:
                xst.dead_count += 1
            xst.phase_label = (
                f"Base test: {xst.done_count}/{len(test_ips)} "
                f"({len(xst.working_ips)} working)")

    for _ci in range(0, len(_base_vars), 20):
        if xst.interrupted:
            break
        batch = _base_vars[_ci:_ci + 20]
        await asyncio.gather(*[_test_base(ip, var) for ip, var in batch])

    # Fallback: if no IPs work, try alternative SNIs on original IP
    # Skip for REALITY (SNI is crypto-bound) and no-TLS (SNI meaningless)
    if not xst.working_ips and not xst.interrupted and not _is_reality and not _no_tls:
        _fb_base = [_alt_sni] if _alt_sni else []
        _fb_common = ["speed.cloudflare.com", "dash.cloudflare.com", "chatgpt.com"]
        fallback_snis = _fb_base + [s for s in _fb_common if s not in _fb_base]
        fallback_snis = [s for s in fallback_snis if s and s != orig_sni]
        xst.phase_label = "Trying fallback SNIs..."
        for fb_sni in fallback_snis:
            if xst.interrupted:
                break
            cfg_json = build_xray_config(pcfg.parsed, fb_sni, None, XRAY_BASE_PORT,
                                         address_override=orig_addr)
            _fb_p = copy.copy(pcfg.parsed)
            _fb_p["address"] = orig_addr
            fb_result_uri = _build_uri(_fb_p, fb_sni, f"{orig_addr}|{fb_sni}|none")
            var = XrayVariation(
                tag=f"{orig_addr}|{fb_sni}|none",
                sni=fb_sni, fragment=None,
                config_json=cfg_json,
                source_uri=pcfg.uri, result_uri=fb_result_uri,
            )
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            if alive:
                orig_sni = fb_sni  # Update SNI for Stage 3
                xst.working_ips.append(orig_addr)
                xst.variations.append(var)
                xst.alive_count += 1
                break

    xst.pipeline_stages[1]["status"] = "interrupted" if xst.interrupted else "done"

    # If base config failed but we have live CF IPs, don't give up --
    # proceed to expansion with different SNIs/fragments/transports.
    _base_failed = not xst.working_ips
    _fallback_ips: List[str] = []
    if _base_failed and not xst.interrupted and _is_cf and xst.live_ips:
        _fallback_ips = [ip for ip, _ in xst.live_ips[:min(20, pcfg.max_stage2_ips)]]
        xst.phase_label = (
            f"Base config failed -- expanding with fragments "
            f"on {len(_fallback_ips)} IPs...")
    elif not xst.working_ips or xst.interrupted:
        xst.finished = True
        if not _is_cf:
            xst.phase_label = (
                f"Connection failed -- server {orig_addr}:{orig_port} "
                f"not responding to xray")
        elif xst.cf_origin_errors > 0:
            xst.phase_label = (
                "CF edge IPs found but origin is unreachable -- "
                "check server config (UUID, path, protocol)")
        else:
            xst.phase_label = (
                "No working IP found -- config may be invalid or "
                "server not properly behind Cloudflare")
        _xray_calc_scores(xst)
        return

    # -- Stage 3: Expansion --
    xst.pipeline_stage = 2
    xst.pipeline_stages[2]["status"] = "active"
    xst.phase = "expansion"

    # When base config failed, use live CF IPs for expansion instead
    _expansion_ips = xst.working_ips if xst.working_ips else (
        _fallback_ips if _base_failed else [])

    # Ensure the proven working SNI is first in the pool for Stage 3
    if orig_sni:
        if orig_sni in pcfg.sni_pool:
            pcfg.sni_pool.remove(orig_sni)
        pcfg.sni_pool.insert(0, orig_sni)

    _dbg(f"[expansion] IPs={len(_expansion_ips)} sni_pool={len(pcfg.sni_pool)} "
         f"frag={pcfg.frag_preset} transports={pcfg.transport_variants} "
         f"max_exp={pcfg.max_expansion} max_snis={pcfg.max_snis_per_ip} "
         f"sni_sample={pcfg.sni_pool[:5]}")

    expansion_vars = generate_pipeline_variations(
        pcfg.parsed, pcfg.uri, _expansion_ips, pcfg.sni_pool,
        pcfg.frag_preset, pcfg.transport_variants,
        XRAY_BASE_PORT, pcfg.max_expansion, pcfg.max_snis_per_ip,
        ip_ports=xst.live_ip_ports if xst.live_ip_ports else None,
    )

    _dbg(f"[expansion] generated={len(expansion_vars)} "
         f"unique_snis={len(set(v.sni for v in expansion_vars))}")

    # Remove duplicates (variations already tested in Stage 2)
    tested_tags = {v.tag for v in xst.variations}
    expansion_vars = [v for v in expansion_vars if v.tag not in tested_tags]
    _dbg(f"[expansion] after dedup={len(expansion_vars)}")

    _exp_frag_count = len(set(str(v.fragment) for v in expansion_vars))
    xst.total = len(expansion_vars)
    xst.done_count = 0
    xst.phase_label = (f"Expansion: 0/{len(expansion_vars)} "
                       f"({len(_expansion_ips)} IPs, {_exp_frag_count} frags)...")

    # Run expansion tests in parallel batches for speed
    _exp_sem = asyncio.Semaphore(20)

    async def _test_exp(var: XrayVariation) -> None:
        async with _exp_sem:
            if xst.interrupted:
                return
            alive = await _test_single_variation(var, xst.xray_bin,
                                                 XRAY_QUICK_SIZE, XRAY_QUICK_TIMEOUT)
            xst.done_count += 1
            if alive:
                xst.alive_count += 1
            else:
                xst.dead_count += 1
            xst.phase_label = (
                f"Expansion: {xst.done_count}/{len(expansion_vars)} "
                f"({xst.alive_count} alive)")

    # Process in chunks to allow interrupt checks and append results in order
    _chunk = 60
    for _ci in range(0, len(expansion_vars), _chunk):
        if xst.interrupted:
            break
        batch = expansion_vars[_ci:_ci + _chunk]
        await asyncio.gather(*[_test_exp(v) for v in batch])
        xst.variations.extend(batch)

    xst.pipeline_stages[2]["status"] = "interrupted" if xst.interrupted else "done"
    xst.quick_passed = xst.alive_count

    xst.finished = True
    _xray_calc_scores(xst)


def load_input(path: str) -> List[ConfigEntry]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"  Error reading {path}: {e}")
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "data" in data:
            data = data["data"]
        out: List[ConfigEntry] = []
        for i, e in enumerate(data):
            d = e.get("domain", "")
            if d:
                out.append(
                    ConfigEntry(address=d, name=f"d-{i+1}", ip=e.get("ipv4", ""))
                )
        if out:
            return out
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    out = []
    for ln in raw.splitlines():
        c = parse_config(ln)
        if c:
            out.append(c)
    return out


def fetch_sub(url: str) -> List[ConfigEntry]:
    """Fetch configs from a subscription URL (base64 or plain VLESS URIs)."""
    if not url.lower().startswith(("http://", "https://")):
        print(f"  Error: --sub only accepts http:// or https:// URLs")
        return []
    _dbg(f"Fetching subscription: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
    except Exception as e:
        _dbg(f"Subscription fetch failed: {e}")
        print(f"  Error fetching subscription: {e}")
        return []
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
        if "://" in decoded:
            raw = decoded
    except Exception:
        pass
    out = []
    for ln in raw.splitlines():
        c = parse_config(ln.strip())
        if c:
            out.append(c)
    _dbg(f"Subscription loaded: {len(out)} configs")
    return out


def generate_from_template(template: str, addresses: List[str]) -> List[ConfigEntry]:
    """Generate configs by substituting addresses into a VLESS/VMess template."""
    out = []
    parsed = parse_config(template)
    if not parsed:
        return out
    for i, addr in enumerate(addresses):
        addr = addr.strip()
        if not addr:
            continue
        # Handle ip:port format (e.g. from multi-port clean scan)
        addr_ip = addr
        addr_port = None
        if ":" in addr and not addr.startswith("["):
            parts = addr.rsplit(":", 1)
            if parts[1].isdigit():
                addr_ip, addr_port = parts[0], parts[1]
        uri = re.sub(
            r"(@)(\[[^\]]+\]|[^:]+)(:|$)",
            lambda m: m.group(1) + addr_ip + m.group(3),
            template,
            count=1,
        )
        if addr_port:
            # Replace existing port, or insert port if template had none
            if re.search(r"@[^:/?#]+:\d+", uri):
                uri = re.sub(r"(@[^:/?#]+:)\d+", lambda m: m.group(1) + addr_port, uri, count=1)
            else:
                uri = re.sub(r"(@[^/?#]+)([?/#])", lambda m: m.group(1) + ":" + addr_port + m.group(2), uri, count=1)
        uri = re.sub(r"#.*$", f"#cfg-{i+1}-{addr_ip[:20]}", uri)
        c = parse_config(uri)
        if c:
            out.append(c)
    return out


def load_addresses(path: str) -> List[str]:
    """Load address list from JSON array or plain text (one per line)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"  Error reading {path}: {e}")
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(d) for d in data if d]
        if isinstance(data, dict):
            for key in ("addresses", "domains", "ips", "data"):
                if key in data and isinstance(data[key], list):
                    return [str(d) for d in data[key] if d]
    except (json.JSONDecodeError, TypeError):
        pass
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def _split_to_24s(subnets: List[str]) -> list:
    """Split CIDR subnets into /24 blocks, deduplicate."""
    seen = set()
    blocks = []
    for sub in subnets:
        try:
            net = ipaddress.IPv4Network(sub.strip(), strict=False)
            if net.prefixlen <= 24:
                for block in net.subnets(new_prefix=24):
                    key = int(block.network_address)
                    if key not in seen:
                        seen.add(key)
                        blocks.append(block)
            else:
                key = int(net.network_address)
                if key not in seen:
                    seen.add(key)
                    blocks.append(net)
        except (ValueError, TypeError):
            continue
    return blocks


def generate_cf_ips(subnets: List[str], sample_per_24: int = 0) -> List[str]:
    """Generate IPs from CIDR subnets. sample_per_24=0 means all hosts."""
    blocks = _split_to_24s(subnets)
    random.shuffle(blocks)
    ips = []
    for net in blocks:
        hosts = [str(ip) for ip in net.hosts()]
        if sample_per_24 > 0 and sample_per_24 < len(hosts):
            hosts = random.sample(hosts, sample_per_24)
        ips.extend(hosts)
    return ips


async def _tls_probe(
    ip: str, sni: str, timeout: float, validate: bool = True, port: int = 443,
) -> Tuple[float, bool, str]:
    """TLS probe with optional Cloudflare header validation.
    Returns (latency_ms, is_cloudflare, error)."""
    w = None
    cf_err = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        tls_ms = (time.monotonic() - t0) * 1000

        is_cf = True
        htxt = ""
        if validate:
            is_cf = False
            try:
                safe_sni = sni.replace("\r", "").replace("\n", "")
                req = f"GET / HTTP/1.1\r\nHost: {safe_sni}\r\nConnection: close\r\n\r\n"
                w.write(req.encode())
                await w.drain()
                hdr = await asyncio.wait_for(r.read(2048), timeout=min(timeout, 3))
                htxt = hdr.decode("latin-1", errors="replace").lower()
                is_cf = "server: cloudflare" in htxt or "cf-ray:" in htxt
            except OSError:
                pass

        if is_cf:
            _status_line = htxt.split("\r\n", 1)[0] if "\r\n" in htxt else ""
            _sm = re.search(r'http/\S+\s+(\d{3})', _status_line)
            if _sm:
                _scode = int(_sm.group(1))
                if _scode >= 400:
                    cf_err = f"cf-origin-{_scode}"

        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        w = None
        return tls_ms, is_cf, cf_err
    except asyncio.TimeoutError:
        return -1, False, "timeout"
    except OSError as e:
        return -1, False, str(e)[:40]
    finally:
        if w:
            try:
                w.close()
            except OSError:
                pass


@dataclass
class CleanScanState:
    """State for clean IP scanning progress."""
    total: int = 0
    done: int = 0
    found: int = 0
    interrupted: bool = False
    results: List[Tuple[str, float]] = field(default_factory=list)  # top 20 for display
    all_results: List[Tuple[str, float]] = field(default_factory=list)  # full reference
    start_time: float = 0.0


async def scan_clean_ips(
    ips: List[str],
    sni: str = "speed.cloudflare.com",
    workers: int = 500,
    timeout: float = 3.0,
    validate: bool = True,
    cs: Optional[CleanScanState] = None,
    ports: Optional[List[int]] = None,
) -> List[Tuple[str, float]]:
    """Scan IPs for TLS + optional CF validation. Returns [(addr, latency_ms)] sorted.
    addr is 'ip' for port 443, or 'ip:port' for other ports."""
    if ports is None:
        ports = [443]
    sem = asyncio.Semaphore(workers)
    results: List[Tuple[str, float]] = []
    lock = asyncio.Lock()

    total_probes = len(ips) * len(ports)
    if cs:
        cs.total = total_probes
        cs.done = 0
        cs.found = 0
        cs.start_time = time.monotonic()

    async def probe(ip: str, port: int):
        if cs and cs.interrupted:
            return
        async with sem:
            if cs and cs.interrupted:
                return
            lat, is_cf, _err = await _tls_probe(ip, sni, timeout, validate, port)
            if lat > 0 and is_cf:
                addr = ip if port == 443 else f"{ip}:{port}"
                async with lock:
                    results.append((addr, lat))
                    if cs:
                        cs.found += 1
                        cs.all_results = results  # full reference for Ctrl+C recovery
                        if cs.found % 10 == 0 or cs.found <= 20:
                            cs.results = sorted(results, key=lambda x: x[1])[:20]
            if cs:
                cs.done += 1

    # Build flat list of (ip, port) pairs
    probes = [(ip, p) for ip in ips for p in ports]
    random.shuffle(probes)  # spread ports across batches for better coverage

    BATCH = 50_000
    for i in range(0, len(probes), BATCH):
        if cs and cs.interrupted:
            break
        batch = probes[i : i + BATCH]
        tasks = [asyncio.ensure_future(probe(ip, port)) for ip, port in batch]
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            break
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

    results.sort(key=lambda x: x[1])
    return results


def load_configs_from_args(args) -> Tuple[List[ConfigEntry], str]:
    """Load configs based on CLI args. Returns (configs, source_label)."""
    if getattr(args, "sub", None):
        configs = fetch_sub(args.sub)
        return configs, args.sub
    if getattr(args, "template", None):
        if not getattr(args, "input", None):
            return [], "ERROR: --template requires -i (address list file)"
        addrs = load_addresses(args.input)
        configs = generate_from_template(args.template, addrs)
        return configs, f"{args.input} ({len(addrs)} addresses)"
    if getattr(args, "input", None):
        configs = load_input(args.input)
        return configs, args.input
    return [], ""


def parse_size(s: str) -> int:
    s = s.strip().upper()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(MB|KB|GB|B)?$", s)
    if not m:
        try:
            return max(1, int(s))
        except ValueError:
            return 1_000_000  # default 1MB
    n = float(m.group(1))
    u = m.group(2) or "B"
    mul = {"B": 1, "KB": 1_000, "MB": 1_000_000, "GB": 1_000_000_000}
    return max(1, int(n * mul.get(u, 1)))


def parse_rounds_str(s: str) -> List[RoundCfg]:
    out = []
    for p in s.split(","):
        p = p.strip()
        if ":" in p:
            sz, top = p.split(":", 1)
            try:
                out.append(RoundCfg(parse_size(sz), int(top)))
            except ValueError:
                pass  # skip malformed round
    return out


def find_config_files() -> List[Tuple[str, str, int]]:
    """Find config files in cwd. Returns [(path, type, count)]."""
    results = []
    for pat in ("*.txt", "*.json", "*.conf", "*.lst"):
        for p in globmod.glob(pat):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(2048)
                count = 0
                json_ok = False
                if head.strip().startswith("{") or head.strip().startswith("["):
                    try:
                        with open(p, encoding="utf-8") as jf:
                            d = json.loads(jf.read())
                        if isinstance(d, dict) and "data" in d:
                            d = d["data"]
                        if isinstance(d, list):
                            count = len(d)
                            results.append((p, "json", count))
                            json_ok = True
                    except Exception:
                        pass
                if not json_ok and ("vless://" in head or "vmess://" in head):
                    with open(p, encoding="utf-8") as f:
                        count = sum(1 for ln in f if ln.strip().startswith(("vless://", "vmess://")))
                    results.append((p, "configs", count))
            except Exception:
                pass
    results.sort(key=lambda x: x[2], reverse=True)
    return results


async def _resolve(e: ConfigEntry, sem: asyncio.Semaphore, counter: List[int]) -> ConfigEntry:
    if e.ip:
        counter[0] += 1
        return e
    async with sem:
        try:
            loop = asyncio.get_running_loop()
            info = await loop.getaddrinfo(e.address, 443, family=socket.AF_INET)
            if info:
                e.ip = info[0][4][0]
        except Exception:
            e.ip = ""
        counter[0] += 1
    return e


async def resolve_all(st: State, workers: int = 100):
    sem = asyncio.Semaphore(workers)
    counter = [0]  # mutable for closure
    total = len(st.configs)

    async def _progress():
        spin = "|/-\\"
        i = 0
        while counter[0] < total:
            s = spin[i % len(spin)]
            pct = counter[0] * 100 // max(1, total)
            _w(f"\r  {A.CYN}{s}{A.RST} Resolving DNS... {counter[0]}/{total}  ({pct}%)  ")
            _fl()
            i += 1
            await asyncio.sleep(0.15)
        _w(f"\r  {A.GRN}OK{A.RST} Resolved {total} domains -> {len(set(c.ip for c in st.configs if c.ip))} unique IPs\n")
        _fl()

    prog_task = asyncio.create_task(_progress())
    try:
        st.configs = list(await asyncio.gather(*[_resolve(c, sem, counter) for c in st.configs]))
    finally:
        prog_task.cancel()
        try:
            await prog_task
        except asyncio.CancelledError:
            pass
    for c in st.configs:
        if c.ip:
            st.ip_map[c.ip].append(c)
    st.ips = list(st.ip_map.keys())
    for ip in st.ips:
        cs = st.ip_map[ip]
        st.res[ip] = Result(
            ip=ip,
            domains=[c.address for c in cs],
            uris=[c.original_uri for c in cs if c.original_uri],
        )


async def _lat_one(ip: str, sni: str, timeout: float) -> Tuple[float, float, str]:
    """Measure TCP RTT and full TLS connection time (TCP+TLS handshake)."""
    try:
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, 443), timeout=timeout
        )
        tcp = (time.monotonic() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
    except asyncio.TimeoutError:
        return -1, -1, "tcp-timeout"
    except Exception as e:
        return -1, -1, f"tcp:{str(e)[:50]}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        tls_full = (time.monotonic() - t0) * 1000  # full TCP+TLS time
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return tcp, tls_full, ""
    except asyncio.TimeoutError:
        return tcp, -1, "tls-timeout"
    except Exception as e:
        return tcp, -1, f"tls:{str(e)[:50]}"


async def phase1(st: State, workers: int, timeout: float):
    st.phase = "latency"
    st.phase_label = "Testing latency"
    st.total = len(st.ips)
    st.done_count = 0
    sem = asyncio.Semaphore(workers)

    async def go(ip: str):
        async with sem:
            if st.interrupted:
                return
            res = st.res[ip]
            # Use speed.cloudflare.com as SNI — filters out non-CF IPs early
            # (non-CF IPs will fail TLS since they don't serve this cert)
            tcp, tls, err = await _lat_one(ip, SPEED_HOST, timeout)
            res.tcp_ms = tcp
            res.tls_ms = tls
            res.error = err
            res.alive = tls > 0
            st.done_count += 1
            if res.alive:
                st.alive_n += 1
            else:
                st.dead_n += 1

    tasks = [asyncio.ensure_future(go(ip)) for ip in st.ips]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


async def _dl_one(
    ip: str, size: int, timeout: float,
    host: str = "", path: str = "",
) -> Tuple[float, float, int, str, str]:
    """Download test. Returns (ttfb_ms, mbps, bytes, colo, error).
    Error "429" means rate-limited — caller should back off."""
    if not host:
        host = SPEED_HOST
    if not path:
        path = f"{SPEED_PATH}?bytes={size}"

    dl_timeout = max(timeout, 30 + (size / 1_000_000) * 2)
    conn_timeout = min(timeout, 15)

    w = None
    total = 0
    dl_start = 0.0
    ttfb = 0.0
    colo = ""

    def _cleanup():
        nonlocal w
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
            w = None

    try:
        ctx = ssl.create_default_context()
        t_start = time.monotonic()
        try:
            t0 = t_start
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=host),
                timeout=conn_timeout,
            )
        except ssl.SSLCertVerificationError:
            _cleanup()
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            t0 = time.monotonic()
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, 443, ssl=ctx2, server_hostname=host
                ),
                timeout=conn_timeout,
            )
        conn_ms = (time.monotonic() - t0) * 1000

        range_hdr = ""
        if "bytes=" not in path:
            range_hdr = f"Range: bytes=0-{size - 1}\r\n"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120\r\n"
            f"Accept: */*\r\n"
            f"{range_hdr}"
            f"Connection: close\r\n\r\n"
        )
        w.write(req.encode())
        await w.drain()

        hbuf = b""
        while b"\r\n\r\n" not in hbuf:
            ch = await asyncio.wait_for(r.read(4096), timeout=min(conn_timeout, 10))
            if not ch:
                _dbg(f"DL {ip} {size}: empty response (no headers)")
                return -1, 0, 0, "", "empty"
            hbuf += ch
            if len(hbuf) > 65536:
                _dbg(f"DL {ip} {size}: header too big")
                return -1, 0, 0, "", "hdr-too-big"

        sep = hbuf.index(b"\r\n\r\n") + 4
        htxt = hbuf[:sep].decode("latin-1", errors="replace")
        body0 = hbuf[sep:]

        status_line = htxt.split("\r\n")[0]
        status_parts = status_line.split(None, 2)
        status_code = status_parts[1] if len(status_parts) >= 2 else ""
        if status_code == "429":
            ra = ""
            for line in htxt.split("\r\n"):
                if line.lower().startswith("retry-after:"):
                    ra = line.split(":", 1)[1].strip()
                    break
            _dbg(f"DL {ip} {size}: 429 rate-limited (retry-after={ra})")
            return -1, 0, 0, "", f"429:{ra}"
        if status_code not in ("200", "206"):
            _dbg(f"DL {ip} {size}: HTTP error: {status_line[:80]}")
            return -1, 0, 0, "", f"http:{status_line[:40]}"

        for line in htxt.split("\r\n"):
            if line.lower().startswith("cf-ray:"):
                ray = line.split(":", 1)[1].strip()
                if "-" in ray:
                    colo = ray.rsplit("-", 1)[-1]
                break

        ttfb = (time.monotonic() - t0) * 1000 - conn_ms
        dl_start = time.monotonic()
        total = len(body0)

        sample_interval = 1_000_000 if size >= 5_000_000 else size + 1
        next_sample = sample_interval
        samples: List[Tuple[int, float]] = []

        min_for_stable = min(size // 2, 20_000_000) if size >= 5_000_000 else size
        min_samples = 5 if size >= 10_000_000 else 3

        while True:
            try:
                elapsed_total = time.monotonic() - t_start
                left = max(1.0, dl_timeout - elapsed_total)
                ch = await asyncio.wait_for(r.read(65536), timeout=min(left, 10))
                if not ch:
                    break
                total += len(ch)
                if total >= next_sample:
                    elapsed = time.monotonic() - dl_start
                    samples.append((total, elapsed))
                    next_sample += sample_interval
                    # only check stability after enough data downloaded
                    if len(samples) >= min_samples and total >= min_for_stable:
                        recent = samples[-4:]
                        sp = []
                        for j in range(1, len(recent)):
                            db = recent[j][0] - recent[j - 1][0]
                            dt = recent[j][1] - recent[j - 1][1]
                            if dt > 0:
                                sp.append(db / dt)
                        if len(sp) >= 2:
                            mn = statistics.mean(sp)
                            if mn > 0:
                                try:
                                    sd = statistics.stdev(sp)
                                    if sd / mn < 0.10:
                                        break
                                except statistics.StatisticsError:
                                    pass
            except asyncio.TimeoutError:
                break
            except Exception:
                break

        dl_t = time.monotonic() - dl_start
        mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
        _dbg(f"DL {ip} {size}: OK {mbps:.2f}MB/s total={total} dt={dl_t:.1f}s host={host}")
        return ttfb, mbps, total, colo, ""

    except asyncio.TimeoutError:
        if total > 0 and dl_start > 0:
            dl_t = time.monotonic() - dl_start
            mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
            _dbg(f"DL {ip} {size}: TIMEOUT partial={total}B mbps={mbps:.2f} dt={dl_t:.1f}s")
            if mbps > 0:
                return ttfb, mbps, total, colo, ""
        _dbg(f"DL {ip} {size}: TIMEOUT no data total={total}")
        return -1, 0, 0, "", "timeout"
    except Exception as e:
        if total > 0 and dl_start > 0:
            dl_t = time.monotonic() - dl_start
            mbps = (total / 1_000_000) / dl_t if dl_t > 0 else 0
            _dbg(f"DL {ip} {size}: ERR partial={total}B mbps={mbps:.2f} err={e}")
            if mbps > 0:
                return ttfb, mbps, total, colo, ""
        _dbg(f"DL {ip} {size}: ERR no data err={e}")
        return -1, 0, 0, "", str(e)[:60]
    finally:
        _cleanup()


async def phase2_round(
    st: State,
    rcfg: RoundCfg,
    candidates: List[str],
    workers: int,
    timeout: float,
    rlim: Optional[CFRateLimiter] = None,
    cdn_host: str = "",
    cdn_path: str = "",
):
    st.total = len(candidates)
    st.done_count = 0
    if rcfg.size >= 50_000_000:
        workers = min(workers, 6)
    elif rcfg.size >= 10_000_000:
        workers = min(workers, 8)
    sem = asyncio.Semaphore(workers)

    max_retries = 2

    async def go(ip: str):
        best_mbps_this = 0.0
        best_ttfb = -1.0
        best_colo = ""
        last_err = ""
        force_cdn = False  # set True when CF rejects (403/429)

        for attempt in range(max_retries):
            if st.interrupted:
                break

            # Pick endpoint: speed.cloudflare.com if budget available, else fallback CDN
            use_host = cdn_host
            use_path = cdn_path
            if force_cdn and CDN_FALLBACK:
                use_host, use_path = CDN_FALLBACK
                _dbg(f"DL {ip}: forced fallback CDN {use_host}")
            elif rlim and rlim.would_block() and CDN_FALLBACK:
                use_host, use_path = CDN_FALLBACK
                _dbg(f"DL {ip}: using fallback CDN {use_host}")
            elif rlim:
                await rlim.acquire(st)

            # acquire sem for the actual download
            await sem.acquire()
            try:
                if st.interrupted:
                    break
                ttfb, mbps, _total, colo, err = await _dl_one(
                    ip, rcfg.size, timeout, host=use_host, path=use_path,
                )
            finally:
                sem.release()  # free slot immediately after download

            if mbps > 0:
                best_mbps_this = mbps
                best_ttfb = ttfb
                best_colo = colo
                break

            # 429 from speed.cloudflare.com: report + force CDN on retry
            if err.startswith("429") and use_host == SPEED_HOST:
                ra_str = err.split(":", 1)[1] if ":" in err else ""
                try:
                    ra = int(ra_str)
                except (ValueError, TypeError):
                    ra = 60
                if rlim:
                    rlim.report_429(ra)
                    _dbg(f"DL {ip}: 429 reported to limiter (retry-after={ra})")
                force_cdn = True
            # 403 from speed.cloudflare.com: CF rejected size, force CDN
            elif err.startswith("http:") and use_host == SPEED_HOST:
                _dbg(f"DL {ip}: {err} from CF, switching to CDN fallback")
                force_cdn = True
            # error from fallback CDN
            elif err.startswith("429") or err.startswith("http:"):
                _dbg(f"DL {ip}: {err} from {use_host}, will retry")
            last_err = err

        res = st.res[ip]
        res.speeds.append(best_mbps_this)
        if best_mbps_this > 0:
            if best_mbps_this > res.best_mbps:
                res.best_mbps = best_mbps_this
            if best_ttfb > 0 and (res.ttfb_ms < 0 or best_ttfb < res.ttfb_ms):
                res.ttfb_ms = best_ttfb
            if best_colo and not res.colo:
                res.colo = best_colo
            if best_mbps_this > st.best_speed:
                st.best_speed = best_mbps_this
        elif last_err:
            res.error = last_err
        st.done_count += 1

    tasks = [asyncio.ensure_future(go(ip)) for ip in candidates]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()


def calc_scores(st: State):
    has_speed = any(r.best_mbps > 0 for r in st.res.values())
    for r in st.res.values():
        if not r.alive:
            r.score = 0
            continue
        lat = max(0, 100 - r.tls_ms / 10) if r.tls_ms > 0 else 0
        spd = min(100, r.best_mbps * 20) if r.best_mbps > 0 else 0
        ttfb = max(0, 100 - r.ttfb_ms / 5) if r.ttfb_ms > 0 else 0
        if r.best_mbps > 0:
            r.score = round(lat * 0.35 + spd * 0.50 + ttfb * 0.15, 1)
        elif has_speed:
            # Speed rounds ran but this IP wasn't tested - rank below tested ones
            r.score = round(lat * 0.35, 1)
        else:
            # No speed rounds at all (latency-only mode)
            r.score = round(lat, 1)


def sorted_alive(st: State, key: str = "score") -> List[Result]:
    alive = [r for r in st.res.values() if r.alive]
    if key == "score":
        alive.sort(key=lambda r: r.score, reverse=True)
    elif key == "latency":
        alive.sort(key=lambda r: r.tls_ms)
    elif key == "speed":
        alive.sort(key=lambda r: r.best_mbps, reverse=True)
    return alive


def sorted_all(st: State, key: str = "score") -> List[Result]:
    """Return all results: alive sorted by key, then dead at the bottom."""
    alive = sorted_alive(st, key)
    dead = [r for r in st.res.values() if not r.alive]
    dead.sort(key=lambda r: r.ip)
    return alive + dead


def draw_menu_header(cols: int) -> List[str]:
    W = cols - 2
    lines = []
    lines.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
    t = f" {A.BOLD}{A.WHT}CF Config Scanner{A.RST} {A.DIM}v{VERSION}{A.RST}"
    lines.append(f"{A.CYN}║{A.RST}" + t + " " * (W - _vl(t)) + f"{A.CYN}║{A.RST}")
    lines.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    return lines


def draw_box_line(content: str, cols: int) -> str:
    W = cols - 2
    vl = _vl(content)
    pad = " " * max(0, W - vl)
    return f"{A.CYN}║{A.RST}{content}{pad}{A.CYN}║{A.RST}"


def draw_box_sep(cols: int) -> str:
    return f"{A.CYN}╠{'═' * (cols - 2)}╣{A.RST}"


def draw_box_bottom(cols: int) -> str:
    return f"{A.CYN}╚{'═' * (cols - 2)}╝{A.RST}"


def _help_show_page(title: str, content: List[str]):
    """Render a scrollable help sub-page. j/k/arrows scroll, b goes back."""
    scroll = 0
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        W = cols - 2
        visible = max(3, rows - 8)
        page = content[scroll:scroll + visible]
        max_scroll = max(0, len(content) - visible)

        out: List[str] = []
        _cpos = f"\033[{W + 2}G"
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        t = f" {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{t}{' ' * max(0, W - _vl(t))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        ttl = f" {A.BOLD}{A.WHT}{title}{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{ttl}{' ' * max(0, W - _vl(ttl))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        for line in page:
            vl = _vl(line)
            out.append(f"{A.CYN}|{A.RST}{line}{' ' * max(0, W - vl)}{_cpos}{A.CYN}|{A.RST}")
        for _ in range(visible - len(page)):
            out.append(f"{A.CYN}|{A.RST}{' ' * W}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        if max_scroll > 0:
            pct = scroll * 100 // max_scroll if max_scroll else 100
            nav = f" {A.DIM}[j/k] Scroll  [{pct}%]  [b] Back{A.RST}"
        else:
            nav = f" {A.DIM}[b] Back to help menu{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{nav}{' ' * max(0, W - _vl(nav))}{_cpos}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()
        key = _read_key_blocking()
        if key in ("q", "esc", "b", "ctrl-c", "h"):
            _w(A.SHOW)
            return
        if key in ("j", "down") and scroll < max_scroll:
            scroll += 1
        elif key in ("k", "up") and scroll > 0:
            scroll -= 1
        elif key in ("n", "pagedown"):
            scroll = min(max_scroll, scroll + visible)
        elif key in ("p", "pageup"):
            scroll = max(0, scroll - visible)


def _help_getting_started() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is cfray?{A.RST}",
        f"   A Cloudflare config scanner, speed tester, and Xray server",
        f"   deployer. Finds the fastest CF edge IPs and the best proxy",
        f"   configurations for your connection.",
        "",
        f" {A.BOLD}{A.CYN}How to launch{A.RST}",
        f"   {A.WHT}Interactive TUI:{A.RST}  python3 scanner.py",
        f"   {A.WHT}Headless mode:{A.RST}    python3 scanner.py -i file.txt --no-tui",
        f"   {A.WHT}Show CLI help:{A.RST}    python3 scanner.py --help",
        "",
        f" {A.BOLD}{A.CYN}Basic workflow{A.RST}",
        f"   {A.WHT}1.{A.RST} Choose an input source from the main menu",
        f"   {A.WHT}2.{A.RST} cfray resolves domains to Cloudflare edge IPs",
        f"   {A.WHT}3.{A.RST} Tests TCP+TLS latency on all IPs (fast filter)",
        f"   {A.WHT}4.{A.RST} Speed tests the top IPs through progressive rounds",
        f"   {A.WHT}5.{A.RST} Results dashboard shows ranked results live",
        f"   {A.WHT}6.{A.RST} Export best configs — ready to use in your client",
        "",
        f" {A.BOLD}{A.CYN}Scoring formula{A.RST}",
        f"   Score = {A.WHT}latency (35%){A.RST} + {A.WHT}speed (50%){A.RST} + {A.WHT}TTFB (15%){A.RST}",
        f"   Higher score = better overall performance (0-100 scale)",
        "",
        f" {A.BOLD}{A.CYN}What gets exported{A.RST}",
        f"   {A.WHT}CSV file:{A.RST}         IP, latency, speed, score, colo, domains",
        f"   {A.WHT}Top N configs:{A.RST}    Best VLESS/VMess URIs ready to import",
        f"   {A.WHT}Full sorted:{A.RST}      ALL alive configs, best to worst",
        f"   Files saved to {A.WHT}results/{A.RST} directory",
        "",
        f" {A.BOLD}{A.CYN}Main menu keys{A.RST}",
        f"   {A.WHT}1-9{A.RST}  Select a local config file",
        f"   {A.WHT} s {A.RST}  Load from subscription URL",
        f"   {A.WHT} p {A.RST}  Enter a custom file path",
        f"   {A.WHT} t {A.RST}  Template + address list mode",
        f"   {A.WHT} f {A.RST}  Find clean Cloudflare IPs",
        f"   {A.WHT} x {A.RST}  Xray pipeline test (fragment + transport)",
        f"   {A.WHT} d {A.RST}  Deploy Xray on a Linux VPS",
        f"   {A.WHT} o {A.RST}  Worker Proxy (fresh workers.dev SNI)",
        f"   {A.WHT} c {A.RST}  Connection Manager",
        f"   {A.WHT} h {A.RST}  This help menu",
        f"   {A.WHT} q {A.RST}  Quit",
        "",
    ]


def _help_scan_modes() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}Local Files (auto-detected){A.RST}",
        f"   Place config files in the directory where you run cfray.",
        f"   Supported formats: {A.WHT}.txt  .json  .conf  .lst{A.RST}",
        f"   They appear automatically in the {A.WHT}LOCAL FILES{A.RST} section.",
        "",
        f"   {A.BOLD}Text files (.txt):{A.RST}",
        f"   One VLESS or VMess URI per line:",
        f"     {A.GRN}vless://uuid@domain:443?type=ws&host=sni.com#name{A.RST}",
        f"     {A.GRN}vmess://base64-encoded-json{A.RST}",
        "",
        f"   {A.BOLD}JSON files (.json):{A.RST}",
        f'   Domain list: {A.GRN}{{"data":[{{"domain":"x.ir","ipv4":"1.2.3.4"}}]}}{A.RST}',
        "",
        f" {A.BOLD}{A.CYN}[P] Enter File Path{A.RST}",
        f"   Load a config file from any location on disk.",
        f"   Type the full path when prompted.",
        f"   {A.GRN}Example:{A.RST} /home/user/configs/my_vless.txt",
        "",
        f" {A.BOLD}{A.CYN}[S] Subscription URL{A.RST}",
        f"   Fetches VLESS/VMess configs from a remote URL.",
        f"   Supports both plain text and base64-encoded content.",
        f"   {A.GRN}Example:{A.RST} https://example.com/sub.txt",
        "",
        f"   {A.BOLD}How to use:{A.RST}",
        f"   1. Press {A.WHT}s{A.RST} in the main menu",
        f"   2. Paste your subscription URL",
        f"   3. cfray fetches and parses the configs automatically",
        "",
        f" {A.BOLD}{A.CYN}[T] Template + Address List{A.RST}",
        f"   Have one working config but want to test many IPs?",
        f"   This mode takes your config and a file of IPs/domains,",
        f"   replaces the address in the config for each one, and",
        f"   tests them all to find the fastest.",
        "",
        f"   {A.BOLD}How to use:{A.RST}",
        f"   1. Press {A.WHT}t{A.RST} in the main menu",
        f"   2. Paste your VLESS/VMess URI (the template)",
        f"   3. Enter path to a .txt file with one IP per line",
        f"   4. cfray generates a config for each IP and scans all",
        "",
        f"   {A.BOLD}CLI equivalent:{A.RST}",
        f"   {A.GRN}python3 scanner.py --template 'vless://...' -i addrs.txt{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}Scan rounds{A.RST}",
        f"   {A.WHT}Quick:{A.RST}     1 round (small download, fast)",
        f"   {A.WHT}Normal:{A.RST}    3 rounds (progressive: small -> large)",
        f"   {A.WHT}Thorough:{A.RST}  5 rounds (most accurate, slower)",
        f"   In each round, bottom performers are eliminated.",
        f"   Survivors move to the next round with a bigger download.",
        "",
    ]


def _help_xray_test() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is Xray Pipeline Test?{A.RST}",
        f"   Tests your config through a {A.WHT}real Xray-core proxy tunnel{A.RST}.",
        f"   Unlike basic scanning, this actually routes traffic through",
        f"   your VPN/proxy — measuring real-world speed and latency.",
        "",
        f"   The pipeline generates variations of your config with",
        f"   different fragment settings and transports, then tests",
        f"   each one to find the best combination.",
        "",
        f" {A.BOLD}{A.CYN}3-Stage Pipeline{A.RST}",
        f"   {A.WHT}Stage 1 — IP Scan:{A.RST}",
        f"     TLS probes on Cloudflare IPs to find live edges",
        f"   {A.WHT}Stage 2 — Base Connectivity:{A.RST}",
        f"     Tests your original config on discovered live IPs",
        f"   {A.WHT}Stage 3 — Expansion:{A.RST}",
        f"     Generates fragment + transport variations on working IPs",
        f"     and speed-tests each one to find the fastest combo",
        "",
        f" {A.BOLD}{A.CYN}[X] Xray Pipeline Test — step by step{A.RST}",
        f"   1. Press {A.WHT}x{A.RST} in the main menu",
        f"   2. Paste your working VLESS/VMess URI",
        f"   3. Choose fragment preset:",
        f"      {A.WHT}none{A.RST}:   no fragmentation",
        f"      {A.WHT}light{A.RST}:  gentle DPI bypass (length 100-200)",
        f"      {A.WHT}medium{A.RST}: moderate bypass (2 settings)",
        f"      {A.WHT}heavy{A.RST}:  aggressive bypass (3 settings)",
        f"      {A.WHT}all{A.RST}:    tests all fragment combos",
        f"   4. Choose IP source (auto CF scan or custom IPs)",
        f"   5. Pipeline runs all 3 stages automatically",
        f"   6. Results ranked by real proxy speed",
        "",
        f" {A.BOLD}{A.CYN}What are fragments?{A.RST}",
        f"   TLS Client Hello fragmentation splits the initial TLS",
        f"   handshake into small pieces. This can bypass DPI (Deep",
        f"   Packet Inspection) that filters traffic based on SNI.",
        "",
        f"   {A.WHT}packets:{A.RST}   tlshello (fragment the Client Hello)",
        f"   {A.WHT}length:{A.RST}    size of each fragment (e.g. 100-200 bytes)",
        f"   {A.WHT}interval:{A.RST}  delay between fragments (e.g. 10-20 ms)",
        "",
        f"   Heavier fragments = more likely to bypass DPI but slower.",
        f"   Let cfray test all presets to find the best one for you.",
        "",
        f" {A.BOLD}{A.CYN}Xray binary{A.RST}",
        f"   Xray-core is auto-installed to {A.WHT}~/.cfray/bin/xray{A.RST}",
        f"   Does NOT touch your system xray installation.",
        f"   Use {A.WHT}--xray-install{A.RST} to force reinstall.",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --xray 'vless://...' --xray-frag all{A.RST}",
        "",
    ]


def _help_clean_finder() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is the Clean IP Finder?{A.RST}",
        f"   Scans Cloudflare's IP ranges to find edge servers that",
        f"   are reachable from your network. These 'clean' IPs can be",
        f"   used as the address in your proxy configs for better",
        f"   performance and reliability.",
        "",
        f" {A.BOLD}{A.CYN}How to use{A.RST}",
        f"   1. Press {A.WHT}f{A.RST} in the main menu",
        f"   2. Pick a scan mode:",
        "",
        f"      {A.WHT}Quick{A.RST}    ~4,000 IPs     (fast, samples each /24)",
        f"      {A.WHT}Normal{A.RST}   ~12,000 IPs    (recommended, good coverage)",
        f"      {A.WHT}Full{A.RST}     ~1.5M IPs      (every IP in CF ranges)",
        f"      {A.WHT}Mega{A.RST}     ~3M tests      (all IPs x ports 443+8443)",
        "",
        f"   3. cfray tests TCP+TLS connectivity to each IP",
        f"   4. Results show reachable IPs sorted by latency",
        f"   5. Save clean IPs to a file, or continue to template scan",
        "",
        f" {A.BOLD}{A.CYN}What happens with the results?{A.RST}",
        f"   After the scan completes, you can:",
        f"   - {A.WHT}Save{A.RST} the clean IPs to a text file",
        f"   - {A.WHT}Use with template{A.RST}: pick a config URI and test each IP",
        f"   - {A.WHT}Use with Xray test{A.RST}: full proxy speed test on clean IPs",
        "",
        f" {A.BOLD}{A.CYN}Custom subnets{A.RST}",
        f"   By default cfray scans all official Cloudflare ranges.",
        f"   You can limit to specific subnets:",
        f"   {A.GRN}python3 scanner.py --find-clean --subnets 104.16.0.0/12{A.RST}",
        f"   Or provide a file with one CIDR per line:",
        f"   {A.GRN}python3 scanner.py --find-clean --subnets subnets.txt{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}Validation{A.RST}",
        f"   cfray verifies each IP actually serves Cloudflare by",
        f"   checking for the {A.WHT}server: cloudflare{A.RST} response header.",
        f"   This filters out non-CF IPs within CF ranges.",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --no-tui{A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --clean-mode mega --no-tui{A.RST}",
        "",
    ]


def _help_deploy() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}[D] Deploy Xray Server{A.RST}",
        f"   Install and configure Xray on a Linux VPS in minutes.",
        f"   Generates a full server config + client URI automatically.",
        "",
        f" {A.BOLD}{A.CYN}How to deploy{A.RST}",
        f"   1. Press {A.WHT}d{A.RST} in the main menu",
        f"   2. Choose protocol: {A.WHT}VLESS{A.RST} or {A.WHT}VMess{A.RST}",
        f"   3. Choose transport: {A.WHT}TCP{A.RST}, {A.WHT}WebSocket{A.RST}, {A.WHT}gRPC{A.RST}, {A.WHT}H2{A.RST}, or {A.WHT}XHTTP{A.RST}",
        f"   4. Choose security:",
        f"      {A.WHT}REALITY{A.RST}  Best for censored networks (no domain needed)",
        f"      {A.WHT}TLS{A.RST}      Standard TLS (needs domain + certificate)",
        f"      {A.WHT}None{A.RST}     No encryption (not recommended)",
        f"   5. cfray installs Xray, generates UUID + keys",
        f"   6. Outputs a ready-to-use client URI — just copy it!",
        "",
        f" {A.BOLD}{A.CYN}Multiple configs{A.RST}",
        f"   After creating the first config, the wizard asks if you",
        f"   want to add another. This lets you deploy e.g.:",
        f"   - {A.WHT}TCP + REALITY{A.RST} on port 443 (direct, fast)",
        f"   - {A.WHT}WS + TLS{A.RST} on port 444 (CDN-compatible)",
        f"   REALITY keys and TLS certs are reused across configs.",
        "",
        f" {A.BOLD}{A.CYN}Requirements{A.RST}",
        f"   - Linux VPS (Ubuntu/Debian/CentOS/Fedora)",
        f"   - Run as {A.WHT}root{A.RST}",
        f"   - Port 443 open (or your chosen port)",
        "",
        f" {A.BOLD}{A.CYN}[C] Connection Manager{A.RST}",
        f"   After deploying, use the Connection Manager to manage",
        f"   your server's inbounds and users.",
        "",
        f"   {A.BOLD}Keys:{A.RST}",
        f"   {A.WHT}A{A.RST}  Add a new inbound (new protocol/port)",
        f"   {A.WHT}U{A.RST}  Add a user to an existing inbound",
        f"   {A.WHT}S{A.RST}  Show all client URIs",
        f"   {A.WHT}V{A.RST}  View inbound details (config JSON)",
        f"   {A.WHT}X{A.RST}  Delete an inbound",
        f"   {A.WHT}R{A.RST}  Restart Xray service",
        f"   {A.WHT}L{A.RST}  View Xray logs",
        f"   {A.WHT}D{A.RST}  Uninstall Xray completely",
        f"   {A.WHT}B{A.RST}  Back to main menu",
        "",
        f" {A.BOLD}{A.CYN}CLI equivalent{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-security reality{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-protocol vmess \\{A.RST}",
        f"   {A.GRN}  --deploy-transport ws --deploy-security tls{A.RST}",
        "",
    ]


def _help_worker_proxy() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}What is Worker Proxy?{A.RST}",
        f"   Creates a Cloudflare Worker that proxies your traffic,",
        f"   giving your VLESS config a fresh {A.WHT}*.workers.dev{A.RST} SNI.",
        "",
        f"   This is useful when your current SNI is blocked or slow.",
        f"   The Worker acts as a middleman on Cloudflare's CDN,",
        f"   routing traffic to your origin through a new hostname.",
        "",
        f" {A.BOLD}{A.CYN}How to use{A.RST}",
        f"   1. Press {A.WHT}o{A.RST} in the main menu",
        f"   2. Paste your VLESS URI (must use {A.WHT}WebSocket{A.RST} transport)",
        f"   3. cfray generates a Worker script (JavaScript)",
        f"   4. Deploy it on {A.WHT}dash.cloudflare.com{A.RST} -> Workers & Pages",
        f"   5. Enter your Worker URL (e.g. {A.WHT}my-proxy.user.workers.dev{A.RST})",
        f"   6. cfray builds a new URI with the Worker as address/SNI",
        f"   7. Optionally run a pipeline test on the new config",
        "",
        f" {A.BOLD}{A.CYN}Requirements{A.RST}",
        f"   - Your config must use {A.WHT}WebSocket (ws){A.RST} transport",
        f"   - Free Cloudflare account (100K requests/day free tier)",
        f"   - TCP, gRPC, H2 transports are NOT supported by Workers",
        "",
        f" {A.BOLD}{A.CYN}How it works{A.RST}",
        f"   {A.WHT}Client{A.RST} -> {A.CYN}CF Worker{A.RST} -> {A.WHT}Origin server{A.RST}",
        f"   The Worker receives your WebSocket connection and forwards",
        f"   it to your origin, setting the correct Host header.",
        f"   Your ISP only sees a connection to {A.WHT}*.workers.dev{A.RST}.",
        "",
    ]


def _help_cli_reference() -> List[str]:
    return [
        "",
        f" {A.BOLD}{A.CYN}Input options{A.RST}",
        f"   {A.WHT}-i, --input FILE{A.RST}     Input file (VLESS URIs or domains.json)",
        f"   {A.WHT}--sub URL{A.RST}             Subscription URL (fetches configs)",
        f"   {A.WHT}--template URI{A.RST}        Base VLESS/VMess URI (use with -i)",
        "",
        f" {A.BOLD}{A.CYN}Scan settings{A.RST}",
        f"   {A.WHT}-m, --mode MODE{A.RST}      quick / normal / thorough",
        f"   {A.WHT}--rounds SPEC{A.RST}         Custom, e.g. '1MB:200,5MB:50,20MB:20'",
        f"   {A.WHT}-w, --workers N{A.RST}      Latency workers (default: 300)",
        f"   {A.WHT}--speed-workers N{A.RST}     Download workers (default: 10)",
        f"   {A.WHT}--timeout SEC{A.RST}         Latency timeout (default: 3)",
        f"   {A.WHT}--speed-timeout SEC{A.RST}   Download timeout (default: 10)",
        f"   {A.WHT}--skip-download{A.RST}       Latency only, no speed test",
        "",
        f" {A.BOLD}{A.CYN}Output options{A.RST}",
        f"   {A.WHT}--top N{A.RST}              Export top N configs (0 = all)",
        f"   {A.WHT}--no-tui{A.RST}             Headless mode (plain text output)",
        f"   {A.WHT}-o, --output FILE{A.RST}    CSV output path",
        f"   {A.WHT}--output-configs FILE{A.RST} Save top URIs to file",
        "",
        f" {A.BOLD}{A.CYN}Clean IP Finder{A.RST}",
        f"   {A.WHT}--find-clean{A.RST}         Find clean Cloudflare IPs",
        f"   {A.WHT}--clean-mode MODE{A.RST}    quick / normal / full / mega",
        f"   {A.WHT}--subnets CIDRS{A.RST}      Custom subnets (file or comma-sep)",
        "",
        f" {A.BOLD}{A.CYN}Xray Pipeline Test{A.RST}",
        f"   {A.WHT}--xray URI{A.RST}           VLESS/VMess URI to test",
        f"   {A.WHT}--xray-frag PRESET{A.RST}   none / light / medium / heavy / all",
        f"   {A.WHT}--xray-bin PATH{A.RST}      Path to Xray binary",
        f"   {A.WHT}--xray-install{A.RST}       Force install Xray binary",
        f"   {A.WHT}--xray-keep N{A.RST}        Keep top N results (default: 10)",
        "",
        f" {A.BOLD}{A.CYN}Deploy{A.RST}",
        f"   {A.WHT}--deploy{A.RST}             Deploy Xray on this server",
        f"   {A.WHT}--deploy-port N{A.RST}      Port (default: 443)",
        f"   {A.WHT}--deploy-protocol P{A.RST}  vless / vmess",
        f"   {A.WHT}--deploy-transport T{A.RST} tcp / ws / grpc / h2",
        f"   {A.WHT}--deploy-security S{A.RST}  reality / tls / none",
        f"   {A.WHT}--deploy-sni DOMAIN{A.RST}  SNI domain for REALITY/TLS",
        f"   {A.WHT}--deploy-cert PATH{A.RST}   TLS certificate file",
        f"   {A.WHT}--deploy-key PATH{A.RST}    TLS private key file",
        f"   {A.WHT}--deploy-ip IP{A.RST}       Server IP (auto-detected)",
        f"   {A.WHT}--uninstall{A.RST}          Remove everything cfray installed",
        "",
        f" {A.BOLD}{A.CYN}Examples{A.RST}",
        "",
        f"   {A.DIM}# Scan a config file (headless){A.RST}",
        f"   {A.GRN}python3 scanner.py -i configs.txt --no-tui{A.RST}",
        "",
        f"   {A.DIM}# Subscription URL, export top 20{A.RST}",
        f"   {A.GRN}python3 scanner.py --sub https://example.com/sub --top 20{A.RST}",
        "",
        f"   {A.DIM}# Template scan: one config, many IPs{A.RST}",
        f"   {A.GRN}python3 scanner.py --template 'vless://...' -i ips.txt{A.RST}",
        "",
        f"   {A.DIM}# Xray test with all fragment presets{A.RST}",
        f"   {A.GRN}python3 scanner.py --xray 'vless://...' --xray-frag all{A.RST}",
        "",
        f"   {A.DIM}# Find clean IPs (mega mode, headless){A.RST}",
        f"   {A.GRN}python3 scanner.py --find-clean --clean-mode mega --no-tui{A.RST}",
        "",
        f"   {A.DIM}# Deploy VLESS + REALITY on port 443{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-security reality{A.RST}",
        "",
        f"   {A.DIM}# Deploy VMess + WebSocket + TLS{A.RST}",
        f"   {A.GRN}python3 scanner.py --deploy --deploy-protocol vmess \\{A.RST}",
        f"   {A.GRN}  --deploy-transport ws --deploy-security tls{A.RST}",
        "",
    ]


def tui_show_guide():
    """Multi-page help system. Shows topic hub, dispatches to sub-pages."""
    pages = [
        ("Getting Started",            "First steps, basic workflow, scoring",     _help_getting_started),
        ("Scan & Test Modes",          "File scan, subscription, template",        _help_scan_modes),
        ("Xray Pipeline Test",         "Fragment + transport pipeline testing",    _help_xray_test),
        ("Clean IP Finder",            "Find reachable Cloudflare edge IPs",      _help_clean_finder),
        ("Deploy & Server Management", "Install Xray on VPS, manage connections", _help_deploy),
        ("Worker Proxy",               "Fresh workers.dev SNI for any config",    _help_worker_proxy),
        ("CLI Reference",              "All command-line flags and examples",      _help_cli_reference),
    ]
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        W = cols - 2

        out: List[str] = []
        _cpos = f"\033[{W + 2}G"
        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}|{A.RST}{c}{pad}{_cpos}{A.CYN}|{A.RST}")

        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        t = f" {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        bx(t)
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        bx(f" {A.BOLD}{A.WHT}Help & Guide{A.RST}")
        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")
        bx("")

        icons = ["🚀", "📡", "⚡", "🔍", "🛠", "☁", "💻"]
        for i, (title, desc, _) in enumerate(pages):
            num = f"  {A.CYN}{A.BOLD}{i + 1}{A.RST}"
            bx(f"{num}.  {icons[i]} {A.BOLD}{A.WHT}{title}{A.RST}")
            bx(f"      {A.DIM}{desc}{A.RST}")
            bx("")

        bx(f" {A.DIM}{'─' * (W - 2)}{A.RST}")
        bx(f" {A.DIM}[1-{len(pages)}] Open topic    [q] Back to menu{A.RST}")
        bx("")
        bx(f" {A.BOLD}{A.WHT}Made By Sam — SamNet Technologies{A.RST}")
        bx(f" {A.DIM}https://github.com/SamNet-dev/cfray{A.RST}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()
        key = _read_key_blocking()
        if key in ("q", "b", "esc", "ctrl-c"):
            _w(A.SHOW)
            return
        if key.isdigit() and 1 <= int(key) <= len(pages):
            title, _, fn = pages[int(key) - 1]
            _help_show_page(title, fn())
            continue


def _clean_pick_mode() -> Optional[str]:
    """Pick scan scope for clean IP finder. Returns mode or None/'__back__'."""
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Find Clean Cloudflare IPs{A.RST}", cols))
        lines.append(draw_box_line(f" {A.DIM}Scans Cloudflare IP ranges to find reachable edge IPs{A.RST}", cols))
        lines.append(draw_box_line("", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.BOLD}Select scan scope:{A.RST}", cols))
        lines.append(draw_box_line("", cols))

        for name, key in [("quick", "1"), ("normal", "2"), ("full", "3"), ("mega", "4")]:
            cfg = CLEAN_MODES[name]
            num = f"{A.CYN}{A.BOLD}{key}{A.RST}"
            lbl = f"{A.BOLD}{cfg['label']}{A.RST}"
            if name == "normal":
                lbl += f" {A.GRN}(recommended){A.RST}"
            lines.append(draw_box_line(f"   {num}  {lbl}", cols))
            desc = cfg["desc"]
            if len(cfg.get("ports", [])) > 1:
                desc += f"  (ports: {', '.join(str(p) for p in cfg['ports'])})"
            lines.append(draw_box_line(f"      {A.DIM}{desc}{A.RST}", cols))
            lines.append(draw_box_line("", cols))

        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}[1-4] Select   [B] Back   [Q] Quit{A.RST}", cols))
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c"):
            return None
        if key in ("b", "esc"):
            return "__back__"
        if key == "1":
            return "quick"
        if key == "2" or key == "enter":
            return "normal"
        if key == "3":
            return "full"
        if key == "4":
            return "mega"


def _draw_clean_progress(cs: CleanScanState):
    """Draw live progress screen for clean IP scan."""
    cols, rows = term_size()
    W = cols - 2
    out: List[str] = []

    def bx(c: str):
        out.append(f"{A.CYN}║{A.RST}" + c + " " * max(0, W - _vl(c)) + f"{A.CYN}║{A.RST}")

    out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
    elapsed = _fmt_elapsed(time.monotonic() - cs.start_time) if cs.start_time else "0s"
    title = f" {A.BOLD}{A.WHT}Finding Clean Cloudflare IPs{A.RST}"
    right = f"{A.DIM}{elapsed}  |  ^C stop{A.RST}"
    bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

    pct = cs.done * 100 // max(1, cs.total)
    bw = max(1, min(30, W - 40))
    filled = int(bw * pct / 100)
    bar = f"{A.GRN}{'█' * filled}{A.DIM}{'░' * (bw - filled)}{A.RST}"
    bx(f" Probing [{bar}] {cs.done:,}/{cs.total:,}  {pct}%")

    found_line = f" {A.GRN}Found: {cs.found:,} clean IPs{A.RST}"
    if cs.results:
        best_lat = cs.results[0][1]
        found_line += f"   {A.DIM}Best: {best_lat:.0f}ms{A.RST}"
    bx(found_line)

    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    bx(f" {A.BOLD}Top IPs found (by latency):{A.RST}")

    vis = min(15, rows - 12)
    if cs.results:
        for i, (ip, lat) in enumerate(cs.results[:vis]):
            bx(f"   {A.CYN}{i+1:>3}.{A.RST} {ip:<22} {A.GRN}{lat:>6.0f}ms{A.RST}")
    else:
        bx(f"   {A.DIM}Scanning...{A.RST}")

    # Fill remaining space
    used = len(cs.results[:vis]) if cs.results else 1
    for _ in range(vis - used):
        bx("")

    out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
    bx(f" {A.DIM}Press Ctrl+C to stop early and show results{A.RST}")
    out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

    _w(A.HOME)
    _w("\n".join(out) + "\n")
    _fl()


def _clean_show_results(results: List[Tuple[str, float]], elapsed: str) -> Optional[str]:
    """Show clean IP results with j/k scrolling. Returns action string or None."""
    MAX_SHOW = 300
    display = results[:MAX_SHOW]
    offset = 0

    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        lines = draw_menu_header(cols)

        if results:
            lines.append(draw_box_line(
                f" {A.BOLD}{A.GRN}Scan Complete!{A.RST}  "
                f"Found {A.BOLD}{len(results):,}{A.RST} clean IPs in {elapsed}", cols))
        else:
            lines.append(draw_box_line(f" {A.YEL}Scan Complete — no clean IPs found.{A.RST}", cols))
        lines.append(draw_box_sep(cols))

        if display:
            # header + separator = 2 rows, footer area = 5 rows, menu header = 3 rows
            vis = max(5, rows - 13)
            end = min(len(display), offset + vis)

            hdr = f" {A.BOLD}{'#':>4}  {'Address':<22} {'Latency':>8}{A.RST}"
            if len(display) > vis:
                pos = f"{A.DIM}[{offset+1}-{end} of {len(display)}"
                if len(results) > MAX_SHOW:
                    pos += f", {len(results):,} total"
                pos += f"]{A.RST}"
                hdr += " " * max(1, cols - 2 - _vl(hdr) - _vl(pos) - 1) + pos
            lines.append(draw_box_line(hdr, cols))
            lines.append(draw_box_line(
                f" {A.DIM}{'─'*4}  {'─'*22} {'─'*8}{A.RST}", cols))

            for i in range(offset, end):
                ip, lat = display[i]
                lines.append(draw_box_line(
                    f" {i+1:>4}  {ip:<22} {A.GRN}{lat:>6.0f}ms{A.RST}", cols))

        lines.append(draw_box_line("", cols))
        lines.append(draw_box_sep(cols))
        ft = ""
        if results:
            ft += f" {A.CYN}[S]{A.RST} Save all  {A.CYN}[T]{A.RST} Template+SpeedTest  "
        ft += f" {A.CYN}[B]{A.RST} Back"
        lines.append(draw_box_line(ft, cols))
        if display and len(display) > vis:
            lines.append(draw_box_line(
                f" {A.DIM}j/↓ down  k/↑ up  n/p page down/up{A.RST}", cols))
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("b", "esc", "q", "ctrl-c"):
            return "back"
        if key in ("j", "down"):
            vis = max(5, rows - 13)
            offset = min(offset + 1, max(0, len(display) - vis))
            continue
        if key in ("k", "up"):
            offset = max(0, offset - 1)
            continue
        if key == "n":
            vis = max(5, rows - 13)
            offset = min(offset + vis, max(0, len(display) - vis))
            continue
        if key == "p":
            vis = max(5, rows - 13)
            offset = max(0, offset - vis)
            continue
        if key == "s" and results:
            return "save"
        if key == "t" and results:
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Speed Test with Clean IPs{A.RST}\n")
            _w(f" {A.DIM}Paste a VLESS/VMess config URI. The address in it will be{A.RST}\n")
            _w(f" {A.DIM}replaced with each clean IP, then all configs get speed-tested.{A.RST}\n\n")
            _w(f" {A.CYN}Template:{A.RST} ")
            _fl()
            try:
                tpl = input().strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not tpl or not parse_config(tpl):
                _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            return f"template:{tpl}"


async def tui_run_clean_finder() -> Optional[Tuple[str, str]]:
    """Run the clean IP finder flow. Returns (input_method, input_value) or None."""

    mode = _clean_pick_mode()
    if mode is None:
        return None
    if mode == "__back__":
        return ("__back__", "")

    scan_cfg = CLEAN_MODES[mode]

    # Generate IPs
    _w(A.CLR + A.HOME)
    cols, _ = term_size()
    lines = draw_menu_header(cols)
    lines.append(draw_box_line(
        f" {A.BOLD}Generating IPs from {len(CF_SUBNETS)} Cloudflare ranges...{A.RST}", cols))
    lines.append(draw_box_bottom(cols))
    _w("\n".join(lines) + "\n")
    _fl()

    ips = generate_cf_ips(CF_SUBNETS, scan_cfg["sample"])
    ports = scan_cfg.get("ports", [443])
    _dbg(f"CLEAN: Generated {len(ips):,} IPs × {len(ports)} port(s), sample={scan_cfg['sample']}")

    # Run scan with live progress
    cs = CleanScanState()
    scan_task = asyncio.ensure_future(
        scan_clean_ips(
            ips, workers=scan_cfg["workers"], timeout=5.0,
            validate=scan_cfg["validate"], cs=cs, ports=ports,
        )
    )

    old_sigint = signal.getsignal(signal.SIGINT)
    _loop = asyncio.get_running_loop()
    def _sig(sig, frame):
        cs.interrupted = True
        _loop.call_soon_threadsafe(scan_task.cancel)
    signal.signal(signal.SIGINT, _sig)

    _w(A.CLR + A.HIDE)
    try:
        while not scan_task.done():
            _draw_clean_progress(cs)
            await asyncio.sleep(0.3)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        _dbg(f"CLEAN: progress loop error: {e}")
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    try:
        results = await scan_task
    except asyncio.CancelledError:
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])
    except Exception as e:
        _dbg(f"CLEAN: scan_task error: {e}")
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])

    elapsed = _fmt_elapsed(time.monotonic() - cs.start_time) if cs.start_time > 0 else "0s"
    _dbg(f"CLEAN: Done in {elapsed}. Found {len(results):,} / {len(ips):,}")

    # Show results and get user action
    action = _clean_show_results(results, elapsed)

    if action is None or action == "back":
        return ("__back__", "")

    if action == "save":
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = os.path.abspath(_results_path("clean_ips.txt"))
            with open(path, "w", encoding="utf-8") as f:
                for ip, lat in results:
                    f.write(f"{ip}\n")
            _w(f"\n {A.GRN}Saved {len(results):,} IPs to {path}{A.RST}\n")
        except Exception as e:
            _w(f"\n {A.RED}Save error: {e}{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _wait_any_key()
        return ("__back__", "")

    if action.startswith("template:"):
        template_uri = action[9:]
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = os.path.abspath(_results_path("clean_ips.txt"))
            with open(path, "w", encoding="utf-8") as f:
                for ip, lat in results:
                    f.write(f"{ip}\n")
        except Exception as e:
            _w(f"\n {A.RED}Save error: {e}{A.RST}\n")
            _fl()
            time.sleep(2)
            return ("__back__", "")
        return ("template", f"{template_uri}|||{path}")

    return None


def _tui_prompt_text(label: str) -> Optional[str]:
    """Show cursor, prompt for text input, return stripped text or None."""
    _w(A.SHOW)
    _w(f"\n {A.CYN}{label}{A.RST} ")
    _fl()
    try:
        val = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return val if val else None


def tui_pick_file() -> Optional[Tuple[str, str]]:
    """Interactive file/input picker. Returns (method, value) or None.
    method is one of: 'file', 'sub', 'template'.
    For 'file': value is the file path.
    For 'sub': value is the subscription URL.
    For 'template': value is 'template_uri|||address_file_path'.
    """
    enable_ansi()
    files = find_config_files()

    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, rows = term_size()
        W = cols - 2

        out: List[str] = []
        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}║{A.RST}{c}{pad}\033[{W + 2}G{A.CYN}║{A.RST}")

        # Single clean box — no internal double-line separators
        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        title = f" ⚡ {A.BOLD}{A.WHT}cfray{A.RST} {A.DIM}v{VERSION}{A.RST}"
        subtitle = f"{A.DIM}Cloudflare Config Scanner{A.RST}"
        bx(title + "  " + subtitle)
        bx("")

        # Section: Local Files
        bx(f" {A.DIM}── {A.BOLD}{A.WHT}📁 LOCAL FILES{A.RST} {A.DIM}{'─' * max(1, W - 19)}{A.RST}")
        if files:
            for i, (path, ftype, count) in enumerate(files[:9]):
                num = f" {A.CYN}{A.BOLD}{i + 1}{A.RST}."
                name = os.path.basename(path)
                desc = f"{A.DIM}{ftype}, {count} entries{A.RST}"
                bx(f" {num}  📄 {name:<28} {desc}")
        else:
            bx(f"    {A.DIM}No config files found in current directory{A.RST}")
            bx(f"    {A.DIM}Drop .txt or .json files here, or use options below{A.RST}")
        bx("")

        # Section: Remote Sources
        bx(f" {A.DIM}── {A.BOLD}{A.WHT}🌐 REMOTE SOURCES{A.RST} {A.DIM}{'─' * max(1, W - 22)}{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}s{A.RST}.  🔗 {A.WHT}Subscription URL{A.RST}        {A.DIM}Fetch configs from remote URL{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}p{A.RST}.  📂 {A.WHT}Enter File Path{A.RST}         {A.DIM}Load from custom file path{A.RST}")
        bx("")

        # Section: Tools
        bx(f" {A.DIM}── {A.BOLD}{A.WHT}🔧 TOOLS{A.RST} {A.DIM}{'─' * max(1, W - 13)}{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}t{A.RST}.  🧩 {A.WHT}Template + Addresses{A.RST}    {A.DIM}Test one config against many IPs{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}f{A.RST}.  🔍 {A.WHT}Clean IP Finder{A.RST}         {A.DIM}Scan Cloudflare IP ranges{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}x{A.RST}.  ⚡ {A.WHT}Xray Pipeline Test{A.RST}    {A.DIM}Smart: probe → validate → expand → speed{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}d{A.RST}.  🚀 {A.WHT}Deploy Xray Server{A.RST}    {A.DIM}Install Xray on Linux VPS{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}o{A.RST}.  ☁  {A.WHT}Worker Proxy{A.RST}          {A.DIM}Fresh workers.dev SNI for any VLESS config{A.RST}")
        bx(f"  {A.CYN}{A.BOLD}c{A.RST}.  🔧 {A.WHT}Connection Manager{A.RST}    {A.DIM}Manage existing Xray server configs{A.RST}")
        bx("")
        bx(f" {A.DIM}{'─' * (W - 2)}{A.RST}")
        bx(f" {A.DIM}[h] ❓ Help    [q] 🚪 Quit{A.RST}")
        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c", "esc"):
            _w(A.SHOW)
            _fl()
            return None
        if key == "h":
            tui_show_guide()
            files = find_config_files()
            continue
        if key == "p":
            path = _tui_prompt_text("Enter file path:")
            if path is None:
                continue
            if os.path.isfile(path):
                return ("file", path)
            _w(f" {A.RED}File not found.{A.RST}\n")
            _fl()
            time.sleep(1)
            continue
        if key == "s":
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Subscription URL{A.RST}\n")
            _w(f" {A.DIM}Paste a URL that contains VLESS/VMess configs (plain text or base64).{A.RST}\n")
            _w(f" {A.DIM}Example: https://example.com/sub.txt{A.RST}\n\n")
            _fl()
            url = _tui_prompt_text("URL:")
            if url is None:
                continue
            if not url.lower().startswith(("http://", "https://")):
                _w(f" {A.RED}URL must start with http:// or https://{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            return ("sub", url)
        if key == "t":
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Template + Address List{A.RST}\n")
            _w(f" {A.DIM}This mode takes ONE working config and a list of Cloudflare IPs/domains.{A.RST}\n")
            _w(f" {A.DIM}It replaces the address in your config with each IP from the list,{A.RST}\n")
            _w(f" {A.DIM}then tests all of them to find the fastest.{A.RST}\n\n")
            _w(f" {A.BOLD}Step 1:{A.RST} {A.CYN}Paste your VLESS/VMess config URI:{A.RST}\n")
            _w(f" {A.DIM}(a full vless://... or vmess://... URI){A.RST}\n ")
            _fl()
            try:
                tpl = input().strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not tpl or not parse_config(tpl):
                _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
                _fl()
                time.sleep(1.5)
                continue
            _w(f"\n {A.BOLD}Step 2:{A.RST} {A.CYN}Enter path to address list file:{A.RST}\n")
            _w(f" {A.DIM}(a .txt file with one IP or domain per line){A.RST}\n")
            _fl()
            addr_path = _tui_prompt_text("Path:")
            if addr_path is None:
                continue
            if not os.path.isfile(addr_path):
                _w(f" {A.RED}File not found.{A.RST}\n")
                _fl()
                time.sleep(1)
                continue
            return ("template", f"{tpl}|||{addr_path}")
        if key == "f":
            return ("find_clean", "")
        if key == "x":
            return ("pipeline", "")
        if key == "d":
            return ("deploy", "")
        if key == "o":
            return ("worker_proxy", "")
        if key == "c":
            return ("connection_manager", "")
        if key.isdigit() and 1 <= int(key) <= len(files):
            return ("file", files[int(key) - 1][0])


def tui_pick_mode() -> Optional[str]:
    """Interactive mode picker. Returns mode name or None."""
    while True:
        _w(A.CLR + A.HOME + A.HIDE)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Select scan mode:{A.RST}", cols))
        lines.append(draw_box_line("", cols))

        modes = [("quick", "1"), ("normal", "2"), ("thorough", "3")]
        for name, key in modes:
            p = PRESETS[name]
            num = f"{A.CYN}{A.BOLD}{key}{A.RST}"
            lbl = f"{A.BOLD}{p['label']}{A.RST}"
            if name == "normal":
                lbl += f" {A.GRN}(recommended){A.RST}"
            lines.append(draw_box_line(f"   {num}  {lbl}", cols))
            lines.append(
                draw_box_line(f"      {A.DIM}{p['desc']}{A.RST}", cols)
            )
            lines.append(
                draw_box_line(
                    f"      {A.DIM}Data: {p['data']}  |  Est. time: {p['time']}{A.RST}",
                    cols,
                )
            )
            lines.append(draw_box_line("", cols))

        lines.append(draw_box_sep(cols))
        lines.append(
            draw_box_line(
                f" {A.DIM}[1-3] Select   [B] Back   [Q] Quit{A.RST}", cols
            )
        )
        lines.append(draw_box_bottom(cols))

        _w("\n".join(lines) + "\n")
        _fl()

        key = _read_key_blocking()
        if key in ("q", "ctrl-c"):
            _w(A.SHOW)
            _fl()
            return None
        if key == "b":
            return "__back__"
        if key == "1":
            return "quick"
        if key == "2" or key == "enter":
            return "normal"
        if key == "3":
            return "thorough"


class XrayDashboard:
    """TUI dashboard for xray proxy test progress."""

    def __init__(self, xst: XrayTestState):
        self.xst = xst
        self.sort = "score"
        self.offset = 0

    def _bar(self, cur: int, tot: int, w: int = 24) -> str:
        if tot == 0:
            return "░" * w
        p = min(1.0, cur / tot)
        f = int(w * p)
        return f"{A.GRN}{'█' * f}{A.DIM}{'░' * (w - f)}{A.RST}"

    def draw(self):
        cols, rows = term_size()
        W = cols - 2
        xst = self.xst

        # Live-score alive variations that don't have a score yet
        for _v in xst.variations:
            if _v.alive and _v.score == 0 and _v.connect_ms > 0:
                cms = _v.connect_ms if _v.connect_ms >= 0 else 1000
                tms = _v.ttfb_ms if _v.ttfb_ms >= 0 else 1000
                _lat = max(0.0, 100.0 - cms / 10.0)
                _ttfb = max(0.0, 100.0 - tms / 5.0)
                if _v.native_tested or _v.speed_mbps < 0.01:
                    _v.score = round(_lat * 0.55 + _ttfb * 0.45, 1)
                else:
                    _spd = min(100.0, _v.speed_mbps * 20.0)
                    _v.score = round(_lat * 0.35 + _spd * 0.50 + _ttfb * 0.15, 1)

        out: List[str] = []

        def bx(c: str):
            pad = " " * max(0, W - _vl(c))
            out.append(f"{A.CYN}║{A.RST}{c}{pad}\033[{W + 2}G{A.CYN}║{A.RST}")

        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        elapsed = _fmt_elapsed(time.monotonic() - xst.start_time) if xst.start_time else "0s"
        _pipeline = getattr(xst, 'pipeline_mode', False)
        title = f" {A.BOLD}{A.WHT}Xray Pipeline Test{A.RST}" if _pipeline else f" {A.BOLD}{A.WHT}Xray Proxy Test{A.RST}"
        right = f"{A.DIM}{elapsed}  |  ^C stop{A.RST}"
        bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        src = xst.source_uri[:60] + "..." if len(xst.source_uri) > 60 else xst.source_uri
        bx(f" {A.DIM}Config:{A.RST} {src}")
        bx(f" {A.DIM}Variations:{A.RST} {len(xst.variations)}  "
           f"{A.GRN}{xst.alive_count} alive{A.RST}  "
           f"{A.RED}{xst.dead_count} dead{A.RST}")
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        bw = max(1, min(24, W - 50))
        _is_pipeline = getattr(xst, 'pipeline_mode', False)

        if _is_pipeline:
            # 3-stage pipeline display
            stage_stats = {
                "ip_scan": f"{len(xst.live_ips)} CF confirmed" if xst.live_ips else "",
                "base_test": (f"{len(xst.working_ips)} working" if xst.working_ips
                              else f"0 working" if xst.pipeline_stages[1]["status"] in ("done", "interrupted")
                              else ""),
                "expansion": (f"{xst.quick_passed} alive" if xst.quick_passed
                              else f"{xst.alive_count} alive" if xst.alive_count
                              else f"0 alive" if xst.pipeline_stages[2]["status"] in ("done", "interrupted")
                              else ""),
            }
            for i, stage in enumerate(xst.pipeline_stages):
                st = stage["status"]
                label = f"{stage['label']:<18}"
                stat = stage_stats.get(stage["name"], "")
                if st == "done":
                    stat_color = A.RED if stat.startswith("0 ") else A.GRN
                    bx(f" {A.GRN}v{A.RST} {label} {stat_color}{stat}{A.RST}")
                elif st == "active":
                    pct = xst.done_count * 100 // max(1, xst.total) if xst.total > 0 else 0
                    bx(f" {A.GRN}>{A.RST} {A.BOLD}{label}{A.RST}"
                       f"[{self._bar(xst.done_count, xst.total, bw)}] "
                       f"{xst.done_count}/{xst.total}  {pct}%")
                elif st == "interrupted":
                    bx(f" {A.YEL}!{A.RST} {label} {A.YEL}interrupted{A.RST}")
                else:
                    bx(f" {A.DIM}o {label} waiting...{A.RST}")
            # Show pre-flight warning if present
            _pf_warn = getattr(xst, 'preflight_warning', '')
            if _pf_warn:
                _pf_text = _pf_warn[:W - 6] if len(_pf_warn) > W - 6 else _pf_warn
                bx(f" {A.YEL}! {_pf_text}{A.RST}")
        elif xst.finished and xst.interrupted:
            if xst.phase == "quick_filter":
                bx(f" {A.YEL}!{A.RST} Quick Filter   {A.YEL}interrupted ({xst.alive_count} passed){A.RST}")
            elif xst.phase == "speed_test":
                qp = xst.quick_passed or xst.alive_count
                bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
                bx(f" {A.YEL}!{A.RST} Speed Test     {A.YEL}interrupted{A.RST}")
            else:
                bx(f" {A.YEL}!{A.RST} Quick Filter   {A.YEL}interrupted before starting{A.RST}")
        elif xst.finished:
            qp = xst.quick_passed or xst.alive_count
            bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
            if xst.phase == "speed_test":
                bx(f" {A.GRN}v{A.RST} Speed Test     {A.GRN}done{A.RST}")
        elif xst.phase == "quick_filter":
            pct = xst.done_count * 100 // max(1, xst.total)
            bx(f" {A.GRN}>{A.RST} {A.BOLD}Quick Filter{A.RST}   [{self._bar(xst.done_count, xst.total, bw)}] "
               f"{xst.done_count}/{xst.total}  {pct}%")
        elif xst.phase == "speed_test":
            qp = xst.quick_passed or xst.alive_count
            bx(f" {A.GRN}v{A.RST} Quick Filter   {A.GRN}{qp} passed{A.RST}")
            pct = xst.done_count * 100 // max(1, xst.total)
            bx(f" {A.GRN}>{A.RST} {A.BOLD}Speed Test{A.RST}     [{self._bar(xst.done_count, xst.total, bw)}] "
               f"{xst.done_count}/{xst.total}  {pct}%")
        else:
            bx(f" {A.DIM}o Quick Filter   starting...{A.RST}")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        # Check if we're testing multiple IPs (tag format: ip|sni|frag)
        _multi_ip = any(v.tag.count("|") >= 2 for v in xst.variations[:3])
        if _multi_ip:
            hdr = (f" {A.BOLD}{'#':>3}  {'IP':<18} {'SNI':<20} {'Frag':>8}  "
                   f"{'Conn':>6}  {'TTFB':>6}  {'Score':>5}{A.RST}")
            bx(hdr)
            bx(f" {A.DIM}{'─'*3}  {'─'*18} {'─'*20} {'─'*8}  {'─'*6}  {'─'*6}  {'─'*5}{A.RST}")
        else:
            hdr = (f" {A.BOLD}{'#':>3}  {'SNI':<26} {'Fragment':>10}  "
                   f"{'Conn':>6}  {'TTFB':>6}  {'Score':>5}{A.RST}")
            bx(hdr)
            bx(f" {A.DIM}{'─'*3}  {'─'*26} {'─'*10}  {'─'*6}  {'─'*6}  {'─'*5}{A.RST}")

        sorted_vars = sorted(
            xst.variations,
            key=lambda v: (
                -v.score if self.sort == "score"
                else (v.connect_ms if v.connect_ms > 0 else 9999)
            ),
        )

        vis = max(3, rows - 18)
        page = sorted_vars[self.offset:self.offset + vis]

        for rank, v in enumerate(page, self.offset + 1):
            frag_s = "none" if v.fragment is None else v.fragment.get("length", "?")
            # Extract IP from tag if multi-IP mode
            if _multi_ip:
                _parts = v.tag.split("|", 2)
                _raw_ip = _parts[0] if len(_parts) >= 3 else ""
                _ip_s = (_raw_ip[:16] + "..") if len(_raw_ip) > 18 else _raw_ip[:18]
                sni_short = v.sni[:20]
                _name_col = f"{_ip_s:<18} {sni_short:<20} {frag_s:>8}"
            else:
                sni_short = v.sni[:26]
                _name_col = f"{sni_short:<26} {frag_s:>10}"
            if not v.alive and v.error:
                _err_s = v.error[:31] if v.error else "dead"
                _pad = max(0, 31 - len(_err_s))
                row = (f" {A.DIM}{rank:>3}  {_name_col}  "
                       f"{A.RED}{_err_s}{A.RST}{A.DIM}{' '*_pad}{A.RST}")
            elif not v.alive and not v.error and v.connect_ms <= 0 and v.score <= 0:
                row = (f" {A.DIM}{rank:>3}  {_name_col}  "
                       f"{'--':>6}  {'--':>6}  {'--':>5}{A.RST}")
            else:
                conn_s = f"{v.connect_ms:6.0f}" if v.connect_ms > 0 else f"{'--':>6}"
                ttfb_s = f"{v.ttfb_ms:6.0f}" if v.ttfb_ms > 0 else f"{'--':>6}"
                if v.score >= 70:
                    sc_s = f"{A.GRN}{v.score:5.1f}{A.RST}"
                elif v.score >= 40:
                    sc_s = f"{A.YEL}{v.score:5.1f}{A.RST}"
                elif v.score > 0:
                    sc_s = f"{v.score:5.1f}"
                else:
                    sc_s = f"{'--':>5}"
                row = (f" {rank:>3}  {_name_col}  "
                       f"{conn_s}  {ttfb_s}  {sc_s}")
            bx(row)

        for _ in range(vis - len(page)):
            bx("")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
        if xst.finished:
            if W >= 100:
                footer = (f" {A.CYN}[S]{A.RST} Sort  {A.CYN}[E]{A.RST} Export  "
                          f"{A.CYN}[C]{A.RST} View URI  "
                          f"{A.CYN}[J/K]{A.RST} Scroll  {A.CYN}[N/P]{A.RST} Page  "
                          f"{A.CYN}[B]{A.RST} Back  {A.CYN}[Q]{A.RST} Quit")
                bx(footer)
            else:
                bx(f" {A.CYN}[S]{A.RST}ort {A.CYN}[E]{A.RST}xp {A.CYN}[C]{A.RST}URI {A.CYN}[B]{A.RST}ack {A.CYN}[Q]{A.RST}uit")
                bx(f" {A.CYN}[J/K]{A.RST} Scroll  {A.CYN}[N/P]{A.RST} Page")
            if xst.export_error:
                bx(f" {A.RED}{xst.export_error}{A.RST}")
        else:
            bx(f" {A.DIM}{xst.phase_label}  |  Press Ctrl+C to stop{A.RST}")
        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w(A.CLR + A.HIDE)
        _w("\n".join(out) + "\n")
        _fl()

    def handle(self, key: str) -> Optional[str]:
        sorts = ["score", "latency"]
        if key == "s":
            idx = sorts.index(self.sort) if self.sort in sorts else 0
            self.sort = sorts[(idx + 1) % len(sorts)]
            self.offset = 0
        elif key in ("j", "down"):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = min(self.offset + 1, max(0, len(self.xst.variations) - vis))
        elif key in ("k", "up"):
            self.offset = max(0, self.offset - 1)
        elif key in ("n",):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = min(self.offset + vis, max(0, len(self.xst.variations) - vis))
        elif key in ("p",):
            _, rows = term_size()
            vis = max(3, rows - 18)
            self.offset = max(0, self.offset - vis)
        elif key == "e" and self.xst.finished:
            return "export"
        elif key == "c" and self.xst.finished:
            return "view_uri"
        elif key == "b":
            return "back"
        elif key in ("q", "ctrl-c"):
            return "quit"
        return None


def xray_save_results(xst: XrayTestState, top: int = 10) -> Tuple[str, str]:
    """Save xray test results: CSV + top VLESS/VMess URIs. Returns (csv_path, uris_path)."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    sorted_vars = sorted(
        [v for v in xst.variations if v.alive],
        key=lambda v: v.score, reverse=True,
    )

    csv_path = _results_path(f"xray_{ts}_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Rank", "Tag", "SNI", "Fragment", "Connect_ms", "TTFB_ms",
                     "Speed_MBps", "Score", "Error", "URI"])
        for rank, v in enumerate(sorted_vars, 1):
            frag_s = json.dumps(v.fragment) if v.fragment else ""
            w.writerow([
                rank, v.tag, v.sni, frag_s,
                f"{v.connect_ms:.0f}" if v.connect_ms > 0 else "",
                f"{v.ttfb_ms:.0f}" if v.ttfb_ms > 0 else "",
                f"{v.speed_mbps:.3f}" if v.speed_mbps > 0 else "",
                f"{v.score:.1f}", v.error, v.result_uri,
            ])

    uri_path = _results_path(f"xray_{ts}_top{top}.txt")
    with open(uri_path, "w", encoding="utf-8") as f:
        count = 0
        for v in sorted_vars:
            if count >= top:
                break
            if v.result_uri:
                f.write(v.result_uri + "\n")
                count += 1

    return csv_path, uri_path


async def _run_pipeline_core(
    xst: "XrayTestState", pcfg: "PipelineConfig", xray_bin: str,
) -> "XrayDashboard":
    """Run pipeline test with dashboard. Returns the dashboard for post-test use."""
    xst.source_uri = pcfg.uri
    xst.xray_bin = xray_bin

    xdash = XrayDashboard(xst)

    async def _pipeline_refresh():
        while not xst.finished:
            try:
                xdash.draw()
            except (OSError, ValueError):
                pass
            await asyncio.sleep(0.3)

    _w(A.CLR + A.HOME + A.HIDE)
    refresh_task = asyncio.create_task(_pipeline_refresh())
    pipeline_task = asyncio.ensure_future(xray_pipeline_test(xst, pcfg))

    old_sigint = signal.getsignal(signal.SIGINT)
    _loop_pl = asyncio.get_running_loop()

    def _sig(sig, frame):
        xst.interrupted = True
        xst.finished = True
        _loop_pl.call_soon_threadsafe(pipeline_task.cancel)
    signal.signal(signal.SIGINT, _sig)

    try:
        await pipeline_task
    except (asyncio.CancelledError, KeyboardInterrupt):
        xst.interrupted = True
        xst.finished = True
        _xray_calc_scores(xst)
    except Exception as e:
        _dbg(f"pipeline exception: {e}")
        xst.interrupted = True
        xst.finished = True
        _xray_calc_scores(xst)
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    refresh_task.cancel()
    try:
        await refresh_task
    except asyncio.CancelledError:
        pass

    return xdash


async def _post_pipeline_results(
    xst: "XrayTestState", xdash: "XrayDashboard", args,
) -> None:
    """Post-test results: auto-export, interactive loop (export, view)."""
    top_n = getattr(args, "xray_keep", 10)
    csv_p = uri_p = ""

    # Auto-export alive results
    if any(v.alive for v in xst.variations):
        try:
            csv_p, uri_p = xray_save_results(xst, top=top_n)
        except Exception as e:
            csv_p = uri_p = ""
            xst.export_error = f"Export failed: {e}"

    # Show final dashboard
    xdash.draw()

    # -- Post-scan interactive loop --
    try:
        while True:
            key = _read_key_nb(0.1)
            if key is None:
                continue
            act = xdash.handle(key)
            if act in ("quit", "back"):
                break
            elif act == "export":
                try:
                    csv_p, uri_p = xray_save_results(xst, top=top_n)
                    _n_alive = sum(1 for v in xst.variations if v.alive)
                    xst.export_error = f"Exported {_n_alive} configs -> {uri_p}"
                except Exception as e:
                    xst.export_error = f"Export failed: {e}"
            elif act == "view_uri":
                alive = sorted(
                    [v for v in xst.variations if v.alive],
                    key=lambda v: v.score, reverse=True,
                )
                if alive and alive[0].result_uri:
                    while True:
                        _w(A.CLR + A.HOME + A.SHOW)
                        _w(f"\n {A.BOLD}Top configs ({len(alive)} alive):{A.RST}\n\n")
                        for _vi, _vv in enumerate(alive[:10], 1):
                            _vc = A.GRN if _vi == 1 else A.CYN
                            _conn_s = f"conn={_vv.connect_ms:.0f}ms" if _vv.connect_ms > 0 else ""
                            _w(f"  {A.BOLD}#{_vi:<3}{A.RST} "
                               f"{_vc}{_vv.sni:<28}{A.RST} "
                               f"score={_vv.score:<6.1f} "
                               f"{_conn_s}\n")
                        if len(alive) > 10:
                            _w(f"  {A.DIM}... +{len(alive) - 10} more{A.RST}\n")
                        _w(f"\n")
                        if csv_p:
                            _w(f" {A.DIM}Full results: {csv_p}{A.RST}\n")
                        if uri_p:
                            _w(f" {A.DIM}Top URIs:     {uri_p}{A.RST}\n")
                        _w(f"\n {A.YEL}Enter #{A.RST} to view full URI"
                           f" {A.DIM}(or press Enter to go back):{A.RST} ")
                        _fl()
                        try:
                            _choice = input().strip()
                        except (EOFError, KeyboardInterrupt):
                            _choice = ""
                        if not _choice:
                            break
                        try:
                            _idx = int(_choice.lstrip("#")) - 1
                            if 0 <= _idx < len(alive) and alive[_idx].result_uri:
                                _conn_s2 = f"conn={alive[_idx].connect_ms:.0f}ms" if alive[_idx].connect_ms > 0 else ""
                                _w(f"\n {A.BOLD}#{_idx + 1} "
                                   f"(score={alive[_idx].score:.1f}"
                                   f"{', ' + _conn_s2 if _conn_s2 else ''}):"
                                   f"{A.RST}\n\n")
                                _w(f" {A.GRN}{alive[_idx].result_uri}{A.RST}\n")
                            else:
                                _w(f"\n {A.RED}No config #{_choice} "
                                   f"(1-{len(alive)} available){A.RST}\n")
                        except ValueError:
                            _w(f"\n {A.RED}Enter a number 1-{len(alive)}{A.RST}\n")
                        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
                        _fl()
                        _read_key_blocking()
                    _w(A.HIDE)
                else:
                    xst.export_error = "No alive configs to view"
            xdash.draw()
    except (KeyboardInterrupt, EOFError, OSError):
        pass
    _w(A.SHOW)


def tui_pipeline_input(configless: bool = False) -> Optional[PipelineConfig]:
    """Unified input wizard for the progressive xray pipeline.

    Config mode: paste URI -> pick SNIs/frags/transports
    Returns PipelineConfig or None (cancelled).
    """
    _w(A.SHOW)

    # -- Config mode --
    _w(f"\n {A.BOLD}{A.CYN}Xray Pipeline Test{A.RST}\n")
    _w(f" {A.YEL}For:{A.RST} You have a working config {A.WHT}behind Cloudflare{A.RST} and want to find the fastest IPs and fragment settings.\n")
    _w(f" {A.DIM}Smart: probe IPs -> validate config -> expand (IPs x fragments){A.RST}\n\n")

    # Step 1: URI
    _w(f" {A.BOLD}Step 1:{A.RST} {A.CYN}Paste your VLESS/VMess config URI:{A.RST}\n")
    _w(f" {A.DIM}(must be behind Cloudflare -- CDN, Tunnel, or Workers){A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    parsed = parse_vless_full(uri) or parse_vmess_full(uri)
    if not parsed:
        _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n"); _fl()
        time.sleep(1.5); return None

    _proto = parsed.get("protocol", "vless")
    _net = parsed.get("type") or parsed.get("net") or "tcp"
    _sec = parsed.get("security") or "none"
    _addr = parsed.get("address", "?")
    _port = parsed.get("port", "?")
    _is_reality = _sec == "reality"
    _no_tls = _sec in ("none", "")
    _is_cf = _is_cf_address(_addr)
    # For domain addresses (CDN fronting like chatgpt.com), resolve DNS
    if not _is_cf and not _is_reality and not _no_tls:
        _is_cf = _resolve_is_cf(_addr)

    _mode_label = "Cloudflare" if _is_cf else ("REALITY" if _is_reality else "Direct")
    _w(f" {A.GRN}OK{A.RST} {_proto}/{_net}/{_sec} @ {_addr}:{_port}"
       f" {A.DIM}({_mode_label}){A.RST}\n")
    _fl()

    # Block non-CF, non-REALITY configs -- they can't benefit from the pipeline
    if not _is_cf and not _is_reality:
        _w(f"\n {A.RED}{'─' * 50}{A.RST}\n")
        _w(f" {A.BOLD}{A.RED}Server is not behind Cloudflare{A.RST}\n")
        _w(f" {A.RED}{'─' * 50}{A.RST}\n\n")
        _w(f" {A.DIM}The pipeline scanner works by rotating Cloudflare IPs, SNIs,{A.RST}\n")
        _w(f" {A.DIM}and fragment settings. This only works when your server is{A.RST}\n")
        _w(f" {A.DIM}behind the Cloudflare CDN.{A.RST}\n\n")
        _w(f" {A.DIM}Press any key to go back...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return None

    # REALITY: skip SNI/frag/transport config -- only test original IP
    if _is_reality:
        _w(f"\n {A.DIM}REALITY config -- testing with original SNI, no fragments.{A.RST}\n")
        _w(f" {A.DIM}Pipeline will validate connectivity on the original server.{A.RST}\n")
        _fl()
        return PipelineConfig(
            uri=uri, parsed=parsed,
            sni_pool=[], frag_preset="none",
            transport_variants=[],
        )

    # No SNI rotation -- CF zone matching means only the original Host SNI works.
    sni_pool = []

    # Step 2: Fragment preset
    _w(f"\n {A.BOLD}Step 2:{A.RST} {A.CYN}Fragment settings (DPI bypass):{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. All presets (none + light + medium + heavy) {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. No fragmentation\n")
    _w(f"  {A.CYN}3{A.RST}. Light only\n")
    _w(f"  {A.CYN}4{A.RST}. Heavy only\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        frag_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None
    frag_map = {"1": "all", "2": "none", "3": "light", "4": "heavy"}
    frag_preset = frag_map.get(frag_ch, "all")

    # Transport: locked to original -- server/tunnel only supports what it's configured for
    transport_variants = []
    _w(f"\n {A.DIM}Transport: {A.WHT}{_net}{A.RST}{A.DIM} (from config -- only testing {_net}){A.RST}\n")

    # Step 3: Custom IPs
    _w(f"\n {A.BOLD}Step 3:{A.RST} {A.CYN}IP source:{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. Random CF IPs ({len(CF_TEST_IPS)} IPs across all ranges) {A.GRN}(recommended){A.RST}\n")
    # Check if clean_ips.txt exists from Clean IP Finder
    _clean_ip_path = os.path.join(RESULTS_DIR, "clean_ips.txt")
    _clean_count = 0
    if os.path.isfile(_clean_ip_path):
        try:
            with open(_clean_ip_path, "r") as _cf:
                _clean_count = sum(1 for l in _cf if l.strip() and not l.startswith("#"))
        except OSError:
            pass
    if _clean_count > 0:
        _w(f"  {A.CYN}2{A.RST}. Clean IP Finder results ({_clean_count} IPs from {_clean_ip_path})\n")
    else:
        _w(f"  {A.CYN}2{A.RST}. Clean IP Finder results {A.DIM}(none found -- run [f] first){A.RST}\n")
    _w(f"  {A.CYN}3{A.RST}. Load from file path\n")
    _w(f"  {A.CYN}4{A.RST}. Enter IPs/CIDRs manually\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        ip_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None

    custom_ips: List[str] = []
    if ip_ch == "2":
        if _clean_count > 0:
            custom_ips = expand_custom_ips(_clean_ip_path)
            if custom_ips:
                _w(f" {A.GRN}Loaded {len(custom_ips)} IPs from clean_ips.txt{A.RST}\n")
                _fl()
            else:
                _w(f" {A.RED}Failed to read clean_ips.txt{A.RST}\n"); _fl()
                time.sleep(1); return None
        else:
            _w(f" {A.RED}No clean IPs found. Run Clean IP Finder [f] from the main menu first.{A.RST}\n")
            _fl(); time.sleep(2); return None
    elif ip_ch == "3":
        _w(f" {A.CYN}Enter file path:{A.RST}\n ")
        _w(f" {A.DIM}e.g. results/clean_ips.txt or /path/to/ips.txt{A.RST}\n ")
        _fl()
        try:
            raw_ips = input().strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw_ips:
            custom_ips = expand_custom_ips(raw_ips)
            if not custom_ips:
                _w(f" {A.RED}No valid IPs found in file.{A.RST}\n"); _fl()
                time.sleep(1); return None
            _w(f" {A.GRN}Loaded {len(custom_ips)} IPs{A.RST}\n")
            _fl()
        else:
            _w(f" {A.RED}No path entered.{A.RST}\n"); _fl()
            time.sleep(1); return None
    elif ip_ch == "4":
        _w(f" {A.CYN}Enter IPs, CIDRs (comma-separated):{A.RST}\n ")
        _w(f" {A.DIM}e.g. 104.16.0.0/24, 172.67.1.1{A.RST}\n ")
        _fl()
        try:
            raw_ips = input().strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if raw_ips:
            custom_ips = expand_custom_ips(raw_ips)
            if not custom_ips:
                _w(f" {A.RED}No valid IPs found.{A.RST}\n"); _fl()
                time.sleep(1); return None
            _w(f" {A.GRN}Expanded to {len(custom_ips)} IPs{A.RST}\n")
            _fl()
        else:
            _w(f" {A.RED}No IPs entered.{A.RST}\n"); _fl()
            time.sleep(1); return None

    # Step 4: Ports to scan
    _orig_port = int(parsed.get("port", 443))
    _w(f"\n {A.BOLD}Step 4:{A.RST} {A.CYN}Ports to scan per IP:{A.RST}\n")
    _w(f"  {A.CYN}1{A.RST}. Original port ({_orig_port}) only {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. All CF HTTPS ports (443, 8443, 2053, 2083, 2087, 2096)\n")
    _w(f"  {A.CYN}3{A.RST}. Custom ports\n")
    _w(f" Choice [1]: ")
    _fl()
    try:
        port_ch = input().strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None

    if port_ch == "2":
        probe_ports = list(CF_HTTPS_PORTS)
        if _orig_port not in probe_ports:
            probe_ports.insert(0, _orig_port)
    elif port_ch == "3":
        _w(f" {A.CYN}Enter ports (comma-separated):{A.RST} ")
        _fl()
        try:
            raw_ports = input().strip()
        except (EOFError, KeyboardInterrupt):
            return None
        probe_ports = []
        for p in raw_ports.split(","):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                probe_ports.append(int(p))
        if not probe_ports:
            _w(f" {A.RED}No valid ports. Using {_orig_port}.{A.RST}\n"); _fl()
            probe_ports = [_orig_port]
    else:
        probe_ports = [_orig_port]

    # Step 5: Test intensity (max variations in expansion)
    _n_frags = len(XRAY_FRAG_PRESETS.get(frag_preset, XRAY_FRAG_PRESETS.get("all", [])))
    _potential = 120 * max(1, _n_frags)
    _w(f"\n {A.BOLD}Step 5:{A.RST} {A.CYN}Test intensity:{A.RST}\n")
    _w(f" {A.DIM}How many IP x fragment combinations to test in expansion.{A.RST}\n")
    _w(f" {A.DIM}More = better coverage but takes longer.{A.RST}\n\n")
    _w(f"  {A.CYN}1{A.RST}. {A.WHT}Quick{A.RST}      500 variations   {A.DIM}~2-3 min{A.RST}\n")
    _w(f"  {A.CYN}2{A.RST}. {A.WHT}Normal{A.RST}    1,500 variations   {A.DIM}~5-8 min{A.RST} {A.GRN}(recommended){A.RST}\n")
    _w(f"  {A.CYN}3{A.RST}. {A.WHT}Thorough{A.RST}  3,000 variations   {A.DIM}~10-15 min{A.RST}\n")
    _w(f"  {A.CYN}4{A.RST}. {A.WHT}Maximum{A.RST}   7,500 variations   {A.DIM}~25-40 min{A.RST}\n")
    _w(f"\n Choice [2]: ")
    _fl()
    try:
        _int_ch = input().strip() or "2"
    except (EOFError, KeyboardInterrupt):
        return None
    _int_map = {"1": 500, "2": 1500, "3": 3000, "4": 7500}
    max_expansion = _int_map.get(_int_ch, 1500)
    _w(f" {A.GRN}-> Up to {max_expansion:,} variations{A.RST}\n")

    return PipelineConfig(
        uri=uri, parsed=parsed,
        sni_pool=sni_pool,
        frag_preset=frag_preset,
        transport_variants=transport_variants,
        custom_ips=custom_ips,
        probe_ports=probe_ports,
        max_expansion=max_expansion,
    )


async def _tui_run_pipeline(args, cli_uri: str = ""):
    """Run the progressive xray pipeline in TUI mode."""

    # -- Input --
    if cli_uri:
        parsed = parse_vless_full(cli_uri) or parse_vmess_full(cli_uri)
        if not parsed:
            _w(A.SHOW)
            print(f"  Invalid VLESS/VMess URI: {cli_uri[:60]}...")
            time.sleep(2)
            return
        # Block non-CF, non-REALITY configs
        _addr = parsed.get("address", "")
        _sec = parsed.get("security") or "none"
        _is_cf_smart = _is_cf_address(_addr) or (
            _sec not in ("reality", "none", "") and _resolve_is_cf(_addr))
        if not _is_cf_smart and _sec != "reality":
            _w(A.SHOW)
            _w(f"\n {A.RED}Server is not behind Cloudflare.{A.RST}\n")
            _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            return
        # No SNI rotation -- CF zone matching blocks cross-zone SNIs.
        sni_pool = []
        if getattr(args, "xray_sni", None):
            sni_pool = [s.strip() for s in args.xray_sni.split(",") if s.strip()]
        frag_preset = getattr(args, "xray_frag", "all")
        # REALITY: no frag/transport expansion
        if _sec == "reality":
            frag_preset = "none"
            transport_vars = []
        else:
            transport_vars = ["ws", "xhttp"]
        pcfg = PipelineConfig(
            uri=cli_uri, parsed=parsed,
            sni_pool=sni_pool, frag_preset=frag_preset,
            transport_variants=transport_vars,
            max_expansion=1500,
        )
    else:
        pcfg = tui_pipeline_input()
        if pcfg is None:
            return

    # -- Xray binary --
    _w(A.SHOW)
    _w(f"\n {A.DIM}Looking for xray-core binary...{A.RST}\n")
    _fl()
    xray_bin = xray_find_binary(getattr(args, "xray_bin", None))
    if not xray_bin:
        _w(f" {A.YEL}Xray not found. Installing to ~/.cfray/bin/...{A.RST}\n")
        _fl()
        xray_bin = xray_install()
        if not xray_bin:
            _w(f" {A.RED}ERROR: Could not install xray-core.{A.RST}\n")
            _fl()
            time.sleep(3)
            return
    _w(f" {A.GRN}OK{A.RST} Using {xray_bin}\n")
    _fl()

    # -- Pipeline execution --
    xst = XrayTestState()
    xdash = await _run_pipeline_core(xst, pcfg, xray_bin)
    await _post_pipeline_results(xst, xdash, args)


# ─── Xray Server Deploy — Core Functions ──────────────────────────────────────


def deploy_check_prerequisites() -> Tuple[bool, str]:
    """Check that we're on Linux as root with systemd."""
    if sys.platform != "linux":
        return False, f"Server deploy is Linux-only (detected: {sys.platform})"
    try:
        if os.geteuid() != 0:
            return False, "Must run as root (try: sudo python3 scanner.py --deploy)"
    except AttributeError:
        return False, "Cannot detect root status"
    if not shutil.which("systemctl"):
        return False, "systemd not found (systemctl not in PATH)"
    return True, ""


def deploy_detect_server_ip() -> str:
    """Detect server's public IP by querying external services."""
    for url in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read(1024).decode().strip()
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return ""


def deploy_check_port(port: int) -> bool:
    """Check if a TCP port is free."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def deploy_generate_uuid() -> str:
    """Generate a random UUID v4."""
    import uuid as _uuid_mod
    return str(_uuid_mod.uuid4())


def deploy_generate_reality_keys(xray_bin: str) -> Tuple[str, str]:
    """Generate x25519 key pair using xray binary. Returns (private, public).

    Handles both output formats:
    - Old: "Private key: xxx\\nPublic key: yyy"
    - New: "PrivateKey: xxx\\nPassword: yyy"  (Password = public key)
    """
    try:
        kw = {}
        if sys.platform == "win32":
            kw["creationflags"] = 0x08000000
        result = subprocess.run(
            [xray_bin, "x25519"],
            capture_output=True, text=True, timeout=10, **kw,
        )
        if result.returncode != 0:
            return "", ""
        private_key = ""
        public_key = ""
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("private key:") or low.startswith("privatekey:"):
                private_key = line.split(":", 1)[1].strip()
            elif low.startswith("public key:") or low.startswith("publickey:"):
                public_key = line.split(":", 1)[1].strip()
            elif low.startswith("password:"):
                # New xray format: "Password" is the public key
                public_key = line.split(":", 1)[1].strip()
        return private_key, public_key
    except (OSError, subprocess.SubprocessError, ValueError):
        return "", ""


def deploy_generate_short_id() -> str:
    """Generate a random short ID (8 hex chars) for REALITY."""
    return os.urandom(4).hex()


def _build_single_inbound(parsed: dict, ds: "DeployState", index: int) -> dict:
    """Build a single server inbound from a parsed client config dict."""
    protocol = parsed.get("protocol", "vless")
    if protocol not in ("vless", "vmess"):
        raise ValueError(f"Unsupported protocol: {protocol}")
    try:
        raw_port = ds.listen_port if index == 0 else int(parsed.get("port", 443))
    except (ValueError, TypeError):
        raw_port = 443
    port = raw_port if 1 <= raw_port <= 65535 else 443

    inbound: dict = {
        "tag": f"inbound-{index}",
        "port": port,
        "listen": "::",
        "protocol": protocol,
        "settings": {},
        "streamSettings": {},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }

    # -- Settings (clients) --
    uuid_val = parsed.get("uuid", "")
    if not uuid_val:
        uuid_val = deploy_generate_uuid()
    if protocol == "vmess":
        try:
            alter_id = int(parsed.get("aid", 0))
        except (ValueError, TypeError):
            alter_id = 0
        inbound["settings"] = {
            "clients": [{
                "id": uuid_val,
                "alterId": alter_id,
            }],
        }
    else:  # vless
        client: dict = {"id": uuid_val}
        flow = parsed.get("flow", "")
        if flow:
            client["flow"] = flow
        inbound["settings"] = {
            "clients": [client],
            "decryption": "none",
        }

    # -- Stream Settings --
    net = parsed.get("type", "tcp")
    sec = parsed.get("security", "none")
    stream: dict = {"network": net, "security": sec}

    # Security layer
    if sec == "reality":
        sni_val = parsed.get("sni", "") or "www.google.com"
        stream["realitySettings"] = {
            "show": False,
            "dest": f"{sni_val}:443",
            "xver": 0,
            "serverNames": [sni_val],
            "privateKey": ds.reality_private_key,
            "shortIds": [ds.reality_short_id or ""],
        }
    elif sec == "tls":
        tls_settings: dict = {
            "certificates": [{
                "certificateFile": ds.tls_cert_path or "/usr/local/etc/xray/cert.pem",
                "keyFile": ds.tls_key_path or "/usr/local/etc/xray/key.pem",
            }],
        }
        alpn = parsed.get("alpn", "")
        if alpn:
            tls_settings["alpn"] = alpn.split(",")
        stream["tlsSettings"] = tls_settings

    # Transport layer
    if net == "ws":
        ws_cfg: dict = {"path": parsed.get("path", "/")}
        stream["wsSettings"] = ws_cfg
    elif net == "grpc":
        sn = parsed.get("serviceName") or parsed.get("path", "")
        if sn == "/":
            sn = ""
        stream["grpcSettings"] = {"serviceName": sn or "grpc"}
    elif net in ("h2", "http"):
        host_val = parsed.get("host") or parsed.get("sni", "")
        stream["httpSettings"] = {
            "host": [host_val] if host_val else [],
            "path": parsed.get("path", "/"),
        }
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xhttp_cfg: dict = {"path": parsed.get("path", "/xhttp")}
        mode = parsed.get("mode", "")
        if mode and mode != "auto":
            xhttp_cfg["mode"] = mode
        stream["xhttpSettings"] = xhttp_cfg
    elif net == "tcp":
        htype = parsed.get("headerType", "")
        if htype == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "response": {
                        "version": "1.1",
                        "status": "200",
                        "reason": "OK",
                    },
                },
            }

    inbound["streamSettings"] = stream
    return inbound


def build_server_config(ds: "DeployState") -> dict:
    """Build Xray server JSON config from DeployState."""
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            ],
        },
    }

    for i, parsed in enumerate(ds.parsed_configs):
        inbound = _build_single_inbound(parsed, ds, i)
        config["inbounds"].append(inbound)

    ds.server_config = config
    return config


def build_client_uri_for_server(parsed: dict, ds: "DeployState", tag: str, index: int = 0) -> str:
    """Build a client URI pointing to the deployed server."""
    p = copy.copy(parsed)
    p["address"] = ds.server_ip
    try:
        p["port"] = int(ds.listen_port if index == 0 else parsed.get("port", 443))
    except (ValueError, TypeError):
        p["port"] = 443
    if p.get("security") == "reality" and ds.reality_public_key:
        p["pbk"] = ds.reality_public_key
    if p.get("security") == "reality" and ds.reality_short_id:
        p["sid"] = ds.reality_short_id

    sni = p.get("sni") or p.get("host") or ""
    return _build_uri(p, sni, tag)


def deploy_fresh_config(
    protocol: str, transport: str, security: str,
    port: int, uuid_val: str, sni: str, ds: "DeployState",
) -> dict:
    """Generate a fresh parsed-config dict for from-scratch deployment."""
    parsed = {
        "protocol": protocol,
        "uuid": uuid_val,
        "address": ds.server_ip,
        "port": port,
        "name": f"cfray-{protocol}-{transport}",
        "type": transport,
        "security": security,
        "sni": sni,
        "host": sni,
        "path": "/ws" if transport == "ws" else ("/xhttp" if transport in ("xhttp", "splithttp") else ("/" if transport in ("h2", "http") else "")),
        "fp": "chrome",
        "flow": "xtls-rprx-vision" if (protocol == "vless" and security == "reality" and transport == "tcp") else "",
        "alpn": "h2,http/1.1" if security == "tls" else "",
        "encryption": "none",
        "serviceName": "grpc" if transport == "grpc" else "",
        "headerType": "",
        "mode": "auto" if transport in ("xhttp", "splithttp") else "",
        "pbk": ds.reality_public_key if security == "reality" else "",
        "sid": ds.reality_short_id if security == "reality" else "",
        "spx": "",
    }
    if protocol == "vmess":
        parsed["aid"] = 0
        parsed["scy"] = "auto"
    return parsed


def generate_configless_base(
    server: str, port: int, uuid_val: str, protocol: str = "vless",
) -> List[Tuple[str, dict]]:
    """Generate base (uri, parsed) configs for config-less pipeline mode.

    Creates ws/tls and xhttp/tls variants (plus vmess/ws/tls if vmess protocol).
    Returns list of (uri_string, parsed_dict) tuples.
    """
    results: List[Tuple[str, dict]] = []
    default_sni = "speed.cloudflare.com"

    transports = ["ws", "xhttp"]
    for transport in transports:
        path = "/ws" if transport == "ws" else "/xhttp"
        parsed = {
            "protocol": protocol,
            "uuid": uuid_val,
            "address": server,
            "port": port,
            "name": f"cfray-{protocol}-{transport}",
            "type": transport,
            "security": "tls",
            "sni": default_sni,
            "host": default_sni,
            "path": path,
            "fp": "chrome",
            "flow": "",
            "alpn": "h2,http/1.1",
            "encryption": "none",
            "serviceName": "",
            "headerType": "",
            "pbk": "",
            "sid": "",
            "spx": "",
            "mode": "auto" if transport == "xhttp" else "",
        }
        if protocol == "vmess":
            parsed["aid"] = 0
            parsed["scy"] = "auto"
        uri = _build_uri(parsed, default_sni, parsed["name"])
        results.append((uri, parsed))

    # If VMess, also add a VLESS ws/tls variant for broader testing
    if protocol == "vmess":
        vless_parsed = {
            "protocol": "vless", "uuid": uuid_val,
            "address": server, "port": port,
            "name": "cfray-vless-ws", "type": "ws",
            "security": "tls", "sni": default_sni, "host": default_sni,
            "path": "/ws", "fp": "chrome", "flow": "",
            "alpn": "h2,http/1.1", "encryption": "none",
            "serviceName": "", "headerType": "",
            "pbk": "", "sid": "", "spx": "", "mode": "",
        }
        vless_uri = build_vless_uri(vless_parsed, default_sni, "cfray-vless-ws")
        results.append((vless_uri, vless_parsed))

    return results


# ─── Xray Server Deploy — Pipeline Functions ─────────────────────────────


def deploy_install_xray_system() -> Tuple[bool, str]:
    """Install xray to /usr/local/bin/ with geo files. Returns (ok, message)."""
    if os.path.isfile(DEPLOY_XRAY_BIN):
        try:
            result = subprocess.run([DEPLOY_XRAY_BIN, "version"],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ver = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"
                return True, f"Xray already installed: {ver}"
        except (OSError, subprocess.SubprocessError):
            pass

    local_bin = xray_find_binary()
    if not local_bin:
        local_bin = xray_install()
    if not local_bin:
        return False, "Failed to download Xray binary"

    try:
        os.makedirs(os.path.dirname(DEPLOY_XRAY_BIN), exist_ok=True)
        shutil.copy2(local_bin, DEPLOY_XRAY_BIN)
        os.chmod(DEPLOY_XRAY_BIN, 0o755)
    except OSError as e:
        return False, f"Failed to install to {DEPLOY_XRAY_BIN}: {e}"

    try:
        os.makedirs(DEPLOY_XRAY_SHARE, exist_ok=True)
        for gf in ("geoip.dat", "geosite.dat"):
            src = os.path.join(XRAY_BIN_DIR, gf)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(DEPLOY_XRAY_SHARE, gf))
    except OSError:
        pass  # geo files are optional

    return True, f"Installed to {DEPLOY_XRAY_BIN}"


def deploy_write_config(ds: "DeployState") -> Tuple[bool, str]:
    """Write server config JSON with backup of existing."""
    try:
        os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
        if os.path.isfile(DEPLOY_XRAY_CONFIG):
            os.makedirs(DEPLOY_XRAY_BACKUP_DIR, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            backup = os.path.join(DEPLOY_XRAY_BACKUP_DIR, f"config_{ts}.json")
            shutil.copy2(DEPLOY_XRAY_CONFIG, backup)

        config_str = json.dumps(ds.server_config, indent=2, ensure_ascii=False)
        tmp_path = DEPLOY_XRAY_CONFIG + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(config_str + "\n")
            os.replace(tmp_path, DEPLOY_XRAY_CONFIG)
        except BaseException:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        return True, DEPLOY_XRAY_CONFIG
    except OSError as e:
        return False, f"Failed to write config: {e}"


def deploy_validate_config() -> Tuple[bool, str]:
    """Run xray to validate the config file."""
    try:
        result = subprocess.run(
            [DEPLOY_XRAY_BIN, "run", "-test", "-c", DEPLOY_XRAY_CONFIG],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, "Config validated OK"
        err_msg = (result.stderr or result.stdout).strip()[:200]
        return False, f"Config validation failed: {err_msg}"
    except FileNotFoundError:
        return False, "Xray binary not found — cannot validate config"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Validation error: {e}"


def deploy_setup_certbot(domain: str) -> Tuple[bool, str, str]:
    """Try to obtain TLS cert via certbot. Returns (ok, cert_path, key_path)."""
    if not domain:
        return False, "", ""
    # Validate domain: must look like a hostname (no flags, no special chars)
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$', domain):
        return False, "", ""
    # Certbot standalone needs port 80
    if not deploy_check_port(80):
        return False, "", ""
    certbot = shutil.which("certbot")
    if not certbot:
        for cmd in (
            ["apt-get", "install", "-y", "certbot"],
            ["yum", "install", "-y", "certbot"],
            ["dnf", "install", "-y", "certbot"],
        ):
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=120)
                if result.returncode == 0:
                    certbot = shutil.which("certbot")
                    break
            except (OSError, subprocess.SubprocessError):
                continue

    if not certbot:
        return False, "", ""

    try:
        result = subprocess.run(
            [certbot, "certonly", "--standalone", "--agree-tos",
             "--register-unsafely-without-email", "-d", domain,
             "--non-interactive"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            key = f"/etc/letsencrypt/live/{domain}/privkey.pem"
            if os.path.isfile(cert) and os.path.isfile(key):
                # Copy certs to xray config dir for reliable access
                try:
                    os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
                    dst_cert = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "cert.pem")
                    dst_key = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "key.pem")
                    shutil.copy2(cert, dst_cert)
                    shutil.copy2(key, dst_key)
                    os.chmod(dst_cert, 0o644)
                    os.chmod(dst_key, 0o600)
                    return True, dst_cert, dst_key
                except OSError:
                    return True, cert, key
        return False, "", ""
    except (OSError, subprocess.SubprocessError):
        return False, "", ""


def deploy_systemd_service() -> Tuple[bool, str]:
    """Write systemd unit, enable and start xray service."""
    try:
        with open(DEPLOY_XRAY_SERVICE, "w", encoding="utf-8") as f:
            f.write(DEPLOY_SYSTEMD_UNIT)
    except OSError as e:
        return False, f"Failed to write service file: {e}"

    for cmd, label in [
        (["systemctl", "daemon-reload"], "daemon-reload"),
        (["systemctl", "enable", "xray"], "enable"),
        (["systemctl", "restart", "xray"], "start"),
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return False, f"systemctl {label} failed: {result.stderr.strip()[:100]}"
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"systemctl {label} error: {e}"

    time.sleep(1)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() == "active":
            return True, "Xray service running"
        return False, f"Service status: {result.stdout.strip()}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Status check failed: {e}"


def deploy_run_pipeline(ds: "DeployState", print_fn) -> bool:
    """Run the full deploy pipeline. Returns True on success."""

    # Direct Mode: write config.json + systemd
    steps = [
        ("Installing Xray binary", deploy_install_xray_system),
        ("Writing server config", lambda: deploy_write_config(ds)),
        ("Validating config", deploy_validate_config),
        ("Setting up systemd service", deploy_systemd_service),
    ]

    for label, step_fn in steps:
        print_fn(f"  [{label}]...")
        ok, msg = step_fn()
        if ok:
            print_fn(f"    OK: {msg}")
            ds.steps_done.append(label)
        else:
            print_fn(f"    FAILED: {msg}")
            ds.error = f"{label}: {msg}"
            return False

    # Generate client URIs
    ds.client_uris = []
    try:
        for i, parsed in enumerate(ds.parsed_configs):
            tag = f"cfray-{parsed.get('protocol', 'vless')}-{i + 1}"
            uri = build_client_uri_for_server(parsed, ds, tag, index=i)
            ds.client_uris.append(uri)
    except (KeyError, ValueError, TypeError) as e:
        print_fn(f"    FAILED to generate client URIs: {e}")
        ds.error = f"URI generation: {e}"
        return False

    return True


def deploy_save_results(ds: "DeployState") -> str:
    """Save client URIs and deployment info to results/deploy_<ts>.txt."""
    try:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = _results_path(f"deploy_{ts}.txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# Xray Server Deploy - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Server IP: {ds.server_ip}\n")
            f.write(f"# Port: {ds.listen_port}\n")
            f.write(f"# Config: {DEPLOY_XRAY_CONFIG}\n\n")
            f.write("# Client URIs (paste into v2rayNG / Nekobox / Hiddify):\n\n")
            for uri in ds.client_uris:
                f.write(uri + "\n")
            f.write(f"\n# Server config JSON:\n")
            f.write(json.dumps(ds.server_config, indent=2) + "\n")
        return path
    except OSError as e:
        _dbg(f"deploy_save_results failed: {e}")
        return ""


# ─── Xray Server Deploy — Server Config Management ───────────────────────────


def _read_server_config() -> Optional[dict]:
    """Read and parse the xray server config."""
    try:
        with open(DEPLOY_XRAY_CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return None


def _write_server_config(config: dict) -> bool:
    """Write xray server config atomically with backup. Returns True on success."""
    os.makedirs(DEPLOY_XRAY_CONFIG_DIR, exist_ok=True)
    backup_dir = os.path.join(DEPLOY_XRAY_CONFIG_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    # Validate JSON serialisable before touching disk
    try:
        data = json.dumps(config, indent=2)
    except (TypeError, ValueError):
        return False
    # Backup existing config
    if os.path.isfile(DEPLOY_XRAY_CONFIG):
        ts = time.strftime("%Y%m%d_%H%M%S")
        try:
            shutil.copy2(DEPLOY_XRAY_CONFIG, os.path.join(backup_dir, f"config_{ts}.json"))
        except OSError:
            pass
    # Atomic write: write to tmp then rename
    tmp_path = DEPLOY_XRAY_CONFIG + ".tmp"
    try:
        _fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp_path, DEPLOY_XRAY_CONFIG)
        return True
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


def _restart_xray_service() -> Tuple[bool, str]:
    """Restart xray via systemctl. Returns (success, message)."""
    if sys.platform in ("win32", "darwin"):
        return False, "systemctl not available on this platform"
    try:
        result = subprocess.run(
            ["systemctl", "restart", "xray"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return False, f"restart failed: {result.stderr.strip()[:100]}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"restart error: {e}"
    time.sleep(1)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "xray"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() == "active":
            return True, "Xray service running"
        return False, f"Service status: {result.stdout.strip()}"
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"Status check: {e}"


def _parse_inbound_summary(inbound: dict) -> dict:
    """Extract readable summary from a server inbound config."""
    stream = inbound.get("streamSettings") or {}
    if isinstance(stream, str):
        try:
            stream = json.loads(stream)
        except (ValueError, TypeError):
            stream = {}
    if not isinstance(stream, dict):
        stream = {}
    clients = []
    settings = inbound.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except (ValueError, TypeError):
            settings = {}
    if not isinstance(settings, dict):
        settings = {}
    if isinstance(settings.get("clients"), list):
        clients = settings["clients"]
    return {
        "tag": inbound.get("remark") or inbound.get("tag", "?"),
        "id": inbound.get("id"),
        "protocol": inbound.get("protocol", "?"),
        "port": inbound.get("port", "?"),
        "transport": stream.get("network", "tcp"),
        "security": stream.get("security", "none"),
        "users": len(clients),
    }


def _cm_build_client_uri(inbound: dict, uuid_val: str, server_ip: str) -> Optional[str]:
    """Build a client URI from an existing inbound config + UUID. Returns None on failure."""
    try:
        stream = inbound.get("streamSettings") or {}
        if isinstance(stream, str):
            stream = json.loads(stream)
        if not isinstance(stream, dict):
            stream = {}
        protocol = inbound.get("protocol", "vless")
        port = int(inbound.get("port", 443))
        transport = stream.get("network", "tcp")
        security = stream.get("security", "none")
        parsed: dict = {
            "protocol": protocol, "address": server_ip,
            "port": port, "uuid": uuid_val,
            "type": transport, "security": security, "fp": "chrome",
        }
        # Transport paths
        if transport == "ws":
            ws = stream.get("wsSettings") or {}
            parsed["path"] = ws.get("path", "/ws")
            parsed["host"] = ws.get("headers", {}).get("Host", "")
        elif transport in ("xhttp", "splithttp"):
            parsed["type"] = "xhttp"
            xh = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
            parsed["path"] = xh.get("path", "/xhttp")
        elif transport == "grpc":
            gs = stream.get("grpcSettings") or {}
            parsed["serviceName"] = gs.get("serviceName", "grpc")
        elif transport in ("h2", "http"):
            hs = stream.get("httpSettings") or {}
            parsed["path"] = hs.get("path", "/h2")
        # Security: REALITY
        sni = ""
        if security == "reality":
            rs = stream.get("realitySettings") or {}
            snames = rs.get("serverNames") or []
            sni = snames[0] if snames else ""
            parsed["sni"] = sni
            sid_list = rs.get("shortIds") or []
            parsed["sid"] = sid_list[0] if sid_list else ""
            # Derive public key from private key
            priv = rs.get("privateKey", "")
            if priv:
                _xbin = xray_find_binary(None)
                if _xbin:
                    try:
                        kw = {}
                        if sys.platform == "win32":
                            kw["creationflags"] = 0x08000000
                        r = subprocess.run(
                            [_xbin, "x25519", "-i", priv],
                            capture_output=True, text=True, timeout=10, **kw,
                        )
                        for line in r.stdout.strip().splitlines():
                            if line.strip().lower().startswith("public key:"):
                                parsed["pbk"] = line.split(":", 1)[1].strip()
                                break
                    except (OSError, subprocess.SubprocessError):
                        pass
            if protocol == "vless" and transport == "tcp":
                parsed["flow"] = "xtls-rprx-vision"
        elif security == "tls":
            tls_s = stream.get("tlsSettings") or {}
            sni = tls_s.get("serverName", "")
            parsed["sni"] = sni
        tag = f"cfray-{protocol}-{port}"
        return _build_uri(parsed, sni, tag)
    except (KeyError, ValueError, TypeError, IndexError):
        return None


# ─── Xray Server Deploy — TUI Functions ──────────────────────────────────────


def _tui_deploy_detect_ip(ds: "DeployState"):
    """Auto-detect server IP and prompt for override."""
    _w(f"\n {A.DIM}Detecting server IP...{A.RST}")
    _fl()
    ds.server_ip = deploy_detect_server_ip()
    if ds.server_ip:
        _w(f" {A.GRN}{ds.server_ip}{A.RST}\n")
    else:
        _w(f" {A.YEL}could not detect{A.RST}\n")
    _w(f" {A.BOLD}Server IP [{ds.server_ip or 'enter manually'}]:{A.RST} ")
    _fl()
    try:
        ip_input = input().strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if ip_input:
        try:
            ipaddress.ip_address(ip_input)
            ds.server_ip = ip_input
        except ValueError:
            _w(f" {A.RED}Invalid IP address.{A.RST}\n")
            _fl()
            time.sleep(1)
            return False
    if not ds.server_ip:
        _w(f" {A.RED}No server IP.{A.RST}\n")
        _fl()
        time.sleep(1)
        return False
    return True


def _tui_deploy_handle_security(parsed: dict, ds: "DeployState") -> bool:
    """Handle REALITY key gen or TLS cert setup for an existing config."""
    sec = parsed.get("security", "none")
    if sec == "reality":
        _w(f"\n {A.DIM}Generating REALITY keys...{A.RST}")
        _fl()
        xray_bin = xray_find_binary() or ""
        if not xray_bin:
            xray_bin = xray_install() or ""
        if not xray_bin:
            _w(f" {A.RED}Need Xray to generate keys.{A.RST}\n")
            _fl()
            time.sleep(2)
            return False
        priv, pub = deploy_generate_reality_keys(xray_bin)
        if not priv or not pub:
            _w(f" {A.RED}Key generation failed.{A.RST}\n")
            _fl()
            time.sleep(2)
            return False
        ds.reality_private_key = priv
        ds.reality_public_key = pub
        ds.reality_short_id = deploy_generate_short_id()
        parsed["pbk"] = pub
        parsed["sid"] = ds.reality_short_id
        _w(f" {A.GRN}OK{A.RST}\n")
    elif sec == "tls":
        _w(f"\n {A.BOLD}TLS Certificate:{A.RST}\n")
        _w(f"  {A.CYN}1{A.RST}. Auto-obtain via certbot\n")
        _w(f"  {A.CYN}2{A.RST}. Enter cert/key paths\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            cc = input().strip() or "1"
        except (EOFError, KeyboardInterrupt):
            return False
        ds.tls_domain = parsed.get("sni", "") or parsed.get("host", "")
        if cc == "1" and not ds.tls_domain:
            _w(f" {A.YEL}No domain found in config. Enter cert paths manually.{A.RST}\n")
            cc = "2"
        if cc == "1" and ds.tls_domain:
            _w(f" {A.DIM}Running certbot for {ds.tls_domain}...{A.RST}\n")
            _fl()
            ok, cert, key = deploy_setup_certbot(ds.tls_domain)
            if ok:
                ds.tls_cert_path = cert
                ds.tls_key_path = key
                _w(f" {A.GRN}Certificate obtained!{A.RST}\n")
            else:
                _w(f" {A.RED}Certbot failed. Enter paths manually.{A.RST}\n")
                cc = "2"
        if cc == "2":
            _w(f" {A.CYN}Certificate file path:{A.RST} ")
            _fl()
            try:
                ds.tls_cert_path = input().strip()
            except (EOFError, KeyboardInterrupt):
                return False
            _w(f" {A.CYN}Private key file path:{A.RST} ")
            _fl()
            try:
                ds.tls_key_path = input().strip()
            except (EOFError, KeyboardInterrupt):
                return False
            if not os.path.isfile(ds.tls_cert_path) or not os.path.isfile(ds.tls_key_path):
                _w(f" {A.RED}Cert/key files not found.{A.RST}\n")
                _fl()
                time.sleep(1)
                return False
    return True


def _tui_deploy_fresh_wizard(ds: "DeployState") -> Optional["DeployState"]:
    """Wizard for generating a fresh Xray server config (supports multiple configs)."""
    if not _tui_deploy_detect_ip(ds):
        return None

    ds.parsed_configs = []
    config_num = 0
    _reality_done = False
    _tls_done = False
    _saved_reality_sni = ""
    _saved_tls_sni = ""

    while True:
        if config_num > 0:
            _w(f"\n {A.BOLD}{A.CYN}── Config #{config_num + 1} ──{A.RST}\n")

        # Protocol
        _w(f"\n {A.BOLD}Protocol:{A.RST}\n")
        _w(f"  {A.CYN}1{A.RST}. VLESS {A.GRN}(recommended){A.RST}\n")
        _w(f"  {A.CYN}2{A.RST}. VMess\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            proto = input().strip() or "1"
        except (EOFError, KeyboardInterrupt):
            break
        protocol = "vmess" if proto == "2" else "vless"

        # Security
        _w(f"\n {A.BOLD}Security:{A.RST}\n")
        _w(f"  {A.CYN}1{A.RST}. REALITY (no certs needed) {A.GRN}(recommended){A.RST}\n")
        _w(f"  {A.CYN}2{A.RST}. TLS (needs domain + certificate)\n")
        _w(f"  {A.CYN}3{A.RST}. None (no encryption)\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            sec_choice = input().strip() or "1"
        except (EOFError, KeyboardInterrupt):
            break
        security = {"1": "reality", "2": "tls", "3": "none"}.get(sec_choice, "reality")

        if security == "reality" and protocol == "vmess":
            _w(f" {A.YEL}REALITY requires VLESS. Switching to VLESS.{A.RST}\n")
            protocol = "vless"

        # Transport
        _w(f"\n {A.BOLD}Transport:{A.RST}\n")
        if security == "reality":
            _w(f"  {A.CYN}1{A.RST}. TCP (+ XTLS Vision) {A.GRN}(recommended for REALITY){A.RST}\n")
            _w(f"  {A.CYN}2{A.RST}. gRPC\n")
            _w(f"  {A.CYN}3{A.RST}. H2\n")
        else:
            _w(f"  {A.CYN}1{A.RST}. TCP\n")
            _w(f"  {A.CYN}2{A.RST}. WebSocket {A.GRN}(CDN-compatible){A.RST}\n")
            _w(f"  {A.CYN}3{A.RST}. gRPC {A.GRN}(CDN-compatible){A.RST}\n")
            _w(f"  {A.CYN}4{A.RST}. H2\n")
            _w(f"  {A.CYN}5{A.RST}. XHTTP {A.GRN}(CDN-compatible){A.RST}\n")
        _w(f" Choice [1]: ")
        _fl()
        try:
            trans_choice = input().strip() or "1"
        except (EOFError, KeyboardInterrupt):
            break
        if security == "reality":
            transport = {"1": "tcp", "2": "grpc", "3": "h2"}.get(trans_choice, "tcp")
        else:
            transport = {"1": "tcp", "2": "ws", "3": "grpc", "4": "h2", "5": "xhttp"}.get(trans_choice, "tcp")

        # Port
        if config_num == 0:
            _w(f"\n {A.BOLD}Port [443]:{A.RST} ")
            _fl()
            try:
                port_input = input().strip() or "443"
            except (EOFError, KeyboardInterrupt):
                break
            try:
                port = int(port_input)
                if not (1 <= port <= 65535):
                    port = 443
            except ValueError:
                port = 443
            ds.listen_port = port

            # Check if port is free
            if not deploy_check_port(port):
                _w(f" {A.YEL}Warning: port {port} is already in use by another process{A.RST}\n")
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    break
                if _pc not in ("y", "yes"):
                    break
        else:
            port = ds.listen_port + config_num
            _w(f"\n {A.DIM}Port: {port}{A.RST}\n")

        # SNI / domain
        sni = ""
        if security == "reality":
            if _saved_reality_sni and config_num > 0:
                sni = _saved_reality_sni
                _w(f"\n {A.DIM}REALITY dest: {sni} (reusing){A.RST}\n")
            else:
                _w(f"\n {A.BOLD}REALITY dest domain [www.google.com]:{A.RST} ")
                _fl()
                try:
                    sni = input().strip() or "www.google.com"
                except (EOFError, KeyboardInterrupt):
                    break
                _saved_reality_sni = sni
        elif security == "tls":
            if _saved_tls_sni and config_num > 0:
                sni = _saved_tls_sni
                _w(f"\n {A.DIM}TLS domain: {sni} (reusing){A.RST}\n")
            else:
                _w(f"\n {A.BOLD}Domain for TLS certificate:{A.RST} ")
                _fl()
                try:
                    sni = input().strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not sni:
                    _w(f" {A.RED}Domain required for TLS.{A.RST}\n")
                    _fl()
                    time.sleep(1)
                    break
                _saved_tls_sni = sni
                ds.tls_domain = sni

        # Generate UUID
        uuid_val = deploy_generate_uuid()
        _w(f"\n {A.DIM}Generated UUID: {uuid_val}{A.RST}\n")

        # Generate REALITY keys (once)
        if security == "reality" and not _reality_done:
            _w(f" {A.DIM}Generating REALITY keys...{A.RST}")
            _fl()
            xray_bin = xray_find_binary() or ""
            if not xray_bin:
                _w(f" {A.YEL}installing Xray first...{A.RST}")
                _fl()
                xray_bin = xray_install() or ""
            if not xray_bin:
                _w(f" {A.RED}Failed to install Xray.{A.RST}\n")
                _fl()
                time.sleep(2)
                break
            priv, pub = deploy_generate_reality_keys(xray_bin)
            if not priv or not pub:
                _w(f" {A.RED}Key generation failed.{A.RST}\n")
                _fl()
                time.sleep(2)
                break
            ds.reality_private_key = priv
            ds.reality_public_key = pub
            ds.reality_short_id = deploy_generate_short_id()
            _w(f" {A.GRN}OK{A.RST}\n")
            _reality_done = True
        elif security == "reality":
            _w(f" {A.DIM}Reusing REALITY keys{A.RST}\n")

        # Handle TLS certs (once)
        if security == "tls" and not _tls_done:
            _tmp_parsed = {"security": "tls", "sni": sni, "host": sni}
            if not _tui_deploy_handle_security(_tmp_parsed, ds):
                break
            _tls_done = True
        elif security == "tls":
            _w(f" {A.DIM}Reusing TLS certificate{A.RST}\n")

        # Build this config
        parsed = deploy_fresh_config(protocol, transport, security, port, uuid_val, sni, ds)
        parsed["port"] = port
        ds.parsed_configs.append(parsed)
        config_num += 1

        _w(f"\n {A.GRN}Config #{config_num} added: {protocol}/{transport}/{security} on port {port}{A.RST}\n")
        _w(f"\n {A.CYN}Add another config? [y/N]:{A.RST} ")
        _fl()
        try:
            again = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if again not in ("y", "yes"):
            break

    if not ds.parsed_configs:
        return None
    build_server_config(ds)
    return ds


def _tui_deploy_from_uri(ds: "DeployState") -> Optional["DeployState"]:
    """Deploy from an existing VLESS/VMess URI."""
    _w(f"\n {A.BOLD}Paste VLESS/VMess URI:{A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None

    parsed = parse_vless_full(uri) or parse_vmess_full(uri)
    if not parsed:
        _w(f" {A.RED}Invalid VLESS/VMess URI.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    ds.source_uris = [uri]
    ds.parsed_configs = [parsed]

    if not _tui_deploy_detect_ip(ds):
        return None

    try:
        ds.listen_port = int(parsed.get("port", 443))
    except (ValueError, TypeError):
        ds.listen_port = 443
    if not (1 <= ds.listen_port <= 65535):
        ds.listen_port = 443
    _w(f" {A.BOLD}Port [{ds.listen_port}]:{A.RST} ")
    _fl()
    try:
        port_in = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if port_in:
        try:
            pv = int(port_in)
            if 1 <= pv <= 65535:
                ds.listen_port = pv
        except ValueError:
            pass

    # Reject VMess + REALITY (not supported by Xray)
    if parsed.get("protocol") == "vmess" and parsed.get("security") == "reality":
        _w(f" {A.RED}VMess + REALITY is not supported. Use VLESS instead.{A.RST}\n")
        _fl()
        time.sleep(2)
        return None

    if not _tui_deploy_handle_security(parsed, ds):
        return None

    parsed["address"] = ds.server_ip
    build_server_config(ds)
    return ds


def _tui_deploy_from_file(ds: "DeployState") -> Optional["DeployState"]:
    """Deploy from a file of URIs."""
    _w(f" {A.CYN}File path:{A.RST} ")
    _fl()
    try:
        path = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not os.path.isfile(path):
        _w(f" {A.RED}File not found.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    configs = load_input(path)
    if not configs:
        _w(f" {A.RED}No valid configs found.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    for c in configs:
        if c.original_uri:
            parsed = parse_vless_full(c.original_uri) or parse_vmess_full(c.original_uri)
            if parsed:
                ds.source_uris.append(c.original_uri)
                ds.parsed_configs.append(parsed)

    if not ds.parsed_configs:
        _w(f" {A.RED}No parseable VLESS/VMess URIs in file.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None

    _w(f" {A.GRN}Found {len(ds.parsed_configs)} config(s){A.RST}\n")

    if not _tui_deploy_detect_ip(ds):
        return None

    try:
        ds.listen_port = int(ds.parsed_configs[0].get("port", 443))
    except (ValueError, TypeError):
        ds.listen_port = 443
    if not (1 <= ds.listen_port <= 65535):
        ds.listen_port = 443
    _w(f" {A.BOLD}Port [{ds.listen_port}]:{A.RST} ")
    _fl()
    try:
        port_in = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if port_in:
        try:
            pv = int(port_in)
            if 1 <= pv <= 65535:
                ds.listen_port = pv
        except ValueError:
            pass

    # Filter out VMess + REALITY (not supported) -- keep source_uris in sync
    paired = [(u, p) for u, p in zip(ds.source_uris, ds.parsed_configs)
              if not (p.get("protocol") == "vmess" and p.get("security") == "reality")]
    skipped = len(ds.parsed_configs) - len(paired)
    if skipped:
        _w(f" {A.YEL}Skipped {skipped} VMess+REALITY config(s) (not supported){A.RST}\n")
    if not paired:
        _w(f" {A.RED}No valid configs after filtering.{A.RST}\n")
        _fl()
        time.sleep(1)
        return None
    ds.source_uris = [u for u, _ in paired]
    ds.parsed_configs = [p for _, p in paired]

    # Warn about mixed security types
    sec_types = set(p.get("security", "none") for p in ds.parsed_configs)
    if len(sec_types) > 1:
        _w(f" {A.YEL}Warning: mixed security types ({', '.join(sec_types)}). "
           f"Keys/certs configured for first config only.{A.RST}\n")
        _fl()

    if not _tui_deploy_handle_security(ds.parsed_configs[0], ds):
        return None

    for p in ds.parsed_configs:
        p["address"] = ds.server_ip

    build_server_config(ds)
    return ds


def tui_deploy_input() -> Optional["DeployState"]:
    """Interactive wizard for server deployment.
    Returns a configured DeployState or None.
    """
    _w(A.SHOW)
    _w(f"\n {A.BOLD}{A.CYN}Deploy Xray Server{A.RST}\n")
    _w(f" {A.YEL}For:{A.RST} You have a Linux VPS and want to install xray on it (no tunnel).\n")
    _w(f" {A.DIM}Installs xray, generates config, starts the service. Run this ON your server.{A.RST}\n\n")

    ok, err = deploy_check_prerequisites()
    if not ok:
        _w(f" {A.RED}ERROR: {err}{A.RST}\n")
        _fl()
        time.sleep(3)
        return None

    ds = DeployState()

    ds.fresh_mode = True
    return _tui_deploy_fresh_wizard(ds)


async def _tui_run_deploy(args, preloaded_uri: str = ""):
    """Run the deploy flow inside TUI."""
    if preloaded_uri:
        ds = DeployState()
        parsed = parse_vless_full(preloaded_uri) or parse_vmess_full(preloaded_uri)
        if parsed:
            ds.source_uris = [preloaded_uri]
            ds.parsed_configs = [parsed]
            _w(A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Deploy Xray Server{A.RST}\n")
            _w(f" {A.DIM}Deploying best config from xray test.{A.RST}\n")
            ok, err = deploy_check_prerequisites()
            if not ok:
                _w(f" {A.RED}ERROR: {err}{A.RST}\n")
                _fl()
                time.sleep(3)
                return
            if not _tui_deploy_detect_ip(ds):
                return
            try:
                ds.listen_port = int(parsed.get("port", 443))
            except (ValueError, TypeError):
                ds.listen_port = 443
            if not (1 <= ds.listen_port <= 65535):
                ds.listen_port = 443
            if not deploy_check_port(ds.listen_port):
                _w(f" {A.YEL}Warning: port {ds.listen_port} is already in use{A.RST}\n")
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    return
                if _pc not in ("y", "yes"):
                    return
            if parsed.get("protocol") == "vmess" and parsed.get("security") == "reality":
                _w(f" {A.RED}VMess + REALITY is not supported.{A.RST}\n")
                _fl()
                time.sleep(2)
                return
            if not _tui_deploy_handle_security(parsed, ds):
                return
            parsed["address"] = ds.server_ip
            build_server_config(ds)
        else:
            _w(f" {A.RED}Failed to parse config URI.{A.RST}\n")
            _fl()
            time.sleep(2)
            return
    else:
        ds = tui_deploy_input()
    if ds is None:
        return

    _w(A.SHOW)
    _w(f"\n {A.BOLD}{A.CYN}Deploying Xray Server{A.RST}\n")
    _w(f" {A.DIM}{'=' * 50}{A.RST}\n\n")

    def tui_print(msg):
        _w(f"{msg}\n")
        _fl()

    success = deploy_run_pipeline(ds, tui_print)

    if success:
        _w(f"\n {A.GRN}{'=' * 50}{A.RST}\n")
        _w(f" {A.BOLD}{A.GRN}Deploy successful!{A.RST}\n")
        _w(f" {A.GRN}{'=' * 50}{A.RST}\n\n")
        _w(f" {A.BOLD}Server:{A.RST} {ds.server_ip}:{ds.listen_port}\n")
        _w(f" {A.BOLD}Config:{A.RST} {DEPLOY_XRAY_CONFIG}\n")
        _w(f" {A.BOLD}Status:{A.RST} systemctl status xray\n\n")

        _w(f" {A.BOLD}{A.CYN}Client URIs (paste into v2rayNG / Nekobox / Hiddify):{A.RST}\n\n")
        for uri in ds.client_uris:
            _w(f" {A.GRN}{uri}{A.RST}\n\n")

        save_path = deploy_save_results(ds)
        if save_path:
            _w(f" {A.DIM}Saved to: {save_path}{A.RST}\n")
        else:
            _w(f" {A.RED}Could not save deploy results.{A.RST}\n")
    else:
        _w(f"\n {A.RED}Deploy failed: {ds.error}{A.RST}\n")
        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    # Post-deploy interactive menu
    while True:
        _w(f"\n {A.CYN}[V]{A.RST} View configs/URIs  ")
        _w(f"{A.CYN}[M]{A.RST} Connection Manager  ")
        _w(f"{A.CYN}[Q]{A.RST} Back to menu\n")
        _w(f" Choice: ")
        _fl()
        post_key = _read_key_blocking()
        if isinstance(post_key, str):
            post_key = post_key.lower()
        if post_key in ("q", "esc", "ctrl-c", "b"):
            break
        elif post_key == "v":
            _w(f"\n {A.BOLD}{A.CYN}Client URIs:{A.RST}\n\n")
            for uri in ds.client_uris:
                _w(f" {A.GRN}{uri}{A.RST}\n\n")
            if save_path:
                _w(f" {A.DIM}Saved to: {save_path}{A.RST}\n")
            _fl()
        elif post_key == "m":
            await _tui_connection_manager(args)
            break


# ─── Uninstall ─────────────────────────────────────────────────────────────────


def _uninstall_all() -> Tuple[bool, str]:
    """Remove everything cfray installed on this system."""
    _out: list = []
    _had_errors = False

    def _log(msg: str):
        _out.append(msg)
        print(f"  {msg}")

    def _log_err(msg: str):
        nonlocal _had_errors
        _had_errors = True
        _out.append(msg)
        print(f"  ERROR: {msg}")

    if sys.platform in ("win32", "darwin"):
        if os.path.isdir(XRAY_HOME):
            shutil.rmtree(XRAY_HOME, ignore_errors=True)
            if os.path.isdir(XRAY_HOME):
                _log_err(f"Could not fully remove {XRAY_HOME}")
            else:
                _log(f"Removed {XRAY_HOME}")
        else:
            _log("Nothing to remove (no local cfray directory)")
        return not _had_errors, "; ".join(_out)

    # --- 1. Stop xray service ---
    for action in ["stop", "disable"]:
        try:
            subprocess.run(["systemctl", action, "xray"],
                           capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
    _log("Stopped and disabled xray service")

    # --- 2. Remove xray server files ---
    _removed = []
    for path in [DEPLOY_XRAY_SERVICE, DEPLOY_XRAY_BIN]:
        if os.path.isfile(path):
            try:
                os.remove(path)
                _removed.append(path)
            except OSError:
                _log_err(f"Could not remove {path}")
    for dpath in [DEPLOY_XRAY_CONFIG_DIR, DEPLOY_XRAY_SHARE]:
        if os.path.isdir(dpath):
            shutil.rmtree(dpath, ignore_errors=True)
            if os.path.isdir(dpath):
                _log_err(f"Could not fully remove {dpath}")
            else:
                _removed.append(dpath)
    if _removed:
        _log(f"Removed xray server: {', '.join(os.path.basename(p) for p in _removed)}")
    elif not _had_errors:
        _log("No xray server files found")

    # --- 3. Reload systemd ---
    try:
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass

    # --- 4. Remove local client dir (~/.cfray/) ---
    if os.path.isdir(XRAY_HOME):
        shutil.rmtree(XRAY_HOME, ignore_errors=True)
        if os.path.isdir(XRAY_HOME):
            _log_err(f"Could not fully remove {XRAY_HOME}")
        else:
            _log(f"Removed {XRAY_HOME}")
    else:
        _log(f"No local directory at {XRAY_HOME}")

    return not _had_errors, "; ".join(_out)


# ─── Connection Manager (Direct JSON mode) ───────────────────────────────────


async def _tui_connection_manager(args):
    """TUI for managing xray server configs and connections."""
    if sys.platform in ("win32", "darwin"):
        _w(A.SHOW)
        _w(f"\n {A.RED}Connection Manager requires Linux (systemctl).{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    _cm_server_ip = ""  # Cached; detected on first need

    while True:
        # Direct JSON mode only
        config = _read_server_config()
        if config is not None:
            ib_val = config.get("inbounds")
            if not isinstance(ib_val, list):
                ib_val = []
                config["inbounds"] = ib_val
            inbounds = ib_val
        else:
            inbounds = []
        inbound_indices = [i for i, ib in enumerate(inbounds) if isinstance(ib, dict)]

        summaries = [_parse_inbound_summary(inbounds[i]) for i in inbound_indices]

        # Service status
        xray_running = False
        try:
            r = subprocess.run(["systemctl", "is-active", "xray"],
                                capture_output=True, text=True, timeout=5)
            xray_running = r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            pass

        _w(A.CLR + A.HOME + A.SHOW)
        W, _ = term_size()
        W = max(60, W - 2)
        out = []
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")
        _cmhdr = f" {A.BOLD}{A.CYN}Connection Manager{A.RST}"
        out.append(f"{A.CYN}|{A.RST}{_cmhdr}{' ' * max(0, W - _vl(_cmhdr))}{A.CYN}|{A.RST}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        # Service status
        def bx(txt):
            vlen = _vl(txt)
            if vlen > W:
                vis = 0
                i = 0
                while i < len(txt) and vis < W - 1:
                    if txt[i] == '\033' and i + 1 < len(txt) and txt[i + 1] == '[':
                        j = i + 2
                        while j < len(txt) and txt[j] != 'm':
                            j += 1
                        i = j + 1
                    else:
                        vis += _char_width(txt[i])
                        i += 1
                txt = txt[:i] + A.RST + "..."
                vlen = _vl(txt)
            pad = ' ' * max(0, W - vlen)
            out.append(f"{A.CYN}|{A.RST}{txt}{pad}{A.CYN}|{A.RST}")

        xray_dot = f"{A.GRN}*{A.RST} running" if xray_running else f"{A.RED}*{A.RST} stopped"
        bx(f"  Xray Service: {xray_dot}  {A.DIM}(system){A.RST}")

        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")

        # Inbounds
        _has_inbounds = bool(summaries)
        if not config:
            bx(f"  {A.DIM}No xray server config found.{A.RST}")
            bx(f"  {A.DIM}Use [D] Deploy to set up xray first.{A.RST}")
        elif not summaries:
            bx(f"  {A.DIM}No inbounds configured.{A.RST}")
        else:
            bx(f"  {A.BOLD}Server Inbounds ({len(summaries)}){A.RST}")
            bx(f"  {A.DIM}{'-' * (W - 4)}{A.RST}")
            hdr = f"  {'#':>2}  {'Protocol':<10} {'Port':>6} {'Transport':<12} {'Security':<10} {'Users':>5}"
            bx(f"{A.BOLD}{hdr}{A.RST}")
            for i, s in enumerate(summaries[:20]):
                line = f"  {i+1:>2}  {s['protocol']:<10} {s['port']:>6} {s['transport']:<12} {s['security']:<10} {s['users']:>5}"
                bx(line)

        out.append(f"{A.CYN}{'-' * (W + 2)}{A.RST}")

        # Footer
        parts = []
        if _has_inbounds:
            parts.append(f"{A.CYN}[V]{A.RST} View")
            parts.append(f"{A.CYN}[S]{A.RST} Show URIs")
            parts.append(f"{A.CYN}[U]{A.RST} Add user")
            parts.append(f"{A.CYN}[X]{A.RST} Remove")
        parts.append(f"{A.CYN}[A]{A.RST} Add inbound")
        parts.append(f"{A.CYN}[R]{A.RST} Restart xray")
        parts.append(f"{A.CYN}[L]{A.RST} Logs")
        parts.append(f"{A.CYN}[D]{A.RST} Uninstall")
        parts.append(f"{A.CYN}[B]{A.RST} Back")
        bx(f"  {'  '.join(parts)}")
        out.append(f"{A.CYN}{'=' * (W + 2)}{A.RST}")

        _w("\n".join(out) + "\n")
        _fl()

        key = _read_key_blocking()
        if isinstance(key, str):
            key = key.lower()
        if key in ("b", "esc", "q", "ctrl-c"):
            return

        if key == "r":
            _w(f"\n {A.DIM}Restarting xray...{A.RST}\n")
            _fl()
            ok, msg = _restart_xray_service()
            if ok:
                _w(f" {A.GRN}{msg}{A.RST}\n")
            else:
                _w(f" {A.RED}{msg}{A.RST}\n")
            _fl()
            time.sleep(1.5)
            continue

        if key == "l":
            _w(A.CLR + A.HOME)
            _w(f"\n {A.BOLD}{A.CYN}xray Logs (last 30 lines){A.RST}\n")
            _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
            _fl()
            try:
                result = subprocess.run(
                    ["journalctl", "-u", "xray", "-n", "30", "--no-pager"],
                    capture_output=True, text=True, timeout=10,
                )
                _w(result.stdout[:3000] if result.stdout else f" {A.DIM}(no logs){A.RST}\n")
            except (OSError, subprocess.SubprocessError) as e:
                _w(f" {A.RED}Failed to read logs: {e}{A.RST}\n")
            _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            continue

        if key == "d":
            _w(A.SHOW)
            _w(f"\n {A.RED}{A.BOLD}Uninstall Xray completely?{A.RST}\n")
            _w(f" {A.DIM}This will stop xray, remove the binary, config, and systemd service.{A.RST}\n")
            _w(f"\n {A.RED}Type 'uninstall' to confirm:{A.RST} ")
            _fl()
            try:
                confirm = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if confirm == "uninstall":
                _w(f"\n {A.DIM}Uninstalling...{A.RST}\n")
                _fl()
                ok, msg = _uninstall_all()
                if ok:
                    _w(f"\n {A.GRN}{msg}{A.RST}\n")
                else:
                    _w(f"\n {A.RED}{msg}{A.RST}\n")
                _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
                _fl()
                _read_key_blocking()
                return
            else:
                _w(f" {A.DIM}Cancelled.{A.RST}\n")
                _fl()
                time.sleep(1)
            continue

        if key == "v" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(f"View which inbound? [1-{len(summaries)}]:")
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        ib_data = inbounds[inbound_indices[sel]]
                        _w(A.CLR + A.HOME)
                        _w(f"\n {A.BOLD}{A.CYN}Inbound #{sel+1}{A.RST}\n")
                        _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
                        pretty = json.dumps(ib_data, indent=2, ensure_ascii=False)
                        _w(f"{pretty[:3000]}\n")
                        _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
                        _fl()
                        _read_key_blocking()
                except (ValueError, IndexError):
                    pass
            continue

        if key == "s" and summaries:
            _w(A.CLR + A.HOME)
            _w(f"\n {A.BOLD}{A.CYN}All Client URIs{A.RST}\n")
            _w(f" {A.DIM}{'-' * 50}{A.RST}\n\n")
            if not _cm_server_ip:
                _cm_server_ip = deploy_detect_server_ip() or "<server-ip>"
            for i, s in enumerate(summaries):
                real_idx = inbound_indices[i]
                ib_data = inbounds[real_idx]
                settings = ib_data.get("settings") or {}
                clients = settings.get("clients") or []
                _w(f" {A.BOLD}Inbound #{i+1}{A.RST} ({s['protocol']}:{s['port']} {s['transport']}/{s['security']})\n")
                for cl in clients:
                    _cl_uuid = cl.get("id", "")
                    if _cl_uuid:
                        _cl_uri = _cm_build_client_uri(ib_data, _cl_uuid, _cm_server_ip)
                        if _cl_uri:
                            _w(f"   {A.GRN}{_cl_uri}{A.RST}\n")
                _w("\n")
            _w(f" {A.DIM}Press any key to go back...{A.RST}\n")
            _fl()
            _read_key_blocking()
            continue

        if key == "u" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(f"Add user to which inbound? [1-{len(summaries)}]:")
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        new_uuid = deploy_generate_uuid()
                        _user_add_ok = False
                        real_idx = inbound_indices[sel]
                        ib = inbounds[real_idx]
                        settings = ib.get("settings")
                        if not isinstance(settings, dict):
                            settings = {}
                            ib["settings"] = settings
                        clients = settings.get("clients")
                        if not isinstance(clients, list):
                            clients = []
                            settings["clients"] = clients
                        proto = ib.get("protocol", "vless")
                        new_client = {"id": new_uuid}
                        if proto == "vmess":
                            new_client["alterId"] = 0
                        clients.append(new_client)
                        if _write_server_config(config):
                            ok, msg = _restart_xray_service()
                            _w(f"\n {A.GRN}User added: {new_uuid}{A.RST}\n")
                            if not ok:
                                _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                            _user_add_ok = True
                        else:
                            clients.pop()
                            _w(f"\n {A.RED}Failed to write config (run as root?){A.RST}\n")
                        if _user_add_ok:
                            if not _cm_server_ip:
                                _cm_server_ip = deploy_detect_server_ip() or "<server-ip>"
                            _u_uri = _cm_build_client_uri(ib, new_uuid, _cm_server_ip)
                            if _u_uri:
                                _w(f"\n {A.BOLD}{A.CYN}Client URI:{A.RST}\n")
                                _w(f" {A.GRN}{_u_uri}{A.RST}\n")
                        _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
                        _fl()
                        _wait_any_key()
                except (ValueError, IndexError):
                    pass
            continue

        if key == "x" and summaries:
            _w(A.SHOW)
            which = _tui_prompt_text(f"Remove which inbound? [1-{len(summaries)}]:")
            if which:
                try:
                    sel = int(which) - 1
                    if 0 <= sel < len(summaries):
                        s = summaries[sel]
                        _w(f" {A.YEL}Remove {s['protocol']}:{s['port']}? [y/N]:{A.RST} ")
                        _fl()
                        try:
                            confirm = input().strip().lower()
                        except (EOFError, KeyboardInterrupt):
                            confirm = ""
                        if confirm in ("y", "yes"):
                            real_idx = inbound_indices[sel]
                            removed = inbounds[real_idx]
                            inbounds.pop(real_idx)
                            if _write_server_config(config):
                                ok, msg = _restart_xray_service()
                                _w(f" {A.GRN}Inbound removed.{A.RST}\n")
                                if not ok:
                                    _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                            else:
                                # Restore in-memory state on write failure
                                inbounds.insert(real_idx, removed)
                                _w(f" {A.RED}Failed to write config (run as root?){A.RST}\n")
                            _fl()
                            time.sleep(1.5)
                except (ValueError, IndexError):
                    pass
            continue

        if key == "a":
            # Add inbound wizard
            _w(A.CLR + A.HOME + A.SHOW)
            _w(f"\n {A.BOLD}{A.CYN}Add New Inbound{A.RST}\n")
            _w(f" {A.DIM}{'-' * 40}{A.RST}\n\n")
            _w(f"  {A.CYN}1{A.RST}. VLESS\n")
            _w(f"  {A.CYN}2{A.RST}. VMess\n")
            _w(f"\n Protocol [1]: ")
            _fl()
            try:
                proto_ch = input().strip() or "1"
            except (EOFError, KeyboardInterrupt):
                continue
            protocol = "vmess" if proto_ch == "2" else "vless"

            _w(f" Port [443]: ")
            _fl()
            try:
                port_str = input().strip() or "443"
                new_port = int(port_str)
                if not (1 <= new_port <= 65535):
                    _w(f" {A.YEL}Invalid port, using 443{A.RST}\n")
                    new_port = 443
            except (EOFError, KeyboardInterrupt):
                continue
            except ValueError:
                _w(f" {A.YEL}Invalid port, using 443{A.RST}\n")
                new_port = 443
            # Check for port conflicts -- our own inbounds
            used_ports = {int(ib.get("port", 0)) for ib in inbounds if isinstance(ib, dict) and ib.get("port")}
            if new_port in used_ports:
                _w(f" {A.YEL}Warning: port {new_port} already used by another inbound{A.RST}\n")
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    continue
                if _pc not in ("y", "yes"):
                    continue
            elif not deploy_check_port(new_port):
                _w(f" {A.YEL}Warning: port {new_port} is already in use by another process{A.RST}\n")
                _w(f" {A.CYN}Continue anyway? [y/N]:{A.RST} ")
                _fl()
                try:
                    _pc = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    continue
                if _pc not in ("y", "yes"):
                    continue

            _w(f"\n  {A.CYN}1{A.RST}. TCP\n")
            _w(f"  {A.CYN}2{A.RST}. WebSocket (ws)\n")
            _w(f"  {A.CYN}3{A.RST}. XHTTP (xhttp)\n")
            _w(f"  {A.CYN}4{A.RST}. gRPC\n")
            _w(f"  {A.CYN}5{A.RST}. HTTP/2 (h2)\n")
            _w(f"\n Transport [1]: ")
            _fl()
            try:
                tr_ch = input().strip() or "1"
            except (EOFError, KeyboardInterrupt):
                continue
            tr_map = {"1": "tcp", "2": "ws", "3": "xhttp", "4": "grpc", "5": "h2"}
            transport = tr_map.get(tr_ch, "tcp")

            _w(f"\n  {A.CYN}1{A.RST}. REALITY\n")
            _w(f"  {A.CYN}2{A.RST}. TLS\n")
            _w(f"  {A.CYN}3{A.RST}. None\n")
            _w(f"\n Security [3]: ")
            _fl()
            try:
                sec_ch = input().strip() or "3"
            except (EOFError, KeyboardInterrupt):
                continue
            sec_map = {"1": "reality", "2": "tls", "3": "none"}
            security = sec_map.get(sec_ch, "none")

            # REALITY needs x25519 keys
            _reality_priv = _reality_pub = _reality_sid = _rsni = ""
            _tls_cert = _tls_key = ""
            if security == "reality":
                _xbin = xray_find_binary(None)
                if not _xbin:
                    _w(f" {A.RED}REALITY requires xray binary for key generation.{A.RST}\n")
                    _w(f" {A.DIM}Falling back to no security. Use Deploy for REALITY.{A.RST}\n")
                    _fl()
                    time.sleep(1.5)
                    security = "none"
                else:
                    _reality_priv, _reality_pub = deploy_generate_reality_keys(_xbin)
                    if not _reality_priv:
                        _w(f" {A.RED}Key generation failed. Falling back to none.{A.RST}\n")
                        _fl()
                        time.sleep(1.5)
                        security = "none"
                    else:
                        _reality_sid = deploy_generate_short_id()
                        _w(f" {A.DIM}SNI for REALITY [www.google.com]:{A.RST} ")
                        _fl()
                        try:
                            _rsni = input().strip() or "www.google.com"
                        except (EOFError, KeyboardInterrupt):
                            _rsni = "www.google.com"
            elif security == "tls":
                _w(f" {A.DIM}TLS cert path [/usr/local/etc/xray/cert.pem]:{A.RST} ")
                _fl()
                try:
                    _tls_cert = input().strip() or "/usr/local/etc/xray/cert.pem"
                except (EOFError, KeyboardInterrupt):
                    _tls_cert = "/usr/local/etc/xray/cert.pem"
                _w(f" {A.DIM}TLS key path  [/usr/local/etc/xray/key.pem]:{A.RST} ")
                _fl()
                try:
                    _tls_key = input().strip() or "/usr/local/etc/xray/key.pem"
                except (EOFError, KeyboardInterrupt):
                    _tls_key = "/usr/local/etc/xray/key.pem"

            new_uuid = deploy_generate_uuid()
            _w(f"\n {A.DIM}Generated UUID: {new_uuid}{A.RST}\n")

            # Build inbound manually (use uuid4 suffix for unique tag)
            _tag_id = deploy_generate_uuid()[:8]
            new_inbound: dict = {
                "tag": f"inbound-{_tag_id}",
                "port": new_port,
                "listen": "::",
                "protocol": protocol,
                "settings": {},
                "streamSettings": {"network": transport, "security": security},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            }

            # Client
            client_entry: dict = {"id": new_uuid}
            if protocol == "vmess":
                client_entry["alterId"] = 0
                new_inbound["settings"] = {"clients": [client_entry]}
            else:
                new_inbound["settings"] = {
                    "clients": [client_entry],
                    "decryption": "none",
                }

            # Transport settings
            stream = new_inbound["streamSettings"]
            if transport == "ws":
                stream["wsSettings"] = {"path": "/ws"}
            elif transport in ("xhttp", "splithttp"):
                stream["network"] = "xhttp"
                stream["xhttpSettings"] = {"path": "/xhttp"}
            elif transport == "grpc":
                stream["grpcSettings"] = {"serviceName": "grpc"}
            elif transport in ("h2", "http"):
                stream["httpSettings"] = {"host": [], "path": "/h2"}

            # Security settings
            if security == "reality" and _reality_priv:
                stream["realitySettings"] = {
                    "show": False,
                    "dest": f"{_rsni}:443",
                    "xver": 0,
                    "serverNames": [_rsni],
                    "privateKey": _reality_priv,
                    "shortIds": [_reality_sid],
                }
                # VLESS+REALITY+TCP needs flow
                if protocol == "vless" and transport == "tcp":
                    client_entry["flow"] = "xtls-rprx-vision"
                _w(f" {A.DIM}Public key: {_reality_pub}{A.RST}\n")
                _w(f" {A.DIM}Short ID:   {_reality_sid}{A.RST}\n")
            elif security == "tls":
                stream["tlsSettings"] = {
                    "certificates": [{
                        "certificateFile": _tls_cert,
                        "keyFile": _tls_key,
                    }],
                }

            if config is None:
                config = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [],
                    "outbounds": [
                        {"tag": "direct", "protocol": "freedom"},
                        {"tag": "block", "protocol": "blackhole"},
                    ],
                    "routing": {
                        "domainStrategy": "AsIs",
                        "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}],
                    },
                }
                inbounds = config["inbounds"]

            _add_ok = False
            inbounds.append(new_inbound)
            if _write_server_config(config):
                ok, msg = _restart_xray_service()
                _w(f"\n {A.GRN}Inbound added: {protocol}:{new_port} ({transport}/{security}){A.RST}\n")
                if not ok:
                    _w(f" {A.YEL}Warning: {msg}{A.RST}\n")
                _add_ok = True
            else:
                inbounds.pop()
                _w(f"\n {A.RED}Failed to write config (run as root?){A.RST}\n")

            # Generate and display client URI after successful add
            if _add_ok:
                if not _cm_server_ip:
                    _cm_server_ip = deploy_detect_server_ip() or "<server-ip>"
                _uri_sni = _rsni or ""
                _uri_parsed = {
                    "protocol": protocol,
                    "address": _cm_server_ip,
                    "port": new_port,
                    "uuid": new_uuid,
                    "type": transport,
                    "security": security,
                    "fp": "chrome",
                }
                if transport == "ws":
                    _uri_parsed["path"] = "/ws"
                    _uri_parsed["host"] = _uri_sni
                elif transport in ("xhttp", "splithttp"):
                    _uri_parsed["type"] = "xhttp"
                    _uri_parsed["path"] = "/xhttp"
                elif transport == "grpc":
                    _uri_parsed["serviceName"] = "grpc"
                elif transport in ("h2", "http"):
                    _uri_parsed["path"] = "/h2"
                if security == "reality" and _reality_pub:
                    _uri_parsed["pbk"] = _reality_pub
                    _uri_parsed["sid"] = _reality_sid
                    _uri_parsed["sni"] = _rsni
                    if protocol == "vless" and transport == "tcp":
                        _uri_parsed["flow"] = "xtls-rprx-vision"
                elif security == "tls":
                    _uri_parsed["sni"] = _uri_sni
                _uri_tag = f"cfray-{protocol}-{new_port}"
                try:
                    _client_uri = _build_uri(_uri_parsed, _uri_sni, _uri_tag)
                    _w(f"\n {A.BOLD}{A.CYN}Client URI:{A.RST}\n")
                    _w(f" {A.GRN}{_client_uri}{A.RST}\n")
                except (KeyError, ValueError, TypeError) as _uri_err:
                    _w(f" {A.DIM}(Could not generate client URI: {_uri_err}){A.RST}\n")

            _w(f"\n {A.DIM}Press any key to continue...{A.RST}\n")
            _fl()
            _wait_any_key()
            continue


# ─── End Xray Server Deploy ──────────────────────────────────────────────


# ─── Worker Proxy ─────────────────────────────────────────────────────────────


def _worker_proxy_generate_script(origin_host: str, origin_port: int,
                                   origin_security: str = "tls") -> str:
    """Generate CF Worker script to proxy WS to an origin behind CF CDN.

    Unlike _cdn_generate_worker_script (which targets a raw IP you own),
    this targets an existing CF-backed host domain.  The Worker rewrites
    the Host header so CF routes the internal fetch to the real origin.
    """
    scheme = "https" if origin_security in ("tls", "reality") else "http"
    port_part = ("" if (scheme == "https" and origin_port == 443)
                      or (scheme == "http" and origin_port == 80)
                 else f":{origin_port}")
    return f"""\
// CFray Worker Proxy — route ANY SNI to origin
// Deploy: dash.cloudflare.com → Workers & Pages → Create → Deploy
// Free tier: 100K requests/day

export default {{
  async fetch(request) {{
    const url = new URL(request.url);
    const origin = "{scheme}://{origin_host}{port_part}" + url.pathname;
    const headers = new Headers(request.headers);
    headers.set("Host", "{origin_host}");
    return fetch(origin, {{
      method: request.method,
      headers: headers,
    }});
  }}
}};"""


async def _tui_worker_proxy(args):
    """Worker Proxy — paste any VLESS URI, deploy a CF Worker, run pipeline
    with ALL CF SNIs enabled.

    CF enforces zone matching (SNI must match Host domain's zone), so a
    random VLESS config only works with the original SNI.  A CF Worker
    sits in its own zone (*.workers.dev); the Worker rewrites Host to the
    origin domain and proxies internally.  Result: every CF SNI works.
    """
    enable_ansi()
    _w(A.CLR + A.HOME + A.SHOW)
    cols, _ = term_size()
    W = cols - 2

    _w(f"\n{A.CYN}{'=' * (W + 2)}{A.RST}\n")
    _w(f"{A.CYN}|{A.RST} {A.BOLD}{A.WHT}Worker Proxy -- Fresh SNI for Any VLESS Config{A.RST}" +
       " " * max(0, W - 50) + f"{A.CYN}|{A.RST}\n")
    _w(f"{A.CYN}{'=' * (W + 2)}{A.RST}\n\n")

    _w(f" {A.DIM}If the original domain's SNI is blocked by DPI, a CF Worker gives{A.RST}\n")
    _w(f" {A.DIM}you a fresh *.workers.dev SNI. The Worker proxies to the original{A.RST}\n")
    _w(f" {A.DIM}server, so your configs work with a different (unblocked) SNI.{A.RST}\n\n")

    # -- Step 1: Paste VLESS URI --
    _restore_console_input()
    _w(f" {A.BOLD}{A.CYN}[1/3]{A.RST} {A.BOLD}Paste your VLESS config URI:{A.RST}\n")
    _w(f" {A.DIM}(a full vless://... URI){A.RST}\n ")
    _fl()
    try:
        uri = input().strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not uri:
        _w(f"\n {A.RED}Cancelled.{A.RST}\n")
        time.sleep(1)
        return

    parsed = parse_vless_full(uri)
    if not parsed:
        _w(f"\n {A.RED}Invalid VLESS URI.{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    # Must be WS transport
    if parsed.get("type") not in ("ws", "websocket"):
        _w(f"\n {A.RED}Only WebSocket (ws) transport is supported for Worker proxy.{A.RST}\n")
        _w(f" {A.DIM}Your config uses: {parsed.get('type', 'unknown')}{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    # Extract origin info — Host header is what CF uses for internal routing
    origin_host = parsed.get("host") or parsed.get("sni") or parsed.get("address", "")
    origin_port = parsed.get("port", 443)
    ws_path = parsed.get("path", "/")
    uuid_val = parsed.get("uuid", "")
    security = parsed.get("security", "tls")

    _w(f"\n   {A.GRN}Protocol: VLESS  |  Transport: WS  |  Security: {security}{A.RST}\n")
    _w(f"   {A.GRN}Origin host: {origin_host}:{origin_port}  |  Path: {ws_path}{A.RST}\n")
    _w(f"   {A.GRN}UUID: {uuid_val[:8]}...{A.RST}\n\n")

    # -- Step 2: Generate Worker script --
    _w(f" {A.BOLD}{A.CYN}[2/3]{A.RST} {A.BOLD}Worker script generated:{A.RST}\n\n")
    script = _worker_proxy_generate_script(origin_host, origin_port, security)
    _w(f" {A.DIM}{'-' * (W - 2)}{A.RST}\n")
    for line in script.split("\n"):
        _w(f" {A.WHT}{line}{A.RST}\n")
    _w(f" {A.DIM}{'-' * (W - 2)}{A.RST}\n\n")

    _w(f" {A.BOLD}Deploy instructions:{A.RST}\n\n")
    _w(f"   {A.WHT}1.{A.RST} Go to {A.CYN}dash.cloudflare.com{A.RST} -> Workers & Pages -> Create\n")
    _w(f"   {A.WHT}2.{A.RST} Click {A.WHT}\"Create Worker\"{A.RST}, name it anything\n")
    _w(f"   {A.WHT}3.{A.RST} Click {A.WHT}\"Deploy\"{A.RST}, then {A.WHT}\"Edit Code\"{A.RST}\n")
    _w(f"   {A.WHT}4.{A.RST} Delete all default code, paste the script above\n")
    _w(f"   {A.WHT}5.{A.RST} Click {A.WHT}\"Deploy\"{A.RST} again\n")
    _w(f"   {A.WHT}6.{A.RST} Copy your Worker URL (e.g. {A.GRN}my-proxy.username.workers.dev{A.RST})\n\n")

    # -- Step 3: Get Worker URL --
    _flush_stdin()  # drain stale bytes from multi-line URI paste
    _restore_console_input()  # re-enable line editing (arrow keys, backspace)
    _w(f" {A.BOLD}{A.CYN}[3/3]{A.RST} {A.YEL}Enter your Worker URL when deployed{A.RST} (or Enter to skip): ")
    _fl()
    try:
        worker_url = input().strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not worker_url:
        _w(f"\n {A.DIM}Skipped. Deploy the Worker first, then come back.{A.RST}\n")
        _w(f" {A.DIM}Press any key...{A.RST}\n")
        _fl()
        _read_key_blocking()
        return

    # Clean up URL — strip protocol prefix and stale paste garbage
    worker_url = worker_url.replace("https://", "").replace("http://", "").rstrip("/")
    # Multi-line paste can leave stale chars (e.g. "6" from "#polaris\n6")
    # prefixed to the URL.  Strip leading non-letter chars before the domain.
    _m = re.search(r'[a-zA-Z]', worker_url)
    if _m and _m.start() > 0 and ".workers.dev" in worker_url:
        worker_url = worker_url[_m.start():]
    _w(f"\n   {A.GRN}Worker URL: {worker_url}{A.RST}\n")

    # Build new VLESS URI pointing through the Worker
    new_parsed = dict(parsed)
    new_parsed["address"] = worker_url
    new_parsed["host"] = worker_url
    new_parsed["sni"] = worker_url
    new_parsed["port"] = 443
    new_parsed["security"] = "tls"
    new_uri = build_vless_uri(new_parsed, worker_url, "Worker-Proxy")

    _w(f"\n {A.BOLD}New config URI:{A.RST}\n")
    _w(f" {A.GRN}{new_uri}{A.RST}\n\n")

    _w(f" {A.BOLD}{A.CYN}How it works:{A.RST}\n")
    _w(f"   {A.DIM}Client -> any CF IP (SNI={worker_url}) -> CF routes to Worker{A.RST}\n")
    _w(f"   {A.DIM}Worker -> Host={origin_host} -> CF routes to original server{A.RST}\n")
    _w(f"   {A.DIM}Result: fresh *.workers.dev SNI instead of original domain!{A.RST}\n\n")

    # Offer pipeline test
    _w(f" {A.YEL}Run pipeline test with ALL SNIs?{A.RST} [Y/n]: ")
    _fl()
    try:
        ans = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"

    if ans in ("", "y", "yes"):
        re_parsed = parse_vless_full(new_uri)
        if re_parsed:
            # CF zone matching applies to Workers too — only the Worker URL
            # works as SNI (it's in the workers.dev zone).  Other CF domains
            # (discord.com, etc.) return 403 because Host is cross-zone.
            # The Worker gives you a fresh random *.workers.dev SNI instead
            # of the original (possibly blocked) domain.
            pcfg = PipelineConfig(
                uri=new_uri, parsed=re_parsed,
                sni_pool=[],
                frag_preset="all",
                transport_variants=[],
                max_expansion=1500,
            )
            xray_bin = xray_find_binary(getattr(args, "xray_bin", None))
            if not xray_bin:
                _w(f" {A.YEL}Xray not found. Installing...{A.RST}\n")
                _fl()
                xray_bin = xray_install()
            if xray_bin:
                xst = XrayTestState()
                xdash = await _run_pipeline_core(xst, pcfg, xray_bin)
                await _post_pipeline_results(xst, xdash, args)
                return  # interactive loop handles exit
            else:
                _w(f"   {A.RED}Could not find/install xray-core{A.RST}\n")
        else:
            _w(f"   {A.RED}Failed to parse generated URI{A.RST}\n")

    _w(f"\n {A.DIM}Press any key to go back...{A.RST}\n")
    _fl()
    _read_key_blocking()


# ─── End Worker Proxy ─────────────────────────────────────────────────────────


class Dashboard:
    def __init__(self, st: State):
        self.st = st
        self.sort = "score"
        self.offset = 0
        self.show_domains = False

    def _bar(self, cur: int, tot: int, w: int = 24) -> str:
        if tot == 0:
            return "░" * w
        p = min(1.0, cur / tot)
        f = int(w * p)
        return f"{A.GRN}{'█' * f}{A.DIM}{'░' * (w - f)}{A.RST}"

    def _cscore(self, v: float) -> str:
        if v >= 70:
            return f"{A.GRN}{v:5.1f}{A.RST}"
        if v >= 40:
            return f"{A.YEL}{v:5.1f}{A.RST}"
        if v > 0:
            return f"{A.RED}{v:5.1f}{A.RST}"
        return f"{A.DIM}    -{A.RST}"

    def _speed_str(self, v: float) -> str:
        if v <= 0:
            return f"{A.DIM}     -{A.RST}"
        if v >= 1:
            return f"{A.GRN}{v:5.1f}{A.RST}"
        return f"{A.YEL}{v * 1000:4.0f}K{A.RST}"

    def draw(self):
        cols, rows = term_size()
        W = cols - 2
        s = self.st
        vis = max(3, rows - 18 - len(s.rounds))
        out: List[str] = []

        def bx(c: str):
            out.append(f"{A.CYN}║{A.RST}" + c + " " * max(0, W - _vl(c)) + f"{A.CYN}║{A.RST}")

        out.append(f"{A.CYN}╔{'═' * W}╗{A.RST}")
        elapsed = _fmt_elapsed(time.monotonic() - s.start_time) if s.start_time else "0s"
        title = f" {A.BOLD}{A.WHT}CF Config Scanner{A.RST}"
        right = f"{A.DIM}{elapsed}  |  {s.mode}  |  ^C stop{A.RST}"
        bx(title + " " * max(1, W - _vl(title) - _vl(right)) + right)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        fname = os.path.basename(s.input_file)
        info = f" {A.DIM}File:{A.RST} {fname}   {A.DIM}Configs:{A.RST} {len(s.configs)}   {A.DIM}Unique IPs:{A.RST} {len(s.ips)}"
        if s.latency_cut_n > 0:
            info += f"   {A.DIM}Cut:{A.RST} {s.latency_cut_n}"
        bx(info)
        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        bw = min(24, W - 55)

        if s.phase == "latency":
            pct = s.done_count * 100 // max(1, s.total)
            bx(f" {A.GRN}▶{A.RST} {A.BOLD}Latency{A.RST}          [{self._bar(s.done_count, s.total, bw)}] {s.done_count}/{s.total}  {pct}%")
        elif s.alive_n > 0:
            cut_info = f"  {A.DIM}cut {s.latency_cut_n}{A.RST}" if s.latency_cut_n > 0 else ""
            bx(f" {A.GRN}✓{A.RST} Latency          {A.GRN}{s.alive_n} alive{A.RST}  {A.DIM}{s.dead_n} dead{A.RST}{cut_info}")
        else:
            bx(f" {A.DIM}○ Latency          waiting...{A.RST}")

        for i, rc in enumerate(s.rounds):
            rn = i + 1
            lbl = f"Speed R{rn} ({rc.label}x{rc.keep})"
            if s.cur_round == rn and s.phase.startswith("speed") and not s.finished:
                pct = s.done_count * 100 // max(1, s.total)
                bx(f" {A.GRN}▶{A.RST} {A.BOLD}{lbl:<18}{A.RST}[{self._bar(s.done_count, s.total, bw)}] {s.done_count}/{s.total}  {pct}%")
            elif s.cur_round > rn or (s.cur_round >= rn and s.finished):
                bx(f" {A.GRN}✓{A.RST} {lbl:<18}{A.GRN}done{A.RST}")
            else:
                bx(f" {A.DIM}○ {lbl:<18}waiting...{A.RST}")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")
        parts = []
        if s.alive_n > 0:
            alats = [r.tls_ms for r in s.res.values() if r.alive and r.tls_ms > 0]
            avg_lat = statistics.mean(alats) if alats else 0
            parts.append(f"{A.GRN}● {s.alive_n}{A.RST} alive")
            parts.append(f"{A.RED}● {s.dead_n}{A.RST} dead")
            if avg_lat:
                parts.append(f"{A.DIM}avg latency:{A.RST} {avg_lat:.0f}ms")
            if s.best_speed > 0:
                parts.append(f"{A.CYN}best:{A.RST} {s.best_speed:.2f} MB/s")
        bx(" " + "   ".join(parts) if parts else " ")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        hdr = f" {A.BOLD}{'#':>3}  {'IP':<16} {'Dom':>3}  {'Ping':>6}  {'Conn':>6}"
        for i, rc in enumerate(s.rounds):
            hdr += f"  {'R' + str(i + 1):>5}"
        hdr += f"  {'Colo':>4}  {'Score':>5}{A.RST}"
        bx(hdr)

        sep = f" {'─' * 3}  {'─' * 16} {'─' * 3}  {'─' * 6}  {'─' * 6}"
        for _ in s.rounds:
            sep += f"  {'─' * 5}"
        sep += f"  {'─' * 4}  {'─' * 5}"
        bx(f"{A.DIM}{sep}{A.RST}")

        results = sorted_all(s, self.sort)
        total_results = len(results)
        page = results[self.offset : self.offset + vis]

        for rank, r in enumerate(page, self.offset + 1):
            if not r.alive:
                row = f" {A.DIM}{rank:>3}  {r.ip:<16} {len(r.domains):>3}  {A.RED}{'dead':>6}{A.RST}{A.DIM}  {'':>6}"
                for j in range(len(s.rounds)):
                    row += f"  {'':>5}"
                row += f"  {'':>4}  {A.RED}{'--':>5}{A.RST}"
                bx(row)
                continue
            tcp = f"{r.tcp_ms:6.0f}" if r.tcp_ms > 0 else f"{A.DIM}     -{A.RST}"
            tls = f"{r.tls_ms:6.0f}" if r.tls_ms > 0 else f"{A.DIM}     -{A.RST}"
            row = f" {rank:>3}  {r.ip:<16} {len(r.domains):>3}  {tcp}  {tls}"
            for j in range(len(s.rounds)):
                if j < len(r.speeds) and r.speeds[j] > 0:
                    row += f"  {self._speed_str(r.speeds[j])}"
                else:
                    row += f"  {A.DIM}    -{A.RST}"
            if r.colo:
                cl = f"{r.colo:>4}"
            else:
                cl = f"{A.DIM}   -{A.RST}"
            row += f"  {cl}  {self._cscore(r.score)}"
            bx(row)

        for _ in range(vis - len(page)):
            bx("")

        out.append(f"{A.CYN}╠{'═' * W}╣{A.RST}")

        if s.notify and time.monotonic() < s.notify_until:
            bx(f" {A.GRN}{A.BOLD}{s.notify}{A.RST}")
        elif s.finished:
            sort_hint = f"sort:{A.BOLD}{self.sort}{A.RST}"
            page_hint = f"{self.offset + 1}-{min(self.offset + vis, total_results)}/{total_results}"
            ft = (
                f" {A.CYN}[S]{A.RST} {sort_hint}  "
                f"{A.CYN}[E]{A.RST} Export  "
                f"{A.CYN}[A]{A.RST} ExportAll  "
                f"{A.CYN}[C]{A.RST} Configs  "
                f"{A.CYN}[D]{A.RST} Domains  "
                f"{A.CYN}[H]{A.RST} Help  "
                f"{A.CYN}[J/K]{A.RST}"
            )
            ft2 = (
                f" Scroll  {A.CYN}[N/P]{A.RST} Page ({page_hint})  "
                f"{A.CYN}[B]{A.RST} Back  "
                f"{A.CYN}[Q]{A.RST} Quit"
            )
            bx(ft)
            bx(ft2)
        else:
            bx(f" {A.DIM}{s.phase_label}...  Press Ctrl+C to stop and export partial results{A.RST}")

        out.append(f"{A.CYN}╚{'═' * W}╝{A.RST}")

        _w(A.HOME)
        _w("\n".join(out) + "\n")
        _fl()

    def draw_domain_popup(self, r: Result):
        """Show domains for the selected IP."""
        _w(A.CLR)
        cols, rows = term_size()
        vis = min(len(r.domains), rows - 10)
        lines = []
        lines.append(f"{A.CYN}╔{'═' * (cols - 2)}╗{A.RST}")
        lines.append(draw_box_line(f" {A.BOLD}Domains for {r.ip}  ({len(r.domains)} total){A.RST}", cols))
        ping_s = f"{r.tcp_ms:.0f}ms" if r.tcp_ms > 0 else "-"
        conn_s = f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-"
        lines.append(draw_box_line(f" {A.DIM}Score: {r.score:.1f}  |  Ping: {ping_s}  |  Conn: {conn_s}{A.RST}", cols))
        lines.append(draw_box_sep(cols))
        for d in r.domains[:vis]:
            lines.append(draw_box_line(f"  {d}", cols))
        if len(r.domains) > vis:
            lines.append(draw_box_line(f"  {A.DIM}...and {len(r.domains) - vis} more{A.RST}", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}Press any key to go back{A.RST}", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)  # clear before dashboard redraws

    def draw_config_popup(self, r: Result):
        """Show all VLESS/VMess URIs for the selected IP."""
        _w(A.CLR)
        cols, rows = term_size()
        lines = []
        lines.append(f"{A.CYN}╔{'═' * (cols - 2)}╗{A.RST}")
        lines.append(draw_box_line(f" {A.BOLD}Configs for {r.ip}  ({len(r.uris)} URIs){A.RST}", cols))
        ping_s = f"{r.tcp_ms:.0f}ms" if r.tcp_ms > 0 else "-"
        conn_s = f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-"
        speed_s = f"{r.best_mbps:.1f} MB/s" if r.best_mbps > 0 else "-"
        lines.append(draw_box_line(
            f" {A.DIM}Score: {r.score:.1f}  |  Ping: {ping_s}  |  Conn: {conn_s}  |  Speed: {speed_s}{A.RST}", cols
        ))
        lines.append(draw_box_sep(cols))
        if r.uris:
            max_show = rows - 10
            for i, uri in enumerate(r.uris[:max_show]):
                # Truncate long URIs to fit terminal width
                tag = f" {A.CYN}{i+1}.{A.RST} "
                max_uri = cols - 8
                display = uri if len(uri) <= max_uri else uri[:max_uri - 3] + "..."
                lines.append(draw_box_line(f"{tag}{A.GRN}{display}{A.RST}", cols))
            if len(r.uris) > max_show:
                lines.append(draw_box_line(f"  {A.DIM}...and {len(r.uris) - max_show} more{A.RST}", cols))
        else:
            lines.append(draw_box_line(f"  {A.DIM}No VLESS/VMess URIs stored for this IP{A.RST}", cols))
            lines.append(draw_box_line(f"  {A.DIM}(only available when loaded from URIs or subscriptions){A.RST}", cols))
        lines.append(draw_box_sep(cols))
        lines.append(draw_box_line(f" {A.DIM}Press any key to go back{A.RST}", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)

    def draw_help_popup(self):
        """Show keybinding help + column explanations overlay."""
        _w(A.CLR)
        cols, rows = term_size()
        W = min(64, cols - 4)
        lines = []
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Keyboard Shortcuts{A.RST}")
        lines.append(f"  {A.CYN}{'-' * W}{A.RST}")
        help_items = [
            ("S", "Cycle sort order: score / latency / speed"),
            ("E", "Export results (CSV + top N configs)"),
            ("A", "Export ALL configs sorted best to worst"),
            ("C", "View VLESS/VMess URIs for an IP (enter rank #)"),
            ("D", "View domains for an IP (enter rank #)"),
            ("J / K", "Scroll down / up one row"),
            ("N / P", "Page down / up"),
            ("B", "Back to main menu (new scan)"),
            ("H", "Show this help screen"),
            ("Q", "Quit (results auto-saved on exit)"),
        ]
        for key, desc in help_items:
            lines.append(f"  {A.CYN}{key:<10}{A.RST} {desc}")
        lines.append("")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Column Guide{A.RST}")
        lines.append(f"  {A.CYN}{'-' * W}{A.RST}")
        col_items = [
            ("#", "Rank (sorted by current sort order)"),
            ("IP", "Cloudflare edge IP address"),
            ("Dom", "How many domains share this IP"),
            ("Ping", "TCP connect time in ms (like ping)"),
            ("Conn", "Full connection time in ms (TCP + TLS handshake)"),
            ("R1,R2..", "Download speed per round (MB/s or KB/s)"),
            ("Colo", "CF datacenter code (e.g. FRA, IAH, MRS)"),
            ("Score", "Combined score (0-100, higher = better)"),
        ]
        for key, desc in col_items:
            lines.append(f"  {A.CYN}{key:<10}{A.RST} {desc}")
        lines.append("")
        lines.append(f"  {A.DIM}Score = Conn latency (35%) + speed (50%) + TTFB (15%){A.RST}")
        lines.append(f"  {A.DIM}'-' means not tested yet (only top IPs get speed tested){A.RST}")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.BOLD}{A.WHT}  Made By Sam - SamNet Technologies{A.RST}")
        lines.append(f"  {A.DIM}  https://github.com/SamNet-dev/cfray{A.RST}")
        lines.append(f"  {A.CYN}{'=' * W}{A.RST}")
        lines.append(f"  {A.DIM}Press any key to go back{A.RST}")

        _w("\n".join(lines) + "\n")
        _fl()
        _wait_any_key()
        _w(A.CLR)  # clear before dashboard redraws

    def handle(self, key: str) -> Optional[str]:
        sorts = ["score", "latency", "speed"]
        if key == "s":
            idx = sorts.index(self.sort) if self.sort in sorts else 0
            self.sort = sorts[(idx + 1) % len(sorts)]
        elif key in ("j", "down"):
            self.offset = min(self.offset + 1, max(0, len(sorted_all(self.st, self.sort)) - 3))
        elif key in ("k", "up"):
            self.offset = max(0, self.offset - 1)
        elif key == "n":
            # page down
            _, rows = term_size()
            page = max(3, rows - 18 - len(self.st.rounds))
            self.offset = min(self.offset + page, max(0, len(sorted_all(self.st, self.sort)) - 3))
        elif key == "p":
            # page up
            _, rows = term_size()
            page = max(3, rows - 18 - len(self.st.rounds))
            self.offset = max(0, self.offset - page)
        elif key == "e":
            return "export"
        elif key == "a":
            return "export-all"
        elif key == "c":
            return "configs"
        elif key == "d":
            return "domains"
        elif key == "h":
            return "help"
        elif key == "b":
            return "back"
        elif key in ("q", "ctrl-c"):
            return "quit"
        return None


def save_csv(st: State, path: str, sort_by: str = "score"):
    results = sorted_alive(st, sort_by)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        hdr = ["Rank", "IP", "Domains", "Domain_Count", "Ping_ms", "Conn_ms", "TTFB_ms"]
        for i, rc in enumerate(st.rounds):
            hdr.append(f"R{i + 1}_{rc.label}_MBps")
        hdr += ["Best_MBps", "Colo", "Score", "Error"]
        w.writerow(hdr)
        for rank, r in enumerate(results, 1):
            row = [
                rank,
                r.ip,
                "|".join(r.domains[:5]),
                len(r.domains),
                f"{r.tcp_ms:.1f}" if r.tcp_ms > 0 else "",
                f"{r.tls_ms:.1f}" if r.tls_ms > 0 else "",
                f"{r.ttfb_ms:.1f}" if r.ttfb_ms > 0 else "",
            ]
            for i in range(len(st.rounds)):
                row.append(
                    f"{r.speeds[i]:.3f}"
                    if i < len(r.speeds) and r.speeds[i] > 0
                    else ""
                )
            row += [
                f"{r.best_mbps:.3f}" if r.best_mbps > 0 else "",
                r.colo,
                f"{r.score:.1f}",
                r.error,
            ]
            w.writerow(row)


def save_configs(st: State, path: str, top: int = 50, sort_by: str = "score"):
    """Save top configs. Use top=0 for ALL configs sorted best to worst."""
    results = sorted_alive(st, sort_by)
    has_uris = any(r.uris for r in results)
    limit = top if top > 0 else len(results)
    with open(path, "w", encoding="utf-8") as f:
        n = 0
        for r in results:
            if n >= limit:
                break
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
                    n += 1
                    if n >= limit:
                        break
            else:
                # JSON input: write IP and domains as a reference list
                doms = ", ".join(r.domains[:3])
                extra = f" (+{len(r.domains) - 3} more)" if len(r.domains) > 3 else ""
                f.write(f"{r.ip}  # score={r.score:.1f} domains={doms}{extra}\n")
                n += 1


def save_all_configs_sorted(st: State, path: str, sort_by: str = "score"):
    """Save ALL raw configs (every URI) sorted by their IP's score, best to worst."""
    results = sorted_alive(st, sort_by)
    dead = [r for r in st.res.values() if not r.alive]
    has_uris = any(r.uris for r in results)
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
            else:
                doms = ", ".join(r.domains[:3])
                extra = f" (+{len(r.domains) - 3} more)" if len(r.domains) > 3 else ""
                f.write(f"{r.ip}  # score={r.score:.1f} domains={doms}{extra}\n")
        for r in dead:
            if has_uris:
                for uri in r.uris:
                    f.write(uri + "\n")
            else:
                doms = ", ".join(r.domains[:3])
                f.write(f"{r.ip}  # DEAD domains={doms}\n")


RESULTS_DIR = "results"


def _results_path(filename: str) -> str:
    """Return path inside the results/ directory, creating it if needed."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, filename)


def do_export(
    st: State, base_path: str, sort_by: str = "score", top: int = 50,
    output_csv: str = "", output_configs: str = "",
) -> Tuple[str, str, str]:
    stem = os.path.basename(base_path).rsplit(".", 1)[0] if base_path else "scan"
    csv_path = output_csv if output_csv else _results_path(stem + "_results.csv")
    if output_configs:
        cfg_path = output_configs
    elif top <= 0:
        cfg_path = _results_path(stem + "_all_sorted.txt")
    else:
        cfg_path = _results_path(stem + f"_top{top}.txt")
    full_path = _results_path(stem + "_full_sorted.txt")
    save_csv(st, csv_path, sort_by)
    save_configs(st, cfg_path, top, sort_by)
    save_all_configs_sorted(st, full_path, sort_by)
    st.saved = True
    return csv_path, cfg_path, full_path


async def _refresh_loop(dash: Dashboard, st: State):
    while not st.finished:
        try:
            dash.draw()
        except Exception:
            pass
        await asyncio.sleep(0.3)


async def run_scan(st: State, workers: int, speed_workers: int, timeout: float, speed_timeout: float):
    """Run the scan phases with dynamic round sizing."""
    try:
        os.makedirs("results", exist_ok=True)
        with open(DEBUG_LOG, "w") as f:
            f.write(f"=== Scan started {time.strftime('%Y-%m-%d %H:%M:%S')} mode={st.mode} ===\n")
    except Exception:
        pass
    st.start_time = time.monotonic()

    if not st.interrupted:
        await phase1(st, workers, timeout)

    if st.interrupted or st.alive_n == 0:
        st.finished = True
        calc_scores(st)
        return

    preset = PRESETS.get(st.mode, PRESETS["normal"])

    alive = sorted(
        (ip for ip, r in st.res.items() if r.alive),
        key=lambda ip: st.res[ip].tls_ms,
    )

    cut_pct = preset.get("latency_cut", 0)
    if cut_pct > 0 and len(alive) > 50:
        cut_n = max(1, int(len(alive) * cut_pct / 100))
        alive = alive[:-cut_n]
        st.latency_cut_n = cut_n
        _dbg(f"=== Latency cut: removed bottom {cut_pct}% = {cut_n} IPs, {len(alive)} remaining ===")

    if not st.rounds:
        st.rounds = build_dynamic_rounds(st.mode, len(alive))
        _dbg(f"=== Dynamic rounds: {[(r.label, r.keep) for r in st.rounds]} ===")

    if not st.interrupted and st.rounds:
        rlim = CFRateLimiter()
        cands = list(alive)
        cdn_host = SPEED_HOST
        cdn_path = ""  # _dl_one uses default

        for i, rc in enumerate(st.rounds):
            if st.interrupted:
                break
            st.cur_round = i + 1
            st.phase = f"speed_r{i + 1}"
            actual_count = min(rc.keep, len(cands))
            st.phase_label = f"Speed R{i + 1} ({rc.label} x {actual_count})"
            _dbg(f"=== Round R{i+1}: {rc.size}B x {actual_count} IPs, workers={speed_workers}, timeout={speed_timeout}s, budget={rlim.BUDGET - rlim.count} left ===")

            if i > 0:
                calc_scores(st)
                cands = sorted(cands, key=lambda ip: st.res[ip].score, reverse=True)
            cands = cands[: rc.keep]

            await phase2_round(
                st, rc, cands, speed_workers, speed_timeout,
                rlim=rlim, cdn_host=cdn_host, cdn_path=cdn_path,
            )
            calc_scores(st)

    st.finished = True
    calc_scores(st)


async def run_tui(args, deploy_mode=False):
    """TUI mode: interactive startup + dashboard."""
    enable_ansi()

    # Determine initial input source from CLI args
    input_method = None  # "file", "sub", or "template"
    input_value = None
    if deploy_mode:
        input_method, input_value = "deploy", ""
    if getattr(args, "sub", None):
        input_method, input_value = "sub", args.sub
    elif getattr(args, "template", None):
        if getattr(args, "input", None):
            input_method, input_value = "template", f"{args.template}|||{args.input}"
        else:
            print("Error: --template requires -i (address list file)")
            return
    elif getattr(args, "find_clean", False):
        input_method, input_value = "find_clean", ""
    elif getattr(args, "input", None):
        input_method, input_value = "file", args.input

    while True:  # outer loop: back returns here
        interactive = input_method is None
        while True:
            if input_method is None:
                pick = tui_pick_file()
                if not pick:
                    _w(A.SHOW)
                    return
                input_method, input_value = pick

            if input_method == "pipeline":
                await _tui_run_pipeline(args, cli_uri=input_value or "")
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return

            if input_method == "deploy":
                await _tui_run_deploy(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return

            if input_method == "worker_proxy":
                await _tui_worker_proxy(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return

            if input_method == "connection_manager":
                await _tui_connection_manager(args)
                if interactive:
                    input_method = None
                    input_value = None
                    continue
                else:
                    return

            if input_method == "find_clean":
                result = await tui_run_clean_finder()
                if result is None:
                    _w(A.SHOW)
                    return
                if result[0] == "__back__":
                    input_method = None
                    input_value = None
                    continue
                input_method, input_value = result

            mode = args.mode
            if not getattr(args, "_mode_set", False) and interactive:
                picked = tui_pick_mode()
                if not picked:
                    _w(A.SHOW)
                    return
                if picked == "__back__":
                    input_method = None
                    input_value = None
                    continue
                mode = picked
            break

        st = State()
        st.mode = mode
        st.top = args.top

        if args.rounds:
            st.rounds = parse_rounds_str(args.rounds)
        elif args.skip_download:
            st.rounds = []

        # Determine display label for loading screen
        if input_method == "sub":
            load_label = input_value.split("/")[-1][:40] or "subscription"
        elif input_method == "template":
            parts = input_value.split("|||", 1)
            load_label = os.path.basename(parts[1]) if len(parts) > 1 else "template"
        else:
            load_label = os.path.basename(input_value)

        _w(A.CLR + A.HOME)
        cols, _ = term_size()
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Starting scan...{A.RST}", cols))
        lines.append(draw_box_line("", cols))
        lines.append(draw_box_line(f" {A.CYN}>{A.RST} Loading {load_label}...", cols))
        lines.append(draw_box_bottom(cols))
        _w("\n".join(lines) + "\n")
        _fl()

        # Load configs based on input method
        if input_method == "sub":
            st.configs = fetch_sub(input_value)
            st.input_file = input_value
        elif input_method == "template":
            tpl_uri, addr_path = input_value.split("|||", 1)
            addrs = load_addresses(addr_path)
            st.configs = generate_from_template(tpl_uri, addrs)
            st.input_file = f"{addr_path} ({len(addrs)} addresses)"
        else:
            st.configs = load_input(input_value)
            st.input_file = input_value

        if not st.configs:
            _w(A.SHOW)
            print(f"No configs found in {st.input_file}")
            return

        _w(A.CLR + A.HOME)
        lines = draw_menu_header(cols)
        lines.append(draw_box_line(f" {A.BOLD}Starting scan...{A.RST}", cols))
        lines.append(draw_box_line("", cols))
        lines.append(draw_box_line(f" {A.GRN}OK{A.RST} Loaded {len(st.configs)} configs", cols))
        lines.append(draw_box_line("", cols))
        _w("\n".join(lines) + "\n")
        _fl()

        st.phase = "dns"
        st.phase_label = "Resolving DNS"
        try:
            await resolve_all(st)
        except Exception as e:
            _w(A.SHOW + "\n")
            print(f"DNS resolution error: {e}")
            return
        if not st.ips:
            _w(A.SHOW + "\n")
            print("No IPs resolved — check network or config addresses.")
            return

        dash = Dashboard(st)
        refresh = asyncio.create_task(_refresh_loop(dash, st))

        scan_task = asyncio.ensure_future(
            run_scan(st, args.workers, args.speed_workers, args.timeout, args.speed_timeout)
        )

        old_sigint = signal.getsignal(signal.SIGINT)

        def _sig(sig, frame):
            st.interrupted = True
            st.finished = True
            scan_task.cancel()
        signal.signal(signal.SIGINT, _sig)

        try:
            await scan_task
        except asyncio.CancelledError:
            st.interrupted = True
            st.finished = True
            calc_scores(st)

        # Restore original SIGINT so Ctrl+C works in post-scan loop
        signal.signal(signal.SIGINT, old_sigint)

        if refresh:
            refresh.cancel()
            try:
                await refresh
            except asyncio.CancelledError:
                pass

        try:
            csv_p, cfg_p, full_p = do_export(st, input_value, dash.sort, st.top)
            st.notify = f"Saved to results/ folder"
        except Exception as e:
            csv_p = cfg_p = full_p = ""
            st.notify = f"Export error: {e}"
        st.notify_until = time.monotonic() + 5

        dash.draw()

        go_back = False
        try:
            while True:
                key = _read_key_nb(0.1)
                if key is None:
                    # refresh notification timeout
                    if st.notify and time.monotonic() >= st.notify_until:
                        st.notify = ""
                        dash.draw()
                    continue

                act = dash.handle(key)
                if act == "quit":
                    break
                elif act == "back":
                    # show save summary and go to main menu
                    _w(A.CLR)
                    save_lines = [
                        f"  {A.CYN}{'=' * 50}{A.RST}",
                        f"  {A.BOLD}{A.WHT}  Results saved:{A.RST}",
                        f"  {A.CYN}{'-' * 50}{A.RST}",
                        f"  {A.GRN}CSV:{A.RST}     {csv_p}",
                        f"  {A.GRN}Top:{A.RST}     {cfg_p}",
                        f"  {A.GRN}Full:{A.RST}    {full_p}",
                        f"  {A.CYN}{'=' * 50}{A.RST}",
                        "",
                        f"  {A.DIM}Press any key to go to main menu...{A.RST}",
                    ]
                    _w("\n".join(save_lines) + "\n")
                    _fl()
                    _wait_any_key()
                    go_back = True
                    break
                elif act == "export":
                    try:
                        csv_p, cfg_p, full_p = do_export(st, input_value, dash.sort, st.top)
                        st.notify = f"Exported to results/ folder"
                    except Exception as e:
                        st.notify = f"Export error: {e}"
                    st.notify_until = time.monotonic() + 4
                elif act == "export-all":
                    try:
                        csv_p, cfg_p, full_p = do_export(st, input_value, dash.sort, 0)
                        st.notify = f"Exported ALL to results/ folder"
                    except Exception as e:
                        st.notify = f"Export error: {e}"
                    st.notify_until = time.monotonic() + 4
                elif act == "configs":
                    results = sorted_all(st, dash.sort)
                    if results:
                        n = _prompt_number(f"{A.CYN}Enter rank # to view configs (1-{len(results)}):{A.RST} ", len(results))
                        if n is not None:
                            dash.draw_config_popup(results[n - 1])
                elif act == "domains":
                    results = sorted_all(st, dash.sort)
                    if results:
                        n = _prompt_number(f"{A.CYN}Enter rank # to view domains (1-{len(results)}):{A.RST} ", len(results))
                        if n is not None:
                            dash.draw_domain_popup(results[n - 1])
                elif act == "help":
                    dash.draw_help_popup()
                dash.draw()
        except (KeyboardInterrupt, EOFError, OSError):
            pass

        if go_back:
            # reset for next run — clear CLI input so file picker shows
            args.input = None
            args.sub = None
            args.template = None
            args._mode_set = False
            input_method = None
            input_value = None
            continue

        _w(A.SHOW + "\n")
        _fl()
        print(f"Results saved to {RESULTS_DIR}/ folder")
        break


async def run_headless(args):
    """Headless mode (--no-tui)."""
    st = State()
    st.input_file = args.input
    st.mode = args.mode

    if args.rounds:
        st.rounds = parse_rounds_str(args.rounds)
    elif args.skip_download:
        st.rounds = []

    print(f"CF Config Scanner v{VERSION}")
    st.configs, src = load_configs_from_args(args)
    print(f"Loading: {src}")
    print(f"Loaded {len(st.configs)} configs")
    if not st.configs:
        return

    print("Resolving DNS...")
    await resolve_all(st)
    print(f"  {len(st.ips)} unique IPs")
    if not st.ips:
        return

    scan_task = asyncio.ensure_future(
        run_scan(st, args.workers, args.speed_workers, args.timeout, args.speed_timeout)
    )

    old_sigint = signal.getsignal(signal.SIGINT)

    def _sig(sig, frame):
        st.interrupted = True
        st.finished = True
        scan_task.cancel()
    signal.signal(signal.SIGINT, _sig)

    try:
        await scan_task
    except asyncio.CancelledError:
        st.interrupted = True
        st.finished = True
        calc_scores(st)
        print("\n  Interrupted! Exporting partial results...")

    signal.signal(signal.SIGINT, old_sigint)

    results = sorted_alive(st, "score")
    elapsed = _fmt_elapsed(time.monotonic() - st.start_time)
    print(f"\nDone in {elapsed}. {st.alive_n} alive IPs.\n")
    print(f"{'=' * 95}")
    hdr = f"{'#':>4} {'IP':<16} {'Dom':>4} {'Ping ms':>7} {'Conn ms':>7}"
    for i in range(len(st.rounds)):
        hdr += f" {'R' + str(i + 1) + ' MB/s':>9}"
    hdr += f" {'Colo':>5} {'Score':>6}"
    print(hdr)
    print("=" * 95)
    for rank, r in enumerate(results[:50], 1):
        tcp = f"{r.tcp_ms:7.1f}" if r.tcp_ms > 0 else "      -"
        tls = f"{r.tls_ms:7.1f}" if r.tls_ms > 0 else "      -"
        row = f"{rank:>4} {r.ip:<16} {len(r.domains):>4} {tcp} {tls}"
        for j in range(len(st.rounds)):
            if j < len(r.speeds) and r.speeds[j] > 0:
                row += f" {r.speeds[j]:>9.2f}"
            else:
                row += "         -"
        cl = f"{r.colo:>5}" if r.colo else "    -"
        sc = f"{r.score:>6.1f}" if r.score > 0 else "     -"
        row += f" {cl} {sc}"
        print(row)

    try:
        csv_p, cfg_p, full_p = do_export(
            st, args.input or "scan", top=args.top,
            output_csv=getattr(args, "output", "") or "",
            output_configs=getattr(args, "output_configs", "") or "",
        )
        print(f"\nResults saved:")
        print(f"  CSV:     {csv_p}")
        print(f"  Configs: {cfg_p}")
        print(f"  Full:    {full_p}")
    except Exception as e:
        print(f"\nError saving results: {e}")


async def run_headless_clean(args):
    """Headless clean IP finder (--find-clean --no-tui)."""
    scan_cfg = CLEAN_MODES.get(getattr(args, "clean_mode", "normal"), CLEAN_MODES["normal"])

    subnets = CF_SUBNETS
    if getattr(args, "subnets", None):
        if os.path.isfile(args.subnets):
            with open(args.subnets, encoding="utf-8") as f:
                subnets = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        else:
            subnets = [s.strip() for s in args.subnets.split(",") if s.strip()]

    ports = scan_cfg.get("ports", [443])
    print(f"CF Config Scanner v{VERSION} — Clean IP Finder")
    print(f"Ranges: {len(subnets)}  |  Sample: {scan_cfg['sample'] or 'all'}  |  Workers: {scan_cfg['workers']}  |  Ports: {', '.join(str(p) for p in ports)}")

    ips = generate_cf_ips(subnets, scan_cfg["sample"])
    total_probes = len(ips) * len(ports)
    print(f"Scanning {len(ips):,} IPs × {len(ports)} port(s) = {total_probes:,} probes...")

    cs = CleanScanState()
    start = time.monotonic()

    scan_task = asyncio.ensure_future(
        scan_clean_ips(
            ips, workers=scan_cfg["workers"], timeout=3.0,
            validate=scan_cfg["validate"], cs=cs, ports=ports,
        )
    )

    old_sigint = signal.getsignal(signal.SIGINT)
    def _sig(sig, frame):
        cs.interrupted = True
        scan_task.cancel()
    signal.signal(signal.SIGINT, _sig)

    last_pct = -1
    try:
        while not scan_task.done():
            pct = cs.done * 100 // max(1, cs.total)
            if pct != last_pct and pct % 5 == 0:
                print(f"  {pct}%  ({cs.done:,}/{cs.total:,})  found {cs.found:,} clean")
                last_pct = pct
            await asyncio.sleep(1)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    try:
        results = await scan_task
    except (asyncio.CancelledError, Exception):
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])

    elapsed = _fmt_elapsed(time.monotonic() - start)
    print(f"\nDone in {elapsed}. Found {len(results):,} clean IPs.\n")
    print(f"{'='*50}")
    print(f"{'#':>4} {'Address':<22} {'Latency':>8}")
    print(f"{'='*50}")
    for i, (ip, lat) in enumerate(results[:30]):
        print(f"{i+1:>4} {ip:<22} {lat:>6.0f}ms")
    if len(results) > 30:
        print(f"     ...and {len(results)-30:,} more")

    if results:
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            path = os.path.abspath(_results_path("clean_ips.txt"))
            with open(path, "w", encoding="utf-8") as f:
                for ip, lat in results:
                    f.write(f"{ip}\n")
            print(f"\nSaved {len(results):,} IPs to {path}")
        except Exception as e:
            print(f"\nSave error: {e}")
            path = ""
    else:
        print("\nNo clean IPs found. Nothing saved.")
        path = ""

    # If --template also given, proceed to speed test
    if getattr(args, "template", None) and results:
        print(f"\nContinuing to speed test with template...")
        addrs = [ip for ip, _ in results]
        configs = generate_from_template(args.template, addrs)
        if configs:
            args.input = path
            st = State()
            st.input_file = f"clean ({len(results)} IPs)"
            st.mode = args.mode
            st.configs = configs
            if args.rounds:
                st.rounds = parse_rounds_str(args.rounds)
            elif args.skip_download:
                st.rounds = []
            print(f"Generated {len(configs)} configs")
            print("Resolving DNS...")
            await resolve_all(st)
            print(f"  {len(st.ips)} unique IPs")
            if st.ips:
                start2 = time.monotonic()
                scan2 = asyncio.ensure_future(
                    run_scan(st, args.workers, args.speed_workers, args.timeout, args.speed_timeout)
                )
                old2 = signal.getsignal(signal.SIGINT)
                def _sig2(sig, frame):
                    st.interrupted = True
                    st.finished = True
                    scan2.cancel()
                signal.signal(signal.SIGINT, _sig2)
                try:
                    await scan2
                except asyncio.CancelledError:
                    st.interrupted = True
                    st.finished = True
                    calc_scores(st)
                signal.signal(signal.SIGINT, old2)

                alive_results = sorted_alive(st, "score")
                elapsed2 = _fmt_elapsed(time.monotonic() - start2)
                print(f"\nSpeed test done in {elapsed2}. {st.alive_n} alive.")
                print(f"{'='*80}")
                for rank, r in enumerate(alive_results[:20], 1):
                    spd = f"{r.best_mbps:.2f}" if r.best_mbps > 0 else "    -"
                    lat_s = f"{r.tls_ms:.0f}" if r.tls_ms > 0 else "  -"
                    print(f"{rank:>3} {r.ip:<16} {lat_s:>6}ms  {spd:>8} MB/s  score={r.score:.1f}")
                try:
                    csv_p, cfg_p, full_p = do_export(st, path, top=args.top)
                    print(f"\nSaved: {csv_p}  |  {cfg_p}  |  {full_p}")
                except Exception as e:
                    print(f"Export error: {e}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    p = argparse.ArgumentParser(
        description="CF Config Scanner - test VLESS configs for latency + download speed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Run with no arguments for interactive TUI.

Modes (sort by latency first, then speed-test the best):
  quick      Cut 50%% latency, 1MB x100 -> 5MB x20     (~200 MB, ~2-3 min)
  normal     Cut 40%% latency, 1MB x200 -> 5MB x50 -> 20MB x20  (~850 MB, ~5-10 min)
  thorough   Cut 15%% latency, 5MB xALL -> 25MB x150 -> 100MB x50  (~8-15 GB, ~30-60 min)

Examples:
  %(prog)s                                          Interactive TUI
  %(prog)s -i configs.txt                           TUI with file
  %(prog)s --sub https://example.com/sub.txt        Fetch from subscription URL
  %(prog)s --template "vless://UUID@{ip}:443?..." -i addrs.json  Generate from template
  %(prog)s -i configs.txt --mode quick              Quick scan
  %(prog)s -i configs.txt --top 0                   Export ALL sorted
  %(prog)s -i configs.txt --no-tui -o results.csv   Headless
  %(prog)s --find-clean --no-tui                     Find clean CF IPs (headless)
  %(prog)s --find-clean --no-tui --template "vless://..."  Find + speed test
""",
    )
    p.add_argument("-i", "--input", help="Input file (VLESS URIs or domains.json)")
    p.add_argument("--sub", help="Subscription URL (fetches VLESS URIs from URL)")
    p.add_argument("--template", help="Base VLESS URI template (use with -i address list)")
    p.add_argument("-m", "--mode", choices=["quick", "normal", "thorough"], default="normal")
    p.add_argument("--rounds", help='Custom rounds, e.g. "1MB:200,5MB:50,20MB:20"')
    p.add_argument("-w", "--workers", type=int, default=LATENCY_WORKERS, help="Latency workers")
    p.add_argument("--speed-workers", type=int, default=SPEED_WORKERS, help="Download workers")
    p.add_argument("--timeout", type=float, default=LATENCY_TIMEOUT, help="Latency timeout (s)")
    p.add_argument("--speed-timeout", type=float, default=SPEED_TIMEOUT, help="Download timeout (s)")
    p.add_argument("--skip-download", action="store_true", help="Latency only")
    p.add_argument("--top", type=int, default=50, help="Export top N configs (0 = ALL sorted best to worst)")
    p.add_argument("--no-tui", action="store_true", help="Plain text output")
    p.add_argument("-o", "--output", help="CSV output path (headless)")
    p.add_argument("--output-configs", help="Save top VLESS URIs (headless)")
    p.add_argument("--find-clean", action="store_true", help="Find clean Cloudflare IPs")
    p.add_argument("--clean-mode", choices=["quick", "normal", "full", "mega"], default="normal",
                   help="Clean IP scan scope (quick=~4K, normal=~12K, full=~1.5M, mega=~3M multi-port)")
    p.add_argument("--subnets", help="Custom subnets file or comma-separated CIDRs")
    # Xray Proxy Testing
    p.add_argument("--xray", metavar="URI",
                   help="VLESS/VMess URI to test through Xray-core proxy")
    p.add_argument("--xray-frag", metavar="PRESET",
                   choices=["none", "light", "medium", "heavy", "all"], default="all",
                   help="Fragment preset (default: all)")
    p.add_argument("--xray-bin", metavar="PATH",
                   help="Path to xray binary (auto-detect if not set)")
    p.add_argument("--xray-install", action="store_true",
                   help="Download and install xray-core to ~/.cfray/bin/")
    p.add_argument("--xray-keep", type=int, default=10,
                   help="Export top N xray results (default: 10)")
    # Deploy
    p.add_argument("--deploy", nargs="?", const="interactive", metavar="URI_OR_FILE",
                   help="Deploy Xray server on this Linux VPS")
    p.add_argument("--deploy-port", type=int, default=443)
    p.add_argument("--deploy-protocol", choices=["vless", "vmess"], default="vless")
    p.add_argument("--deploy-transport", choices=["tcp", "ws", "grpc", "h2"], default="tcp")
    p.add_argument("--deploy-security", choices=["reality", "tls", "none"], default="reality")
    p.add_argument("--deploy-sni", metavar="DOMAIN")
    p.add_argument("--deploy-cert", metavar="PATH")
    p.add_argument("--deploy-key", metavar="PATH")
    p.add_argument("--deploy-ip", metavar="IP")
    p.add_argument("--uninstall", action="store_true",
                   help="Remove everything cfray installed")
    args = p.parse_args()

    args._mode_set = any(a == "-m" or a.startswith("--mode") for a in sys.argv)

    try:
        if getattr(args, "xray_install", False):
            path = xray_install()
            if path:
                print(f"Installed: {path}")
            return
        if getattr(args, "uninstall", False):
            ok, msg = _uninstall_all()
            print(msg)
            return
        if getattr(args, "deploy", None):
            asyncio.run(run_tui(args, deploy_mode=True))
            return
        if getattr(args, "find_clean", False) and args.no_tui:
            asyncio.run(run_headless_clean(args))
        elif args.no_tui:
            if not args.input and not args.sub and not args.template:
                p.error("--input, --sub, or --template is required in --no-tui mode")
            asyncio.run(run_headless(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        pass
    finally:
        _w(A.SHOW + "\n")
        _fl()


if __name__ == "__main__":
    main()
