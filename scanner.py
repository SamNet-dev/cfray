#!/usr/bin/env python3
#
# ┌─────────────────────────────────────────────────────────────────┐
# │                                                                 │
# │   ⚡  CF CONFIG SCANNER v1.0                                    │
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
import csv
import glob as globmod
import ipaddress
import json
import os
import random
import re
import signal
import socket
import ssl
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


VERSION = "1.0"
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
        if validate:
            is_cf = False
            try:
                req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                w.write(req.encode())
                await w.drain()
                hdr = await asyncio.wait_for(r.read(2048), timeout=min(timeout, 3))
                htxt = hdr.decode("latin-1", errors="replace").lower()
                is_cf = "server: cloudflare" in htxt or "cf-ray:" in htxt
            except Exception:
                pass

        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        w = None
        return tls_ms, is_cf, ""
    except asyncio.TimeoutError:
        return -1, False, "timeout"
    except Exception as e:
        return -1, False, str(e)[:40]
    finally:
        if w:
            try:
                w.close()
            except Exception:
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


def tui_show_guide():
    """Show help/guide screen explaining input formats."""
    _w(A.CLR + A.HOME)
    cols, rows = term_size()
    lines = draw_menu_header(cols)
    lines.append(draw_box_line(f" {A.BOLD}{A.WHT}How to prepare input files{A.RST}", cols))
    lines.append(draw_box_sep(cols))

    guide = [
        "",
        f" {A.BOLD}{A.CYN}Local Files (auto-detected){A.RST}",
        f"   {A.DIM}Place config files in the same directory where you run cfray.{A.RST}",
        f"   {A.DIM}Supported formats: {A.WHT}.txt  .json  .conf  .lst{A.RST}",
        f"   {A.DIM}They will appear automatically under {A.WHT}LOCAL FILES{A.DIM} in the menu.{A.RST}",
        f"   {A.GRN}Example:{A.RST} {A.DIM}cp configs.txt /root/ && cd /root && python3 scanner.py{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}[P] Enter File Path{A.RST}",
        f"   {A.DIM}Load a config file from any location by typing its full path.{A.RST}",
        f"   {A.GRN}Example:{A.RST} {A.DIM}/home/user/configs/my_vless.txt{A.RST}",
        "",
        f" {A.CYN}{'─' * 46}{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}[1-9] VLESS/VMess URI file (.txt){A.RST}",
        f"   {A.DIM}Text file, one URI per line. Can mix VLESS and VMess.{A.RST}",
        f"   {A.GRN}vless://uuid@domain:443?type=ws&host=sni.com&...#name{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}[1-9] Domain JSON file (.json){A.RST}",
        f'   {A.DIM}JSON with domain+IP:{A.RST} {A.GRN}{{"data": [{{"domain":"x.ir","ipv4":"1.2.3.4"}}]}}{A.RST}',
        "",
        f" {A.BOLD}{A.CYN}[S] Subscription URL{A.RST}",
        f"   {A.DIM}Fetches VLESS/VMess configs from a remote URL (plain or base64).{A.RST}",
        f"   {A.GRN}https://example.com/sub.txt{A.RST}",
        f"   {A.DIM}CLI: python3 scanner.py --sub URL{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}[T] Template + Address list{A.RST}",
        f"   {A.DIM}Give one VLESS/VMess template + a file of CF IPs/domains.{A.RST}",
        f"   {A.DIM}Scanner replaces the address for each entry and tests them all.{A.RST}",
        f"   {A.WHT}Template:{A.RST}  {A.GRN}vless://uuid@ADDR:443?type=ws&...#name{A.RST}",
        f"   {A.WHT}Addresses:{A.RST} {A.GRN}one IP or domain per line (.txt){A.RST}",
        f"   {A.DIM}CLI: python3 scanner.py --template 'vless://...' -i addrs.txt{A.RST}",
        "",
        f" {A.BOLD}{A.CYN}[F] Find Clean Cloudflare IPs{A.RST}",
        f"   {A.DIM}Scans all CF IP ranges to find reachable edge IPs.{A.RST}",
        f"   {A.DIM}Modes: Quick (~4K), Normal (~12K), Full (~1.5M), Mega (~3M multi-port){A.RST}",
        f"   {A.DIM}Mega tests all IPs on ports 443+8443 for maximum coverage.{A.RST}",
        f"   {A.DIM}Found IPs can be saved or used with a template for speed test.{A.RST}",
        f"   {A.DIM}CLI: python3 scanner.py --find-clean --no-tui --clean-mode mega{A.RST}",
        "",
        f" {A.CYN}{'─' * 46}{A.RST}",
        f" {A.BOLD}{A.CYN}How it works:{A.RST}",
        f"   {A.DIM}1. Resolve domains to CF edge IPs, deduplicate{A.RST}",
        f"   {A.DIM}2. Test TCP+TLS latency, cut bottom by latency{A.RST}",
        f"   {A.DIM}3. Speed test top candidates in progressive rounds{A.RST}",
        f"   {A.DIM}4. Score = latency 35% + speed 50% + TTFB 15%{A.RST}",
        f"   {A.DIM}5. Export top configs ranked by score{A.RST}",
        "",
        f" {A.BOLD}{A.WHT}Made By Sam - SamNet Technologies{A.RST}",
        f" {A.DIM}https://github.com/SamNet-dev/cfray{A.RST}",
    ]

    # Fit within terminal: header(3) + title(1) + sep(1) + guide + footer(3)
    max_guide = rows - 8
    if max_guide < len(guide):
        guide = guide[:max_guide]

    for g in guide:
        lines.append(draw_box_line(g, cols))

    lines.append(draw_box_line("", cols))
    lines.append(draw_box_sep(cols))
    lines.append(draw_box_line(f" {A.DIM}Press any key to go back{A.RST}", cols))
    lines.append(draw_box_bottom(cols))

    _w("\n".join(lines) + "\n")
    _fl()
    _read_key_blocking()


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
            ips, workers=scan_cfg["workers"], timeout=3.0,
            validate=scan_cfg["validate"], cs=cs, ports=ports,
        )
    )

    old_sigint = signal.getsignal(signal.SIGINT)
    def _sig(sig, frame):
        cs.interrupted = True
        scan_task.cancel()
    signal.signal(signal.SIGINT, _sig)

    _w(A.CLR + A.HIDE)
    try:
        while not scan_task.done():
            _draw_clean_progress(cs)
            await asyncio.sleep(0.3)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    try:
        results = await scan_task
    except (asyncio.CancelledError, Exception):
        results = sorted(cs.all_results or cs.results, key=lambda x: x[1])

    elapsed = _fmt_elapsed(time.monotonic() - cs.start_time)
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
            out.append(f"{A.CYN}║{A.RST}" + c + " " * max(0, W - _vl(c)) + f"{A.CYN}║{A.RST}")

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


async def run_tui(args):
    """TUI mode: interactive startup + dashboard."""
    enable_ansi()

    # Determine initial input source from CLI args
    input_method = None  # "file", "sub", or "template"
    input_value = None
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
    args = p.parse_args()

    args._mode_set = any(a == "-m" or a.startswith("--mode") for a in sys.argv)

    try:
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
