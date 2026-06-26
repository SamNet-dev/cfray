# 🚀 cfray v1.2.0: The Ultimate All-in-One Xray & Cloudflare Proxy Toolkit

We are thrilled to announce **`cfray v1.2.0`** — a massive release that transforms `cfray` from a lightning-fast VLESS config scanner into a comprehensive, single-file Swiss Army knife for Cloudflare edge routing, proxy management, and censorship circumvention.

Keeping our strict philosophy of **zero external dependencies**, every single line of this release runs natively on **Python 3.8+ standard library** across Linux, Windows, and macOS.

---

## 🔥 Highlights & 14 Major New Features

### 🖥️ 1. Standalone Interactive TUI Tools (Menu Hotkeys)
Run `python3 scanner.py` without arguments to access new interactive tools directly from the main dashboard:
*   🛡️ **`[W]` WARP WireGuard Generator** — Instantly register a free, anonymous Cloudflare WARP+ account. Generates a clean WireGuard VPN profile (`warp.conf`) with Cloudflare edge endpoints ready for WireGuard client apps or Xray chain routing (`--warp`).
*   📡 **`[G]` Local Subscription Web Server** — Host your fastest scanned configs locally over a built-in lightweight HTTP server. Client applications (v2rayNG, Nekobox, Sing-box) can subscribe directly to `http://localhost:8080/` or fetch base64 encoded nodes via `/b64` (`--serve-sub`).
*   🧹 **`[L]` Subscription Deduplicator & Cleaner** — Paste any remote subscription feed URL or local file to automatically validate, clean, and strip out duplicate proxy links (`--clean-subs`).
*   🕵️ **`[I]` Deep Config Inspector & Validator** — Paste any `vless://` or `vmess://` URI to inspect protocol headers, transport parameters, and ALPN settings. Automatically diagnoses UUID typos, out-of-bounds ports, invalid WebSocket paths, and shortened REALITY public keys (`--inspect URI`).

### 📦 2. Instant Client Profile Exporters
Whenever you export scan results (via TUI dashboard keys `[E]` / `[A]` or CLI flags), `cfray` now automatically builds production-ready client profiles alongside standard `.txt` and `.csv` files:
*   🟢 **Sing-box Profile (`*_singbox.json`)** — Fully structured JSON outbounds array with TLS/REALITY parameters, WebSocket headers, and gRPC ALPN ready for Sing-box clients.
*   🐱 **Clash Meta Profile (`*_clash.yaml`)** — Ready-to-import YAML proxy nodes compatible with Clash Meta / Mihomo core.
*   ✈️ **Telegram Proxy Links (`*_telegram.txt`)** — Instant clickable `tg://socks` and `https://t.me/socks` proxy links pointing to local Xray SOCKS5 client tunnels (`--export-tg`).

### 🔬 3. Advanced Networking & Latency Benchmarks
*   📊 **Jitter & Packet Loss Benchmark (`--jitter`)** — Executes rapid multi-probe connection sequences during Phase 1 testing. Calculates ping standard deviation (Jitter) and dropped packet percentage, heavily penalizing unstable nodes during score ranking.
*   ⚡ **HTTP/2 ALPN Multiplexing Probe (`--alpn-h2`)** — Tests ALPN negotiation during TLS handshakes. Edge routers that successfully establish `h2` multiplexed tunnels receive a priority score bonus (`+5.0 points`).
*   🛡️ **UDP Latency Probe (`--udp`)** — Verifies full UDP packet transmission over established Xray tunnels (critical for gaming, DNS resolution, and VoIP calls).
*   🌐 **Censorship Circumvention Probe (`--check-censorship`)** — Executes real HTTP request probes against blocked target destinations (e.g., YouTube) through local proxy tunnels to verify complete DPI firewall bypass.

### 🤖 4. Enterprise Automation & Edge Routing
*   🤖 **Watchdog Daemon Mode (`--watch SECONDS`)** — Run `cfray` as a continuous background daemon. Automatically re-scans your config list at specified intervals to keep your proxy pools perpetually refreshed.
*   🔔 **Discord & Telegram Webhooks (`--notify WEBHOOK_URL`)** — Automatically dispatch rich summary notifications and alive node counts to your team channel or personal bot whenever a background scan finishes.
*   🌍 **Cloudflare DoH Resolution (`--doh`)** — Bypass ISP DNS poisoning by resolving all target domain names securely through Cloudflare DNS over HTTPS.
*   📍 **Geo-IP Colocation Tagging (`--geo`)** — Automatically query Cloudflare edge headers to tag each responding IP with its precise airport colocation code (e.g., `FRA`, `AMS`, `LHR`) and country code.

---

## 🖥️ TUI & CLI Integration Map

| Feature / Tool | Interactive TUI Mode | Command-Line (CLI) Flag |
| :--- | :---: | :--- |
| **WARP WireGuard VPN Gen** | Hotkey `[W]` | `--warp` |
| **Local HTTP Sub Server** | Hotkey `[G]` | `--serve-sub [PORT]` |
| **Sub Cleaner & Deduplicator** | Hotkey `[L]` | `--clean-subs URL_OR_FILE` |
| **Deep Config Inspector** | Hotkey `[I]` | `--inspect URI` |
| **Sing-box & Clash Meta Export**| Auto on Export `[E]` / `[A]` | `--export-client {singbox,clash}` |
| **Telegram Proxy Links** | Auto on Export `[E]` / `[A]` | `--export-tg` |
| **Jitter & Loss Benchmark** | Engine Setting | `--jitter` |
| **HTTP/2 ALPN Probe** | Engine Setting | `--alpn-h2` |
| **DoH DNS Resolution** | Engine Setting | `--doh` |
| **Geo-IP Colo Tagging** | Engine Setting | `--geo` |
| **UDP & Censorship Probes** | Engine Setting | `--udp` / `--check-censorship` |
| **Background Watchdog Daemon**| Headless Mode | `--watch SECONDS` |
| **Webhook Alerts** | Headless Mode | `--notify WEBHOOK_URL` |

---

## 🇮🇷 هماهنگی کامل مستندات فارسی

در نسخه `v1.2.0` تمام راهنماها، جدول گزینه‌های خط فرمان و مثال‌های کاربردی در بخش **🇮🇷 فارسی** فایل `README.md` به صورت ۱۰۰٪ همگام با بخش انگلیسی به‌روزرسانی شدند.

---

### ⭐ Quick Start
```bash
git clone https://github.com/SamNet-dev/cfray.git
cd cfray
python3 scanner.py
```
*Made with ❤️ by Sam — SamNet Technologies*
