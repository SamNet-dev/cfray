<div align="center">

# ⚡ cfray

### Cloudflare Proxy Toolkit

**Scan configs + Find clean IPs + Deploy Xray servers + Pipeline test with DPI bypass + Worker proxy**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-green.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version 1.1](https://img.shields.io/badge/Version-1.1-orange.svg)](#)

[English](#-english) • [فارسی](#-فارسی)

---

</div>

## 🇬🇧 English

### 📖 What is cfray?

cfray is a single-file Python proxy toolkit for VLESS/VMess configs behind Cloudflare. What started as an IP scanner is now a full suite:

- **Config Scanner** — test hundreds of IPs for latency + download speed, rank by score, export the best configs
- **Clean IP Finder** — scan all ~1.5M Cloudflare IPv4 addresses to find reachable edge IPs (Mega mode: ~3M probes on 2 ports)
- **Xray Pipeline Test** — 3-stage pipeline that scans IPs, swaps them into your config, and expands with fragment presets + SNI variations to bypass DPI/firewall blocks
- **Deploy Xray Server** — deploy a full xray-core server on any Linux VPS with systemd, TLS certs, REALITY keys, and multi-config support
- **Worker Proxy** — generate a Cloudflare Worker script for a fresh `workers.dev` SNI on any VLESS WebSocket config
- **Connection Manager** — manage inbounds, users, URIs, and uninstall on deployed servers

**Zero dependencies.** Just Python 3.8+ and one file.

---

### 🚀 Quick Start

```bash
# Download
git clone https://github.com/SamNet-dev/cfray.git
cd cfray

# Run interactive TUI
python3 scanner.py

# That's it! Pick your input, choose a mode, and watch the results.
```

---

### 📥 Input Methods

cfray supports **5 ways** to load your configs:

#### 1️⃣ Config File `[1-9]`
A `.txt` file with one VLESS or VMess URI per line:
```
vless://uuid@domain1.ir:443?type=ws&host=sni.com&path=/dl&security=tls#config-1
vless://uuid@domain2.ir:443?type=ws&host=sni.com&path=/dl&security=tls#config-2
vmess://eyJ2IjoiMiIsImFkZCI6...
```
Drop your file in the same folder as `scanner.py` and it shows up automatically.

#### 2️⃣ Subscription URL `[S]`
Paste a remote URL that serves VLESS/VMess configs:
```bash
# Interactive
python3 scanner.py
# Press S, paste URL

# CLI
python3 scanner.py --sub https://example.com/sub.txt
```
Supports both **plain text** (one URI per line) and **base64-encoded** subscriptions.

#### 3️⃣ Template + Address List `[T]`
Have ONE working config but want to test it against many Cloudflare IPs? This is for you.

**How it works:**
1. You give a VLESS/VMess config as a **template**
2. You give a `.txt` file with **Cloudflare IPs or domains** (one per line)
3. cfray creates a config for **each address** by replacing the IP in your template
4. Tests them all and finds the fastest

```bash
# Interactive
python3 scanner.py
# Press T, paste your config, enter path to address list

# CLI
python3 scanner.py --template 'vless://uuid@placeholder:443?type=ws&...' -i addresses.txt
```

**Example address list** (`addresses.txt`):
```
104.21.12.206
188.114.96.7
172.67.132.102
172.67.166.192
```

#### 4️⃣ Domain JSON File
A JSON file with domain + IP data:
```json
{"data": [
  {"domain": "example.ir", "ipv4": "104.21.x.x"},
  {"domain": "other.ir", "ipv4": "172.67.x.x"}
]}
```

#### 5️⃣ Clean IP Finder `[F]`
Don't have any configs or IPs? cfray can **scan all Cloudflare IP ranges** to find clean, reachable edge IPs — then use them directly with a template for speed testing.

**How it works:**
1. Generates IPs from all 14 Cloudflare IPv4 subnets (~1.5M IPs)
2. Probes each IP with TLS handshake + Cloudflare header validation
3. Returns all responding IPs sorted by latency
4. Save the results or feed them into Template mode for a full speed test

**Scan modes:**

| Mode      | IPs Tested   | Ports       | Est. Time   | Description                              |
|-----------|-------------|-------------|-------------|------------------------------------------|
| Quick     | ~4,000      | 443         | ~30 sec     | 1 random IP per /24 block                |
| Normal    | ~12,000     | 443         | ~2 min      | 3 IPs per /24 + CF verify (recommended)  |
| Full      | ~1,500,000  | 443         | 20+ min     | All IPs + CF verify                      |
| Mega      | ~3,000,000  | 443 + 8443  | 30-60 min   | All IPs on 2 ports for maximum coverage  |

Cloudflare publishes [14 IPv4 subnets](https://www.cloudflare.com/ips-v4/) totaling **~1,511,808 unique IPs**. Full and Mega modes scan all of them. **Mega mode** tests every IP on both port 443 and 8443 (Cloudflare's alternate HTTPS port), doubling the probes to **~3M** (1.5M IPs × 2 ports). This is useful when some IPs are blocked on one port but reachable on another. Results include the port (e.g., `104.16.5.20:8443`).

```bash
# Interactive
python3 scanner.py
# Press F, choose scan mode

# CLI
python3 scanner.py --find-clean --no-tui --clean-mode mega

# With custom subnets
python3 scanner.py --find-clean --no-tui --subnets "104.16.0.0/13,172.64.0.0/13"
```

Found IPs are saved to `results/clean_ips.txt` (full absolute path shown). You can then use them with Template mode to speed test a config against all discovered IPs.

---

### 🔬 How the Scan Works

```
Step 1: 🔍 DNS Resolution
  Resolve all domains to their Cloudflare edge IPs
  Group configs by IP (many domains share the same CF edge)

Step 2: 📡 Latency Test
  TCP connect + TLS handshake to each unique IP
  Mark alive/dead, measure ping & connection time

Step 3: 📊 Speed Test (progressive rounds)
  R1: Small file (1-5MB) → test all alive IPs
  R2: Medium file (5-25MB) → test top candidates
  R3: Large file (20-50MB) → test the best ones
  (For <50 IPs, ALL are tested in every round)

Step 4: 🏆 Scoring & Export
  Score = Latency (35%) + Speed (50%) + TTFB (15%)
  Export top configs ranked by score
```

---

### ⚙️ Scan Modes

| Mode           | Rounds              | Est. Data | Est. Time  | Best For               |
|----------------|----------------------|-----------|------------|------------------------|
| ⚡ Quick       | 1MB → 5MB           | ~200 MB   | ~2-3 min   | Fast check             |
| 🔄 Normal      | 1MB → 5MB → 20MB    | ~850 MB   | ~5-10 min  | Balanced (recommended) |
| 🔬 Thorough    | 5MB → 25MB → 50MB   | ~5-10 GB  | ~20-45 min | Maximum accuracy       |

---

### 🖥️ Dashboard Controls

After the scan, you get an interactive dashboard:

| Key   | Action                                     |
|-------|--------------------------------------------|
| `S`   | 🔄 Cycle sort: score → latency → speed     |
| `C`   | 📋 View all VLESS/VMess URIs for an IP     |
| `D`   | 🌐 View domains for an IP                  |
| `E`   | 💾 Export results (CSV + top N configs)    |
| `A`   | 📦 Export ALL configs sorted best → worst  |
| `J/K` | ⬆️⬇️ Scroll up/down                        |
| `N/P` | 📄 Page up/down                            |
| `B`   | ◀️ Back to main menu (new scan)            |
| `H`   | ❓ Help                                    |
| `Q`   | 🚪 Quit                                    |

---

### 🔧 CLI Options

```bash
python3 scanner.py [options]
```

| Option              | Description                              | Default  |
|---------------------|------------------------------------------|----------|
| `-i, --input`       | Input file (VLESS URIs or .json)         | —        |
| `--sub`             | Subscription URL                         | —        |
| `--template`        | VLESS/VMess template URI (use with `-i`) | —        |
| `-m, --mode`        | `quick` / `normal` / `thorough`          | `normal` |
| `--rounds`          | Custom rounds, e.g. `"1MB:200,5MB:50"`  | auto     |
| `-w, --workers`     | Latency test workers                     | 300      |
| `--speed-workers`   | Download test workers                    | 10       |
| `--timeout`         | Latency timeout (seconds)                | 5        |
| `--speed-timeout`   | Download timeout (seconds)               | 30       |
| `--skip-download`   | Latency only, no speed test              | off      |
| `--top`             | Export top N configs (0 = all)            | 50       |
| `--no-tui`          | Headless mode (plain text output)        | off      |
| `-o, --output`      | CSV output path                          | auto     |
| `--output-configs`  | Config file output path                  | auto     |
| `--find-clean`      | Find clean Cloudflare IPs                | off      |
| `--clean-mode`      | `quick` / `normal` / `full` / `mega`     | `normal` |
| `--subnets`         | Custom subnets (file or comma-separated) | all CF   |

---

### 💡 Examples

```bash
# Interactive TUI — easiest way
python3 scanner.py

# Quick scan with subscription
python3 scanner.py --sub https://example.com/sub.txt --mode quick

# Template: test one config against 500 IPs
python3 scanner.py --template 'vless://uuid@x:443?type=ws&host=sni.com&security=tls#test' -i ips.txt

# Headless mode for scripts/cron
python3 scanner.py -i configs.txt --no-tui --mode normal -o results.csv

# Latency only (no download test)
python3 scanner.py -i configs.txt --skip-download

# Custom rounds
python3 scanner.py -i configs.txt --rounds "2MB:100,10MB:30,50MB:10"

# Find clean Cloudflare IPs (interactive)
python3 scanner.py   # Press F

# Find clean IPs (headless, mega mode — ~3M probes)
python3 scanner.py --find-clean --no-tui --clean-mode mega
```

---

### 📁 Output Files

Results are saved to the `results/` folder:

| File                 | Contents                                |
|----------------------|-----------------------------------------|
| `*_results.csv`      | Full CSV with all metrics               |
| `*_top50.txt`        | Top 50 VLESS/VMess URIs (ready to use)  |
| `*_full_sorted.txt`  | ALL configs sorted best → worst         |
| `clean_ips.txt`      | Clean Cloudflare IPs from IP finder     |

---

### 🛡️ Rate Limiting & CDN Fallback

cfray is smart about Cloudflare's speed test limits:
- Tracks request budget (550 requests per 10-minute window)
- When rate-limited (429), automatically switches to **CDN mirror** (`cloudflaremirrors.com`)
- When CF blocks large downloads (403), retries through CDN
- Shows countdown timer when waiting for rate limit reset

---

### 🆕 What's New in v1.1

v1.1 adds **server deployment**, **pipeline testing**, **worker proxy**, and a **connection manager** — turning cfray from a scanner into a full proxy toolkit.

---

### ⚡ Xray Pipeline Test `[X]`

A smart 3-stage pipeline that takes a single VLESS/VMess config and finds the best way to connect through it — including DPI bypass via TLS fragmentation.

**How it works:**

```
Stage 1: 🔍 IP Scan
  Scans Cloudflare IP ranges to find clean, reachable IPs.
  Tests thousands of IPs in parallel via TLS handshake.

Stage 2: 🧪 Base Test
  Swaps each clean IP into your config and tests if it actually
  passes traffic. Uses a direct VLESS tunnel to verify real
  connectivity — not just a handshake. Filters down to IPs
  that work with your specific config.

Stage 3: 🔧 Fragment Expansion
  Takes the working IPs and expands them with DPI bypass fragment
  presets + SNI variations:
  - light:  100-200 byte fragments, 10-20ms interval
  - medium: 50-200 byte fragments, 10-40ms interval
  - heavy:  10-300 byte fragments, 5-50ms interval
  Finds the best combination of IP + fragment + SNI.
```

**Use case:** You have a config that doesn't connect (blocked by DPI/firewall). Instead of manually trying different IPs and fragment settings, the pipeline automatically finds working combinations.

**xray-core** is required — cfray downloads it automatically on first use or you can install manually:

```bash
# Auto-install xray-core
python3 scanner.py --xray-install

# Interactive pipeline
python3 scanner.py    # Press X

# CLI — test a specific config
python3 scanner.py --xray 'vless://uuid@domain:443?type=ws&security=tls#myconfig'

# CLI — only heavy fragments, keep top 5
python3 scanner.py --xray 'vless://...' --xray-frag heavy --xray-keep 5
```

---

### 🚀 Deploy Xray Server `[D]`

Deploy a fully configured Xray proxy server on any Linux VPS in under 2 minutes. The wizard walks you through every step — protocol, transport, security, port — and generates ready-to-use client URIs.

**What it sets up:**
- Downloads and installs **xray-core** binary
- Generates server config with your chosen protocol/transport/security
- Creates **systemd service** for auto-start on boot
- Obtains **TLS certificates** via certbot (for TLS security)
- Generates **x25519 keypair** (for REALITY security)
- Outputs client VLESS/VMess URIs you can import directly into your app

**Supported options:**

| Category   | Options                                      |
|------------|----------------------------------------------|
| Protocol   | VLESS, VMess                                 |
| Transport  | TCP, WebSocket, gRPC, HTTP/2, XHTTP          |
| Security   | REALITY, TLS, None                           |
| Ports      | Any port (default 443)                       |

> **Note:** REALITY mode only supports TCP, gRPC, and HTTP/2 transports. WebSocket and XHTTP are available with TLS or None security.

**REALITY** is the recommended security mode — it doesn't need a domain or TLS certificates. It uses x25519 key exchange with a "camouflage" SNI (like `yahoo.com` or `google.com`) to make traffic look like normal HTTPS.

**XHTTP** (also called SplitHTTP) is a CDN-compatible transport that works well behind Cloudflare and other CDN providers. It splits HTTP requests in a way that bypasses many DPI systems.

**Multi-config deploy:** You can deploy multiple protocol configurations in a single session. For example, deploy TCP+REALITY on port 443 *and* WS+TLS on port 444 on the same server. Each config gets its own UUID and port. REALITY keys and TLS certificates are generated once and reused across configs.

```bash
# Interactive wizard (recommended)
python3 scanner.py    # Press D

# CLI — deploy TCP+REALITY
python3 scanner.py --deploy --deploy-transport tcp --deploy-security reality

# CLI — deploy WS+TLS with custom domain
python3 scanner.py --deploy --deploy-transport ws --deploy-security tls --deploy-sni yourdomain.com

# CLI — custom port and protocol
python3 scanner.py --deploy --deploy-protocol vmess --deploy-transport grpc --deploy-port 8443
```

**After deploy,** you get an interactive menu:
- **[V] View URIs** — display all generated client configs again (they don't disappear)
- **[M] Connection Manager** — jump straight to managing the server
- **[Q] Back** — return to main menu

---

### ☁️ Worker Proxy `[O]`

Get a fresh **Cloudflare Workers** SNI for any VLESS config. cfray generates a Worker script that proxies WebSocket traffic to your backend server — you deploy it to your Cloudflare account and get a clean, unblocked `workers.dev` SNI.

**How it works:**
1. You provide a working VLESS config (WebSocket transport required)
2. cfray generates a JavaScript Worker script that relays WebSocket connections to your backend
3. cfray shows the script + step-by-step instructions to deploy it on `dash.cloudflare.com`
4. You paste the resulting Worker URL back into cfray
5. cfray outputs a new config with the fresh `*.workers.dev` domain as SNI

**Use case:** Your config works but the SNI/domain is blocked in your region. Instead of finding a new domain, you create a Workers proxy that gives you a clean `workers.dev` SNI. Since Cloudflare Workers domains are widely used for legitimate purposes, they're rarely blocked.

**Requirements:**
- A Cloudflare account (free tier works)
- Your original config must use **WebSocket** transport (Workers only proxy WS traffic)

```bash
# Interactive
python3 scanner.py    # Press O

# The wizard will ask for:
# 1. Your VLESS config URI
# 2. Generates script + shows manual deploy instructions
# 3. Your Worker URL (after you deploy it on dash.cloudflare.com)
```

---

### 🔧 Connection Manager `[C]`

Manage an existing Xray server's configuration directly — add/remove inbounds, manage users, view client URIs, and uninstall. Works with any xray-core server deployed by cfray.

**What you can do:**

| Key | Action |
|-----|--------|
| `A` | **Add inbound** — create a new protocol/transport/port |
| `V` | **View** — view inbound JSON details |
| `U` | **Add user** — add a new UUID to an existing inbound |
| `X` | **Remove inbound** — delete an existing inbound |
| `S` | **Show URIs** — display all client URIs for every user |
| `R` | **Restart xray** — restart the xray service |
| `L` | **Logs** — view xray service logs |
| `D` | **Uninstall** — completely remove xray, configs, systemd |
| `B` | **Back** — return to main menu |

**Show URIs** generates VLESS/VMess client URIs from the server's config file for every inbound and every user. This is useful when you've deployed multiple configs and need to share the URIs with users, or when you've lost the original URIs from deploy time.

**Uninstall** completely removes everything cfray installed: stops the xray service, removes the binary, deletes config files, removes the systemd service, and cleans up the `~/.cfray/` directory. Requires typing "uninstall" to confirm (safety check).

```bash
# Interactive
python3 scanner.py    # Press C
```

---

### 🔧 Updated CLI Options

New flags added in v1.1:

| Option              | Description                                  | Default       |
|---------------------|----------------------------------------------|---------------|
| `--xray URI`        | Test a VLESS/VMess URI through xray pipeline | —             |
| `--xray-frag`       | Fragment preset: `none`/`light`/`medium`/`heavy`/`all` | `all` |
| `--xray-bin PATH`   | Path to xray binary (auto-detect if not set) | auto          |
| `--xray-install`    | Download and install xray-core to `~/.cfray/bin/` | off      |
| `--xray-keep N`     | Export top N pipeline results                | 10            |
| `--deploy`          | Deploy Xray server on this Linux VPS         | —             |
| `--deploy-port`     | Server listen port                           | 443           |
| `--deploy-protocol` | `vless` / `vmess`                            | `vless`       |
| `--deploy-transport`| `tcp` / `ws` / `grpc` / `h2`                 | `tcp`         |
| `--deploy-security` | `reality` / `tls` / `none`                   | `reality`     |
| `--deploy-sni`      | SNI domain for TLS/REALITY                   | —             |
| `--deploy-cert`     | Path to TLS certificate                      | —             |
| `--deploy-key`      | Path to TLS private key                      | —             |
| `--deploy-ip`       | Override auto-detected server IP             | auto          |
| `--uninstall`       | Remove everything cfray installed            | off           |

---

### 💡 More Examples (v1.1)

```bash
# Install xray-core (needed for Pipeline Test)
python3 scanner.py --xray-install

# Pipeline test — find working IP + fragment combo for a blocked config
python3 scanner.py --xray 'vless://uuid@blocked-domain:443?type=ws&security=tls#config'

# Pipeline test — only try heavy fragments, export top 3
python3 scanner.py --xray 'vless://...' --xray-frag heavy --xray-keep 3

# Deploy — quick TCP+REALITY server (recommended for beginners)
python3 scanner.py --deploy

# Deploy — WS+TLS for CDN routing
python3 scanner.py --deploy --deploy-transport ws --deploy-security tls --deploy-sni example.com

# Deploy — VMess over gRPC
python3 scanner.py --deploy --deploy-protocol vmess --deploy-transport grpc

# Uninstall everything cfray deployed
python3 scanner.py --uninstall
```

---

## 🇮🇷 فارسی

### 📖 cfray چیه؟

cfray یه ابزار کامل پایتونی برای کانفیگ‌های VLESS/VMess پشت کلادفلره. یه فایل تکی که همه چیز رو داره:

- **اسکنر کانفیگ** — تست صدها آی‌پی برای پینگ + سرعت دانلود، رتبه‌بندی و خروجی بهترین کانفیگ‌ها
- **جستجوگر آی‌پی تمیز** — اسکن تمام ~۱.۵ میلیون آی‌پی IPv4 کلادفلر (حالت Mega: ~۳ میلیون پروب روی ۲ پورت)
- **تست پایپلاین Xray** — پایپلاین ۳ مرحله‌ای: اسکن آی‌پی، جایگزینی توی کانفیگ، گسترش با فرگمنت و SNI برای دور زدن DPI/فایروال
- **دیپلوی سرور Xray** — نصب سرور xray-core روی هر VPS لینوکسی با systemd، گواهی TLS، کلید REALITY و پشتیبانی چند کانفیگ
- **پروکسی ورکر** — تولید اسکریپت Worker کلادفلر برای SNI تازه `workers.dev` روی هر کانفیگ VLESS WebSocket
- **مدیریت اتصالات** — مدیریت inbound‌ها، کاربران، URI‌ها و حذف نصب سرورهای دیپلوی شده

**بدون نیاز به نصب چیز اضافه.** فقط Python 3.8+ و یه فایل.

---

### 🚀 شروع سریع

```bash
# دانلود
git clone https://github.com/SamNet-dev/cfray.git
cd cfray

# اجرا
python3 scanner.py
```

---

### 📥 روش‌های ورودی

cfray **۵ روش** برای بارگذاری کانفیگ‌ها داره:

#### 1️⃣ فایل کانفیگ `[1-9]`
یه فایل `.txt` که هر خط یه آدرس VLESS یا VMess داره:
```
vless://uuid@domain1.ir:443?type=ws&host=sni.com&path=/dl&security=tls#config-1
vmess://eyJ2IjoiMiIsImFkZCI6...
```
فایلتون رو کنار `scanner.py` بذارید، خودش پیداش می‌کنه.

#### 2️⃣ لینک اشتراک (Subscription) `[S]`
یه لینک بدید که توش کانفیگ‌های VLESS/VMess هست:
```bash
python3 scanner.py --sub https://example.com/sub.txt
```
هم **متن ساده** (هر خط یه URI) و هم **base64** رو ساپورت می‌کنه.

#### 3️⃣ قالب + لیست آدرس (Template) `[T]`
یه کانفیگ دارید ولی می‌خواید با کلی آی‌پی کلادفلر تستش کنید؟ این روش مال شماست!

**چطوری کار می‌کنه:**
1. یه کانفیگ VLESS/VMess به عنوان **قالب** میدید
2. یه فایل `.txt` با **آی‌پی‌ها یا دامنه‌های کلادفلر** میدید (هر خط یکی)
3. cfray به تعداد آدرس‌ها **کانفیگ می‌سازه** — آدرس توی قالب رو با هر آی‌پی عوض می‌کنه
4. همه رو تست می‌کنه و سریع‌ترین رو پیدا می‌کنه

```bash
# تعاملی
python3 scanner.py
# T رو بزن، کانفیگتو پیست کن، مسیر فایل آدرس‌ها رو بده

# خط فرمان
python3 scanner.py --template 'vless://uuid@x:443?type=ws&...' -i addresses.txt
```

**مثال فایل آدرس** (`addresses.txt`):
```
104.21.12.206
188.114.96.7
172.67.132.102
```

#### 4️⃣ فایل JSON دامنه‌ها
```json
{"data": [
  {"domain": "example.ir", "ipv4": "104.21.x.x"},
  {"domain": "other.ir", "ipv4": "172.67.x.x"}
]}
```

#### 5️⃣ پیدا کردن آی‌پی تمیز کلادفلر `[F]`
کانفیگ یا آی‌پی ندارید؟ cfray می‌تونه **تمام رنج آی‌پی‌های کلادفلر** رو اسکن کنه و آی‌پی‌های تمیز و قابل دسترس رو پیدا کنه — بعد مستقیم با حالت Template تست سرعت کنید.

**چطوری کار می‌کنه:**
1. آی‌پی‌ها رو از ۱۴ زیرشبکه IPv4 کلادفلر تولید می‌کنه (~۱.۵ میلیون آی‌پی)
2. هر آی‌پی رو با TLS handshake + بررسی هدر کلادفلر تست می‌کنه
3. آی‌پی‌های جواب‌دهنده رو بر اساس پینگ مرتب برمی‌گردونه
4. نتایج رو ذخیره کنید یا با حالت Template برای تست سرعت استفاده کنید

**حالت‌های اسکن:**

| حالت | تعداد آی‌پی | پورت‌ها | زمان تقریبی | توضیحات |
|------|------------|---------|------------|---------|
| Quick | ~4,000 | 443 | ~30 ثانیه | 1 آی‌پی تصادفی از هر بلاک /24 |
| Normal | ~12,000 | 443 | ~2 دقیقه | 3 آی‌پی از هر بلاک + تایید CF (پیشنهادی) |
| Full | ~1,500,000 | 443 | 20+ دقیقه | همه آی‌پی‌ها + تایید CF |
| Mega | ~3,000,000 | 443+8443 | 30-60 دقیقه | همه آی‌پی‌ها روی 2 پورت |

کلادفلر [۱۴ زیرشبکه IPv4](https://www.cloudflare.com/ips-v4/) منتشر کرده که مجموعاً **~۱,۵۱۱,۸۰۸ آی‌پی یکتا** هستن. حالت‌های Full و Mega همه رو اسکن می‌کنن. **حالت Mega** هر آی‌پی رو روی پورت 443 و 8443 (پورت جایگزین HTTPS کلادفلر) تست می‌کنه و تعداد پروب‌ها رو به **~۳ میلیون** می‌رسونه (۱.۵ میلیون آی‌پی × ۲ پورت). وقتی بعضی آی‌پی‌ها روی یه پورت مسدود هستن ولی روی پورت دیگه کار می‌کنن، این حالت خیلی مفیده.

```bash
# تعاملی
python3 scanner.py
# F رو بزن، حالت اسکن رو انتخاب کن

# خط فرمان
python3 scanner.py --find-clean --no-tui --clean-mode mega
```

آی‌پی‌های پیدا شده توی `results/clean_ips.txt` ذخیره میشن. بعد می‌تونید با حالت Template تست سرعت کنید.

---

### 🔬 اسکن چطوری کار می‌کنه؟

```
مرحله ۱: 🔍 تبدیل دامنه به آی‌پی (DNS)
  هر دامنه رو به آی‌پی کلادفلرش تبدیل می‌کنه
  کانفیگ‌هایی که آی‌پی مشترک دارن رو گروه می‌کنه

مرحله ۲: 📡 تست پینگ (Latency)
  اتصال TCP + TLS به هر آی‌پی
  زنده/مرده مشخص میشه، پینگ اندازه‌گیری میشه

مرحله ۳: 📊 تست سرعت (دانلود مرحله‌ای)
  R1: فایل کوچک (1-5MB) → همه آی‌پی‌ها
  R2: فایل متوسط (5-25MB) → بهترین‌ها
  R3: فایل بزرگ (20-50MB) → برترین‌ها
  (اگه کمتر از ۵۰ آی‌پی باشه، همه توی هر مرحله تست میشن)

مرحله ۴: 🏆 امتیازدهی و خروجی
  امتیاز = پینگ (۳۵%) + سرعت (۵۰%) + TTFB (۱۵%)
  بهترین کانفیگ‌ها رتبه‌بندی و ذخیره میشن
```

---

### ⚙️ حالت‌های اسکن

| حالت | مراحل | حجم تقریبی | زمان تقریبی | مناسب برای |
|------|-------|-----------|------------|-----------|
| Quick سریع | 1MB → 5MB | ~200 MB | ~2-3 دقیقه | بررسی سریع |
| Normal معمولی | 1MB → 5MB → 20MB | ~850 MB | ~5-10 دقیقه | متعادل (پیشنهادی) |
| Thorough دقیق | 5MB → 25MB → 50MB | ~5-10 GB | ~20-45 دقیقه | حداکثر دقت |

---

### 🖥️ کلیدهای داشبورد

بعد از اتمام اسکن، یه داشبورد تعاملی دارید:

| کلید | عملکرد |
|------|--------|
| `S` | تغییر مرتب‌سازی: امتیاز → پینگ → سرعت |
| `C` | نمایش کانفیگ‌های VLESS/VMess یه آی‌پی |
| `D` | نمایش دامنه‌های یه آی‌پی |
| `E` | خروجی گرفتن (CSV + بهترین N تا) |
| `A` | خروجی همه کانفیگ‌ها (مرتب شده) |
| `J/K` | بالا/پایین |
| `N/P` | صفحه بعد/قبل |
| `B` | برگشت به منو (اسکن جدید) |
| `H` | راهنما |
| `Q` | خروج |

---

### 📁 فایل‌های خروجی

نتایج توی پوشه `results/` ذخیره میشن:

| فایل | محتوا |
|------|-------|
| `*_results.csv` | فایل CSV با تمام اطلاعات |
| `*_top50.txt` | 50 تا بهترین کانفیگ (آماده استفاده) |
| `*_full_sorted.txt` | همه کانفیگ‌ها مرتب شده |
| `clean_ips.txt` | آی‌پی‌های تمیز کلادفلر از IP Finder |

---

### 🛡️ مدیریت محدودیت کلادفلر

cfray هوشمندانه با محدودیت‌های سرعت‌سنجی کلادفلر کار می‌کنه:
- بودجه درخواست‌ها رو پیگیری می‌کنه (۵۵۰ درخواست در هر ۱۰ دقیقه)
- وقتی محدود بشه (429)، خودکار به **سرور CDN** سوئیچ می‌کنه
- وقتی فایل بزرگ رد بشه (403)، از طریق CDN دوباره امتحان می‌کنه
- تایمر شمارش معکوس نشون میده

---

### 🆕 چه چیزهایی در v1.1 اضافه شده

v1.1 قابلیت‌های **دیپلوی سرور**، **تست پایپلاین**، **پروکسی ورکر** و **مدیریت اتصالات** رو اضافه کرده — cfray رو از یه اسکنر به یه ابزار کامل پروکسی تبدیل کرده.

---

### ⚡ تست پایپلاین Xray `[X]`

یه پایپلاین هوشمند ۳ مرحله‌ای که یه کانفیگ VLESS/VMess می‌گیره و بهترین راه اتصال رو پیدا می‌کنه — شامل دور زدن DPI با فرگمنت TLS.

**چطوری کار می‌کنه:**

```
مرحله ۱: 🔍 اسکن آی‌پی
  رنج‌های آی‌پی کلادفلر رو اسکن می‌کنه تا آی‌پی‌های تمیز و قابل
  دسترس پیدا کنه. هزاران آی‌پی رو همزمان با TLS handshake تست می‌کنه.

مرحله ۲: 🧪 تست پایه
  هر آی‌پی تمیز رو توی کانفیگتون جایگزین می‌کنه و تست می‌کنه که آیا
  واقعاً ترافیک رد می‌کنه یا نه. از تانل مستقیم VLESS برای تایید
  اتصال واقعی استفاده می‌کنه — نه فقط handshake. آی‌پی‌هایی که با
  کانفیگ خاص شما کار می‌کنن فیلتر میشن.

مرحله ۳: 🔧 گسترش فرگمنت
  آی‌پی‌های کار‌کننده رو با پریست‌های فرگمنت DPI bypass و تغییرات
  SNI گسترش میده:
  - light: فرگمنت 100-200 بایت، فاصله 10-20 میلی‌ثانیه
  - medium: فرگمنت 50-200 بایت، فاصله 10-40 میلی‌ثانیه
  - heavy: فرگمنت 10-300 بایت، فاصله 5-50 میلی‌ثانیه
  بهترین ترکیب آی‌پی + فرگمنت + SNI رو پیدا می‌کنه.
```

**کاربرد:** کانفیگی دارید که وصل نمیشه (مسدود شده توسط DPI/فایروال). به جای اینکه دستی آی‌پی و تنظیمات فرگمنت مختلف رو امتحان کنید، پایپلاین خودکار ترکیب‌های کار‌کننده رو پیدا می‌کنه.

**xray-core** لازمه — cfray اولین بار خودش دانلود می‌کنه یا می‌تونید دستی نصب کنید:

```bash
# نصب خودکار xray-core
python3 scanner.py --xray-install

# پایپلاین تعاملی
python3 scanner.py    # X رو بزنید

# خط فرمان — تست یه کانفیگ خاص
python3 scanner.py --xray 'vless://uuid@domain:443?type=ws&security=tls#myconfig'

# خط فرمان — فقط فرگمنت سنگین، ۵ تا برتر
python3 scanner.py --xray 'vless://...' --xray-frag heavy --xray-keep 5
```

---

### 🚀 دیپلوی سرور Xray `[D]`

یه سرور پروکسی Xray کاملاً پیکربندی‌شده رو روی هر VPS لینوکسی در کمتر از ۲ دقیقه نصب کنید. ویزارد شما رو قدم به قدم راهنمایی می‌کنه — پروتکل، ترنسپورت، امنیت، پورت — و URI کلاینت آماده استفاده تحویل میده.

**چه چیزهایی نصب می‌کنه:**
- دانلود و نصب **xray-core**
- تولید کانفیگ سرور با پروتکل/ترنسپورت/امنیت دلخواه شما
- ساخت **سرویس systemd** برای اجرای خودکار
- دریافت **گواهی TLS** با certbot (برای امنیت TLS)
- تولید **کلید x25519** (برای امنیت REALITY)
- خروجی URI کلاینت VLESS/VMess که مستقیم وارد اپ می‌کنید

**گزینه‌های پشتیبانی شده:**

| دسته | گزینه‌ها |
|------|---------|
| پروتکل | VLESS, VMess |
| ترنسپورت | TCP, WebSocket, gRPC, HTTP/2, XHTTP |
| امنیت | REALITY, TLS, None |
| پورت | هر پورتی (پیشفرض 443) |

> **توجه:** حالت REALITY فقط از TCP، gRPC و HTTP/2 پشتیبانی می‌کنه. WebSocket و XHTTP با امنیت TLS یا None در دسترس هستن.

**REALITY** حالت امنیتی پیشنهادی هست — نیازی به دامنه یا گواهی TLS نداره. از تبادل کلید x25519 با SNI استتاری (مثل `yahoo.com` یا `google.com`) استفاده می‌کنه تا ترافیک شبیه HTTPS عادی به نظر بیاد.

**XHTTP** (SplitHTTP) یه ترنسپورت سازگار با CDN هست که پشت کلادفلر و CDN‌های دیگه خوب کار می‌کنه. درخواست‌های HTTP رو طوری تقسیم می‌کنه که از بسیاری از سیستم‌های DPI رد بشه.

**دیپلوی چند کانفیگ:** می‌تونید چندین کانفیگ با پروتکل‌های مختلف رو توی یه نشست نصب کنید. مثلاً TCP+REALITY روی پورت 443 *و* WS+TLS روی پورت 444 روی همون سرور. هر کانفیگ UUID و پورت خودش رو داره. کلیدهای REALITY و گواهی TLS یکبار تولید و بعد مجدداً استفاده میشن.

```bash
# ویزارد تعاملی (پیشنهادی)
python3 scanner.py    # D رو بزنید

# خط فرمان — TCP+REALITY
python3 scanner.py --deploy --deploy-transport tcp --deploy-security reality

# خط فرمان — WS+TLS با دامنه
python3 scanner.py --deploy --deploy-transport ws --deploy-security tls --deploy-sni yourdomain.com
```

**بعد از دیپلوی** یه منوی تعاملی دارید:
- **[V] مشاهده URI** — نمایش دوباره همه کانفیگ‌های تولید شده (دیگه ناپدید نمیشن)
- **[M] مدیریت اتصالات** — مستقیم به Connection Manager برید
- **[Q] برگشت** — برگشت به منوی اصلی

---

### ☁️ پروکسی ورکر `[O]`

یه **SNI تازه از Cloudflare Workers** برای هر کانفیگ VLESS بسازید. cfray یه اسکریپت Worker تولید می‌کنه که ترافیک WebSocket رو به سرور شما پروکسی می‌کنه — شما خودتون روی حساب کلادفلرتون دیپلوی می‌کنید و یه SNI تمیز `workers.dev` می‌گیرید.

**چطوری کار می‌کنه:**
1. یه کانفیگ VLESS کار‌کننده میدید (ترنسپورت WebSocket لازمه)
2. cfray یه اسکریپت JavaScript Worker تولید می‌کنه که اتصالات WebSocket رو به سرور شما رله می‌کنه
3. cfray اسکریپت + راهنمای قدم به قدم دیپلوی روی `dash.cloudflare.com` رو نشون میده
4. آدرس Worker خودتون رو توی cfray وارد می‌کنید
5. cfray یه کانفیگ جدید با دامنه تازه `*.workers.dev` به عنوان SNI خروجی میده

**کاربرد:** کانفیگتون کار می‌کنه ولی SNI/دامنه توی منطقه‌تون مسدود شده. به جای پیدا کردن دامنه جدید، یه پروکسی Workers می‌سازید که SNI تمیز `workers.dev` بهتون میده. چون دامنه‌های Workers کلادفلر برای کارهای قانونی زیادی استفاده میشن، به ندرت مسدود میشن.

**نیازمندی‌ها:**
- حساب کلادفلر (تیر رایگان کافیه)
- کانفیگ اصلی باید ترنسپورت **WebSocket** داشته باشه

```bash
# تعاملی
python3 scanner.py    # O رو بزنید
```

---

### 🔧 مدیریت اتصالات (Connection Manager) `[C]`

کانفیگ سرور Xray موجود رو مستقیم مدیریت کنید — اضافه/حذف inbound، مدیریت کاربران، مشاهده URI کلاینت‌ها و حذف نصب.

**کلیدهای مدیریت:**

| کلید | عملکرد |
|------|--------|
| `A` | **اضافه کردن inbound** — پروتکل/ترنسپورت/پورت جدید بسازید |
| `V` | **مشاهده** — جزئیات JSON اینباند رو ببینید |
| `U` | **اضافه کردن کاربر** — UUID جدید به یه inbound اضافه کنید |
| `X` | **حذف inbound** — یه inbound موجود رو پاک کنید |
| `S` | **نمایش URI** — همه URI‌های کلاینت برای همه کاربران |
| `R` | **ریستارت xray** — سرویس xray رو ریستارت کنید |
| `L` | **لاگ‌ها** — لاگ‌های سرویس xray رو ببینید |
| `D` | **حذف نصب** — xray، کانفیگ، systemd رو کامل پاک کنید |
| `B` | **برگشت** — برگشت به منوی اصلی |

**نمایش URI** از فایل کانفیگ سرور، URI‌های VLESS/VMess کلاینت رو برای هر inbound و هر کاربر تولید می‌کنه. وقتی چندین کانفیگ دیپلوی کردید و باید URI‌ها رو با کاربران به اشتراک بذارید، یا وقتی URI‌های اصلی از زمان دیپلوی گم شدن، خیلی مفیده.

**حذف نصب** هر چیزی که cfray نصب کرده رو کامل حذف می‌کنه: سرویس xray رو متوقف می‌کنه، باینری رو حذف می‌کنه، فایل‌های کانفیگ رو پاک می‌کنه، سرویس systemd رو حذف می‌کنه و پوشه `~/.cfray/` رو تمیز می‌کنه. برای ایمنی باید عبارت "uninstall" رو تایپ کنید.

```bash
# تعاملی
python3 scanner.py    # C رو بزنید
```

---

### 🔧 فلگ‌های جدید CLI در v1.1

| فلگ | توضیحات | پیشفرض |
|-----|---------|--------|
| `--xray URI` | تست URI از طریق پایپلاین xray | — |
| `--xray-frag` | پریست فرگمنت: `none`/`light`/`medium`/`heavy`/`all` | `all` |
| `--xray-bin PATH` | مسیر باینری xray | خودکار |
| `--xray-install` | دانلود و نصب xray-core در `~/.cfray/bin/` | خاموش |
| `--xray-keep N` | تعداد نتایج برتر پایپلاین | 10 |
| `--deploy` | دیپلوی سرور Xray روی VPS لینوکسی | — |
| `--deploy-port` | پورت سرور | 443 |
| `--deploy-protocol` | `vless` / `vmess` | `vless` |
| `--deploy-transport` | `tcp` / `ws` / `grpc` / `h2` | `tcp` |
| `--deploy-security` | `reality` / `tls` / `none` | `reality` |
| `--deploy-sni` | دامنه SNI برای TLS/REALITY | — |
| `--deploy-cert` | مسیر گواهی TLS | — |
| `--deploy-key` | مسیر کلید خصوصی TLS | — |
| `--deploy-ip` | جایگزین آی‌پی شناسایی خودکار سرور | خودکار |
| `--uninstall` | حذف کامل همه چیزهایی که cfray نصب کرده | خاموش |

---

### 💡 مثال‌های بیشتر (v1.1)

```bash
# نصب xray-core (برای تست پایپلاین لازمه)
python3 scanner.py --xray-install

# تست پایپلاین — پیدا کردن ترکیب آی‌پی + فرگمنت برای کانفیگ مسدود شده
python3 scanner.py --xray 'vless://uuid@domain:443?type=ws&security=tls#config'

# فقط فرگمنت سنگین، ۳ تا برتر
python3 scanner.py --xray 'vless://...' --xray-frag heavy --xray-keep 3

# دیپلوی سریع TCP+REALITY (پیشنهادی برای تازه‌کارها)
python3 scanner.py --deploy

# دیپلوی WS+TLS برای مسیریابی CDN
python3 scanner.py --deploy --deploy-transport ws --deploy-security tls --deploy-sni example.com

# حذف نصب کامل
python3 scanner.py --uninstall
```

---

<div align="center">

### ⭐ Made by Sam — SamNet Technologies

</div>
