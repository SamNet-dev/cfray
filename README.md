<div align="center">

# ⚡ cfray

### Cloudflare Config Scanner & Clean IP Finder

**Test VLESS/VMess proxy configs for latency & speed + Scan all ~1.5M Cloudflare IPs to find clean, reachable edges**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-green.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](#-english) • [فارسی](#-فارسی)

---

</div>

## 🇬🇧 English

### 📖 What is cfray?

cfray is a single-file Python tool that finds the **fastest Cloudflare edge IPs** for your VLESS/VMess proxy configs. It tests latency (ping) and download speed across hundreds of IPs, ranks them by score, and exports the best configs — ready to use. It also includes a **Clean IP Finder** that scans all ~1.5M Cloudflare IPv4 addresses (from 14 published subnets) to discover reachable edge IPs. Mega mode tests each IP on 2 ports for ~3M total probes.

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
| `E`   | 💾 Export results (CSV + top N configs)     |
| `A`   | 📦 Export ALL configs sorted best → worst   |
| `J/K` | ⬆️⬇️ Scroll up/down                        |
| `N/P` | 📄 Page up/down                             |
| `B`   | ◀️ Back to main menu (new scan)             |
| `H`   | ❓ Help                                     |
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

## 🇮🇷 فارسی

### 📖 cfray چیه؟

cfray یه ابزار پایتونه که **سریع‌ترین آی‌پی‌های کلادفلر** رو برای کانفیگ‌های VLESS/VMess پیدا می‌کنه. پینگ و سرعت دانلود رو تست می‌کنه، بهترین‌ها رو امتیاز میده و خروجی آماده استفاده میده. همچنین شامل **جستجوگر آی‌پی تمیز** هست که تمام ~۱.۵ میلیون آی‌پی IPv4 کلادفلر (از ۱۴ زیرشبکه) رو اسکن می‌کنه. حالت Mega هر آی‌پی رو روی ۲ پورت تست می‌کنه (~۳ میلیون پروب).

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

| حالت       | تعداد آی‌پی   | پورت‌ها     | زمان تقریبی  | توضیحات                                   |
|-----------|---------------|-------------|--------------|-------------------------------------------|
| Quick     | ~۴,۰۰۰       | 443         | ~۳۰ ثانیه    | ۱ آی‌پی تصادفی از هر بلاک /24             |
| Normal    | ~۱۲,۰۰۰      | 443         | ~۲ دقیقه     | ۳ آی‌پی از هر بلاک + تایید CF (پیشنهادی)  |
| Full      | ~۱,۵۰۰,۰۰۰  | 443         | ۲۰+ دقیقه    | همه آی‌پی‌ها + تایید CF                    |
| Mega      | ~۳,۰۰۰,۰۰۰  | 443 + 8443  | ۳۰-۶۰ دقیقه  | همه آی‌پی‌ها روی ۲ پورت برای حداکثر پوشش  |

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

| حالت                | مراحل               | حجم تقریبی | زمان تقریبی  | مناسب برای         |
|---------------------|----------------------|------------|--------------|---------------------|
| ⚡ سریع (Quick)     | 1MB → 5MB           | ~200 MB    | ~2-3 دقیقه   | بررسی سریع         |
| 🔄 معمولی (Normal)  | 1MB → 5MB → 20MB    | ~850 MB    | ~5-10 دقیقه  | متعادل (پیشنهادی)  |
| 🔬 دقیق (Thorough)  | 5MB → 25MB → 50MB   | ~5-10 GB   | ~20-45 دقیقه | حداکثر دقت         |

---

### 🖥️ کلیدهای داشبورد

بعد از اتمام اسکن، یه داشبورد تعاملی دارید:

| کلید  | عملکرد                                           |
|-------|--------------------------------------------------|
| `S`   | 🔄 تغییر مرتب‌سازی: امتیاز → پینگ → سرعت        |
| `C`   | 📋 نمایش کانفیگ‌های VLESS/VMess یه آی‌پی          |
| `D`   | 🌐 نمایش دامنه‌های یه آی‌پی                       |
| `E`   | 💾 خروجی گرفتن (CSV + بهترین N تا)               |
| `A`   | 📦 خروجی همه کانفیگ‌ها (مرتب شده)                 |
| `J/K` | ⬆️⬇️ بالا/پایین                                   |
| `N/P` | 📄 صفحه بعد/قبل                                   |
| `B`   | ◀️ برگشت به منو (اسکن جدید)                       |
| `H`   | ❓ راهنما                                          |
| `Q`   | 🚪 خروج                                           |

---

### 📁 فایل‌های خروجی

نتایج توی پوشه `results/` ذخیره میشن:

| فایل                 | محتوا                                   |
|----------------------|-----------------------------------------|
| `*_results.csv`      | فایل CSV با تمام اطلاعات                |
| `*_top50.txt`        | ۵۰ تا بهترین کانفیگ (آماده استفاده)     |
| `*_full_sorted.txt`  | همه کانفیگ‌ها مرتب شده                   |
| `clean_ips.txt`      | آی‌پی‌های تمیز کلادفلر از IP Finder      |

---

### 🛡️ مدیریت محدودیت کلادفلر

cfray هوشمندانه با محدودیت‌های سرعت‌سنجی کلادفلر کار می‌کنه:
- بودجه درخواست‌ها رو پیگیری می‌کنه (۵۵۰ درخواست در هر ۱۰ دقیقه)
- وقتی محدود بشه (429)، خودکار به **سرور CDN** سوئیچ می‌کنه
- وقتی فایل بزرگ رد بشه (403)، از طریق CDN دوباره امتحان می‌کنه
- تایمر شمارش معکوس نشون میده

---

<div align="center">

### ⭐ Made by Sam — SamNet Technologies

</div>
