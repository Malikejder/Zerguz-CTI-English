# 🛡️ ZERGUZ CTI

**ZERGUZ CTI** is a terminal-based, multi-source **Cyber Threat Intelligence** tool. It queries files, IPs/hosts, and hashes against trusted threat intelligence sources such as **ThreatFox**, **MalwareBazaar**, **Shodan**, **AbuseIPDB**, **Feodo Tracker**, **FireHOL**, and **CINS Score**, then produces a unified risk score.

```
███████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗████████╗██╗
╚══███╔╝██╔════╝██╔══██╗██╔════╝ ██║   ██║╚══███╔╝    ██╔════╝╚══██╔══╝██║
  ███╔╝ █████╗  ██████╔╝██║  ███╗██║   ██║  ███╔╝     ██║        ██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ███╔╝      ██║        ██║   ██║
███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████╗    ╚██████╗   ██║   ██║
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝   ╚═╝   ╚═╝
```

---

## ✨ Features

- **📄 File Scanning** — Computes the file's MD5 / SHA1 / SHA256 hashes, checks them against ThreatFox and MalwareBazaar, and runs a local heuristic analysis (dangerous extensions, double extensions, suspicious filenames, embedded suspicious commands, etc.).
- **🌐 IP / Host Scanning** — Checks the target IP or hostname against ThreatFox, Shodan, AbuseIPDB, as well as the Feodo Tracker, FireHOL Level-1, and CINS Score blocklists. Also inspects open ports, CVE vulnerabilities, reverse DNS, and suspicious hostname patterns.
- **📁 Directory Scanning** — Recursively scans every file in a given directory and produces a summarized threat report.
- **🔎 Hash Lookup** — If you only have an MD5/SHA256 hash, you can query ThreatFox and MalwareBazaar directly without needing the actual file.
- **🔄 Feed Caching** — Large IP feeds like Feodo, FireHOL, and CINS are cached for 1 hour and can be manually refreshed at any time.
- **🎯 0–10 Threat Score** — All results are mapped to one of six severity levels: CLEAN, LOW RISK, SUSPICIOUS, MEDIUM THREAT, HIGH THREAT, and CRITICAL THREAT.
- **⌨️ Interactive Menu + CLI** — Usable both as an interactive terminal menu and via command-line arguments for scripting/automation.
- **🎨 Colorful Terminal UI** — Readable, trackable output with ANSI colors and progress bars.

---

## ⚙️ Requirements

- Python **3.8+**
- [`requests`](https://pypi.org/project/requests/) library

```bash
pip install requests
```

> If `requests` is not installed, the program will still run, but all network-based queries (API calls) will be disabled; only local hash/heuristic analysis will continue to work.

---

## 📥 Installation

```bash
git clone https://github.com/<your-username>/ZERGUZ-CTI.git
cd ZERGUZ-CTI
pip install -r requirements.txt   # or simply: pip install requests
python3 Zerguz-CTI.py
```

> If the repo doesn't include a `requirements.txt`, adding the single `requests` package is enough.

---

## 🔑 API Keys

Some sources (ThreatFox, MalwareBazaar, Shodan, AbuseIPDB) support an **optional** API key. Without a key, the tool still works, but results from these sources will be more limited/rate-limited. Feodo, FireHOL, and CINS work without any key.

You can set the keys in three different ways:

**1) From inside the program (Menu 6 — Configure API Keys)**
```text
6 → API Anahtarlarini Ayarla (Configure API Keys)
```

**2) Via command-line arguments**
```bash
python3 Zerguz-CTI.py --shodan-key XXXX --abuseipdb-key XXXX \
                       --threatfox-key XXXX --malwarebazaar-key XXXX
```

**3) By editing the source directly**
Edit the `API_KEYS` dictionary at the top of `Zerguz-CTI.py`:
```python
API_KEYS = {
    "shodan": "YOUR_SHODAN_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "threatfox": "YOUR_THREATFOX_KEY",
    "malwarebazaar": "YOUR_MALWAREBAZAAR_KEY"
}
```

> ⚠️ **Important:** If you hardcode your keys into the source file, **never** push this file to a public GitHub repo with the keys still in it. Use a `.gitignore` entry or pass the keys via environment variables/CLI arguments instead.

You can get free API keys here:

| Source | Link |
|---|---|
| ThreatFox | https://threatfox.abuse.ch/api/ |
| MalwareBazaar | https://bazaar.abuse.ch/api/ |
| Shodan | https://account.shodan.io |
| AbuseIPDB | https://www.abuseipdb.com/api |

---

## 🚀 Usage

### Interactive Menu

Running the script without any arguments opens the menu:

```bash
python3 Zerguz-CTI.py
```

```
┌──────────────────────────────────────────────────┐
│  1  Scan File       (ThreatFox + MalwareBazaar)   │
│  2  Scan IP / Host   (TF + Shodan + AbuseIPDB)    │
│  3  Scan Directory   (Bulk)                       │
│  4  Lookup Hash      (MD5 / SHA256)                │
│  5  Refresh Feeds                                  │
│  6  Configure API Keys                             │
│  0  Exit                                           │
└──────────────────────────────────────────────────┘
```

### Command-Line (CLI) Mode

For automation, scripting, and quick lookups, you can pass arguments directly:

| Argument | Description |
|---|---|
| `-f`, `--file <path>` | Scan a single file |
| `-i`, `--ip <ip/host>` | Scan an IP address or hostname |
| `-d`, `--dir <path>` | Recursively scan a directory |
| `-H`, `--hash <hash>` | Look up an MD5 or SHA256 hash |
| `--shodan-key <key>` | Set the Shodan API key |
| `--abuseipdb-key <key>` | Set the AbuseIPDB API key |
| `--threatfox-key <key>` | Set the ThreatFox API key |
| `--malwarebazaar-key <key>` | Set the MalwareBazaar API key |
| `--no-banner` | Hide the startup banner |

#### Examples

**Scan a file:**
```bash
python3 Zerguz-CTI.py -f /home/user/downloads/setup.exe
```

**Scan an IP address:**
```bash
python3 Zerguz-CTI.py -i 185.220.101.1
```

**Scan a hostname:**
```bash
python3 Zerguz-CTI.py -i example.com
```

**Scan a directory in bulk:**
```bash
python3 Zerguz-CTI.py -d /home/user/downloads
```

**Look up a hash only (no file needed):**
```bash
python3 Zerguz-CTI.py -H 44d88612fea8a8f36de82e1278abb02f
```

**Run with API keys, without the banner:**
```bash
python3 Zerguz-CTI.py -i 8.8.8.8 --shodan-key XXXX --abuseipdb-key XXXX --no-banner
```

---

## 📊 How Is the Threat Score Calculated?

Every scan produces a score between **0 and 10**:

| Score | Level |
|---|---|
| 0 | ✅ CLEAN |
| 1–2 | 🔵 LOW RISK |
| 3–4 | 🟡 SUSPICIOUS |
| 5–6 | 🟠 MEDIUM THREAT |
| 7–8 | 🔴 HIGH THREAT |
| 9–10 | ☠ CRITICAL THREAT |

The score is the highest value among live threat intelligence results (ThreatFox/MalwareBazaar matches, blocklist matches, etc.) and the local heuristic analysis.

---

## ⚠️ Disclaimer

This tool is intended **for defensive security purposes only** (auditing your own systems/network, inspecting suspicious files you own, etc.). Scanning third-party systems without authorization may be illegal in your jurisdiction; only use this tool against systems and files you are **authorized** to test. The developer is not responsible for any misuse of this tool.

---

## 🤝 Contributing

Bug reports, suggestions, and pull requests are welcome. Please check existing issues before opening a new one.

