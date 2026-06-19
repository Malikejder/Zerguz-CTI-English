#!/usr/bin/env python3

import os, sys, hashlib, socket, time, ipaddress, argparse
import json, urllib.parse, threading
from pathlib import Path
from datetime import datetime

RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
BLUE   = "\033[94m"; CYAN   = "\033[96m"; WHITE  = "\033[97m"
BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
BG_RED = "\033[41m"

THREATFOX_HOST     = "threatfox-api.abuse.ch"
THREATFOX_PATH     = "/api/v1/"
MALWAREBAZAAR_HOST = "mb-api.abuse.ch"
MALWAREBAZAAR_PATH = "/api/v1/"
FEODO_HOST         = "feodotracker.abuse.ch"
FEODO_PATH         = "/downloads/ipblocklist.json"
FIREHOL_HOST       = "raw.githubusercontent.com"
FIREHOL_PATH       = "/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
CINS_HOST          = "cinsscore.com"
CINS_PATH          = "/list/ci-badguys.txt"
SHODAN_HOST        = "api.shodan.io"
ABUSEIPDB_HOST     = "api.abuseipdb.com"

# You can paste your API keys directly here, inside the quotes
API_KEYS = {
    "shodan": "", 
    "abuseipdb": "", 
    "threatfox": "", 
    "malwarebazaar": "" 
}

_feodo_cache = _firehol_cache = _cinss_cache = None
_cache_time  = {}
CACHE_TTL    = 3600

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

def banner():
    print(f"""
{RED}{BOLD}
  ███████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗     ██████╗████████╗██╗
  ╚══███╔╝██╔════╝██╔══██╗██╔════╝ ██║   ██║╚══███╔╝    ██╔════╝╚══██╔══╝██║
    ███╔╝ █████╗  ██████╔╝██║  ███╗██║   ██║  ███╔╝     ██║        ██║   ██║
   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║ ███╔╝      ██║        ██║   ██║
  ███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝███████╗    ╚██████╗   ██║   ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝     ╚═════╝   ╚═╝   ╚═╝
{RESET}{DIM}
  [ ZERGUZ CTI v4.2 | ThreatFox · MalwareBazaar · Shodan · AbuseIPDB · Feodo · FireHOL · CINS ]
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
""")

def api_status_line():
    sh_ok = bool(API_KEYS["shodan"].strip())
    ab_ok = bool(API_KEYS["abuseipdb"].strip())
    tf_ok = bool(API_KEYS["threatfox"].strip())
    mb_ok = bool(API_KEYS["malwarebazaar"].strip())
    print(
        f"{'  ' + GREEN + '● ThreatFox ✔' if tf_ok else '  ' + YELLOW + '● ThreatFox (→Menu 6)'}{RESET}  "
        f"{'  ' + GREEN + '● MalwareBazaar ✔' if mb_ok else '  ' + YELLOW + '● MalwareBazaar (→Menu 6)'}{RESET}  "
        f"{GREEN}● Feodo  ● FireHOL  ● CINS{RESET}\n"
        f"{'  ' + GREEN + '● Shodan ✔' if sh_ok else '  ' + YELLOW + '● Shodan (→Menu 6)'}{RESET}  "
        f"{'  ' + GREEN + '● AbuseIPDB ✔' if ab_ok else '  ' + YELLOW + '● AbuseIPDB (→Menu 6)'}{RESET}\n"
    )

def sep(w=67): print(f"  {DIM}{'─'*w}{RESET}")

def threat_bar(n):
    c = RED if n>=8 else YELLOW if n>=5 else CYAN if n>=2 else GREEN
    return f"[{c}{'█'*int(n)}{RESET}{DIM}{'░'*(10-int(n))}{RESET}] {c}{BOLD}{n}/10{RESET}"

def threat_label(n):
    if   n == 0: return f"{GREEN}{BOLD}✅ CLEAN{RESET}"
    elif n <= 2: return f"{CYAN}{BOLD}🔵 LOW RISK{RESET}"
    elif n <= 4: return f"{YELLOW}{BOLD}🟡 SUSPICIOUS{RESET}"
    elif n <= 6: return f"{YELLOW}{BOLD}🟠 MEDIUM THREAT{RESET}"
    elif n <= 8: return f"{RED}{BOLD}🔴 HIGH THREAT{RESET}"
    else:        return f"{BG_RED}{WHITE}{BOLD} ☠ CRITICAL THREAT ☠ {RESET}"

def stag(name, hit=True):
    return f"{BG_RED}{WHITE} {name} {RESET}" if hit else f"{DIM}[{name}]{RESET}"

def pbar(lbl, dur=0.8, n=25):
    sys.stdout.write(f"  {CYAN}{lbl}{RESET}  [")
    sys.stdout.flush()
    for _ in range(n):
        time.sleep(dur/n)
        sys.stdout.write(f"{CYAN}█{RESET}")
        sys.stdout.flush()
    print(f"] {GREEN}✔{RESET}")

# ─── HTTP CORE ───────────────────────────────────

try:
    import requests as _req
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

def _make_session():
    if not REQUESTS_OK:
        return None
    s = _req.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent":      UA,
        "Accept-Encoding": "gzip, deflate",
        "Accept":          "*/*",
        "Connection":      "keep-alive",
    })
    return s

_SESSION = None

def _session():
    global _SESSION
    if _SESSION is None:
        _SESSION = _make_session()
    return _SESSION

def _parse_json(raw):
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    try:
        return json.loads(raw)
    except Exception:
        return None

def _spinner_run(label, fn):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    res=[None]; err=[None]
    def worker():
        try:
            res[0] = fn()
        except Exception as e:
            err[0] = str(e)
    t = threading.Thread(target=worker)
    t.start(); i = 0
    while t.is_alive():
        sys.stdout.write(f"\r  {CYAN}{frames[i%len(frames)]}{RESET} {label}")
        sys.stdout.flush()
        time.sleep(0.08); i += 1
    t.join()
    ok = res[0] is not None
    sys.stdout.write(
        f"\r  {GREEN}✔{RESET} {label}{' '*20}\n" if ok
        else f"\r  {RED}✖{RESET} {label} — {err[0] or 'error'}{' '*10}\n"
    )
    sys.stdout.flush()
    return res[0]

def api_post_json(label, host, path, payload_dict, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests module not found: pip install requests")
        hdrs = {"Content-Type": "application/json"}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.post(url, json=payload_dict, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        data = r.json()
        return data
    return _spinner_run(label, fn)

def api_post_form(label, host, path, payload_dict, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests module not found: pip install requests")
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.post(url, data=payload_dict, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        data = r.json()
        return data
    return _spinner_run(label, fn)

def api_get(label, host, path, extra_headers=None):
    url = f"https://{host}{path}"
    def fn():
        s = _session()
        if not s:
            raise Exception("requests module not found: pip install requests")
        hdrs = {}
        if extra_headers:
            hdrs.update(extra_headers)
        r = s.get(url, headers=hdrs, timeout=14, verify=True)
        if r.status_code != 200:
            raise Exception(f"HTTP {r.status_code}: {r.text[:150]}")
        return r.text
    return _spinner_run(label, fn)

# ─── FEED LISTS ──────────────────────────────────────────────

def _cache_ok(k): return k in _cache_time and (time.time()-_cache_time[k]) < CACHE_TTL

def load_feodo():
    global _feodo_cache
    if _cache_ok("feodo") and _feodo_cache is not None: return _feodo_cache
    raw = api_get("Loading Feodo Tracker C2 list...", FEODO_HOST, FEODO_PATH)
    _feodo_cache = {}
    if raw:
        try:
            for e in json.loads(raw):
                ip = e.get("ip_address","")
                if ip: _feodo_cache[ip] = (e.get("malware","?"), e.get("status","?"))
            _cache_time["feodo"] = time.time()
            print(f"  {DIM}→ {len(_feodo_cache)} C2 IPs loaded{RESET}")
        except Exception as ex:
            print(f"  {RED}Feodo parse error: {ex}{RESET}")
    return _feodo_cache

def load_firehol():
    global _firehol_cache
    if _cache_ok("firehol") and _firehol_cache is not None: return _firehol_cache
    raw = api_get("Loading FireHOL Level-1...", FIREHOL_HOST, FIREHOL_PATH)
    _firehol_cache = set()
    if raw:
        _firehol_cache = {l.strip() for l in raw.splitlines()
                          if l.strip() and not l.startswith("#")}
        _cache_time["firehol"] = time.time()
        print(f"  {DIM}→ {len(_firehol_cache)} IP/CIDR entries loaded{RESET}")
    return _firehol_cache

def load_cins():
    global _cinss_cache
    if _cache_ok("cins") and _cinss_cache is not None: return _cinss_cache
    raw = api_get("Loading CINS Score list...", CINS_HOST, CINS_PATH)
    _cinss_cache = set()
    if raw:
        _cinss_cache = {l.strip() for l in raw.splitlines()
                        if l.strip() and not l.startswith("#")}
        _cache_time["cins"] = time.time()
        print(f"  {DIM}→ {len(_cinss_cache)} IPs loaded{RESET}")
    return _cinss_cache

def ip_in_firehol(ip, fset):
    if ip in fset: return True
    try:
        addr = ipaddress.ip_address(ip)
        for e in fset:
            if "/" in e:
                try:
                    if addr in ipaddress.ip_network(e, strict=False): return True
                except: pass
    except: pass
    return False

# ─── ThreatFox ─────────────────────────────────────────────────

def threatfox_hash(md5, sha256):
    best = None
    headers = {}
    # FIXED: changed "API-KEY" to "Auth-Key"
    if API_KEYS["threatfox"].strip():
        headers["Auth-Key"] = API_KEYS["threatfox"].strip()
        
    for h in [x for x in [sha256, md5] if x]:
        data = api_post_json(
            f"Querying ThreatFox hash ({h[:18]}...)...",
            THREATFOX_HOST, THREATFOX_PATH,
            {"query": "search_hash", "hash": h},
            extra_headers=headers
        )
        if not data: continue
        st = data.get("query_status","")
        if st == "hash_found":
            for e in (data.get("data") or []):
                malware = e.get("malware_printable") or e.get("malware") or "Unknown"
                conf    = int(e.get("confidence_level") or 50)
                score   = min(10, int(conf/10) + 2)
                candidate = (score, malware, conf,
                             e.get("tags") or [],
                             e.get("threat_type_desc",""), h)
                if best is None or score > best[0]:
                    best = candidate
        elif st not in ("no_results", ""):
            print(f"  {YELLOW}ThreatFox response: {st}{RESET}")
    return best

def threatfox_ip(ip):
    headers = {}
    # FIXED: changed to "Auth-Key"
    if API_KEYS["threatfox"].strip():
        headers["Auth-Key"] = API_KEYS["threatfox"].strip()
        
    data = api_post_json(
        "Querying ThreatFox IP...",
        THREATFOX_HOST, THREATFOX_PATH,
        {"query": "search_ioc", "search_term": ip},
        extra_headers=headers
    )
    if not data: return None
    st = data.get("query_status","")
    if st == "no_results": return None
    if st not in ("ok", "hash_found"):
        print(f"  {YELLOW}ThreatFox IP response: {st}{RESET}"); return None
    best = None
    for e in (data.get("data") or []):
        malware = e.get("malware_printable") or e.get("malware") or "Unknown"
        conf    = int(e.get("confidence_level") or 50)
        score   = min(10, int(conf/10) + 3)
        if best is None or score > best[0]:
            best = (score, malware, conf, e.get("threat_type_desc",""), e.get("tags") or [])
    return best

# ─── MalwareBazaar ─────────────────────────────────────────────

def _mb_build(e, h):
    sig = e.get("signature") or ""
    if not sig:
        tags = e.get("tags") or []
        sig  = ", ".join(tags) if tags else "Unknown"
    if isinstance(sig, list): sig = ", ".join(sig)
    intel = e.get("intelligence") or {}
    return (9, sig,
            e.get("file_type","?"), e.get("file_size","?"),
            e.get("first_seen","?"), e.get("reporter","?"),
            e.get("tags") or [],
            intel.get("downloads","?"), intel.get("uploads","?"), h)

def malwarebazaar_hash(md5, sha256):
    headers = {}
    # FIXED: changed "API-KEY" to "Auth-Key"
    if API_KEYS["malwarebazaar"].strip():
        headers["Auth-Key"] = API_KEYS["malwarebazaar"].strip()
        
    for h in [x for x in [sha256, md5] if x]:
        data = api_post_form(
            f"MalwareBazaar get_info ({h[:18]}...)...",
            MALWAREBAZAAR_HOST, MALWAREBAZAAR_PATH,
            {"query": "get_info", "hash": h},
            extra_headers=headers
        )
        if not data: continue
        st = data.get("query_status","")
        if st == "ok":
            entries = data.get("data") or []
            if entries: return _mb_build(entries[0], h)
        elif st == "hash_not_found":
            print(f"  {DIM}hash_not_found → searching recent uploads via get_recent...{RESET}")
            data2 = api_post_form(
                "MalwareBazaar get_recent scan...",
                MALWAREBAZAAR_HOST, MALWAREBAZAAR_PATH,
                {"query": "get_recent", "selector": "time"},
                extra_headers=headers
            )
            if data2 and data2.get("query_status") == "ok":
                for e in (data2.get("data") or []):
                    if any(e.get(k,"").lower() == h.lower()
                           for k in ["sha256_hash","md5_hash","sha1_hash"]):
                        print(f"  {GREEN}✔ Match found in recent uploads!{RESET}")
                        return _mb_build(e, h)
        elif st not in ("", None):
            print(f"  {YELLOW}MalwareBazaar response: {st}{RESET}")
    return None

# ─── Shodan ────────────────────────────────────────────────────

def shodan_ip(ip):
    key = API_KEYS["shodan"].strip()
    if not key: return None
    raw = api_get(
        "Querying Shodan IP intelligence...",
        SHODAN_HOST, f"/shodan/host/{ip}?key={key}"
    )
    if not raw: return None
    try:
        d = _parse_json(raw)
        if not d or "error" in d:
            print(f"  {YELLOW}Shodan: {(d or {}).get('error','error')}{RESET}"); return None
        ports  = d.get("ports") or []
        vulns  = list((d.get("vulns") or {}).keys())
        tags   = d.get("tags") or []
        score  = 0; notes = []
        if vulns:
            score += min(len(vulns)*2, 6)
            notes.append(f"CVE vulnerabilities: {', '.join(vulns[:5])}")
        dp = [p for p in ports if p in {21,22,23,25,110,135,139,445,1433,3306,3389,4444,5900,6379,27017}]
        if len(ports) > 10:
            score += 2; notes.append(f"Too many open ports: {len(ports)}")
        if dp:
            score += min(len(dp),3); notes.append(f"Dangerous ports: {dp}")
        for t in tags:
            if any(s in t.lower() for s in ["tor","vpn","proxy","scanner","honeypot"]):
                score += 2; notes.append(f"Suspicious tag: {t}")
        return (min(score,10), d.get("org","?"), d.get("country_name","?"),
                d.get("city","?"), d.get("isp","?"), d.get("asn","?"),
                ports, vulns, tags, d.get("hostnames") or [],
                d.get("last_update","?"), notes)
    except Exception as ex:
        print(f"  {YELLOW}Shodan parse error: {ex}{RESET}"); return None

# ─── AbuseIPDB ─────────────────────────────────────────────────

def abuseipdb_ip(ip):
    key = API_KEYS["abuseipdb"].strip()
    if not key: return None
    path = f"/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose"
    raw  = api_get(
        "Querying AbuseIPDB abuse data...",
        ABUSEIPDB_HOST, path,
        extra_headers={"Key": key}
    )
    if not raw: return None
    try:
        d = _parse_json(raw)
        if not d: return None
        d = d.get("data",{})
        abuse = int(d.get("abuseConfidenceScore",0))
        return (min(10, int(abuse/10)), abuse,
                int(d.get("totalReports",0)),
                d.get("countryCode","?"), d.get("isp","?"),
                d.get("domain","?"), d.get("isWhitelisted",False),
                d.get("lastReportedAt"), d.get("usageType","?"))
    except Exception as ex:
        print(f"  {YELLOW}AbuseIPDB parse error: {ex}{RESET}"); return None

# ─── Hash & Heuristics ──────────────────────────────────────────

def calc_hashes(fp):
    m, s1, s256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    try:
        with open(fp,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                m.update(chunk); s1.update(chunk); s256.update(chunk)
        return m.hexdigest(), s1.hexdigest(), s256.hexdigest()
    except PermissionError:
        print(f"  {RED}✖ Access denied: {fp}{RESET}"); return None,None,None
    except Exception as ex:
        print(f"  {RED}✖ {ex}{RESET}"); return None,None,None

def heuristic(fp):
    score=0; reasons=[]
    name = Path(fp).name.lower()
    for ext in [".exe",".bat",".cmd",".vbs",".js",".ps1",".sh",".elf"]:
        if name.endswith(ext): score+=2; reasons.append(f"Dangerous extension ({ext})"); break
    if name.count(".")>=2: score+=2; reasons.append("Double extension")
    for p in ["invoice","payment","crack","keygen","setup","install"]:
        if p in name: score+=1; reasons.append(f"Suspicious name ({p})"); break
    if name.startswith("."): score+=1; reasons.append("Hidden file")
    try:
        sz = os.path.getsize(fp)
        if sz==0: return 0,["Empty file"]
        if sz<512 and any(name.endswith(e) for e in [".exe",".elf",".sh"]):
            score+=1; reasons.append("Very small executable")
    except: pass
    try:
        if os.path.getsize(fp)<1_000_000:
            with open(fp,"rb") as f: c=f.read(4096)
            if c[:4]==b"\x7fELF": score+=1; reasons.append("ELF binary")
            for s in [b"/etc/passwd",b"chmod 777",b"curl |bash",b"wget -O-",b"base64 -d"]:
                if s in c: score+=2; reasons.append(f"Suspicious command: {s.decode(errors='replace')}")
    except: pass
    return min(score,10), reasons

def ip_basic(ip):
    score=0; reasons=[]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:    return 0,["Private (local) network — internal"]
        if addr.is_loopback:   return 0,["Loopback address"]
        if addr.is_link_local: return 0,["Link-local — internal"]
        if addr.is_multicast:  score+=2; reasons.append("Multicast")
        if addr.is_reserved:   score+=1; reasons.append("Reserved block")
    except ValueError:
        return 10,["Invalid IP"]
    try:
        hn = socket.gethostbyaddr(ip)[0]
        reasons.append(f"Hostname: {hn}")
        for sh in ["tor","proxy","vpn","anon","exit","relay","botnet","scan","attack"]:
            if sh in hn.lower(): score+=3; reasons.append(f"Suspicious hostname: '{sh}'"); break
    except: reasons.append("Reverse DNS: none"); score+=1
    for port in [23,135,139,445,1433,3389,4444,5900,6666,31337][:6]:
        try:
            s=socket.socket(); s.settimeout(0.3)
            if s.connect_ex((ip,port))==0: score+=2; reasons.append(f"Suspicious open port: {port}")
            s.close()
        except: pass
    return min(score,10), reasons

# ─── Scan Functions ──────────────────────────────────────────

def scan_file(fp):
    path = Path(fp)
    print(f"\n{BOLD}{BLUE}  📄 SCANNING FILE{RESET}"); sep()
    print(f"  {WHITE}Path  :{RESET} {path}")
    print(f"  {WHITE}Size  :{RESET} {os.path.getsize(fp):,} bytes")
    print(f"  {WHITE}Time  :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    pbar("Calculating hashes...")
    md5, sha1, sha256 = calc_hashes(fp)
    if not md5: return
    print(f"\n  {CYAN}MD5   :{RESET} {md5}")
    print(f"  {CYAN}SHA1  :{RESET} {sha1}")
    print(f"  {CYAN}SHA256:{RESET} {sha256}"); sep()
    print(f"\n  {BOLD}Querying live threat intelligence...{RESET}\n")
    tf = threatfox_hash(md5, sha256)
    mb = malwarebazaar_hash(md5, sha256)
    pbar("Running heuristic analysis...")
    hs, hr = heuristic(fp)
    final = hs
    if tf: final = max(final, tf[0])
    if mb: final = max(final, mb[0])
    _show_file(final, tf, mb, hr)
    return final

def scan_hash(raw):
    raw = raw.strip().lower()
    hlen = len(raw)
    if hlen==32:   htype="MD5"
    elif hlen==64: htype="SHA256"
    else:
        print(f"\n  {RED}✖ Invalid hash length ({hlen}). MD5=32, SHA256=64.{RESET}\n"); return
    print(f"\n{BOLD}{BLUE}  🔎 LOOKING UP HASH{RESET}"); sep()
    print(f"  {WHITE}Type  :{RESET} {htype}")
    print(f"  {WHITE}Hash  :{RESET} {raw}")
    print(f"  {WHITE}Time  :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    print(f"\n  {BOLD}Querying live threat intelligence...{RESET}\n")
    tf = threatfox_hash(raw if hlen==32 else None, raw if hlen==64 else None)
    mb = malwarebazaar_hash(raw if hlen==32 else None, raw if hlen==64 else None)
    final = 0
    if tf: final = max(final, tf[0])
    if mb: final = max(final, mb[0])
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}HASH RESULT{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}Type         :{RESET}  {htype}")
    print(f"  {WHITE}Hash         :{RESET}  {DIM}{raw}{RESET}")
    print(f"  {WHITE}Threat Score :{RESET}  {threat_bar(final)}")
    print(f"  {WHITE}Threat Level :{RESET}  {threat_label(final)}")
    if tf:
        s,malware,conf,tags,threat,matched = tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} DETECTED!{RESET}")
        print(f"    Malware     : {RED}{BOLD}{malware}{RESET}")
        print(f"    Threat Type : {threat}")
        print(f"    Confidence  : %{conf}")
        print(f"    Matched Hash: {DIM}{matched}{RESET}")
        if tags: print(f"    Tags        : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}No match{RESET}")
    if mb:
        s,sig,ftype,fsize,first,rep,tags,dl,ul,matched = mb
        print(f"\n  {stag('MalwareBazaar')} {RED}{BOLD} DETECTED!{RESET}")
        print(f"    Signature/Family: {RED}{BOLD}{sig}{RESET}")
        print(f"    File Type   : {ftype}  |  Size: {fsize} bytes")
        print(f"    First Seen  : {first}  |  Reporter: {rep}")
        if tags: print(f"    Tags        : {', '.join(tags)}")
    else:
        print(f"\n  {stag('MalwareBazaar',False)} {GREEN}No match{RESET}")
    if final>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  DANGEROUS! Quarantine the file.  {RESET}")
    elif final>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Suspicious. Review recommended.{RESET}")
    else:
        print(f"\n  {YELLOW}ℹ Not found in known databases.{RESET}")
        print(f"  {DIM}  May be clean or not yet reported.{RESET}")
    print(f"  {'━'*67}\n")

def scan_ip(inp):
    print(f"\n{BOLD}{BLUE}  🌐 SCANNING IP / HOST{RESET}"); sep()
    ip = inp
    if not _is_ip(inp):
        print(f"  {CYAN}Resolving hostname:{RESET} {inp}")
        ip = _resolve(inp)
        if not ip:
            print(f"  {RED}✖ Could not resolve: {inp}{RESET}"); return
        print(f"  {WHITE}Resolved IP:{RESET} {ip}")
    print(f"  {WHITE}Target:{RESET} {ip}")
    print(f"  {WHITE}Time  :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"); sep()
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            print(f"\n  {CYAN}Internal address — skipping external queries{RESET}")
            sc, rs = ip_basic(ip); _show_ip(ip,sc,rs,[],None,None,None); return
    except: pass
    print(f"\n  {BOLD}Updating feed lists...{RESET}\n")
    feodo=load_feodo(); fhol=load_firehol(); cins=load_cins()
    print(f"\n  {BOLD}Running API queries...{RESET}\n")
    tf = threatfox_ip(ip)
    sh = shodan_ip(ip)
    ab = abuseipdb_ip(ip)
    pbar("Running basic IP analysis...")
    sc, rs = ip_basic(ip)
    feeds=[]
    if ip in feodo:
        m,st=feodo[ip]; sc=max(sc,9); feeds.append(f"Feodo C2 ({m}, {st})")
    if ip_in_firehol(ip,fhol):
        sc=max(sc,8); feeds.append("FireHOL Level-1")
    if ip in cins:
        sc=max(sc,7); feeds.append("CINS Score")
    if tf: sc=max(sc,tf[0])
    if sh: sc=max(sc,sh[0])
    if ab: sc=max(sc,ab[0])
    _show_ip(ip,sc,rs,feeds,tf,sh,ab)

def scan_dir(dirpath):
    directory = Path(dirpath)
    if not directory.is_dir():
        print(f"  {RED}✖ Invalid directory: {dirpath}{RESET}"); return
    files = [f for f in directory.rglob("*") if f.is_file()]
    print(f"\n{BOLD}{BLUE}  📁 SCANNING DIRECTORY{RESET}"); sep()
    print(f"  {WHITE}Directory:{RESET} {directory}")
    print(f"  {WHITE}Files    :{RESET} {len(files)}"); sep()
    results=[]
    
    # FIXED: changed to "Auth-Key"
    tf_headers = {"Auth-Key": API_KEYS["threatfox"].strip()} if API_KEYS["threatfox"].strip() else {}
    mb_headers = {"Auth-Key": API_KEYS["malwarebazaar"].strip()} if API_KEYS["malwarebazaar"].strip() else {}
    
    for i,f in enumerate(files,1):
        sys.stdout.write(f"\r  {CYAN}[{i}/{len(files)}]{RESET} {str(f)[:55]:<55}")
        sys.stdout.flush()
        md5,sha1,sha256 = calc_hashes(str(f))
        if not md5: continue
        hs,_ = heuristic(str(f))
        tf_score=mb_score=0; tf_name=mb_name=None
        s = _session()
        for h in [x for x in [sha256,md5] if x]:
            try:
                r = s.post(f"https://{THREATFOX_HOST}{THREATFOX_PATH}",
                           json={"query":"search_hash","hash":h}, headers=tf_headers, timeout=10, verify=True)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("query_status")=="hash_found":
                        iocs = d.get("data") or []
                        if iocs:
                            conf = int(iocs[0].get("confidence_level") or 50)
                            cand = min(10, int(conf/10)+2)
                            if cand > tf_score:
                                tf_score=cand; tf_name=iocs[0].get("malware_printable","?")
            except Exception:
                pass
        for h in [x for x in [sha256,md5] if x]:
            try:
                r = s.post(f"https://{MALWAREBAZAAR_HOST}{MALWAREBAZAAR_PATH}",
                           data={"query":"get_info","hash":h}, headers=mb_headers, timeout=10, verify=True)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("query_status")=="ok":
                        entries = d.get("data") or []
                        if entries:
                            sig = entries[0].get("signature") or "?"
                            if isinstance(sig,list): sig=", ".join(sig)
                            mb_score=9; mb_name=sig
                    elif d.get("query_status")=="hash_not_found":
                        r2 = s.post(f"https://{MALWAREBAZAAR_HOST}{MALWAREBAZAAR_PATH}",
                                    data={"query":"get_recent","selector":"time"}, headers=mb_headers, timeout=10, verify=True)
                        if r2.status_code == 200:
                            d2 = r2.json()
                            if d2.get("query_status")=="ok":
                                for e in (d2.get("data") or []):
                                    if any(e.get(k,"").lower()==h.lower()
                                           for k in ["sha256_hash","md5_hash","sha1_hash"]):
                                        sig = e.get("signature") or "?"
                                        if isinstance(sig,list): sig=", ".join(sig)
                                        mb_score=9; mb_name=sig; break
            except Exception:
                pass
        final = max(hs,tf_score,mb_score)
        src   = "ThreatFox" if tf_score>=mb_score and tf_name else "MalwareBazaar" if mb_name else None
        name  = tf_name if tf_score>=mb_score and tf_name else mb_name
        results.append((str(f),md5,sha256,final,name,src))
    threats = sum(1 for *_,s,n,sr in results if s>=5)
    print(f"\n\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}DIRECTORY SCAN REPORT{RESET}"); print(f"  {'━'*67}")
    print(f"  Total  : {len(results)}")
    print(f"  {RED if threats else GREEN}{BOLD}Threats: {threats}{RESET}\n")
    found = [(fp,m,s2,s,n,sr) for fp,m,s2,s,n,sr in results if s>=3]
    if found:
        print(f"  {YELLOW}Suspicious/Malicious Files:{RESET}")
        for fp,m,s2,sc,name,src in sorted(found,key=lambda x:-x[3]):
            print(f"\n  {RED if sc>=7 else YELLOW}■{RESET} {Path(fp).name}")
            print(f"    Path : {DIM}{fp}{RESET}")
            print(f"    Score: {threat_bar(sc)}")
            print(f"    Status: {threat_label(sc)}")
            if name: print(f"    Detected: {RED}{name}{RESET} ({src})")
    else:
        print(f"  {GREEN}✔ No threats detected.{RESET}")
    print(f"\n  {'━'*67}\n")

def _show_file(final, tf, mb, hr):
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}FILE RESULT{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}Threat Score :{RESET}  {threat_bar(final)}")
    print(f"  {WHITE}Threat Level :{RESET}  {threat_label(final)}")
    if tf:
        s,malware,conf,tags,threat,matched = tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} DETECTED!{RESET}")
        print(f"    Malware     : {RED}{BOLD}{malware}{RESET}")
        print(f"    Threat Type : {threat}")
        print(f"    Confidence  : %{conf}")
        print(f"    Matched Hash: {DIM}{matched}{RESET}")
        if tags: print(f"    Tags        : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}No match{RESET}")
    if mb:
        s,sig,ftype,fsize,first,rep,tags,dl,ul,matched = mb
        print(f"\n  {stag('MalwareBazaar')} {RED}{BOLD} DETECTED!{RESET}")
        print(f"    Signature   : {RED}{BOLD}{sig}{RESET}")
        print(f"    Type/Size   : {ftype} / {fsize} bytes")
        print(f"    First Seen  : {first}  |  Reporter: {rep}")
        if tags: print(f"    Tags        : {', '.join(tags)}")
    else:
        print(f"\n  {stag('MalwareBazaar',False)} {GREEN}No match{RESET}")
    if hr:
        print(f"\n  {YELLOW}Heuristics:{RESET}")
        for r in hr: print(f"    {DIM}•{RESET} {r}")
    if final>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  FILE IS DANGEROUS! Quarantine it.  {RESET}")
    elif final>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Suspicious. Review recommended.{RESET}")
    else:          print(f"\n  {GREEN}{BOLD}  ✔  No known threat detected.{RESET}")
    print(f"  {'━'*67}\n")

def _show_ip(ip,score,reasons,feeds,tf,sh,ab):
    print(f"\n  {BOLD}{'━'*67}{RESET}")
    print(f"  {BOLD}IP RESULT{RESET}"); print(f"  {'━'*67}")
    print(f"  {WHITE}IP           :{RESET}  {ip}")
    print(f"  {WHITE}Threat Score :{RESET}  {threat_bar(score)}")
    print(f"  {WHITE}Threat Level :{RESET}  {threat_label(score)}")
    if feeds:
        print(f"\n  {RED}{BOLD}⚠ Feed Matches:{RESET}")
        for f in feeds: print(f"    {RED}▶{RESET} {f}")
    if tf:
        s,malware,conf,threat,tags=tf
        print(f"\n  {stag('ThreatFox')} {RED}{BOLD} DETECTED!{RESET}")
        print(f"    Malware   : {RED}{BOLD}{malware}{RESET}")
        print(f"    Type/Conf : {threat} / %{conf}")
        if tags: print(f"    Tags      : {', '.join(tags)}")
    else:
        print(f"\n  {stag('ThreatFox',False)} {GREEN}No match{RESET}")
    if sh:
        s,org,country,city,isp,asn,ports,vulns,tags,hosts,upd,notes=sh
        print(f"\n  {stag('Shodan',s>0)} Info")
        print(f"    Org/Location :{org} — {city}, {country}")
        print(f"    ISP/ASN      : {isp} / {asn}")
        print(f"    Open Ports   : {ports[:15]}{'...' if len(ports)>15 else ''}")
        if vulns: print(f"    {RED}CVE          : {', '.join(vulns[:6])}{RESET}")
        if tags:  print(f"    Tags         : {', '.join(tags)}")
        for n in notes: print(f"    {YELLOW}⚠ {n}{RESET}")
    elif API_KEYS["shodan"].strip():
        print(f"\n  {stag('Shodan',False)} {YELLOW}No data{RESET}")
    else:
        print(f"\n  {stag('Shodan',False)} {DIM}API key not set → Menu 6{RESET}")
    if ab:
        s,abuse,total,country,isp,dom,wl,last,usage=ab
        c=RED if abuse>=50 else YELLOW if abuse>=20 else GREEN
        print(f"\n  {stag('AbuseIPDB',abuse>0)} Abuse Info")
        print(f"    Score    : {c}{BOLD}%{abuse}{RESET}  |  Reports: {total}")
        print(f"    Country/ISP: {country} / {isp}")
        print(f"    Usage Type: {usage}")
        if last: print(f"    Last Report: {last}")
        if wl:   print(f"    {GREEN}✔ Whitelist{RESET}")
    elif API_KEYS["abuseipdb"].strip():
        print(f"\n  {stag('AbuseIPDB',False)} {YELLOW}No data{RESET}")
    else:
        print(f"\n  {stag('AbuseIPDB',False)} {DIM}API key not set → Menu 6{RESET}")
    if reasons:
        print(f"\n  {YELLOW}Basic Analysis:{RESET}")
        for r in reasons: print(f"    {DIM}•{RESET} {r}")
    if score>=7:   print(f"\n  {BG_RED}{WHITE}{BOLD}  ⚠  THIS IP IS DANGEROUS! Cut the connection.  {RESET}")
    elif score>=4: print(f"\n  {YELLOW}{BOLD}  ⚠  Suspicious. Caution advised.{RESET}")
    else:          print(f"\n  {GREEN}{BOLD}  ✔  No known threat detected.{RESET}")
    print(f"  {'━'*67}\n")

def _is_ip(s):
    try: ipaddress.ip_address(s); return True
    except: return False

def _resolve(h):
    try: return socket.gethostbyname(h)
    except: return None

def api_key_setup():
    print(f"\n  {BOLD}API Key Configuration{RESET}"); sep()
    print(f"  {DIM}ThreatFox    : https://threatfox.abuse.ch/api/{RESET}")
    print(f"  {DIM}MalwareBazaar: https://bazaar.abuse.ch/api/{RESET}")
    print(f"  {DIM}Shodan       : https://account.shodan.io{RESET}")
    print(f"  {DIM}AbuseIPDB    : https://www.abuseipdb.com/api{RESET}"); sep()
    
    tf = input(f"\n  {WHITE}ThreatFox API Key{RESET} (blank=no change): ").strip()
    if tf: API_KEYS["threatfox"]=tf; print(f"  {GREEN}✔ ThreatFox configured.{RESET}")
    
    mb = input(f"  {WHITE}MalwareBazaar API Key{RESET} (blank=no change): ").strip()
    if mb: API_KEYS["malwarebazaar"]=mb; print(f"  {GREEN}✔ MalwareBazaar configured.{RESET}")
    
    sk = input(f"  {WHITE}Shodan API Key{RESET} (blank=no change): ").strip()
    if sk: API_KEYS["shodan"]=sk; print(f"  {GREEN}✔ Shodan configured.{RESET}")
    
    ak = input(f"  {WHITE}AbuseIPDB API Key{RESET} (blank=no change): ").strip()
    if ak: API_KEYS["abuseipdb"]=ak; print(f"  {GREEN}✔ AbuseIPDB configured.{RESET}")
    print()

def menu():
    while True:
        print(f"""
{BOLD}  {RED}┌──────────────────────────────────────────────────┐{RESET}
  {RED}│{RESET}  {WHITE}1{RESET}  Scan File       (ThreatFox + MalwareBazaar)  {RED}│{RESET}
  {RED}│{RESET}  {WHITE}2{RESET}  Scan IP / Host  (TF + Shodan + AbuseIPDB)    {RED}│{RESET}
  {RED}│{RESET}  {WHITE}3{RESET}  Scan Directory  (Bulk)                       {RED}│{RESET}
  {RED}│{RESET}  {WHITE}4{RESET}  Lookup Hash     (MD5 / SHA256)               {RED}│{RESET}
  {RED}│{RESET}  {WHITE}5{RESET}  Refresh Feeds                                {RED}│{RESET}
  {RED}│{RESET}  {WHITE}6{RESET}  Configure API Keys                           {RED}│{RESET}
  {RED}│{RESET}  {WHITE}0{RESET}  Exit                                         {RED}│{RESET}
  {RED}└──────────────────────────────────────────────────┘{RESET}""")
        api_status_line()
        ch = input(f"  {RED}➤{RESET} Your choice: ").strip()
        if   ch=="1":
            p=input(f"  {WHITE}File path:{RESET} ").strip().strip("'\"")
            if os.path.isfile(p): scan_file(p)
            else: print(f"  {RED}✖ File not found.{RESET}")
        elif ch=="2":
            ip=input(f"  {WHITE}IP / Hostname:{RESET} ").strip()
            if ip: scan_ip(ip)
            else:  print(f"  {RED}✖ Invalid.{RESET}")
        elif ch=="3":
            p=input(f"  {WHITE}Directory path:{RESET} ").strip().strip("'\"")
            if os.path.isdir(p): scan_dir(p)
            else: print(f"  {RED}✖ Directory not found.{RESET}")
        elif ch=="4":
            h=input(f"  {WHITE}Hash (MD5/SHA256):{RESET} ").strip()
            if h: scan_hash(h)
            else: print(f"  {RED}✖ No hash entered.{RESET}")
        elif ch=="5":
            global _feodo_cache,_firehol_cache,_cinss_cache
            _feodo_cache=_firehol_cache=_cinss_cache=None; _cache_time.clear()
            print(f"\n  {CYAN}Feed cache cleared.{RESET}\n")
        elif ch=="6":
            api_key_setup()
        elif ch=="0":
            print(f"\n  {DIM}ZERGUZ CTI shutting down... Stay safe!{RESET}\n"); sys.exit(0)
        else:
            print(f"  {YELLOW}Invalid choice.{RESET}")

def main():
    ap = argparse.ArgumentParser(description="ZERGUZ CTI v4.2")
    ap.add_argument("-f","--file"); ap.add_argument("-i","--ip")
    ap.add_argument("-d","--dir");  ap.add_argument("-H","--hash")
    ap.add_argument("--shodan-key"); ap.add_argument("--abuseipdb-key")
    ap.add_argument("--threatfox-key"); ap.add_argument("--malwarebazaar-key")
    ap.add_argument("--no-banner",action="store_true")
    a = ap.parse_args()
    
    if a.shodan_key:        API_KEYS["shodan"]        = a.shodan_key
    if a.abuseipdb_key:     API_KEYS["abuseipdb"]     = a.abuseipdb_key
    if a.threatfox_key:     API_KEYS["threatfox"]     = a.threatfox_key
    if a.malwarebazaar_key: API_KEYS["malwarebazaar"] = a.malwarebazaar_key
    
    if not a.no_banner: banner()
    if a.hash:  scan_hash(a.hash);  sys.exit(0)
    if a.file:
        if os.path.isfile(a.file): scan_file(a.file)
        else: print(f"  {RED}✖ File not found: {a.file}{RESET}")
        sys.exit(0)
    if a.ip:    scan_ip(a.ip);    sys.exit(0)
    if a.dir:
        if os.path.isdir(a.dir): scan_dir(a.dir)
        else: print(f"  {RED}✖ Directory not found: {a.dir}{RESET}")
        sys.exit(0)
    menu()

if __name__ == "__main__":
    main()
