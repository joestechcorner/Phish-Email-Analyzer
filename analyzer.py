"""
Phishing Analyzer - Email & Text File Security Scanner
Analyzes .txt and .eml files for suspicious URLs, spoofed senders, and urgent language.

VirusTotal API key setup (NEVER paste your key into this file):
  Option A — environment variable (recommended):
      Windows PowerShell : $env:VT_API_KEY = "your_key_here"
      Windows CMD        : set VT_API_KEY=your_key_here
      macOS / Linux      : export VT_API_KEY="your_key_here"
      Then run the tool normally — it picks the key up automatically.

  Option B — pass it at runtime:
      python analyzer.py email.eml --vt-key YOUR_KEY_HERE

  The key is never written to disk or printed in any output.
  Free-tier VT accounts are limited to 4 requests/minute and 500/day.
  The tool automatically paces requests to respect that limit.
"""

import re
import os
import sys
import json
import time
import email
import argparse
import urllib.request
import urllib.error
from email import policy
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────
#  CONFIGURATION — edit these lists freely
# ─────────────────────────────────────────────

# Keywords are grouped into three severity tiers.
# Each tier carries a different point value (see SCORING ENGINE below).
KEYWORDS_HIGH = [
    "account suspended", "verify your account", "confirm your identity",
    "compromised", "unauthorized access", "will be terminated",
    "account has been locked", "immediate action", "account closure",
    "legal action", "law enforcement",
]

KEYWORDS_MEDIUM = [
    "urgent", "action required", "immediately", "act now",
    "your account has been", "unusual activity", "suspicious activity",
    "security alert", "final notice", "verify now", "confirm now",
]

KEYWORDS_LOW = [
    "limited time", "login now", "click here", "24 hours", "48 hours",
    "update your information", "billing problem", "payment failed",
    "warning", "last chance", "expires soon", "offer ends",
]

# Known legitimate freemail providers (used in spoof detection)
FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com", "aol.com", "live.com",
}

# Suspicious TLDs often abused in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".date", ".download",
    ".racing", ".review", ".stream", ".gq", ".ml", ".tk",
    ".cf", ".ga", ".click", ".link", ".online", ".site",
}


# ─────────────────────────────────────────────
#  SCORING ENGINE — individual signal weights
# ─────────────────────────────────────────────
#
# Every flag now carries its own point value.
# Signals that are definitive proof of fraud (e.g. VT malicious, SPF hard-fail)
# score much higher than circumstantial hints (e.g. missing DKIM, suspicious TLD).

# Keyword weights (per tier)
PTS_KW_HIGH   = 20
PTS_KW_MEDIUM = 15
PTS_KW_LOW    = 10

# URL / domain weights
PTS_URL_NOT_IN_ALLOWLIST    = 20
PTS_URL_SUSPICIOUS_TLD      = 25
PTS_URL_IP_ADDRESS          = 45
PTS_URL_EXCESS_SUBDOMAINS   = 20
PTS_URL_BRAND_IMPERSONATION = 50
PTS_URL_TYPOSQUAT           = 40
PTS_URL_VT_MALICIOUS        = 80   # 3+ VT engines flagged malicious
PTS_URL_VT_SUSPICIOUS       = 40   # 1-2 malicious OR 3+ suspicious

# Sender / spoofing weights
PTS_SPOOF_SPF_FAIL          = 75   # SPF hard fail
PTS_SPOOF_SPF_SOFTFAIL      = 40   # SPF softfail
PTS_SPOOF_REPLYTO_MISMATCH  = 50   # Reply-To domain != From domain
PTS_SPOOF_RETPATH_MISMATCH  = 45   # Return-Path domain != From domain
PTS_SPOOF_BRAND_FREEMAIL    = 60   # brand display name sent from Gmail/Yahoo etc.
PTS_SPOOF_DN_MISMATCH       = 55   # display-name contains a different email domain
PTS_SPOOF_SUSPICIOUS_TLD    = 30   # sender domain uses a suspicious TLD
PTS_SPOOF_NO_DKIM           = 20   # no DKIM signature at all
PTS_SPOOF_SUBJECT_URGENCY   = 15   # subject line contains urgency trigger

# Multi-category combination bonus
# If all three analysis modules (URL + sender + language) produce at least one
# signal, the raw score is multiplied by this factor before mapping to 0-99%.
COMBO_MULTIPLIER = 1.4

MAX_SCORE_PCT = 99   # hard ceiling

# Severity bands mapped from raw score
SEVERITY_BANDS = [
    (300, "CRITICAL"),
    (150, "HIGH"),
    (75,  "MEDIUM"),
    (25,  "LOW"),
    (0,   "CLEAN"),
]


# ─────────────────────────────────────────────
#  VIRUSTOTAL API
# ─────────────────────────────────────────────

_vt_cache: dict = {}   # domain -> result (avoids duplicate API calls)

def vt_check_domain(domain: str, api_key: str) -> dict:
    """
    Query VirusTotal v3 for a domain reputation score.
    Results are cached so each unique domain is only queried once per run.
    Free-tier rate limit: 4 req/min -> we sleep 15.5s between calls.
    """
    domain = domain.lower().strip()
    if domain in _vt_cache:
        return _vt_cache[domain]

    empty = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": None}

    if not api_key or not domain:
        return empty

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = {
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "error":      None,
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {**empty, "error": "Domain not found in VT database"}
        elif e.code == 401:
            result = {**empty, "error": "VT API key invalid or unauthorized"}
        elif e.code == 429:
            result = {**empty, "error": "VT rate limit hit — slow down requests"}
        else:
            result = {**empty, "error": f"VT HTTP error {e.code}"}
    except Exception as ex:
        result = {**empty, "error": str(ex)}

    _vt_cache[domain] = result
    time.sleep(15.5)   # respect free-tier 4 req/min limit
    return result


# ─────────────────────────────────────────────
#  UTILITY HELPERS
# ─────────────────────────────────────────────

def load_allowlist(path: str) -> set:
    """Load the top-1M domains allowlist (one domain per line or rank,domain CSV)."""
    allowlist = set()
    if not path or not os.path.exists(path):
        return allowlist
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if "," in line:
                domain = line.split(",")[-1].strip()
            else:
                domain = line
            if domain:
                allowlist.add(domain)
    print(f"[+] Loaded {len(allowlist):,} domains from allowlist.")
    return allowlist


def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s<>"\')\]]*|www\.[^\s<>"\')\]]+'
    return re.findall(pattern, text, re.IGNORECASE)


def get_root_domain(hostname: str) -> str:
    parts = hostname.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


def get_tld(hostname: str) -> str:
    parts = hostname.lower().rstrip(".").split(".")
    return "." + parts[-1] if parts else ""


def make_flag(msg: str, pts: int) -> dict:
    return {"msg": msg, "pts": pts}


# ─────────────────────────────────────────────
#  FILE PARSING
# ─────────────────────────────────────────────

def parse_file(filepath: str) -> dict:
    ext = Path(filepath).suffix.lower()
    result = {
        "body": "", "subject": "", "sender": "",
        "reply_to": "", "return_path": "",
        "received_spf": "", "dkim_result": "", "headers_raw": "",
    }

    if ext == ".eml":
        with open(filepath, "rb") as f:
            msg = email.message_from_bytes(f.read(), policy=policy.default)

        result["subject"]      = str(msg.get("Subject", ""))
        result["sender"]       = str(msg.get("From", ""))
        result["reply_to"]     = str(msg.get("Reply-To", ""))
        result["return_path"]  = str(msg.get("Return-Path", ""))
        result["received_spf"] = str(msg.get("Received-SPF", ""))
        result["dkim_result"]  = str(msg.get("DKIM-Signature", "")[:80])
        result["headers_raw"]  = str(msg.items())

        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        pass
        else:
            try:
                parts.append(msg.get_content())
            except Exception:
                parts.append(str(msg.get_payload(decode=True) or ""))
        result["body"] = "\n".join(parts)
    else:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            result["body"] = f.read()

    return result


# ─────────────────────────────────────────────
#  ANALYSIS MODULES
# ─────────────────────────────────────────────

def analyze_urls(text: str, allowlist: set, vt_api_key: str = "") -> dict:
    """
    Extract URLs, run heuristic checks, and optionally query VirusTotal.
    Each flag in entry["reasons"] is {"msg": str, "pts": int}.
    """
    deduped = list(dict.fromkeys(extract_urls(text)))
    flagged, safe = [], []
    checked_vt_domains = set()

    for url in deduped:
        if not url.startswith("http"):
            url = "http://" + url
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""

        root    = get_root_domain(hostname)
        tld     = get_tld(hostname)
        reasons = []

        # Allowlist check
        if allowlist and root not in allowlist:
            reasons.append(make_flag("Not in top-1M allowlist", PTS_URL_NOT_IN_ALLOWLIST))

        # Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            reasons.append(make_flag(f"Suspicious TLD ({tld})", PTS_URL_SUSPICIOUS_TLD))

        # Raw IP address
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
            reasons.append(make_flag("IP address used instead of domain name", PTS_URL_IP_ADDRESS))

        # Excessive subdomains
        if hostname.count(".") > 4:
            reasons.append(make_flag("Excessive subdomain depth (5+ levels)", PTS_URL_EXCESS_SUBDOMAINS))

        # Brand impersonation
        brand_pattern = r'(paypal|amazon|microsoft|apple|google|bank|secure|login|account)'
        if re.search(brand_pattern, hostname, re.I):
            if root not in {"paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com"}:
                reasons.append(make_flag("Brand name impersonation in domain", PTS_URL_BRAND_IMPERSONATION))

        # Typosquatting / homoglyphs
        if re.search(r'[0o][0o]|rn(?=[a-z])|vv|1l|ll1', hostname):
            reasons.append(make_flag("Possible typosquatting / homoglyph characters", PTS_URL_TYPOSQUAT))

        # VirusTotal lookup (one query per unique root domain)
        vt = None
        if vt_api_key and root and root not in checked_vt_domains:
            checked_vt_domains.add(root)
            print(f"    [VT] Checking {root} ...")
            vt = vt_check_domain(root, vt_api_key)
            if vt.get("error"):
                print(f"    [VT] Warning: {vt['error']}")
            elif vt["malicious"] >= 3:
                reasons.append(make_flag(
                    f"VirusTotal: {vt['malicious']} engines flagged domain as MALICIOUS",
                    PTS_URL_VT_MALICIOUS
                ))
            elif vt["malicious"] >= 1 or vt["suspicious"] >= 3:
                reasons.append(make_flag(
                    f"VirusTotal: flagged as suspicious "
                    f"(malicious={vt['malicious']}, suspicious={vt['suspicious']})",
                    PTS_URL_VT_SUSPICIOUS
                ))

        entry = {"url": url, "hostname": hostname, "root_domain": root, "reasons": reasons, "vt": vt}
        if reasons:
            flagged.append(entry)
        else:
            safe.append(entry)

    return {"flagged": flagged, "safe": safe, "total": len(deduped)}


def analyze_sender(data: dict) -> dict:
    """
    Heuristic sender analysis with individually weighted flags.
    Each flag is {"msg": str, "pts": int}.
    """
    sender   = data.get("sender", "")
    reply_to = data.get("reply_to", "")
    ret_path = data.get("return_path", "")
    subject  = data.get("subject", "")
    flags    = []

    match        = re.search(r'<([^>]+)>', sender)
    email_addr   = match.group(1).strip().lower() if match else sender.strip().lower()
    display_name = sender[:sender.find("<")].strip().strip('"') if "<" in sender else ""
    dm           = re.search(r'@([\w.\-]+)', email_addr)
    sender_domain = dm.group(1).lower() if dm else ""

    # SPF result — highest-weight sender signal
    spf = data.get("received_spf", "").lower()
    if spf:
        if "fail" in spf and "softfail" not in spf:
            flags.append(make_flag("SPF check: HARD FAIL — strong forgery indicator", PTS_SPOOF_SPF_FAIL))
        elif "softfail" in spf:
            flags.append(make_flag("SPF check: SOFTFAIL — probable forgery", PTS_SPOOF_SPF_SOFTFAIL))

    # Reply-To mismatch
    if reply_to and email_addr:
        rt_m = re.search(r'[\w.\-+]+@([\w.\-]+)', reply_to)
        if rt_m:
            rt_domain = rt_m.group(1).lower()
            if rt_domain != sender_domain:
                flags.append(make_flag(
                    f"Reply-To domain ({rt_domain}) differs from sender domain ({sender_domain})",
                    PTS_SPOOF_REPLYTO_MISMATCH
                ))

    # Return-Path mismatch
    if ret_path and email_addr:
        rp_m = re.search(r'@([\w.\-]+)', ret_path)
        if rp_m:
            rp_domain = rp_m.group(1).lower()
            if rp_domain and rp_domain != sender_domain:
                flags.append(make_flag(
                    f"Return-Path domain ({rp_domain}) differs from sender domain ({sender_domain})",
                    PTS_SPOOF_RETPATH_MISMATCH
                ))

    # Brand display name via freemail
    if sender_domain in FREEMAIL_PROVIDERS and display_name:
        if re.search(r'(bank|paypal|amazon|apple|microsoft|support|security|alert|team|service|helpdesk)', display_name, re.I):
            flags.append(make_flag(
                f"Corporate/brand display name sent from freemail provider ({sender_domain})",
                PTS_SPOOF_BRAND_FREEMAIL
            ))

    # Display name contains a different domain
    dn_domain = re.search(r'@([\w.\-]+)', display_name)
    if dn_domain and dn_domain.group(1).lower() != sender_domain:
        flags.append(make_flag(
            "Display name contains a different email domain than the actual sender address",
            PTS_SPOOF_DN_MISMATCH
        ))

    # Suspicious sender TLD
    tld = get_tld(sender_domain)
    if tld in SUSPICIOUS_TLDS:
        flags.append(make_flag(f"Sender domain uses suspicious TLD ({tld})", PTS_SPOOF_SUSPICIOUS_TLD))

    # Missing DKIM
    if not data.get("dkim_result"):
        flags.append(make_flag("No DKIM-Signature header present", PTS_SPOOF_NO_DKIM))

    # Subject urgency
    if re.search(r'(urgent|verify|suspended|action required|limited time)', subject, re.I):
        flags.append(make_flag(
            f"Subject line contains urgency trigger: \"{subject[:80]}\"",
            PTS_SPOOF_SUBJECT_URGENCY
        ))

    return {
        "sender_raw":    sender,
        "email_address": email_addr,
        "display_name":  display_name,
        "sender_domain": sender_domain,
        "reply_to":      reply_to,
        "return_path":   ret_path,
        "spf":           data.get("received_spf", "N/A"),
        "dkim_present":  bool(data.get("dkim_result")),
        "flags":         flags,
    }


def analyze_language(text: str, extra_keywords: list = None) -> dict:
    """
    Tiered keyword scan. Each hit carries {"keyword", "tier", "pts", "context"}.
    """
    tiers = [
        (KEYWORDS_HIGH,   PTS_KW_HIGH,   "high"),
        (KEYWORDS_MEDIUM, PTS_KW_MEDIUM, "medium"),
        (KEYWORDS_LOW,    PTS_KW_LOW,    "low"),
    ]
    if extra_keywords:
        tiers.append(([k.lower() for k in extra_keywords], PTS_KW_MEDIUM, "custom"))

    found      = []
    text_lower = text.lower()
    seen_kws   = set()

    for kw_list, pts, tier in tiers:
        for kw in kw_list:
            kw_lower = kw.lower()
            if kw_lower in seen_kws:
                continue
            pos = text_lower.find(kw_lower)
            if pos == -1:
                continue
            seen_kws.add(kw_lower)
            start   = max(0, pos - 40)
            end     = min(len(text), pos + len(kw) + 40)
            snippet = text[start:end].replace("\n", " ").strip()
            found.append({
                "keyword": kw,
                "tier":    tier,
                "pts":     pts,
                "context": f"...{snippet}...",
            })

    return {"found": found, "total_hits": len(found)}


# ─────────────────────────────────────────────
#  SCORING ENGINE
# ─────────────────────────────────────────────

def compute_risk(url_result: dict, sender_result: dict, lang_result: dict) -> dict:
    """
    Sum individual signal weights, apply combination bonus when all three
    modules fire, then map to 0-99% phishing probability.
    """
    url_pts    = sum(r["pts"] for e in url_result["flagged"] for r in e["reasons"])
    sender_pts = sum(f["pts"] for f in sender_result["flags"])
    lang_pts   = sum(h["pts"] for h in lang_result["found"])
    raw        = url_pts + sender_pts + lang_pts

    combo_applied = False
    if url_pts > 0 and sender_pts > 0 and lang_pts > 0:
        raw           = round(raw * COMBO_MULTIPLIER)
        combo_applied = True

    if raw == 0:
        pct = 0
    elif raw >= SEVERITY_BANDS[0][0]:
        pct = MAX_SCORE_PCT
    else:
        pct = min(MAX_SCORE_PCT, round(raw * 99 / (raw + 120)))

    severity = "CLEAN"
    for threshold, label in SEVERITY_BANDS:
        if raw >= threshold:
            severity = label
            break

    return {
        "raw_score":     raw,
        "pct":           pct,
        "severity":      severity,
        "combo_applied": combo_applied,
        "breakdown": {
            "url_pts":      url_pts,
            "sender_pts":   sender_pts,
            "lang_pts":     lang_pts,
            "url_flags":    [r for e in url_result["flagged"] for r in e["reasons"]],
            "sender_flags": sender_result["flags"],
            "lang_hits":    lang_result["found"],
        },
    }


# ─────────────────────────────────────────────
#  VERDICT & REPORT
# ─────────────────────────────────────────────

def print_verdict(risk: dict, C: dict):
    pct  = risk["pct"]
    bd   = risk["breakdown"]
    raw  = risk["raw_score"]
    width = 70

    if pct >= 90:
        bar_color = text_color = C["RED"]
    elif pct >= 60:
        bar_color = text_color = C["YELLOW"]
    elif pct >= 30:
        bar_color = text_color = C["BLUE"]
    else:
        bar_color = text_color = C["GREEN"]

    if pct == MAX_SCORE_PCT:
        verdict_line = (
            f"{C['RED']}{C['BOLD']}"
            f"  !! EXTREMELY HIGH PHISHING SUSPICION !!\n"
            f"  This message exhibits the hallmarks of a coordinated phishing attack.\n"
            f"  Do NOT click any links, reply, or provide any information whatsoever."
            f"{C['RESET']}"
        )
    elif pct >= 75:
        verdict_line = f"{text_color}{C['BOLD']}  LIKELY PHISHING — Strong indicators detected. Treat with extreme caution.{C['RESET']}"
    elif pct >= 50:
        verdict_line = f"{text_color}{C['BOLD']}  PROBABLY PHISHING — Multiple suspicious signals. Do not interact without verification.{C['RESET']}"
    elif pct >= 25:
        verdict_line = f"{text_color}{C['BOLD']}  POSSIBLY SUSPICIOUS — Some concerns present. Verify the sender before acting.{C['RESET']}"
    elif pct > 0:
        verdict_line = f"{text_color}{C['BOLD']}  LOW RISK — Minor indicators only. Likely safe, but stay alert.{C['RESET']}"
    else:
        verdict_line = f"{C['GREEN']}{C['BOLD']}  NOT LIKELY PHISHING — No significant indicators detected.{C['RESET']}"

    bar_width = 40
    filled    = round(pct / 100 * bar_width)
    bar       = "X" * filled + "." * (bar_width - filled)
    pct_label = f"{pct}%" if pct < MAX_SCORE_PCT else "99% (MAX)"

    print(f"\n{C['BOLD']}{'=' * width}{C['RESET']}")
    print(f"{C['BOLD']}  PHISHING LIKELIHOOD VERDICT{C['RESET']}")
    print("-" * width)
    print(verdict_line)
    print()
    print(f"  Score  :  {bar_color}{bar}{C['RESET']}  {C['BOLD']}{pct_label}{C['RESET']}")
    print()
    print(f"  {C['BOLD']}Signal breakdown (individual weights):{C['RESET']}")

    if bd["url_flags"]:
        print(f"\n  {C['CYAN']}URL signals:{C['RESET']}")
        for f in bd["url_flags"]:
            print(f"    {C['YELLOW']}+{f['pts']:>3} pts{C['RESET']}  {f['msg']}")

    if bd["sender_flags"]:
        print(f"\n  {C['CYAN']}Sender signals:{C['RESET']}")
        for f in bd["sender_flags"]:
            print(f"    {C['YELLOW']}+{f['pts']:>3} pts{C['RESET']}  {f['msg']}")

    if bd["lang_hits"]:
        print(f"\n  {C['CYAN']}Language signals:{C['RESET']}")
        for h in bd["lang_hits"]:
            print(f"    {C['YELLOW']}+{h['pts']:>3} pts{C['RESET']}  [{h['tier'].upper()}] \"{h['keyword']}\"")

    subtotal = bd["url_pts"] + bd["sender_pts"] + bd["lang_pts"]
    print(f"\n  {'-'*50}")
    print(f"  URL: {bd['url_pts']} pts  |  Sender: {bd['sender_pts']} pts  |  Language: {bd['lang_pts']} pts")
    if risk["combo_applied"]:
        print(f"  {C['YELLOW']}All three modules fired — combo bonus x{COMBO_MULTIPLIER} applied{C['RESET']}")
        print(f"  Subtotal: {subtotal} pts  ->  After bonus: {raw} pts  ->  {pct_label}")
    else:
        print(f"  Raw total: {raw} pts  ->  {pct_label}")
    print(f"{'=' * width}\n")


def print_report(filepath, data, url_result, sender_result, lang_result):
    risk  = compute_risk(url_result, sender_result, lang_result)
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    width = 70

    C = {
        "RED":    "\033[91m",
        "YELLOW": "\033[93m",
        "BLUE":   "\033[94m",
        "GREEN":  "\033[92m",
        "RESET":  "\033[0m",
        "BOLD":   "\033[1m",
        "DIM":    "\033[2m",
        "CYAN":   "\033[96m",
    }

    severity  = risk["severity"]
    sev_color = (
        C["RED"]    if severity in ("HIGH", "CRITICAL") else
        C["YELLOW"] if severity == "MEDIUM" else
        C["BLUE"]   if severity == "LOW"    else
        C["GREEN"]
    )

    def hr(char="-"):
        print(C["DIM"] + char * width + C["RESET"])

    def header(text):
        print(f"\n{C['BOLD']}{C['CYAN']} {text}{C['RESET']}")
        hr()

    print()
    hr("=")
    print(f"{C['BOLD']}  PHISHING ANALYZER REPORT{C['RESET']}")
    print(f"  File    : {filepath}")
    print(f"  Scanned : {now}")
    hr("=")

    # SENDER ANALYSIS
    header("SENDER ANALYSIS")
    s = sender_result
    print(f"  From        : {s['sender_raw'] or 'N/A'}")
    print(f"  Email       : {s['email_address'] or 'N/A'}")
    print(f"  Display Name: {s['display_name'] or 'N/A'}")
    print(f"  Reply-To    : {s['reply_to'] or 'N/A'}")
    print(f"  Return-Path : {s['return_path'] or 'N/A'}")
    print(f"  SPF         : {s['spf'] or 'N/A'}")
    print(f"  DKIM        : {'Present' if s['dkim_present'] else 'MISSING'}")

    if s["flags"]:
        print(f"\n  {C['BOLD']}Spoofing Indicators:{C['RESET']}")
        for f in s["flags"]:
            print(f"    {sev_color}! +{f['pts']} pts{C['RESET']}  {f['msg']}")
    else:
        print(f"  {C['GREEN']}No spoofing indicators detected.{C['RESET']}")

    # URL ANALYSIS
    header(f"URL ANALYSIS  ({url_result['total']} unique URLs found)")
    if url_result["flagged"]:
        print(f"  {C['BOLD']}Suspicious URLs ({len(url_result['flagged'])}):{C['RESET']}")
        for entry in url_result["flagged"]:
            print(f"\n    {sev_color}> {entry['url'][:80]}{C['RESET']}")
            for r in entry["reasons"]:
                print(f"        +{r['pts']:>3} pts  . {r['msg']}")
            vt = entry.get("vt")
            if vt and not vt.get("error") and (vt["malicious"] + vt["suspicious"] + vt["harmless"]) > 0:
                total_engines = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
                print(f"        {C['DIM']}VT: {vt['malicious']} malicious / {vt['suspicious']} suspicious "
                      f"/ {vt['harmless']} harmless  ({total_engines} engines){C['RESET']}")
    else:
        print("  No suspicious URLs flagged.")

    if url_result["safe"]:
        print(f"\n  {C['DIM']}Safe / allowlisted URLs ({len(url_result['safe'])}):{C['RESET']}")
        for entry in url_result["safe"][:5]:
            print(f"    {C['DIM']}OK {entry['url'][:80]}{C['RESET']}")
        if len(url_result["safe"]) > 5:
            print(f"    {C['DIM']}... and {len(url_result['safe']) - 5} more{C['RESET']}")

    # LANGUAGE ANALYSIS
    header(f"URGENT LANGUAGE  ({lang_result['total_hits']} triggers found)")
    if lang_result["found"]:
        for item in lang_result["found"]:
            print(f"  {sev_color}* +{item['pts']} pts{C['RESET']}  [{item['tier'].upper()}] Keyword: \"{item['keyword']}\"")
            print(f"       Context: {C['DIM']}{item['context']}{C['RESET']}")
    else:
        print("  No urgent language patterns detected.")

    # VERDICT
    print_verdict(risk, C)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Analyzer -- scan .txt and .eml files for threats."
    )
    parser.add_argument("file",
        help="Path to the .txt or .eml file to analyze")
    parser.add_argument("--allowlist", "-a",
        default=None,
        help="Path to top-1M domains file (one domain per line or rank,domain CSV)")
    parser.add_argument("--keywords", "-k",
        nargs="*", default=[],
        help="Extra keywords to flag (use quotes for multi-word phrases)")
    parser.add_argument("--vt-key",
        default=None,
        help=(
            "VirusTotal API key. "
            "Recommended: set the VT_API_KEY environment variable instead of passing here."
        ))
    args = parser.parse_args()

    # Resolve VT key: CLI flag > environment variable > none (never hardcoded)
    vt_api_key = args.vt_key or os.environ.get("VT_API_KEY", "")
    if vt_api_key:
        print("[+] VirusTotal API key loaded -- domain reputation checks enabled.")
    else:
        print("[!] No VirusTotal API key provided -- VT checks skipped.")
        print("    Set the VT_API_KEY environment variable or use --vt-key to enable.")

    filepath = args.file
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    ext = Path(filepath).suffix.lower()
    if ext not in (".txt", ".eml"):
        print(f"[ERROR] Unsupported file type '{ext}'. Only .txt and .eml are supported.")
        sys.exit(1)

    print(f"[*] Loading file: {filepath}")
    allowlist = load_allowlist(args.allowlist)
    data      = parse_file(filepath)
    body      = data["body"]
    full_text = f"{data.get('subject','')} {data.get('sender','')} {body}"

    print("[*] Analyzing URLs...")
    url_result = analyze_urls(full_text, allowlist, vt_api_key=vt_api_key)

    print("[*] Analyzing sender...")
    sender_result = analyze_sender(data)

    print("[*] Analyzing language...")
    lang_result = analyze_language(body, extra_keywords=args.keywords)

    print_report(filepath, data, url_result, sender_result, lang_result)


if __name__ == "__main__":
    main()


# ─────────────────────────────────────────────
#  GUI BRIDGE CLASS
#  Wraps the functional analysis pipeline into
#  the class interface expected by gui.py.
# ─────────────────────────────────────────────

class PhishingAnalyzer:
    """
    Class-based wrapper used by the GUI.
    Reads optional keyword files and the allowlist on construction,
    then exposes analyze_file() for the GUI to call.
    """

    def __init__(self, allowlist_path="", hard_keywords_path="", soft_keywords_path=""):
        # Load allowlist (top-1M or custom list)
        self.allowlist = load_allowlist(allowlist_path) if allowlist_path else set()

        # Load extra keyword files (one keyword/phrase per line)
        self.extra_keywords = []
        for kw_path in (hard_keywords_path, soft_keywords_path):
            if kw_path and os.path.exists(kw_path):
                with open(kw_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.extra_keywords += [ln.strip() for ln in f if ln.strip()]

        # VT key from environment (GUI has no key field — use env var)
        self.vt_api_key = os.environ.get("VT_API_KEY", "")

    def analyze_file(self, filepath: str) -> dict:
        """
        Run the full analysis pipeline and return a dict the GUI can consume:
            score               int  0-99
            risk_level          str  BENIGN | SUSPICIOUS | MALICIOUS
            sender              str
            url_count           int
            suspicious_url_count int
            details             list[str]   — coloured with emoji for the GUI
            recommendations     list[str]
        """
        data      = parse_file(filepath)
        body      = data["body"]
        full_text = f"{data.get('subject','')} {data.get('sender','')} {body}"

        url_result    = analyze_urls(full_text, self.allowlist, vt_api_key=self.vt_api_key)
        sender_result = analyze_sender(data)
        lang_result   = analyze_language(body, extra_keywords=self.extra_keywords)
        risk          = compute_risk(url_result, sender_result, lang_result)

        pct = risk["pct"]

        # Map percentage to the three risk levels the GUI understands
        if pct >= 75:
            risk_level = "MALICIOUS"
        elif pct >= 25:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "BENIGN"

        # ── Build details list (emoji prefixes drive GUI colouring) ──
        details = []

        for entry in url_result["flagged"]:
            short_url = entry["url"][:65]
            for r in entry["reasons"]:
                prefix = "🚨" if r["pts"] >= 45 else "⚠️"
                details.append(f"{prefix} URL (+{r['pts']} pts): {short_url}\n      {r['msg']}")
            vt = entry.get("vt")
            if vt and not vt.get("error") and vt["malicious"] > 0:
                details.append(f"🚨 VirusTotal: {vt['malicious']} engines flagged {entry['root_domain']} as MALICIOUS")

        for f in sender_result["flags"]:
            prefix = "🚨" if f["pts"] >= 50 else "⚠️"
            details.append(f"{prefix} Sender (+{f['pts']} pts): {f['msg']}")

        for h in lang_result["found"]:
            prefix = "🚨" if h["tier"] == "high" else "⚠️"
            details.append(f"{prefix} Keyword [{h['tier'].upper()}] (+{h['pts']} pts): \"{h['keyword']}\"")

        if risk["combo_applied"]:
            details.append(f"🚨 Multi-category bonus applied (x{COMBO_MULTIPLIER}) — all three threat categories fired")

        # ── Build recommendations ──
        recommendations = []
        if risk_level == "MALICIOUS":
            recommendations += [
                "🚨 DO NOT click any links or attachments in this email",
                "🚨 DO NOT reply or provide any personal information",
                "🚨 Report to your IT / security team immediately",
                "🚨 Block the sender domain at your mail gateway",
                "🚨 Delete the email without interacting with it",
            ]
        elif risk_level == "SUSPICIOUS":
            recommendations += [
                "⚠️ Verify the sender through a separate, trusted channel",
                "⚠️ Do not click any links until authenticity is confirmed",
                "⚠️ Quarantine this email and escalate to your security team",
                "⚠️ Check the sender domain reputation independently",
            ]
        else:
            recommendations += [
                "✓ No significant phishing indicators detected",
                "✓ Always remain cautious with unexpected requests for information",
                "✓ Hover over links before clicking to verify the destination",
            ]

        return {
            "score":                pct,
            "risk_level":           risk_level,
            "sender":               sender_result["sender_raw"],
            "url_count":            url_result["total"],
            "suspicious_url_count": len(url_result["flagged"]),
            "details":              details,
            "recommendations":      recommendations,
        }
