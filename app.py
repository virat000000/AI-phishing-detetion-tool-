#!/usr/bin/env python3
"""
AI PhishGuard - Fake Website & Email Detector
Complete single-file Flask application for deployment on Render
Classifications: SAFE, UNSAFE, FAKE, FRAUD, IDENTITY RISK
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import re
import requests
from datetime import datetime
from urllib.parse import urlparse
import os

# ---------- Resilient Imports (optional features) ----------
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("WARNING: 'python-whois' not found. Domain age check will be disabled.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("WARNING: 'dnspython' not found. MX/SPF/DMARC checks will be disabled.")

app = Flask(__name__)
CORS(app)

DB_FILE = "phishing_db.json"

# ================= DATABASE HELPERS =================
def initialize_db():
    if not os.path.exists(DB_FILE):
        default_data = {
            "scans": [],
            "statistics": {"total_scans": 0, "safe_scans": 0, "unsafe_scans": 0, "fake_scans": 0, "fraud_scans": 0, "identity_risk_scans": 0},
            "known_malicious_domains": [
                "phishing-site.tk", "steal-info.ml", "hack-account.ga",
                "fake-login.cf", "scam-paypal.gq", "verify-account.xyz"
            ],
            "known_safe_domains": [
                "google.com", "facebook.com", "amazon.com", "microsoft.com",
                "apple.com", "twitter.com", "github.com", "paypal.com"
            ],
            "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".download", ".bid", ".loan"]
        }
        with open(DB_FILE, "w") as f:
            json.dump(default_data, f, indent=4)

def load_db():
    initialize_db()
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {"scans": [], "statistics": {"total_scans": 0, "safe_scans": 0, "unsafe_scans": 0, "fake_scans": 0, "fraud_scans": 0, "identity_risk_scans": 0}}

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_to_blacklist(domain):
    """Automatically add a detected malicious domain to blacklist"""
    db = load_db()
    if "known_malicious_domains" not in db:
        db["known_malicious_domains"] = []
    if domain not in db["known_malicious_domains"]:
        db["known_malicious_domains"].append(domain)
        save_db(db)
        return True
    return False

# ================= FAKE DOMAIN ENGINE =================
BRAND_DOMAINS = {
    "google": "google.com", "gmail": "google.com", "youtube": "youtube.com",
    "facebook": "facebook.com", "instagram": "facebook.com", "whatsapp": "facebook.com",
    "microsoft": "microsoft.com", "outlook": "microsoft.com", "apple": "apple.com",
    "amazon": "amazon.com", "paypal": "paypal.com", "netflix": "netflix.com",
    "twitter": "twitter.com", "github": "github.com", "yahoo": "yahoo.com",
    "linkedin": "linkedin.com", "bankofamerica": "bankofamerica.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "fedex": "fedex.com", "ups": "ups.com"
}

# Phishing keywords for content detection
PHISHING_KEYWORDS = [
    "verify", "account suspended", "urgent action", "update your information",
    "confirm your identity", "unusual activity", "security alert", "click here",
    "login to verify", "payment required", "your account has been locked",
    "limited access", "restoration required", "validate account"
]

def normalize_domain(domain):
    d = domain.lower()
    subs = {'0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '6':'g', '7':'t', '8':'b', '@':'a', 'vv':'w', 'rn':'m'}
    for k, v in subs.items():
        d = d.replace(k, v)
    return d

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]

def detect_fake_domain(domain):
    clean = re.sub(r'^www\.', '', domain.lower()).split(':')[0]
    parts = clean.split('.')
    if len(parts) < 2:
        return False, None, None, None
    registered = '.'.join(parts[-2:])
    hostname = parts[-2]
    normalized = normalize_domain(hostname)

    for brand, real in BRAND_DOMAINS.items():
        if registered == real or clean.endswith('.' + real):
            return False, None, None, None
        if normalized == brand:
            return True, brand, real, "Homograph Attack (character substitution)"
        if brand in hostname and len(brand) >= 3:
            if hostname != brand:
                return True, brand, real, "Brand Impersonation (embedded brand name)"
        dist = levenshtein_distance(hostname, brand)
        if dist <= (2 if len(brand) >= 6 else 1) and dist > 0:
            return True, brand, real, f"Typosquatting (misspelling distance: {dist})"
    return False, None, None, None

# ================= ENHANCED DETECTOR =================
class PhishingDetector:
    def __init__(self):
        self.db = load_db()
        self.suspicious_keywords = ["login", "verify", "secure", "bank", "password", "account", "update", "confirm", "validate"]

    def analyze_url(self, url):
        risk = 0
        indicators = []
        threats = []
        details = {}
        emails = []
        red_flags = []
        classification = "SAFE"
        reason = ""

        try:
            if not url.startswith(("http", "https")):
                url = "http://" + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]

            # 1. Domain Age Check
            if WHOIS_AVAILABLE:
                try:
                    w = whois.whois(domain)
                    date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if date:
                        age = (datetime.now() - date).days
                        if age < 7:
                            risk += 45
                            indicators.append(f"⏳ CRITICAL: Domain is only {age} days old")
                            threats.append("New Domain")
                            red_flags.append(f"Domain created {age} days ago")
                        elif age < 30:
                            risk += 25
                            indicators.append(f"⏳ New domain ({age} days old)")
                            threats.append("Recently Created Domain")
                except:
                    pass

            # 2. Blacklist Check
            self.db = load_db()
            if domain in self.db.get("known_malicious_domains", []):
                risk = 100
                indicators.append("⛔ DOMAIN BLACKLISTED")
                threats.append("Blacklisted Domain")
                red_flags.append("Domain found in security blacklist")

            # 3. HTTPS Check
            if parsed.scheme != "https":
                risk += 20
                indicators.append("🔓 No HTTPS encryption")
                red_flags.append("No HTTPS/SSL encryption")

            # 4. Redirect symbol @
            if "@" in url:
                risk += 50
                indicators.append("🎯 Redirect symbol '@' - URL spoofing")
                threats.append("URL Spoofing")
                red_flags.append("Contains @ symbol (URL spoofing)")

            # 5. Suspicious TLD
            for tld in self.db.get("suspicious_tlds", []):
                if domain.endswith(tld):
                    risk += 35
                    indicators.append(f"🚩 Suspicious TLD: {tld}")
                    threats.append("Untrusted TLD")
                    red_flags.append(f"Suspicious TLD: {tld}")
                    break

            # 6. Suspicious Keywords
            found = [k for k in self.suspicious_keywords if k in url.lower()]
            if found:
                risk += min(len(found) * 12, 35)
                indicators.append(f"🔑 Suspicious keywords: {', '.join(found)}")
                red_flags.append(f"Contains keywords: {', '.join(found)}")

            # 7. Brand Impersonation
            is_fake, brand, real, attack = detect_fake_domain(domain)
            if is_fake:
                risk += 75
                indicators.append(f"🎭 FAKE BRAND: Impersonating {brand.upper()}")
                indicators.append(f"   Legitimate: {real}")
                threats.append("Brand Spoofing")
                red_flags.append(f"Impersonates {brand.upper()} (real: {real})")
                details = {"fake_brand": brand, "real_domain": real, "attack_type": attack}

            # 8. Content Analysis
            phishing_content = []
            try:
                r = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code == 200:
                    content_lower = r.text.lower()
                    for keyword in PHISHING_KEYWORDS:
                        if keyword.lower() in content_lower:
                            phishing_content.append(keyword)
                            risk += 8
                    if phishing_content:
                        risk += min(len(phishing_content) * 5, 25)
                        indicators.append(f"📧 Phishing language: {', '.join(phishing_content[:3])}")
                    
                    # Check for external forms
                    if "action=\"http" in r.text and parsed.netloc not in r.text:
                        risk += 25
                        indicators.append("⚠️ External login form")
                        red_flags.append("Form submits to external domain")
            except:
                pass

            risk = min(risk, 100)

            # Check for malware extensions
            malware_exts = [".exe", ".apk", ".bat", ".scr", ".vbs", ".cmd", ".msi"]
            is_malware = any(url.lower().split('?')[0].endswith(ext) for ext in malware_exts)
            
            # DETERMINE CLASSIFICATION
            if is_malware:
                classification = "FRAUD"
                reason = "Malware download detected in URL - DO NOT PROCEED"
                indicators.append("🦠 MALWARE DETECTED")
                risk = 100
                red_flags.append("Direct link to executable file")
            elif domain in self.db.get("known_malicious_domains", []):
                classification = "UNSAFE"
                reason = "This domain is blacklisted for malicious activities including phishing"
            elif is_fake:
                classification = "FAKE"
                reason = f"This is a FAKE website impersonating {brand.upper()}. The domain tries to trick you by misspelling the real domain '{real}'."
            elif risk >= 85:
                classification = "FRAUD"
                reason = "Multiple high-risk indicators detected - fraudulent activity suspected"
            elif risk >= 65:
                classification = "UNSAFE"
                reason = "Strong signs of phishing or scam detected. Do not enter any personal information."
            elif risk >= 35:
                classification = "IDENTITY RISK"
                reason = "Suspicious behavior detected that could lead to identity theft"
            elif risk >= 15:
                classification = "SAFE"
                reason = "Minor concerns detected but appears generally legitimate"
            else:
                classification = "SAFE"
                reason = "No security issues detected - appears legitimate"

            # Auto-blacklist
            if classification in ["UNSAFE", "FAKE", "FRAUD"]:
                add_to_blacklist(domain)
                indicators.append("🚫 DOMAIN ADDED TO BLACKLIST")

            return {
                "success": True, "type": "url", "url": url, "domain": domain, "risk_score": risk,
                "result": classification, "reason": reason, "red_flags": red_flags,
                "indicators": indicators, "threats": threats, "details": details,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def analyze_email(self, email):
        risk = 0
        indicators = []
        threats = []
        details = {}
        red_flags = []
        classification = "SAFE"
        reason = ""

        try:
            email = email.strip().lower()
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                return {"success": False, "error": "Invalid email format"}
            
            local_part, domain = email.split("@")

            # 1. Official domain check
            is_official = False
            for brand, official_domain in BRAND_DOMAINS.items():
                if domain == official_domain:
                    is_official = True
                    indicators.append(f"✅ Official domain: {domain}")
                    break

            # 2. Fake/Impersonation Detection
            is_fake, brand, real, attack = detect_fake_domain(domain)
            if is_fake:
                risk += 80
                indicators.append(f"🎭 FAKE DOMAIN: Impersonating {brand.upper()}")
                indicators.append(f"   Real: {real} | Attack: {attack}")
                threats.append("Domain Impersonation")
                red_flags.append(f"Impersonates {brand.upper()} (should be {real})")
                details = {"fake_brand": brand, "real_domain": real, "attack_type": attack}

            # 3. Scam keywords in local part
            scam_keywords = ["urgent", "verify", "update", "security", "billing", "invoice", "alert", "account", "payment", "support"]
            found_kw = [k for k in scam_keywords if k in local_part]
            if found_kw:
                risk += 35
                indicators.append(f"🚩 Scam keywords in address: {', '.join(found_kw)}")
                threats.append("Suspicious Language")
                red_flags.append(f"Contains scam keywords: {', '.join(found_kw)}")

            # 4. DNS Authentication (SPF, DMARC, MX)
            if DNS_AVAILABLE:
                try:
                    dns.resolver.resolve(domain, 'MX')
                    indicators.append("✅ Valid MX records")
                except:
                    risk += 25
                    indicators.append("✉️ No MX records")
                    red_flags.append("No MX records - domain may not receive emails")
                
                # SPF Check
                try:
                    answers = dns.resolver.resolve(domain, 'TXT')
                    spf = any('v=spf1' in rdata.to_text().lower() for rdata in answers)
                    if spf:
                        indicators.append("✅ SPF authenticated")
                    else:
                        risk += 10
                        indicators.append("🔓 No SPF record")
                        red_flags.append("Missing SPF record")
                except:
                    risk += 10
                    indicators.append("🔓 No SPF record")
                
                # DMARC Check
                try:
                    answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
                    dmarc = any('v=dmarc1' in rdata.to_text().lower() for rdata in answers)
                    if dmarc:
                        indicators.append("✅ DMARC authenticated")
                    else:
                        risk += 10
                        indicators.append("🔓 No DMARC record")
                except:
                    risk += 10
                    indicators.append("🔓 No DMARC record")

            # Gmail-specific checks
            if domain == "gmail.com" and found_kw:
                risk += 20
                indicators.append("⚠️ Gmail with official-sounding prefix - potential scam")
                red_flags.append("Gmail address impersonating official role")

            risk = min(risk, 100)

            # DETERMINE CLASSIFICATION
            if domain in self.db.get("known_malicious_domains", []):
                classification = "UNSAFE"
                reason = "This email domain is blacklisted for malicious activities"
            elif is_fake:
                classification = "FAKE"
                reason = f"This is a FAKE email address impersonating {brand.upper()}. The real domain should be '{real}'."
            elif risk >= 80:
                classification = "FRAUD"
                reason = "Clear signs of fraudulent activity - this is likely a scam email"
            elif risk >= 55:
                classification = "UNSAFE"
                reason = "Strong signs of phishing - do not reply or click any links"
            elif risk >= 30:
                classification = "IDENTITY RISK"
                reason = "Suspicious email that could lead to identity theft"
            elif is_official and risk < 15:
                classification = "SAFE"
                reason = f"Legitimate {domain} email address"
            else:
                classification = "SAFE"
                reason = "No significant red flags detected"

            # Auto-blacklist
            if classification in ["UNSAFE", "FAKE", "FRAUD"]:
                add_to_blacklist(domain)
                indicators.append("🚫 DOMAIN ADDED TO BLACKLIST")

            return {
                "success": True, "type": "email", "email": email, "domain": domain, "risk_score": risk,
                "result": classification, "reason": reason, "red_flags": red_flags,
                "indicators": indicators, "threats": threats, "details": details,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

detector = PhishingDetector()

# ================= FRONTEND HTML (embedded) =================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ AI PhishGuard - Fake Website & Email Detector</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e2e8f0; min-height: 100vh; }
    .navbar { background: rgba(10, 14, 26, .95); border-bottom: 1px solid #1e3a5f; backdrop-filter: blur(20px); }
    .brand { font-size: 1.4rem; font-weight: 800; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%); padding: 50px 0 30px; text-align: center; border-bottom: 1px solid #1e3a5f; }
    .hero h1 { font-size: 2.4rem; font-weight: 900; background: linear-gradient(135deg, #38bdf8, #818cf8, #f472b6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { color: #94a3b8; font-size: 1.1rem; margin-top: 10px; }
    .badge-new { background: linear-gradient(135deg, #ef4444, #f97316); color: #fff; font-size: .7rem; padding: 3px 8px; border-radius: 20px; vertical-align: middle; margin-left: 8px; }
    .scanner-card { background: rgba(15, 23, 42, .8); border: 1px solid #1e3a5f; border-radius: 20px; padding: 30px; margin: 30px 0; backdrop-filter: blur(10px); }
    .nav-tabs { border: none; gap: 8px; margin-bottom: 25px; flex-wrap: wrap; }
    .nav-tabs .nav-link { border: 1px solid #1e3a5f; color: #94a3b8; border-radius: 10px; padding: 10px 20px; font-weight: 600; background: rgba(30, 58, 95, .3); transition: all .3s; }
    .nav-tabs .nav-link.active { background: linear-gradient(135deg, #38bdf8, #818cf8); color: #fff; border-color: transparent; }
    .input-wrap { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
    .input-wrap input { flex: 1; background: rgba(30, 58, 95, .4); border: 2px solid #1e3a5f; color: #e2e8f0; border-radius: 12px; padding: 14px 18px; font-size: 1rem; outline: none; min-width: 200px; }
    .input-wrap input:focus { border-color: #38bdf8; }
    .input-wrap input::placeholder { color: #475569; }
    .btn-scan { background: linear-gradient(135deg, #38bdf8, #818cf8); color: #fff; border: none; border-radius: 12px; padding: 14px 28px; font-weight: 700; font-size: 1rem; cursor: pointer; transition: all .3s; white-space: nowrap; }
    .btn-scan:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(56, 189, 248, .4); }
    .result-box { border-radius: 15px; padding: 22px; margin-top: 20px; animation: slideUp .4s ease; }
    @keyframes slideUp { from { opacity: 0; transform: translateY(15px); } to { opacity: 1; transform: translateY(0); } }
    .result-safe { background: linear-gradient(135deg, rgba(16, 185, 129, .15), rgba(6, 78, 59, .2)); border: 2px solid #10b981; }
    .result-suspicious { background: linear-gradient(135deg, rgba(245, 158, 11, .15), rgba(120, 53, 15, .2)); border: 2px solid #f59e0b; }
    .result-danger { background: linear-gradient(135deg, rgba(239, 68, 68, .15), rgba(127, 29, 29, .2)); border: 2px solid #ef4444; }
    .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
    .result-title { font-size: 1.4rem; font-weight: 800; }
    .score-circle { width: 70px; height: 70px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; font-weight: 900; }
    .score-safe { background: rgba(16, 185, 129, .2); border: 3px solid #10b981; color: #10b981; }
    .score-warn { background: rgba(245, 158, 11, .2); border: 3px solid #f59e0b; color: #f59e0b; }
    .score-danger { background: rgba(239, 68, 68, .2); border: 3px solid #ef4444; color: #ef4444; }
    .risk-bar-wrap { background: rgba(255, 255, 255, .1); border-radius: 10px; height: 10px; margin: 12px 0; }
    .risk-bar { height: 100%; border-radius: 10px; transition: width 1s ease; }
    .indicator-list { list-style: none; margin-top: 12px; }
    .indicator-list li { padding: 6px 0; border-bottom: 1px solid rgba(255, 255, 255, .06); font-size: .9rem; color: #cbd5e1; }
    .indicator-list li:last-child { border: none; }
    .threat-badge { display: inline-block; background: rgba(239, 68, 68, .2); color: #f87171; border: 1px solid #ef4444; border-radius: 20px; padding: 3px 12px; font-size: .8rem; margin: 3px; font-weight: 600; }
    .red-flag-badge { display: inline-block; background: rgba(245, 158, 11, .2); color: #fbbf24; border: 1px solid #f59e0b; border-radius: 20px; padding: 3px 12px; font-size: .8rem; margin: 3px; }
    .fake-alert { background: rgba(239, 68, 68, .15); border: 2px solid #ef4444; border-radius: 12px; padding: 15px; margin: 12px 0; }
    .fake-alert .title { color: #f87171; font-weight: 800; font-size: 1rem; margin-bottom: 5px; }
    .fake-alert .detail { color: #fca5a5; font-size: .9rem; }
    .reason-box { background: rgba(0, 0, 0, .3); border-radius: 10px; padding: 12px; margin: 10px 0; border-left: 4px solid; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
    .stat-box { background: rgba(15, 23, 42, .8); border: 1px solid #1e3a5f; border-radius: 15px; padding: 20px; text-align: center; }
    .stat-num { font-size: 2rem; font-weight: 900; margin: 8px 0; }
    .stat-num.blue { color: #38bdf8; }
    .stat-num.green { color: #10b981; }
    .stat-num.red { color: #ef4444; }
    .stat-label { color: #64748b; font-size: .85rem; }
    .history-table { background: rgba(15, 23, 42, .8); border: 1px solid #1e3a5f; border-radius: 15px; overflow-x: auto; }
    .history-table table { width: 100%; border-collapse: collapse; min-width: 500px; }
    .history-table thead { background: linear-gradient(135deg, rgba(56, 189, 248, .2), rgba(129, 140, 248, .2)); }
    .history-table th, .history-table td { padding: 12px 15px; text-align: left; }
    .history-table th { color: #94a3b8; font-size: .85rem; border-bottom: 1px solid #1e3a5f; }
    .history-table td { border-bottom: 1px solid rgba(30, 58, 95, .5); font-size: .85rem; color: #cbd5e1; }
    .history-table tr:last-child td { border: none; }
    .history-table tr:hover td { background: rgba(56, 189, 248, .05); }
    .loading { display: none; text-align: center; padding: 25px; color: #94a3b8; }
    .spinner { width: 40px; height: 40px; border: 3px solid rgba(56, 189, 248, .2); border-top-color: #38bdf8; border-radius: 50%; animation: spin .8s linear infinite; margin: 0 auto 10px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .err-msg { background: rgba(239, 68, 68, .15); border: 1px solid #ef4444; color: #f87171; border-radius: 10px; padding: 12px; margin-top: 10px; display: none; }
    .section-title { font-size: 1.5rem; font-weight: 800; color: #e2e8f0; margin-bottom: 20px; }
    .clear-btn { background: rgba(239, 68, 68, .15); color: #f87171; border: 1px solid #ef4444; border-radius: 8px; padding: 6px 14px; font-size: .85rem; cursor: pointer; }
    .clear-btn:hover { background: rgba(239, 68, 68, .3); }
    .info-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; justify-content: center; }
    .info-pill { background: rgba(56, 189, 248, .1); border: 1px solid rgba(56, 189, 248, .3); color: #38bdf8; border-radius: 20px; padding: 4px 12px; font-size: .8rem; }
    footer { text-align: center; padding: 20px; color: #334155; border-top: 1px solid #1e3a5f; margin-top: 40px; }
    @media (max-width: 768px) {
        .hero h1 { font-size: 1.8rem; }
        .input-wrap { flex-direction: column; }
        .btn-scan { width: 100%; }
    }
  </style>
</head>

<body>

  <nav class="navbar px-4 py-3">
    <div class="container-fluid">
      <span class="brand"><i class="fas fa-shield-halved me-2"></i>AI PhishGuard</span>
      <div style="color:#64748b;font-size:.85rem"><i class="fas fa-circle" style="color:#10b981;font-size:.5rem"></i> Live Detection Active</div>
    </div>
  </nav>

  <div class="hero">
    <div class="container">
      <h1>🛡️ Fake Website & Email Detector <span class="badge-new">PRO</span></h1>
      <p>Instantly detect fake domains, brand impersonation, typosquatting & scam emails</p>
      <div class="info-pills mt-3">
        <span class="info-pill"><i class="fas fa-globe me-1"></i>SAFE / UNSAFE / FAKE</span>
        <span class="info-pill"><i class="fas fa-envelope me-1"></i>FRAUD / IDENTITY RISK</span>
        <span class="info-pill"><i class="fas fa-fingerprint me-1"></i>Brand Impersonation</span>
        <span class="info-pill"><i class="fas fa-keyboard me-1"></i>Typosquatting Detection</span>
      </div>
    </div>
  </div>

  <div class="container py-4">

    <div class="scanner-card">
      <ul class="nav nav-tabs" id="tabs">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#urlTab"><i class="fas fa-globe me-2"></i>Website URL Scanner</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#emailTab"><i class="fas fa-envelope me-2"></i>Email Scanner</a></li>
      </ul>

      <div class="tab-content">
        <div class="tab-pane fade show active" id="urlTab">
          <p style="color:#94a3b8;margin-bottom:15px">Enter any website URL — instantly detect fake or impersonating websites.</p>
          <div class="input-wrap">
            <input type="text" id="urlInput" placeholder="e.g., paypa1.com or g00gle-login.tk" autocomplete="off">
            <button class="btn-scan" onclick="scanURL()"><i class="fas fa-search me-2"></i>Scan URL</button>
          </div>
          <div class="loading" id="urlLoading"><div class="spinner"></div>Analyzing domain...</div>
          <div class="err-msg" id="urlErr"></div>
          <div id="urlResult"></div>
        </div>

        <div class="tab-pane fade" id="emailTab">
          <p style="color:#94a3b8;margin-bottom:15px">Enter any email address — detect fake domains, spoofing & impersonation.</p>
          <div class="input-wrap">
            <input type="text" id="emailInput" placeholder="e.g., support@paypa1.com or security@gmail.com" autocomplete="off">
            <button class="btn-scan" onclick="scanEmail()"><i class="fas fa-shield-alt me-2"></i>Scan Email</button>
          </div>
          <div class="loading" id="emailLoading"><div class="spinner"></div>Analyzing email...</div>
          <div class="err-msg" id="emailErr"></div>
          <div id="emailResult"></div>
        </div>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat-box"><i class="fas fa-search" style="color:#38bdf8"></i><div class="stat-num blue" id="totalScans">0</div><div class="stat-label">Total Scans</div></div>
      <div class="stat-box"><i class="fas fa-check-circle" style="color:#10b981"></i><div class="stat-num green" id="safeCount">0</div><div class="stat-label">SAFE</div></div>
      <div class="stat-box"><i class="fas fa-skull-crossbones" style="color:#ef4444"></i><div class="stat-num red" id="threatCount">0</div><div class="stat-label">Threats Detected</div></div>
    </div>

    <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
      <div class="section-title mb-0"><i class="fas fa-history me-2" style="color:#38bdf8"></i>Recent Scans</div>
      <button class="clear-btn" onclick="clearHistory()"><i class="fas fa-trash me-1"></i>Clear History</button>
    </div>
    <div class="history-table">
      <table>
        <thead><tr><th>Type</th><th>Input</th><th>Result</th><th>Risk Score</th><th>Time</th></tr></thead>
        <tbody id="scanHistory"><tr><td colspan="5" style="text-align:center;padding:20px;color:#475569">No scans yet</td></tr></tbody>
      </table>
    </div>
  </div>

  <footer>🛡️ AI PhishGuard PRO &nbsp;|&nbsp; Advanced Fake Website & Email Detection &nbsp;|&nbsp; Stay Safe Online</footer>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const API = window.location.origin;

    document.addEventListener('DOMContentLoaded', () => { loadDashboard(); setInterval(loadDashboard, 30000); });
    document.getElementById('urlInput').addEventListener('keydown', e => { if (e.key === 'Enter') scanURL(); });
    document.getElementById('emailInput').addEventListener('keydown', e => { if (e.key === 'Enter') scanEmail(); });

    async function scanURL() {
      const url = document.getElementById('urlInput').value.trim();
      if (!url) { showErr('urlErr', 'Please enter a URL'); return; }
      document.getElementById('urlResult').innerHTML = '';
      document.getElementById('urlErr').style.display = 'none';
      document.getElementById('urlLoading').style.display = 'block';
      try {
        const res = await fetch(`${API}/api/scan-url`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
        const data = await res.json();
        document.getElementById('urlLoading').style.display = 'none';
        if (!data.success) { showErr('urlErr', data.error); return; }
        document.getElementById('urlResult').innerHTML = buildResult(data, 'url');
        loadDashboard();
      } catch (e) { document.getElementById('urlLoading').style.display = 'none'; showErr('urlErr', 'Cannot connect to server.'); }
    }

    async function scanEmail() {
      const email = document.getElementById('emailInput').value.trim();
      if (!email) { showErr('emailErr', 'Please enter an email'); return; }
      document.getElementById('emailResult').innerHTML = '';
      document.getElementById('emailErr').style.display = 'none';
      document.getElementById('emailLoading').style.display = 'block';
      try {
        const res = await fetch(`${API}/api/scan-email`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
        const data = await res.json();
        document.getElementById('emailLoading').style.display = 'none';
        if (!data.success) { showErr('emailErr', data.error); return; }
        document.getElementById('emailResult').innerHTML = buildResult(data, 'email');
        loadDashboard();
      } catch (e) { document.getElementById('emailLoading').style.display = 'none'; showErr('emailErr', 'Cannot connect to server.'); }
    }

    function buildResult(data, type) {
      const score = data.risk_score;
      const result = data.result;
      
      let cls = 'result-safe';
      let scoreClass = 'score-safe';
      let barColor = '#10b981';
      let icon = '✅';
      
      if (result === 'FRAUD') { cls = 'result-danger'; scoreClass = 'score-danger'; barColor = '#ef4444'; icon = '🦠'; }
      else if (result === 'FAKE') { cls = 'result-danger'; scoreClass = 'score-danger'; barColor = '#ef4444'; icon = '🎭'; }
      else if (result === 'UNSAFE') { cls = 'result-danger'; scoreClass = 'score-danger'; barColor = '#ef4444'; icon = '⚠️'; }
      else if (result === 'IDENTITY RISK') { cls = 'result-suspicious'; scoreClass = 'score-warn'; barColor = '#f59e0b'; icon = '🆔'; }

      let reasonHtml = '';
      if (data.reason) {
        reasonHtml = `<div class="reason-box" style="border-left-color: ${barColor}"><strong>📋 Reason:</strong> ${escapeHtml(data.reason)}</div>`;
      }

      let fakeAlert = '';
      if (data.details && data.details.fake_brand) {
        fakeAlert = `<div class="fake-alert"><div class="title">🎭 FAKE ${type === 'email' ? 'EMAIL DOMAIN' : 'WEBSITE'} DETECTED!</div>
          <div class="detail">Impersonating: <strong>${data.details.fake_brand.toUpperCase()}</strong></div>
          <div class="detail">Real domain: <strong>${data.details.real_domain}</strong></div>
          <div class="detail">Attack: <strong>${data.details.attack_type}</strong></div></div>`;
      }

      let threatBadges = '';
      if (data.threats && data.threats.length) {
        threatBadges = '<div style="margin:10px 0">' + data.threats.map(t => `<span class="threat-badge">⚠️ ${t}</span>`).join('') + '</div>';
      }

      let redFlagBadges = '';
      if (data.red_flags && data.red_flags.length) {
        redFlagBadges = '<div style="margin:10px 0"><strong>🚩 Red Flags:</strong> ' + data.red_flags.map(f => `<span class="red-flag-badge">${escapeHtml(f)}</span>`).join('') + '</div>';
      }

      let indHTML = '';
      if (data.indicators && data.indicators.length) {
        indHTML = data.indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('');
      } else {
        indHTML = '<li style="color:#10b981">✅ No suspicious indicators found</li>';
      }

      const meta = type === 'url'
        ? `<span style="color:#94a3b8;font-size:.85rem"><i class="fas fa-globe me-1"></i>${escapeHtml(data.domain)}</span>`
        : `<span style="color:#94a3b8;font-size:.85rem"><i class="fas fa-envelope me-1"></i>${escapeHtml(data.email)} &nbsp;|&nbsp; Domain: ${escapeHtml(data.domain)}</span>`;

      return `
    <div class="result-box ${cls}">
      <div class="result-header">
        <div><div class="result-title">${icon} ${result}</div>${meta}</div>
        <div class="${scoreClass} score-circle">${score}</div>
      </div>
      <div class="risk-bar-wrap"><div class="risk-bar" style="width:${score}%;background:${barColor}"></div></div>
      ${reasonHtml}
      ${fakeAlert}
      ${threatBadges}
      ${redFlagBadges}
      <div style="color:#94a3b8;font-size:.85rem;margin-top:12px;margin-bottom:4px"><i class="fas fa-list me-1"></i>Detection Indicators:</div>
      <ul class="indicator-list">${indHTML}</ul>
    </div>`;
    }

    async function loadDashboard() {
      try {
        const res = await fetch(`${API}/api/dashboard`);
        const data = await res.json();
        if (!data.success) return;
        document.getElementById('totalScans').textContent = data.statistics.total_scans;
        document.getElementById('safeCount').textContent = data.statistics.safe_scans;
        const threats = (data.statistics.unsafe_scans || 0) + (data.statistics.fake_scans || 0) + (data.statistics.fraud_scans || 0) + (data.statistics.identity_risk_scans || 0);
        document.getElementById('threatCount').textContent = threats;
        const tbody = document.getElementById('scanHistory');
        if (!data.recent_scans || !data.recent_scans.length) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#475569">No scans yet</td></tr>';
          return;
        }
        tbody.innerHTML = data.recent_scans.map(s => {
          let badge = '';
          if (s.result === 'SAFE') badge = '<span style="color:#10b981">✅ SAFE</span>';
          else if (s.result === 'IDENTITY RISK') badge = '<span style="color:#f59e0b">⚠️ IDENTITY RISK</span>';
          else if (s.result === 'UNSAFE') badge = '<span style="color:#ef4444">⚠️ UNSAFE</span>';
          else if (s.result === 'FAKE') badge = '<span style="color:#ef4444">🎭 FAKE</span>';
          else badge = '<span style="color:#ef4444">🚨 FRAUD</span>';
          const typeIcon = s.type === 'url' ? '🌐 URL' : '📧 Email';
          let barColor = '#10b981';
          if (s.risk_score >= 65) barColor = '#ef4444';
          else if (s.risk_score >= 30) barColor = '#f59e0b';
          const bar = `<div style="background:rgba(255,255,255,.1);border-radius:5px;height:6px;width:80px;display:inline-block;vertical-align:middle;margin-right:5px"><div style="height:100%;border-radius:5px;width:${s.risk_score}%;background:${barColor}"></div></div>${s.risk_score}`;
          return `<tr><td>${typeIcon}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(s.input)}">${escapeHtml(s.input.substring(0, 40))}${s.input.length > 40 ? '...' : ''}</td><td>${badge}</td><td>${bar}</td><td style="color:#64748b">${s.timestamp || ''}</td></tr>`;
        }).join('');
      } catch (e) { console.error('Dashboard error', e); }
    }

    async function clearHistory() {
      if (!confirm('Clear all scan history?')) return;
      await fetch(`${API}/api/clear-history`, { method: 'POST' });
      loadDashboard();
    }

    function showErr(id, msg) {
      const el = document.getElementById(id);
      el.textContent = msg; el.style.display = 'block';
      setTimeout(() => { el.style.display = 'none'; }, 5000);
    }

    function escapeHtml(str) {
      if (!str) return '';
      return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
      });
    }
  </script>
</body>

</html>
"""

# ================= ROUTES =================
@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.json
    if not data or not data.get("url"):
        return jsonify({"success": False, "error": "No URL provided"})
    res = detector.analyze_url(data["url"].strip())
    if res.get("success"):
        db = load_db()
        db["scans"].append({
            "type": "url", "input": data["url"],
            "result": res["result"], "risk_score": res["risk_score"],
            "timestamp": res["timestamp"]
        })
        db["statistics"]["total_scans"] += 1
        stats_map = {"SAFE": "safe_scans", "UNSAFE": "unsafe_scans", "FAKE": "fake_scans", 
                     "FRAUD": "fraud_scans", "IDENTITY RISK": "identity_risk_scans"}
        stat_key = stats_map.get(res["result"], "unsafe_scans")
        db["statistics"][stat_key] = db["statistics"].get(stat_key, 0) + 1
        save_db(db)
    return jsonify(res)

@app.route("/api/scan-email", methods=["POST"])
def scan_email():
    data = request.json
    if not data or not data.get("email"):
        return jsonify({"success": False, "error": "No email provided"})
    res = detector.analyze_email(data["email"].strip())
    if res.get("success"):
        db = load_db()
        db["scans"].append({
            "type": "email", "input": data["email"],
            "result": res["result"], "risk_score": res["risk_score"],
            "timestamp": res["timestamp"]
        })
        db["statistics"]["total_scans"] += 1
        stats_map = {"SAFE": "safe_scans", "UNSAFE": "unsafe_scans", "FAKE": "fake_scans", 
                     "FRAUD": "fraud_scans", "IDENTITY RISK": "identity_risk_scans"}
        stat_key = stats_map.get(res["result"], "unsafe_scans")
        db["statistics"][stat_key] = db["statistics"].get(stat_key, 0) + 1
        save_db(db)
    return jsonify(res)

@app.route("/api/dashboard")
def dashboard():
    db = load_db()
    for key in ["safe_scans", "unsafe_scans", "fake_scans", "fraud_scans", "identity_risk_scans"]:
        if key not in db["statistics"]:
            db["statistics"][key] = 0
    return jsonify({
        "success": True,
        "statistics": db["statistics"],
        "recent_scans": db["scans"][-20:][::-1]
    })

@app.route("/api/clear-history", methods=["POST"])
def clear_history():
    db = load_db()
    db["scans"] = []
    db["statistics"] = {"total_scans": 0, "safe_scans": 0, "unsafe_scans": 0, "fake_scans": 0, "fraud_scans": 0, "identity_risk_scans": 0}
    save_db(db)
    return jsonify({"success": True})

# ================= MAIN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
