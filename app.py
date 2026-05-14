from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import re
import requests
from datetime import datetime
from urllib.parse import urlparse
import os

# --- Resilient Imports ---
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("WARNING: 'python-whois' not found. Domain age check will be disabled.")

try:
    # pyrefly: ignore [missing-import]
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("WARNING: 'dnspython' not found. MX record check will be disabled.")

app = Flask(__name__)
CORS(app)

DB_FILE = "phishing_db.json"

# ================= DATABASE =================

def initialize_db():
    if not os.path.exists(DB_FILE):
        default_data = {
            "scans": [],
            "statistics": {"total_scans": 0, "safe_scans": 0, "threats_detected": 0},
            "known_malicious_domains": [
                "phishing-site.tk", "steal-info.ml", "hack-account.ga",
                "fake-login.cf", "scam-paypal.gq", "verify-account.xyz"
            ],
            "known_safe_domains": [
                "google.com", "facebook.com", "amazon.com", "microsoft.com",
                "apple.com", "twitter.com", "github.com", "paypal.com"
            ],
            "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
        }
        with open(DB_FILE, "w") as f:
            json.dump(default_data, f, indent=4)

def load_db():
    initialize_db()
    try:
        with open(DB_FILE, "r") as f: return json.load(f)
    except: return {"scans": [], "statistics": {"total_scans": 0, "safe_scans": 0, "threats_detected": 0}}

def save_db(data):
    with open(DB_FILE, "w") as f: json.dump(data, f, indent=4)

def add_to_blacklist(domain):
    """Automatically 'block' a detected malicious domain"""
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
    "twitter": "twitter.com", "github": "github.com", "yahoo": "yahoo.com"
}

def normalize_domain(domain):
    d = domain.lower()
    subs = {'0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '6':'g', '7':'t', '8':'b', '@':'a', 'vv':'w', 'rn':'m'}
    for k, v in subs.items(): d = d.replace(k, v)
    return d

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if not s2: return len(s1)
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
    if len(parts) < 2: return False, None, None, None
    registered = '.'.join(parts[-2:])
    hostname = parts[-2]
    normalized = normalize_domain(hostname)

    for brand, real in BRAND_DOMAINS.items():
        if registered == real or clean.endswith('.' + real): return False, None, None, None
        if normalized == brand: return True, brand, real, "Homograph Attack"
        if brand in hostname: return True, brand, real, "Brand Impersonation"
        dist = levenshtein_distance(hostname, brand)
        if dist <= (1 if len(brand) >= 5 else 0) and dist > 0: return True, brand, real, "Typosquatting"
    return False, None, None, None

# ================= DETECTOR =================

class PhishingDetector:
    def __init__(self):
        self.db = load_db()
        self.keywords = ["login", "verify", "secure", "bank", "password", "account", "update"]

    def analyze_url(self, url):
        risk = 0
        indicators = []
        threats = []
        details = {}
        emails = []

        try:
            if not url.startswith(("http", "https")): url = "http://" + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]

            # 1. Age Check
            if WHOIS_AVAILABLE:
                try:
                    w = whois.whois(domain)
                    date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if date:
                        age = (datetime.now() - date).days
                        if age < 30:
                            risk += 30; indicators.append(f"⏳ New domain ({age} days old)"); threats.append("New Domain")
                except: pass

            # 2. Blacklist
            self.db = load_db()
            if domain in self.db.get("known_malicious_domains", []):
                risk += 70; indicators.append("⛔ Blacklisted"); threats.append("Malicious")

            # 3. HTTPS
            if parsed.scheme != "https": risk += 15; indicators.append("🔓 No HTTPS")

            # 4. Redirects / @
            if "@" in url: risk += 30; indicators.append("🎯 Redirect symbol '@'"); threats.append("Redirect")

            # 5. TLD
            for tld in self.db.get("suspicious_tlds", []):
                if domain.endswith(tld): risk += 25; indicators.append(f"🚩 Suspicious TLD: {tld}"); threats.append("Untrusted TLD"); break

            # 6. Keywords
            found = [k for k in self.keywords if k in url.lower()]
            if found: risk += min(len(found) * 10, 30); indicators.append(f"🔑 Keywords: {', '.join(found)}")

            # 7. Brand Impersonation
            is_fake, brand, real, attack = detect_fake_domain(domain)
            if is_fake:
                risk += 60; indicators.append(f"🎭 Fake {brand.upper()} site (Real: {real})"); threats.append("Brand Spoofing")
                details = {"fake_brand": brand, "real_domain": real, "attack_type": attack}

            # 8. Content Check
            try:
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    found_ems = set(re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", r.text, re.I))
                    for e in list(found_ems)[:3]: emails.append(self.analyze_email(e))
            except: pass

            risk = min(risk, 100)
            res = "Phishing" if risk >= 70 else "Suspicious" if risk >= 35 else "Safe"
            
            # BLOCK/BLACKLIST IF PHISHING
            if res == "Phishing":
                add_to_blacklist(domain)
                indicators.append("🚫 DOMAIN BLOCKED — Added to internal blacklist")

            return {
                "success": True, "type": "url", "url": url, "domain": domain, "risk_score": risk,
                "result": res, "color": "danger" if res == "Phishing" else "warning" if res == "Suspicious" else "success",
                "indicators": indicators, "threats": threats, "details": details, "embedded_emails": emails,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e: return {"success": False, "error": str(e)}

    def analyze_email(self, email):
        risk = 0; indicators = []; threats = []; details = {}
        try:
            email = email.strip().lower()
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email): return {"success": False, "error": "Invalid format"}
            domain = email.split("@")[1]
            
            # 1. Fake Provider
            is_fake, brand, real, attack = detect_fake_domain(domain)
            if is_fake:
                risk += 70; indicators.append(f"🎭 Impersonating {brand.upper()}"); threats.append("Email Spoofing")
                details = {"fake_brand": brand, "real_domain": real, "attack_type": attack}

            # 2. MX Check
            if DNS_AVAILABLE:
                try: dns.resolver.resolve(domain, 'MX')
                except: risk += 20; indicators.append("✉️ No MX records"); threats.append("Missing MX")

            risk = min(risk, 100)
            res = "Phishing" if risk >= 60 else "Suspicious" if risk >= 30 else "Safe"
            
            # BLOCK/BLACKLIST IF PHISHING
            if res == "Phishing":
                add_to_blacklist(domain)
                indicators.append("🚫 EMAIL DOMAIN BLOCKED — Added to internal blacklist")

            return {
                "success": True, "type": "email", "email": email, "domain": domain, "risk_score": risk,
                "result": res, "color": "danger" if res == "Phishing" else "warning" if res == "Suspicious" else "success",
                "indicators": indicators, "threats": threats, "details": details,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e: return {"success": False, "error": str(e)}

detector = PhishingDetector()

@app.route("/")
def home(): return render_template("index.html")

@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    data = request.json
    if not data or not data.get("url"): return jsonify({"success": False, "error": "No URL"})
    res = detector.analyze_url(data["url"].strip())
    if res["success"]:
        db = load_db()
        db["scans"].append({"type": "url", "input": data["url"], "result": res["result"], "risk_score": res["risk_score"], "timestamp": res["timestamp"]})
        db["statistics"]["total_scans"] += 1
        if res["result"] == "Safe": db["statistics"]["safe_scans"] += 1
        else: db["statistics"]["threats_detected"] += 1
        save_db(db)
    return jsonify(res)

@app.route("/api/scan-email", methods=["POST"])
def scan_email():
    data = request.json
    if not data or not data.get("email"): return jsonify({"success": False, "error": "No Email"})
    res = detector.analyze_email(data["email"].strip())
    if res["success"]:
        db = load_db()
        db["scans"].append({"type": "email", "input": data["email"], "result": res["result"], "risk_score": res["risk_score"], "timestamp": res["timestamp"]})
        db["statistics"]["total_scans"] += 1
        if res["result"] == "Safe": db["statistics"]["safe_scans"] += 1
        else: db["statistics"]["threats_detected"] += 1
        save_db(db)
    return jsonify(res)

@app.route("/api/dashboard")
def dashboard():
    db = load_db()
    return jsonify({"success": True, "statistics": db["statistics"], "recent_scans": db["scans"][-20:][::-1]})

@app.route("/api/clear-history", methods=["POST"])
def clear_history():
    db = load_db()
    db["scans"] = []; db["statistics"] = {"total_scans": 0, "safe_scans": 0, "threats_detected": 0}
    save_db(db)
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
