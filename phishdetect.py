from urllib.parse import urlparse
import re
import ipaddress
import math
from collections import Counter

# ====================== CONFIG ======================

SUSPICIOUS_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "password", "credential", "confirm",
    "validation", "authenticate", "banking", "wallet", "recover", "unlock",
    "suspended", "limited", "urgent", "action-required", "webscr", "cmd",
    "session", "token", "auth", "oauth"
]

BRANDS = [
    "paypal", "google", "gmail", "facebook", "fb", "instagram", "microsoft",
    "outlook", "office365", "apple", "icloud", "amazon", "netflix", "ebay",
    "whatsapp", "telegram", "easypaisa", "jazzcash", "sadapay", "nayapay",
    "binance", "coinbase", "crypto", "hsbc", "citi", "chase", "wellsfargo",
    "bankofamerica", "dropbox", "linkedin", "twitter", "x.com"
]

WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "paypal.com",
    "github.com", "linkedin.com", "twitter.com", "x.com", "reddit.com",
    "wikipedia.org", "yahoo.com", "bing.com", "live.com", "office.com",
    "easypaisa.com.pk", "jazzcash.com.pk", "sadapay.pk", "nayapay.com"
]

TUNNELING_AND_FREE_HOSTS = [
    "trycloudflare.com", "cloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "loca.lt", "localtunnel.me", "serveo.net", "pagekite.me", "localhost.run",
    "tunnelmole.com", "bore.pub", "pinggy.io", "github.io", "gitlab.io",
    "netlify.app", "vercel.app", "herokuapp.com", "railway.app", "onrender.com",
    "web.app", "firebaseapp.com", "000webhostapp.com", "infinityfreeapp.com",
    "byethost", "freehostia", "repl.co", "glitch.me", "pages.dev"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".icu", ".buzz", ".work", ".click", ".link", ".info", ".biz",
    ".pw", ".cc", ".ws", ".rest", ".monster", ".cyou", ".sbs", ".cfd", ".zip",
    ".mov", ".country", ".stream", ".gdn", ".loan", ".win", ".review"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "bc.vc", "j.mp", "rb.gy", "cutt.ly", "shorturl.at",
    "tiny.cc", "rebrand.ly", "bl.ink", "short.io", "v.gd", "qr.ae"
]

# ====================== HELPERS ======================

def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def calculate_entropy(text):
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def is_whitelisted(host):
    for domain in WHITELIST:
        if host == domain or host.endswith("." + domain):
            return True
    return False

def check_brand_impersonation(host):
    score = 0
    reasons = []
    fixed = (host
             .replace("1", "l").replace("0", "o").replace("3", "e")
             .replace("5", "s").replace("4", "a").replace("7", "t"))

    for brand in BRANDS:
        if brand in fixed and brand not in host:
            score += 3
            reasons.append(f"+3  Homoglyph/look-alike of: {brand}")
        elif brand in host:
            if any(w in host for w in ["secure", "login", "verify", "account", "update", "support"]):
                score += 2
                reasons.append(f"+2  Brand + suspicious word: {brand}")
    return score, reasons

# ====================== MAIN ANALYZER ======================

def analyze(url):
    score = 0
    reasons = []

    if "://" not in url:
        url_to_parse = "//" + url
    else:
        url_to_parse = url

    try:
        parts = urlparse(url_to_parse)
    except Exception:
        return 6, ["+6  Invalid / malformed URL"]

    host = parts.hostname
    if not host:
        return 5, ["+5  Could not extract hostname"]

    host = host.lower()
    full_url = url.lower()
    scheme = parts.scheme.lower() if parts.scheme else ""

    # 1. Dangerous schemes
    if scheme in ["data", "javascript", "vbscript"]:
        score += 6
        reasons.append(f"+6  Dangerous scheme: {scheme}")

    # 2. HTTP
    if scheme == "http":
        score += 2
        reasons.append("+2  Using HTTP instead of HTTPS")

    # 3. Whitelist
    if is_whitelisted(host):
        return 0, ["Domain is in whitelist (major trusted site)"]

    # 4. IP Address
    if is_ip_address(host):
        score += 4
        reasons.append("+4  Using raw IP address")

    # 5. Punycode / IDN
    if "xn--" in host:
        score += 4
        reasons.append("+4  Punycode/IDN detected (possible homograph attack)")

    # 6. Tunneling / Free hosts
    for tunnel in TUNNELING_AND_FREE_HOSTS:
        if host == tunnel or host.endswith("." + tunnel) or tunnel in host:
            score += 5
            reasons.append(f"+5  Known tunneling/free host: {tunnel}")
            break

    # 7. URL Shorteners
    for shortener in URL_SHORTENERS:
        if host == shortener or host.endswith("." + shortener):
            score += 3
            reasons.append(f"+3  URL shortener detected: {shortener}")
            break

    # 8. Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 3
            reasons.append(f"+3  Suspicious TLD: {tld}")
            break

    # 9. Non-standard port (FIXED: invalid port no longer crashes)
    try:
        port = parts.port
    except ValueError:
        port = None
        score += 2
        reasons.append("+2  Invalid port number")

    if port and port not in [80, 443, 8080, 8443]:
        score += 2
        reasons.append(f"+2  Non-standard port: {port}")

    # 10. Suspicious keywords
    found_words = set()
    for word in SUSPICIOUS_WORDS:
        if word in full_url:
            found_words.add(word)
    if found_words:
        score += min(len(found_words), 4)
        reasons.append(f"+{min(len(found_words), 4)}  Suspicious words: {', '.join(list(found_words)[:5])}")

    # 11. Brand impersonation
    brand_score, brand_reasons = check_brand_impersonation(host)
    score += brand_score
    reasons.extend(brand_reasons)

    # 12. Excessive hyphens
    if host.count("-") >= 3:
        score += 2
        reasons.append("+2  Too many hyphens in domain")

    # 13. Many digits
    digit_count = sum(c.isdigit() for c in host)
    if digit_count >= 5:
        score += 2
        reasons.append("+2  Too many digits in domain")

    # 14. High entropy
    subdomain = host.split(".")[0] if "." in host else host
    if len(subdomain) > 12:
        entropy = calculate_entropy(subdomain)
        if entropy > 3.5:
            score += 3
            reasons.append("+3  High entropy / randomly generated subdomain")

    # 15. Too many subdomains
    if host.count(".") >= 4:
        score += 2
        reasons.append("+2  Too many subdomains")

    # 16. @ symbol (FIXED: only checks the website-name part, not the whole URL)
    if "@" in parts.netloc:
        score += 4
        reasons.append("+4  Contains @ symbol (can hide real domain)")

    # 17. Very long URL
    if len(url) > 150:
        score += 1
        reasons.append("+1  Unusually long URL")

    return score, reasons


def get_verdict(score):
    if score == 0:
        return "Likely safe"
    elif score <= 3:
        return "Low risk / Mostly safe"
    elif score <= 6:
        return "Suspicious - be careful"
    elif score <= 9:
        return "Highly suspicious"
    else:
        return "Likely phishing"


# ====================== RUN ======================

if __name__ == "__main__":
    print("Phishing Detector v3")
    print("-" * 40)
    url = input("Enter a URL: ").strip()

    score, reasons = analyze(url)

    print("\n------ Analysis Result ------")
    if reasons:
        for r in reasons:
            print(r)
    else:
        print("No strong phishing signals detected.")

    print(f"\nTotal Score : {score}")
    print(f"Verdict     : {get_verdict(score)}")