from flask import Flask, render_template, request
import joblib
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
import whois
import httpx
from pycaret.classification import predict_model

# ==============================
# FLASK APP
# ==============================
app = Flask(__name__)

# ==============================
# LOAD ML MODEL
# ==============================
MODEL_PATH = "/home/azure/phishing_detector/model/model.pkl"
model = joblib.load(MODEL_PATH)
print("✅ ML model loaded successfully")

# ==============================
# HELPER: Score to 1–10 scale
# ==============================
def score_to_scale(score):
    if score >= 90: return 10
    if score >= 80: return 9
    if score >= 70: return 8
    if score >= 60: return 7
    if score >= 50: return 6
    if score >= 40: return 5
    if score >= 30: return 4
    if score >= 20: return 3
    if score >= 10: return 2
    return 1

# ==============================
# RULE-BASED PENALTY
# ==============================
def rule_based_penalty(url, meta):
    penalty = 0
    rule_hits = {"ip": False, "https": False, "tld": False, "whois": False}

    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        penalty += 35
        rule_hits["ip"] = True

    if not url.startswith("https://"):
        penalty += 25
        rule_hits["https"] = True

    if meta["tld"] in ["tk", "ml", "ga", "cf", "gq", "dev"]:
        penalty += 15
        rule_hits["tld"] = True

    if not meta["whois_ok"]:
        penalty += 20
        rule_hits["whois"] = True

    return penalty, rule_hits

# ==============================
# FEATURE EXTRACTION
# ==============================
def extract_url_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    try:
        w = whois.whois(ext.domain)
        whois_ok = bool(w.creation_date)
    except Exception:
        whois_ok = False

    features = {
        "domain_att": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "URL_Length": len(url),
        "URL_Depth": len([p for p in parsed.path.split("/") if p]),
        "No_Of_Dots": url.count("."),
        "Domain_Age": 0 if whois_ok else 1,
        "Domain_End": 1 if ext.suffix in ["com", "org", "in", "net", "edu", "gov"] else 0,
        "Prefix/Suffix": 1 if "-" in ext.domain else 0,
        "TinyURL": 1 if any(x in url.lower() for x in ["bit.ly", "tinyurl", "goo.gl"]) else 0,
        "Sensitive_Words": 1 if any(x in url.lower() for x in ["login", "bank", "verify"]) else 0,
        "Have_Symbol": 1 if any(x in url for x in ["@", "=", "%"]) else 0,
    }

    meta = {
        "domain": ext.domain.lower(),
        "tld": ext.suffix.lower(),
        "whois_ok": whois_ok
    }

    return features, meta

# ==============================
# EXPLAINABILITY
# ==============================
def get_explainability(features, meta, url):
    reasons = []

    if features["domain_att"]:
        reasons.append("Uses IP address instead of domain")

    if not meta["whois_ok"]:
        reasons.append("WHOIS information missing")

    if features["TinyURL"]:
        reasons.append("Uses URL shortener")

    if features["Sensitive_Words"]:
        reasons.append("Contains sensitive keywords")

    if features["Prefix/Suffix"]:
        reasons.append("Hyphen found in domain name")

    if url.startswith("http://"):
        reasons.append("Does not use HTTPS")

    return reasons

# ==============================
# HOME
# ==============================
@app.route("/")
def index():
    return render_template("index.html", is_phish=None)

# ==============================
# URL SCAN
# ==============================
@app.route("/check", methods=["POST"])
def check():
    try:
        url = request.form.get("url", "").strip()
        features, meta = extract_url_features(url)
        df = pd.DataFrame([features])

        result = predict_model(model, data=df)
        ml_score = float(result.iloc[0]["prediction_score"]) * 100

        penalty, rule_hits = rule_based_penalty(url, meta)
        final_score = max(0, ml_score - penalty)

        return render_template(
            "index.html",
            is_phish=final_score < 70,
            prob=round(final_score, 2),
            reasons=get_explainability(features, meta, url),
            risk_score_10=score_to_scale(final_score),
            rule_hits=rule_hits
        )

    except Exception as e:
        print("❌ Scan Error:", e)
        return render_template("index.html", is_phish=True)

# ==============================
# COOKIE ANALYSIS (FIXED)
# ==============================
def analyze_cookies(cookies):
    if not cookies or len(cookies) == 0:
        return {
            "risk": 0,
            "cookies": [],
            "message": "No cookies were set by this website."
        }

    suspicious_words = ["session", "auth", "login", "track", "ads"]
    risk_points = 0
    details = []

    for c in cookies:
        name = c.name.lower()
        secure = c.secure
        httponly = getattr(c, "httponly", False)

        status = "Safe"
        if any(w in name for w in suspicious_words):
            status = "Suspicious"
            risk_points += 1

        if not secure:
            risk_points += 1

        details.append({
            "name": c.name,
            "domain": c.domain,
            "secure": secure,
            "httponly": httponly,
            "status": status
        })

    risk_score = min(round((risk_points / (len(details) * 2)) * 10), 10)

    return {
        "risk": risk_score,
        "cookies": details,
        "message": "Cookies analyzed successfully."
    }

# ==============================
# COOKIE ROUTE
# ==============================
@app.route("/cookies", methods=["GET", "POST"])
def cookies():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        try:
            resp = httpx.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                follow_redirects=True,
                timeout=10
            )

            result = analyze_cookies(resp.cookies.jar)

        except Exception as e:
            result = {
                "risk": 0,
                "cookies": [],
                "message": "Cookies could not be accessed (site blocked automated requests)."
            }

    return render_template("cookies.html", result=result)

# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
