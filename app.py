from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from utils import extract_features
from risk_engine import (
    calculate_url_risk,
    calculate_domain_risk,
    calculate_page_risk,
    calculate_final_risk
)
import os
import csv
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

model = joblib.load("models/model.pkl")

known_domains = [
    "google.com", "amazon.com", "facebook.com", "paypal.com",
    "netflix.com", "microsoft.com", "apple.com", "github.com",
    "linkedin.com", "twitter.com", "wikipedia.org", "openai.com"
]

def get_risk_level(score):
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"

def detect_context(url):
    url = url.lower()

    if any(word in url for word in ["bank", "paypal", "account", "payment"]):
        return "Financial"
    elif any(word in url for word in ["login", "password", "verify"]):
        return "Authentication"
    else:
        return "General"

def zero_day_check(url):
    url = url.lower()
    return not any(domain in url for domain in known_domains)

def explain(url):
    url = url.lower()
    reasons = []

    if len(url) > 25:
        reasons.append("URL is unusually long")

    if "-" in url:
        reasons.append("URL contains suspicious hyphens")

    if any(word in url for word in ["login", "verify", "secure", "account", "bank", "update"]):
        reasons.append("URL contains phishing-related keywords")

    if url.count(".") > 3:
        reasons.append("URL contains too many subdomains")

    if zero_day_check(url):
        reasons.append("Domain is not in known trusted domains list")

    if not reasons:
        reasons.append("No strong suspicious indicators found")

    return reasons

@app.route("/")
def home():
    return "Phishing Detection Backend is Running"

def get_domain(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def is_trusted_domain(url):
    domain = get_domain(url)

    for trusted in known_domains:
        if domain == trusted or domain.endswith("." + trusted):
            return True

    return False

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    url = data.get("url", "")

    page_analysis = data.get(
        "page_analysis",
        {}
    )

    features = extract_features(url)

    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]

    url_risk, url_reasons = calculate_url_risk(url)

    domain = get_domain(url)

    domain_risk, is_unknown_domain, domain_reasons = (
     calculate_domain_risk(
            domain,
            known_domains
        )
    )

    page_risk, page_reasons = calculate_page_risk(
        page_analysis
    )

    risk_score, risk_breakdown = calculate_final_risk(
        probability,
        url_risk,
        domain_risk,
        page_risk
    )

# Trusted domains receive a strong safety adjustment
    if is_trusted_domain(url):
     risk_score = min(risk_score, 5)

# Final prediction
    prediction = 1 if risk_score >= 60 else 0

    result = {
        "url": url,
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "context": detect_context(url),
        "zero_day": is_unknown_domain,
        "risk_breakdown": risk_breakdown,
        "reasons": (
            url_reasons
            + domain_reasons
            + page_reasons
        )
    }

    LOG_FILE = "phishing_history.csv"

    file_exists = os.path.isfile(LOG_FILE)

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(["url", "risk_score", "status", "time"])

        status = (
            "HIGH RISK" if risk_score >= 70
            else "SUSPICIOUS" if risk_score >= 30
            else "SAFE"
        )

        writer.writerow([
            url,
            risk_score,
            status,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ])

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)