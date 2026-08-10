import os
import re
import base64
import urllib.parse
import logging
import requests
import numpy as np
import tensorflow as tf
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from src.preprocessing import clean_url, URLPreprocessor
from src.heuristics import check_heuristics

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(
    title="Real-Time Phishing & Suspicious Link Detector API",
    description="Multi-Layered Detection Engine: Whitelist -> Heuristics -> Threat Intel (VirusTotal) -> 1D-CNN Deep Learning Model",
    version="2.0.0"
)

# Enable CORS for Chrome Extension & Web Dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Read VirusTotal API Key from .env
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# Paths to ML Artifacts
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KERAS_MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.keras")
H5_MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.h5")
TOKENIZER_PATH = os.path.join(BASE_DIR, "models", "tokenizer.json")

model = None
preprocessor = None

def load_ml_artifacts():
    global model, preprocessor
    model_file = None
    if os.path.exists(KERAS_MODEL_PATH):
        model_file = KERAS_MODEL_PATH
    elif os.path.exists(H5_MODEL_PATH):
        model_file = H5_MODEL_PATH

    if model_file and os.path.exists(TOKENIZER_PATH):
        try:
            logging.info(f"Loading Keras model from {model_file}...")
            model = tf.keras.models.load_model(model_file)
            preprocessor = URLPreprocessor(max_len=150)
            preprocessor.load_tokenizer(TOKENIZER_PATH)
            logging.info("ML Model & Tokenizer loaded successfully!")
        except Exception as e:
            logging.error(f"Error loading ML model artifacts: {e}")
    else:
        logging.warning("Model or Tokenizer files missing! Please run 'python src/train_merged.py' first.")

load_ml_artifacts()

# In-memory cache to prevent redundant API/ML processing
url_cache = {}

# Whitelist of trusted high-traffic legitimate domains and major banking portals
WHITELIST = [
    # Search engines, tech & social
    "google.com", "github.com", "facebook.com", "youtube.com", "linkedin.com",
    "microsoft.com", "wikipedia.org", "amazon.com", "apple.com", "twitter.com", "instagram.com",
    # Egyptian & Regional Banking Portals
    "nbk.com", "nbk.com.eg",              # National Bank of Kuwait
    "nbe.com.eg", "nbeonline.com.eg", "ahlynet.nbe.com.eg", # National Bank of Egypt
    "cibeg.com",                           # Commercial International Bank
    "banquemisr.com",                      # Banque Misr
    "qnb.com", "qnbalahli.com",            # QNB Alahli
    "alexbank.com",                        # Bank of Alexandria
    "saib.com.eg",                         # SAIB Bank
    "faib.com.eg",                         # Faisal Islamic Bank
    "bdc.com.eg",                          # Banque du Caire
    "adib.eg", "adib.com",                 # Abu Dhabi Islamic Bank
    "hsbc.com.eg", "hsbc.com",             # HSBC Bank
    "emiratesnbd.com.eg",                  # Emirates NBD
    "ca-egypt.com"                         # Credit Agricole Egypt
]

class URLRequest(BaseModel):
    url: str

def query_virustotal(url: str) -> dict | None:
    """Queries VirusTotal API v3 for threat analysis."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY in ["your_api_key_here", ""]:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(endpoint, headers=headers, timeout=4)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + harmless + stats.get("undetected", 0)
            
            # Require at least 2 security engines or (1 malicious + 1 suspicious) to avoid single-vendor false positives on real bank sites
            if malicious >= 2 or (malicious >= 1 and suspicious >= 1):
                score = min(100.0, round(((malicious * 1.0 + suspicious * 0.5) / max(1, total)) * 100, 2))
                return {
                    "is_phishing": True,
                    "risk_score": max(85.0, score),
                    "status": "DANGER",
                    "reason": f"VirusTotal Threat Intel: {malicious} engine(s) flagged URL as malicious"
                }
            elif harmless > 0 or malicious <= 1:
                return {
                    "is_phishing": False,
                    "risk_score": 0.0,
                    "status": "SAFE",
                    "reason": f"VirusTotal Threat Intel: Verified clean ({harmless} harmless engines, 1 single vendor alert ignored)" if malicious == 1 else "VirusTotal Threat Intel: Verified clean across security engines"
                }
    except Exception as e:
        logging.warning(f"VirusTotal API query failed/timed out: {e}")
    return None

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "model_loaded": model is not None,
        "virustotal_enabled": bool(VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "your_api_key_here")
    }

@app.post("/scan")
def scan_url(request: URLRequest):
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL string cannot be empty.")

    # Check In-Memory Cache
    if raw_url in url_cache:
        return url_cache[raw_url]

    # Layer 0: Whitelist Check
    try:
        parsed_url = raw_url if raw_url.startswith(('http://', 'https://')) else 'http://' + raw_url
        domain = urllib.parse.urlparse(parsed_url).netloc.lower().replace('www.', '')
        if any(domain == w or domain.endswith('.' + w) for w in WHITELIST):
            result = {
                "url": raw_url,
                "cleaned_url": domain,
                "is_phishing": False,
                "risk_score": 0.0,
                "status": "SAFE",
                "reason": "Whitelisted Legitimate Domain"
            }
            url_cache[raw_url] = result
            return result
    except Exception as e:
        logging.warning(f"Domain parsing warning: {e}")

    cleaned = clean_url(raw_url)

    # Layer 1: Rule-Based Heuristic Check
    is_suspicious, heuristic_reason = check_heuristics(raw_url)
    if is_suspicious:
        result = {
            "url": raw_url,
            "cleaned_url": cleaned,
            "is_phishing": True,
            "risk_score": 85.0,
            "status": "DANGER",
            "reason": heuristic_reason
        }
        url_cache[raw_url] = result
        return result

    # Layer 2: VirusTotal API Check
    vt_result = query_virustotal(raw_url)
    if vt_result:
        result = {
            "url": raw_url,
            "cleaned_url": cleaned,
            "is_phishing": vt_result["is_phishing"],
            "risk_score": vt_result["risk_score"],
            "status": vt_result["status"],
            "reason": vt_result["reason"]
        }
        url_cache[raw_url] = result
        return result

    # Layer 3: 1D-CNN Deep Learning Model Prediction
    if model is not None and preprocessor is not None:
        try:
            padded_input = preprocessor.transform([cleaned])
            score = float(model.predict(padded_input, verbose=0)[0][0])
            risk_score = round(score * 100, 2)
            is_phishing = score > 0.70

            status = "DANGER" if is_phishing else "SAFE"
            reason = f"1D-CNN Deep Learning Model ({risk_score}% risk probability)"

            result = {
                "url": raw_url,
                "cleaned_url": cleaned,
                "is_phishing": is_phishing,
                "risk_score": risk_score,
                "status": status,
                "reason": reason
            }
            url_cache[raw_url] = result
            return result
        except Exception as e:
            logging.error(f"1D-CNN inference error: {e}")

    # Fallback response if no model loaded
    result = {
        "url": raw_url,
        "cleaned_url": cleaned,
        "is_phishing": False,
        "risk_score": 10.0,
        "status": "SAFE",
        "reason": "Passed Heuristic & Whitelist Checks (ML model offline)"
    }
    url_cache[raw_url] = result
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)