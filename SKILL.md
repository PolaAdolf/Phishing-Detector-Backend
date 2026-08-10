---
name: phishing-detector-development
description: Complete guide and skills specification for building, training, and productionizing the Phishing & Suspicious Link Detector system (FastAPI backend, 1D-CNN deep learning model, Chrome Extension Manifest V3, and VirusTotal threat intelligence).
---

# Phishing Detector Project Skill Guide

This skill provides comprehensive instructions for maintaining, testing, and productionizing the **Real-Time Phishing & Suspicious Link Detector System**.

---

## 1. System Architecture Overview

The system operates as a **Multi-Layered Detection Engine**:
1. **Whitelist & Caching Layer**: Immediately validates known legitimate domains (e.g., Google, GitHub, Microsoft) and checks fast in-memory/Redis LRU caches.
2. **Rule-Based Heuristic Engine**: Detects typosquatting, suspicious characters, double slashes `@`, numerical IP hosts, and malicious TLD patterns via regular expressions.
3. **Threat Intelligence Feed**: Queries external APIs (e.g., VirusTotal URL Scanner API v3) when available to leverage global threat detection engines.
4. **Deep Learning Model (1D-CNN)**: Evaluates URL string patterns at the character level (Character-Level Tokenization + Embedding + 1D Convolution + Global Max Pooling + Dense layers with Sigmoid output).

---

## 2. Key Required Skills & Technologies

### Backend & API Engineering
- **Framework**: FastAPI (Python)
- **Server**: Uvicorn (`uvicorn app:app --reload` for dev, multi-worker setup for production)
- **Features**: CORS middleware (`CORSMiddleware`), request validation (`Pydantic BaseModel`), async HTTP clients (`httpx` / `requests`), environment variable management (`python-dotenv`).

### Machine Learning & NLP
- **Framework**: TensorFlow / Keras, Scikit-Learn, Pandas, NumPy
- **Architecture**: 1D-CNN Model (`Input(shape=(150,))` -> `Embedding` -> `Conv1D(64, 5)` -> `GlobalMaxPooling1D` -> `Dense(64)` -> `Dropout(0.3)` -> `Dense(1, sigmoid)`)
- **Preprocessing**: Character-level tokenization (`Tokenizer(char_level=True)`), URL normalization/cleaning, sequence padding (`pad_sequences`).
- **Persistence**: Saving and loading model artifacts (`models/phishing_model.keras` or `.h5` and `models/tokenizer.json`).

### Browser Extension Development
- **Manifest**: Chrome Extension Manifest V3 (`manifest_version: 3`)
- **Background Engine**: Service Worker (`background.js`) monitoring `chrome.tabs.onUpdated` navigation events, updating extension badges (`setBadgeText`), and creating Chrome system notifications.
- **User Interface**: `popup.html` + `popup.js` (Interactive UI showing risk score, status, reason breakdown, and manual scan options).
- **Security Actions**: `warning.html` for intercepting and blocking dangerous phishing links automatically.

### Productionization & DevOps
- **Containerization**: `Dockerfile` and `docker-compose.yml` for backend service deployment.
- **Caching**: LRU / Redis cache to prevent redundant API calls and lower inference latency (< 20ms).
- **Environment**: Configuration via `.env` for secrets like `VIRUSTOTAL_API_KEY`.

---

## 3. Standard Verification Commands

- **Run FastAPI Backend**:
  ```bash
  uvicorn app:app --reload --port 8000
  ```
- **Train Model**:
  ```bash
  python src/train_merged.py
  ```
- **Test Endpoint**:
  ```bash
  curl -X POST "http://127.0.0.1:8000/scan" -H "Content-Type: application/json" -d "{\"url\": \"http://g00gle-security-login.top\"}"
  ```
