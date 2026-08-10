# 🛡️ Real-Time Phishing & Suspicious Link Detector System

[![CI/CD Pipeline](https://github.com/PolaAdolf/Phishing-Detector-Backend/actions/workflows/ci.yml/badge.svg)](https://github.com/PolaAdolf/Phishing-Detector-Backend/actions)
![Python 3.10](https://img.shields.io/badge/Python-3.10-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-2.0-green.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.11+-orange.svg)
![Chrome Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-yellow.svg)
![Docker Hub](https://img.shields.io/badge/Docker_Hub-polaadolf%2Fphishing--detector--api-blue.svg)

An end-to-end, production-grade cybersecurity solution for real-time URL phishing detection. Built using a **$0-Cost Local Multi-Layer Detection Pipeline** combining a **1D-Convolutional Neural Network (1D-CNN)** deep learning model, rule-based heuristics engine, domain whitelist, and a Chrome Extension (Manifest V3).

---

## 📐 System Architecture Overview

```
                      +----------------------------------+
                      |   User Opens Link / Browses Tab  |
                      +----------------------------------+
                                       |
                                       v
                      +----------------------------------+
                      |   Chrome Extension (Manifest V3) |
                      |    (background.js / popup.js)    |
                      +----------------------------------+
                                       |
                                       v  HTTP POST /scan
                      +----------------------------------+
                      |     FastAPI Backend Service      |
                      +----------------------------------+
                                       |
       +-------------------------------+-------------------------------+
       |                               |                               |
       v                               v                               v
[ Layer 0: Whitelist ]       [ Layer 1: Heuristics ]       [ Layer 2: 1D-CNN ML ]
 Sub-5ms check for            Detects typosquatting,        Character-level NLP
 trusted banking/tech          IP hosts, suspicious          Deep Learning Model
 domains (SAFE)                TLDs (DANGER)                 (94.07% Accuracy)
```

1. **Layer 0: Whitelist & LRU Cache**: Sub-5ms validation for legitimate bank portals (NBE, NBK Egypt, CIB, Banque Misr, QNB, AlexBank, etc.) and global high-traffic domains (Google, GitHub, Microsoft).
2. **Layer 1: Rule-Based Heuristics**: Instant regex-based detection for typosquatting (`g00gle`, `paypa1`, `nbe-*-verify`), numerical IP addresses, path `@` symbols, and high-risk TLDs (`.tk`, `.xyz`, `.top`).
3. **Layer 2: 1D-CNN Deep Learning Model**: Offline Keras neural network trained on character-level URL sequences for zero-cost ($0.00 API fees) high-accuracy classification.
4. **Layer 3: Optional Threat Intel (VirusTotal)**: Optional fallback when API credentials are provided in `.env`.

---

## 🗂️ Clean Project Directory Structure

```
phishing-detector-backend/
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI/CD Pipeline (Builds & Pushes to Docker Hub)
├── data/                      # Training Datasets Directory
│   ├── phishing_site_urls.csv # Dataset 1 (500k+ URLs)
│   ├── URL dataset.csv        # Dataset 2 (300k+ URLs)
│   └── Phishing URLs.csv      # Dataset 3 (Malicious feeds)
├── models/                    # Trained Model & Tokenizer Artifacts
│   ├── phishing_model.keras   # Native Keras 1D-CNN Model
│   ├── phishing_model.h5      # Legacy Keras HDF5 Model
│   └── tokenizer.json         # Character Tokenizer JSON
├── src/                       # Backend Source Code
│   ├── __init__.py
│   ├── heuristics.py          # Rule-based pattern matching
│   ├── preprocessing.py       # Character tokenization & URL cleaning
│   ├── model.py              # 1D-CNN Model Architecture definition
│   └── train_merged.py        # Model training & dataset merging script
├── phishing-extension/        # Chrome Extension (Manifest V3)
│   ├── manifest.json          # Extension configuration
│   ├── background.js          # Navigation listener service worker
│   ├── popup.html             # Status dashboard UI layout
│   ├── popup.js               # Popup logic & API client
│   ├── warning.html           # Full-screen block alert page
│   ├── warning.js             # Standalone CSP-compliant warning script
│   └── icon.png               # Extension icon
├── app.py                     # Main FastAPI Application & Pipeline
├── Dockerfile                 # Production Container Build Instructions
├── docker-compose.yml         # Container Orchestration Specification
├── requirements.txt           # Python Dependencies
├── SKILL.md                   # Agent & Developer Skill Guide
├── .gitignore                 # Git ignore rules
└── ReadME.md                  # Comprehensive Documentation
```

---

## 🧠 1D-CNN Deep Learning Architecture Details

The model utilizes a **Character-Level 1D Convolutional Neural Network (1D-CNN)** based on recent research in neural URL analysis:

1. **Input Layer**: Fixed vector length of `150` characters (`Input(shape=(150,))`).
2. **Character Embedding Layer**: Learns dense numerical vector representations for vocabulary characters (`Embedding(vocab_size, 32)`).
3. **1D Convolution Layer**: Extracts local character n-gram spatial features (`Conv1D(filters=64, kernel_size=5, activation='relu')`).
4. **Global Max Pooling**: Extracts dominant salient features across the sequence (`GlobalMaxPooling1D()`).
5. **Dense & Dropout Layers**: Fully-connected decision layers with dropout to prevent overfitting (`Dense(64, relu)` -> `Dropout(0.3)`).
6. **Output Layer**: Sigmoid activation outputting probability score from `0.0` (Safe) to `1.0` (Malicious) (`Dense(1, sigmoid)`).

### Model Training Performance Metrics
- **Accuracy**: **94.07%**
- **Recall**: **91.68%**
- **Precision**: **90.46%**
- **F1-Score**: **91.07%**

---

## 🚀 Step-by-Step Installation & Running Guide

### 1. Prerequisites
- Python 3.10 or higher
- Git
- Docker & Docker Compose (Optional for containerized deployment)

### 2. Local Environment Setup

```bash
# Clone the repository
git clone https://github.com/PolaAdolf/Phishing-Detector-Backend.git
cd Phishing-Detector-Backend

# Create and activate virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Model Training Pipeline

To train or re-train the 1D-CNN model on the datasets inside `data/`:

```bash
python src/train_merged.py
```

### 4. Running the FastAPI Server

```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive Swagger API Docs**: `http://127.0.0.1:8000/docs`
- **Health Check Endpoint**: `http://127.0.0.1:8000/health`

---

## 🐳 Docker Hub & CI/CD Automated Build Pipeline

We have automated Docker Hub publishing so that **whenever you push code to GitHub (`git push origin main`), GitHub Actions automatically builds and pushes the updated Docker image to Docker Hub**!

```
 Developers Push Code ──> GitHub Actions CI Pipeline ──> Auto-Build & Push ──> Docker Hub Image
 (git push origin main)    (.github/workflows/ci.yml)                          polaadolf/phishing-detector-api:latest
```

### How to Enable Docker Hub Auto-Push in GitHub:

1. Log into your **GitHub Repository** -> **Settings** -> **Secrets and variables** -> **Actions**.
2. Click **New repository secret** and add:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username (e.g. `polaadolf`)
   - `DOCKERHUB_TOKEN`: Your Docker Hub Personal Access Token (created at `hub.docker.com` -> Account Settings -> Security)

Now, whenever you push code changes to `main`, GitHub Actions automatically updates your image on Docker Hub!

### Running Docker Image from Docker Hub:

```bash
# Pull and start latest image from Docker Hub
docker-compose pull
docker-compose up -d
```

---

## 📝 GitHub Readiness Checklist

- [x] All dataset files organized under `data/`
- [x] Pre-trained model & tokenizer artifacts present under `models/`
- [x] Clean `.gitignore` excluding bytecode, virtualenvs, and secrets
- [x] GitHub Actions CI/CD workflow configured under `.github/workflows/ci.yml` (With Docker Hub auto-push)
- [x] Dockerfile and Docker Compose ready for production deployment
- [x] Comprehensive documentation in README.md
