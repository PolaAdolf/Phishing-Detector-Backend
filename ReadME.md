# 🛡️ Real-Time Phishing & Suspicious Link Detector System

[![CI/CD Pipeline](https://github.com/your-username/phishing-detector-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/phishing-detector-backend/actions)
![Python 3.10](https://img.shields.io/badge/Python-3.10-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-2.0-green.svg)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.11+-orange.svg)
![Chrome Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-yellow.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)

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
│       └── ci.yml             # GitHub Actions CI/CD Pipeline
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
git clone https://github.com/your-username/phishing-detector-backend.git
cd phishing-detector-backend

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
*This loads all datasets from `data/`, cleans URLs, trains the 1D-CNN model, and outputs saved artifacts to `models/`.*

### 4. Running the FastAPI Server

```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive Swagger API Docs**: `http://127.0.0.1:8000/docs`
- **Health Check Endpoint**: `http://127.0.0.1:8000/health`

---

## 🔌 API Reference & Usage

### `POST /scan`
Scans a target URL and returns detailed threat analysis.

**Request Body**:
```json
{
  "url": "http://g00gle-security-login.top"
}
```

**Response Payload**:
```json
{
  "url": "http://g00gle-security-login.top",
  "cleaned_url": "g00gle-security-login.top",
  "is_phishing": true,
  "risk_score": 85.0,
  "status": "DANGER",
  "reason": "Heuristic Rule: Suspicious pattern match (g[0o]{2}gle)"
}
```

---

## 🧩 Chrome Extension (Manifest V3) Setup

1. Open Google Chrome and enter `chrome://extensions/` in the address bar.
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked** and choose the `phishing-extension/` directory.
4. Browse any website! If a phishing link is accessed, the extension will automatically intercept it, change the badge status to `!`, trigger a notification, and show the safety `warning.html` block page.

---

## 🐳 Deep-Dive into Docker & Production Deployment

### 1. What is Docker Used For in This Project?
Docker packages the entire FastAPI backend, Python 3.10 runtime, TensorFlow libraries, source code (`src/`), and pre-trained 1D-CNN model (`models/`) into an isolated **container**.

**Why use Docker?**
- **Eliminates "It works on my machine" issues**: Ensures the API runs identically on Windows, Linux servers, macOS, AWS, DigitalOcean, or Azure.
- **Dependency Isolation**: Prevents conflicts with system-installed Python packages.
- **Portability**: Allows one-command server deployment without manually setting up virtual environments or installing C++ compilers.

---

### 2. Does Updating Code in Git Automatically Update Docker?

**Short Answer**: A running Docker container uses a **snapshot image** created at build time. When you `git push` new code, the container does **NOT** update automatically by itself.

**How to sync Docker with Git updates**:

#### Option A: Manual 1-Line Command on Your Production Server
Whenever you pull new code from Git on your server, run:
```bash
git pull
docker-compose up --build -d
```
> The `--build` flag forces Docker to rebuild the image with your latest Git code and restart the container with zero downtime!

#### Option B: Automated Continuous Deployment (CD)
In a cloud deployment setup:
1. GitHub Actions (`ci.yml`) builds a new Docker image on every `git push`.
2. A deployment webhook triggers your cloud server (e.g. AWS EC2 or DigitalOcean) to pull the new image and run `docker-compose up -d`.

---

### 3. Step-by-Step Production Deployment Guide

When you are ready to deploy this system live for production:

#### Step 1: Provision a Cloud Server
Rent a Linux VPS (e.g., AWS EC2, DigitalOcean Droplet, Hetzner, or Render) with Ubuntu 22.04.

#### Step 2: Install Docker on the Server
```bash
sudo apt update && sudo apt install -y docker.io docker-compose
```

#### Step 3: Clone Repository & Run Docker Container
```bash
git clone https://github.com/PolaAdolf/Phishing-Detector-Backend.git
cd Phishing-Detector-Backend

# Start the API service in background
docker-compose up --build -d
```

#### Step 4: Update Chrome Extension Production URL
In `phishing-extension/background.js` and `phishing-extension/popup.js`, change:
```javascript
// Local Development:
const BACKEND_URL = 'http://127.0.0.1:8000/scan';

// Production Live Server:
const BACKEND_URL = 'https://api.your-domain.com/scan';
```

---

## 🔄 CI/CD Process Explanation (Continuous Integration & Continuous Deployment)

This project includes an automated **GitHub Actions CI/CD Pipeline** defined in `.github/workflows/ci.yml`.

### How the CI/CD Pipeline Works:

```
 Push / Pull Request ──> GitHub Actions Trigger
                              │
                              ├──> 1. Environment Setup (Python 3.10)
                              ├──> 2. Install Dependencies (requirements.txt)
                              ├──> 3. Verify Code Integrity & Imports
                              └──> 4. Build Docker Container Image
```

1. **Trigger**: Executes automatically on every `push` or `pull_request` to `main` / `master` branches.
2. **Setup Phase**: Provisions a clean Ubuntu container with Python 3.10 environment.
3. **Dependency Installation**: Upgrades `pip` and installs all project packages.
4. **Automated Verification**: Verifies application module imports, route registrations, and integrity.
5. **Docker Build Check**: Builds the production Docker image to ensure deployment readiness before code merging.

---

## 📝 GitHub Readiness Checklist

- [x] All dataset files organized under `data/`
- [x] Pre-trained model & tokenizer artifacts present under `models/`
- [x] Clean `.gitignore` excluding bytecode, virtualenvs, and secrets
- [x] GitHub Actions CI/CD workflow configured under `.github/workflows/ci.yml`
- [x] Dockerfile and Docker Compose ready for production deployment
- [x] Comprehensive documentation in README.md
