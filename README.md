# Phishing Guardian Backend

FastAPI backend for phishing URL detection using a hybrid approach:
- **ML score** from a trained Random Forest model
- **Rule score** from modular forensic analyzers (impersonation, Unicode, TLD, IP, entropy, and more)

The API exposes a single scoring endpoint (`POST /check-url`) and returns risk level, confidence details, findings, and user guidance.

## Table of Contents

- [Project Overview](#project-overview)
- [Directory Structure](#directory-structure)
- [How Risk Scoring Works](#how-risk-scoring-works)
- [API Endpoints](#api-endpoints)
- [Local Setup](#local-setup)
- [Model Training](#model-training)
- [Response Example](#response-example)
- [Operational Notes](#operational-notes)
- [Known Gaps](#known-gaps)

## Project Overview

### Core Flow

1. `app/main.py` receives API request.
2. `app/detector.py` loads model and orchestrates prediction.
3. `app/risk_engine.py` combines:
   - ML probability from `ml_model/features.py` + trained model
   - Rule findings from `engine/orchestrator.py`
   - Breakdown safety scores from `engine/breakdown_analysis.py`
4. `app/explanation_builder.py` generates user-facing explanation text.

### Tech Stack

- Python
- FastAPI + Uvicorn
- scikit-learn + joblib
- pandas + numpy
- heuristic detection modules in `engine/`

## Directory Structure

```text
backend/
├─ app/
│  ├─ main.py                 # FastAPI app and routes
│  ├─ detector.py             # Inference orchestration
│  ├─ risk_engine.py          # Hybrid risk computation
│  ├─ explanation_builder.py  # Human-readable explanation
│  ├─ brand_loader.py         # Loads trusted brand list
│  └─ models.py               # Pydantic request/response models
├─ engine/
│  ├─ orchestrator.py         # Runs all detection modules
│  ├─ breakdown_analysis.py   # Safety sub-scores (SSL, WHOIS, redirects...)
│  ├─ impersonation.py
│  ├─ character_substitution.py
│  ├─ homoglyph_analysis.py
│  ├─ unicode_analysis.py
│  ├─ tld_analysis.py
│  ├─ subdomain_analysis.py
│  ├─ ip_analysis.py
│  ├─ pattern_analysis.py
│  ├─ linguistic_analysis.py
│  ├─ entropy_analysis.py
│  ├─ dga_detection.py
│  ├─ normalization.py
│  └─ parser.py
├─ ml_model/
│  ├─ features.py             # URL feature extraction for ML
│  ├─ train.py                # Model training pipeline
│  └─ data/                   # Training CSV datasets (expected)
├─ requirements.txt
└─ README.md
```

## How Risk Scoring Works

`app/risk_engine.py` computes:

- `ml_score = model.predict_proba(features) * 100`
- `rule_score = 100 - average(breakdown_safety_scores)`
- `final_score = 0.6 * ml_score + 0.4 * rule_score`

Risk bands:
- `>= 80`: **High**
- `>= 60`: **Medium**
- `>= 30`: **Low**
- `< 30`: **Safe**

### Breakdown Dimensions

`engine/breakdown_analysis.py` returns:
- `domain_structure`
- `ssl_certificate`
- `ip_reputation`
- `phishing_keywords`
- `redirect_chains`
- `domain_age`

## API Endpoints

### `GET /`

Basic API status message.

### `GET /health`

Returns service health payload and version.

### `POST /check-url`

Analyze a URL for phishing risk.

Request body:

```json
{
  "url": "https://example.com/login"
}
```

## Local Setup

### 1) Create and activate virtual environment

Windows (PowerShell):

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

Install base dependencies:

```bash
pip install -r requirements.txt
```

The current code imports additional packages that may not be pinned in `requirements.txt`. If needed, install:

```bash
pip install requests python-whois tldextract python-Levenshtein datasets
```

### 3) Ensure model artifact exists

At runtime, `app/detector.py` loads:

```text
backend/ml_model/phishing_model.pkl
```

If missing, train it first (see [Model Training](#model-training)).

### 4) Run API

From `backend/`:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Swagger docs:
- `http://127.0.0.1:8000/docs`

## Model Training

`ml_model/train.py`:
- loads phishing URLs from local CSV files under `ml_model/data/`
- loads legitimate URLs from local CSV
- streams additional phishing URLs from Hugging Face (`phreshphish/phreshphish`)
- extracts handcrafted URL features
- trains `RandomForestClassifier`
- saves model to `ml_model/phishing_model.pkl`

Run from `backend/`:

```bash
python ml_model/train.py
```

## Response Example

Example response from `POST /check-url`:

```json
{
  "url": "https://secure-paypa1.com/login",
  "is_safe": false,
  "risk_level": "High",
  "risk_score": 92.5,
  "ml_probability": 0.94,
  "rule_score": 88.0,
  "summary": "This website shows clear signs of impersonation or potential phishing...",
  "findings": [
    {
      "category": "character_substitution",
      "severity": "high",
      "attack_type": "lookalike_domain"
    }
  ],
  "guidance": "This website shows signs of impersonation or deception. Avoid entering passwords or personal information.",
  "breakdown": {
    "domain_structure": 22,
    "ssl_certificate": 100,
    "ip_reputation": 100,
    "phishing_keywords": 45,
    "redirect_chains": 60,
    "domain_age": 10
  }
}
```

## Operational Notes

- CORS is currently open to all origins (`allow_origins=["*"]`).
- No authentication/authorization is enforced by the API.
- Some scoring logic performs network calls (WHOIS, SSL socket checks, redirects), so latency and reliability depend on external services.
- Inference can fail at startup if `ml_model/phishing_model.pkl` is missing.

## Known Gaps

- No backend test suite is currently defined.
- `app/models.py` contains nested `URLCheckResponse` model definition and is not used as a FastAPI `response_model`.
- Dependency list may need synchronization with actual imports.

