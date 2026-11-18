# PhishShield Pro: AI-Powered Phishing URL Detection System

A state-of-the-art cybersecurity and machine learning application for real-time URL vulnerability scanning, phishing detection, and deep heuristic inspection. Built directly on the benchmark UCI Phishing Websites dataset (11,055 records) and inspired by the core research pipeline of [vaibhavbichave/Phishing-URL-Detection](https://github.com/vaibhavbichave/Phishing-URL-Detection).

---

## 🌟 Key Features

1. **Exact 30-Attribute Feature Extraction Pipeline**:
   - Matches standard UCI Phishing Websites dataset encoding (`1`: Legitimate, `0`: Suspicious, `-1`: Phishing).
   - Extracts address-bar metrics, SSL/security attributes, DOM content & hyperlink statistics, and behavioral scripts.
   - Built-in graceful offline fallbacks and socket timeout protections.

2. **High-Accuracy Ensemble Models**:
   - Evaluated across 5 competitive machine learning algorithms.
   - **Primary Engine:** Gradient Boosting Classifier achieving **97.01% test accuracy** and **97.34% F1-score**.
   - Comparison benchmarks with Random Forest, Decision Tree, Logistic Regression, and Multi-Layer Perceptron (MLP).

3. **Ultra-Modern Cyberpunk Dashboard UI**:
   - Glassmorphic dark UI built with Inter & JetBrains Mono typography.
   - Real-time safety gauge, phishing risk metric, and categorized 30-feature inspection table.
   - Live feature importance breakdown displaying Gini-importance weights.

4. **Developer-Ready REST API**:
   - `POST /api/analyze`: JSON endpoint for automated URL vulnerability scanning.
   - `GET /api/models`: Model benchmark comparisons and performance metrics.

---

## 🚀 Quick Start Guide

### 1. Requirements
Ensure Python 3.10+ is installed along with the required libraries:
```bash
pip install flask scikit-learn pandas numpy beautifulsoup4 python-whois requests
```

### 2. Retraining the Models (Optional)
The pre-trained models are already provided in the `pickle/` directory. To retrain from `phishing.csv`:
```bash
python train_model.py
```

### 3. Running the Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📊 Model Benchmark Results

| Model Algorithm | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Gradient Boosting Classifier** | **97.01%** | **97.04%** | **97.64%** | **97.34%** | **Production Engine** |
| Multi-Layer Perceptron (MLP) | 97.11% | 97.40% | 97.47% | 97.43% | Alternative |
| Random Forest Classifier | 96.79% | 96.96% | 97.32% | 97.15% | Evaluated |
| Decision Tree Classifier | 95.34% | 95.38% | 96.22% | 95.79% | Evaluated |
| Logistic Regression | 93.89% | 94.13% | 94.97% | 94.55% | Baseline |

---

## 📂 Project Structure

```
phishing_detection_pro/
├── app.py                  # Flask web server & REST API
├── feature.py              # 30-Vector heuristic feature extraction engine
├── train_model.py          # Machine learning training & benchmark pipeline
├── phishing.csv            # Original UCI benchmark dataset (11,054 rows)
├── requirements.txt        # Python dependency manifest
├── README.md               # Quickstart and overview
├── SRS_SYNOPSIS.md         # Full IEEE-830 Software Requirements & Project Synopsis
├── pickle/
│   ├── model.pkl           # Serialized Gradient Boosting Classifier
│   └── meta.pkl            # Benchmark metrics, feature weights & metadata
├── static/
│   └── css/
│       └── style.css       # Enterprise cyberpunk glassmorphism stylesheet
└── templates/
    └── index.html          # High-performance dashboard template
```
