# SOFTWARE REQUIREMENTS SPECIFICATION (SRS) & PROJECT SYNOPSIS
## PhishShield Pro: AI-Powered Phishing URL Detection System

---

## 1. PROJECT SYNOPSIS

### 1.1 Project Title
**PhishShield Pro: Real-Time Machine Learning Architecture for Phishing URL Detection and Heuristic Vulnerability Inspection**

### 1.2 Executive Summary
Phishing remains one of the predominant social engineering attack vectors utilized by malicious actors globally to harvest confidential credentials, personal identifiable information (PII), and financial data. Conventional security mechanisms such as static URL blacklists fail to counteract zero-hour phishing campaigns where novel domain variants and obfuscated uniform resource locators (URLs) are generated dynamically.

This project delivers an enterprise-grade, high-performance web security platform that automates the real-time classification of web links into **Legitimate (`+1`)** or **Phishing (`-1`)** categories. Built on the benchmark 11,055-sample UCI Phishing Websites dataset (derived from PhishTank and MillerSmiles archives), the system implements an exact 30-feature heuristic vector extractor and leverages an optimized **Gradient Boosting Classifier (GBC)** yielding **97.01% classification accuracy** and an **F1-score of 97.34%**. The application features an ultra-responsive, cyberpunk glassmorphic web dashboard and a developer-accessible REST API.

### 1.3 Problem Statement
Traditional rule-based anti-phishing engines suffer from:
1. High latency in discovering and blacklisting zero-day malicious domains.
2. Inability to analyze obfuscated structural traits (e.g., embedded IP addresses, abnormal `@` token masking, multi-level subdomains, URL shortening redirection).
3. Poor user experience in existing open-source implementations, which lack transparent heuristic explainability and modern, accessible interfaces.

### 1.4 Objectives
- **Dataset Fidelity:** Replicate and preserve the exact 30-feature schema from the benchmark repository [`vaibhavbichave/Phishing-URL-Detection`](https://github.com/vaibhavbichave/Phishing-URL-Detection).
- **Comparative Modeling:** Train, evaluate, and benchmark 5 distinct ML algorithms (Gradient Boosting, Random Forest, Decision Tree, Logistic Regression, and Multi-Layer Perceptron).
- **Robust Real-Time Extraction:** Implement a fault-tolerant feature extraction pipeline with strict network timeout protections and offline heuristic fallbacks.
- **Enterprise UI/UX:** Provide a cybersecurity dashboard with dark cyberpunk aesthetics, probability gauges, feature contribution tables, and interactive sample payloads.
- **Microservice Ready:** Provide REST endpoints (`POST /api/analyze`) for integration into security orchestrators and email gateways.

---

## 2. SOFTWARE REQUIREMENTS SPECIFICATION (IEEE-830 STANDARD)

### 2.1 Scope & Purpose
This document specifies the software requirements for **PhishShield Pro v2.0**. It applies to both the web application interface and the backend ML inference microservice.

### 2.2 System Overview & Architecture
The system consists of three architectural tiers:
1. **Presentation Tier:** HTML5, CSS3 Glassmorphism, Lucide Icons, and Vanilla JavaScript with responsive asynchronous form handling.
2. **Application Tier:** Flask-based Python web server handling URL sanitation, feature orchestration, and JSON REST API distribution.
3. **Machine Learning Tier:** Scikit-Learn pipeline powered by a serialized Gradient Boosting Decision Ensemble model (`model.pkl`) and metadata catalog (`meta.pkl`).

```
+-------------------------------------------------------------------------+
|                              PRESENTATION TIER                          |
|         Cyberpunk Dark Dashboard (HTML5 / Glassmorphic CSS3 / JS)       |
+------------------------------------+------------------------------------+
                                     |  HTTP POST (URL Input / REST API)
                                     v
+------------------------------------+------------------------------------+
|                              APPLICATION TIER                           |
|       Flask 3.x Engine | Ingestion | RFC URL Normalization              |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                         FEATURE EXTRACTION ENGINE                       |
|   feature.py (30-Dimensional Vector: Address, SSL, DOM, Behavioral)     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                           PREDICTION ENGINE                             |
|    Gradient Boosting Classifier (model.pkl) | Decision Trees (n=100)    |
|               Empirical Test Accuracy: 97.01% | F1: 97.34%              |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                            OUTPUT DISPATCH                              |
|   - Verdict: Legitimate (+1) / Phishing (-1)                            |
|   - Probability Gauges: Safety % vs Phishing Risk %                     |
|   - Categorized 30-Attribute Vulnerability Inspection Table             |
+-------------------------------------------------------------------------+
```

---

## 3. SPECIFIC 30-FEATURE HEURISTIC SPECIFICATION

The pipeline extracts exactly 30 categorical features mapped to:
- `+1`: Legitimate / Safe
- `0`: Suspicious / Neutral
- `-1`: Phishing / Malicious

### 3.1 Address & Lexical Features (8 Attributes)
1. **`UsingIP`**: Evaluates whether an IPv4 or IPv6 address is directly embedded in the host authority instead of a standard domain name (`-1` if IP detected, `1` otherwise).
2. **`LongURL`**: Evaluates link length (`<54` characters = `1`, `54-75` characters = `0`, `>75` characters = `-1`).
3. **`ShortURL`**: Detects 40+ known URL shortening redirection domains (`bit.ly`, `tinyurl`, `t.co`, etc.).
4. **`Symbol@`**: Detects the presence of `@`, which directs modern browsers to ignore prior text and route to the trailing authority.
5. **`Redirecting//`**: Checks whether double slash delimiters appear after index 6 (indicating secondary redirects).
6. **`PrefixSuffix-`**: Detects hyphen (`-`) characters in the domain component, frequently used in brand spoofing (e.g., `paypal-security.com`).
7. **`SubDomains`**: Counts hierarchical dots (`1` dot = `1`, `2` dots = `0`, `>2` dots = `-1`).
8. **`HTTPSDomainURL`**: Checks if the token "https" is maliciously placed inside the hostname label.

### 3.2 Security & Technical Features (6 Attributes)
9. **`HTTPS`**: Validates whether the protocol scheme is encrypted via HTTPS (`1`) or plaintext HTTP (`-1`).
10. **`DomainRegLen`**: Evaluates domain expiration via WHOIS queries (`>= 12` months = `1`, `< 12` months = `-1`).
11. **`Favicon`**: Checks if the shortcut icon is sourced from an external, unverified domain.
12. **`NonStdPort`**: Detects arbitrary non-standard TCP ports (other than 80 or 443).
13. **`AgeofDomain`**: Determines whether domain age exceeds 6 months.
14. **`DNSRecording`**: Checks active DNS resolution via socket address resolution.

### 3.3 DOM Content & Form Attributes (8 Attributes)
15. **`RequestURL`**: Evaluates the percentage of external image and multimedia assets loaded from foreign origins.
16. **`AnchorURL`**: Percentage of hyperlinks containing empty anchors (`#`), `javascript:void(0)`, or foreign target hosts.
17. **`LinksInScriptTags`**: Assesses scripts and style links loaded from external domains.
18. **`ServerFormHandler`**: Flags `<form action>` handlers submitting to empty strings, `about:blank`, or third-party origins.
19. **`InfoEmail`**: Checks if user credentials or inputs are submitted via `mailto:` mail hooks.
20. **`AbnormalURL`**: Checks if the domain name matches server response headers and WHOIS records.
21. **`WebsiteForwarding`**: Counts HTTP redirect hops (`<=1` hop = `1`, `2-4` hops = `0`, `>4` hops = `-1`).
22. **`IframeRedirection`**: Detects invisible or zero-border `<iframe>` elements used in clickjacking.

### 3.4 Behavioral & Reputation Features (8 Attributes)
23. **`StatusBarCust`**: Detects JavaScript `onmouseover` event scripts altering the status bar link preview.
24. **`DisableRightClick`**: Detects `event.button==2` handlers blocking context menu inspection.
25. **`UsingPopupWindow`**: Detects JavaScript alerts and prompt dialogs collecting credentials.
26. **`WebsiteTraffic`**: Checks web traffic volume and top rank standing.
27. **`PageRank`**: Domain authority rating and institutional TLD recognition.
28. **`GoogleIndex`**: Search directory index verification.
29. **`LinksPointingToPage`**: Inbound hyperlink references on the page.
30. **`StatsReport`**: Cross-references against known malicious IP subnets and phishing campaign blacklists.

---

## 4. MODEL EVALUATION & BENCHMARKING RESULTS

The dataset of 11,054 records was split into **80% Training (8,843 samples)** and **20% Testing (2,211 samples)** using stratified sampling.

| Algorithm | Accuracy | Precision (Legit) | Recall (Legit) | F1-Score | Inference Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Gradient Boosting (GBC)** | **97.01%** | **97.04%** | **97.64%** | **97.34%** | **< 2.5 ms** |
| Multi-Layer Perceptron (MLP) | 97.11% | 97.40% | 97.47% | 97.43% | ~ 4.2 ms |
| Random Forest (100 Trees) | 96.79% | 96.96% | 97.32% | 97.15% | ~ 6.1 ms |
| Decision Tree (Cart) | 95.34% | 95.38% | 96.22% | 95.79% | < 1.0 ms |
| Logistic Regression | 93.89% | 94.13% | 94.97% | 94.55% | < 1.0 ms |

### Feature Importance Weights (Gini Criterion)
1. **`HTTPS`**: `69.81%` (Leading predictive indicator)
2. **`AnchorURL`**: `12.69%`
3. **`WebsiteTraffic`**: `4.28%`
4. **`LinksInScriptTags`**: `3.38%`
5. **`PrefixSuffix-`**: `2.60%`
6. **`SubDomains`**: `1.34%`
7. **`LinksPointingToPage`**: `1.17%`
8. **`DomainRegLen`**: `1.00%`

---

## 5. HARDWARE & SOFTWARE REQUIREMENTS

### 5.1 Software Requirements
- **Operating System:** Windows 10/11, Ubuntu 20.04+, or macOS
- **Runtime Environment:** Python 3.10 to Python 3.13
- **Primary Frameworks:** Flask 3.1+, Scikit-Learn 1.4+, Pandas 2.1+, NumPy 1.26+
- **Parsing & Scraping:** BeautifulSoup4, Requests, Python-Whois
- **Frontend Assets:** HTML5, CSS3 (Custom Glassmorphism), Lucide Web Icons

### 5.2 Hardware Requirements
- **Processor:** Intel Core i3 / AMD Ryzen 3 or higher
- **RAM:** Minimum 2 GB (4 GB recommended)
- **Disk Space:** 100 MB free space for dataset, serialized pickle models, and static assets
- **Network Interface:** Optional active broadband connection (system provides fast offline heuristics when offline)

---

## 6. SYSTEM TESTING & VERIFICATION

### 6.1 Test Cases & Empirical Results
- **Test Case 1 (Legitimate URL):** `https://www.google.com`
  - *Extracted Verdict:* Legitimate (`+1`)
  - *Safety Probability:* `99.99%` | *Result:* PASS
- **Test Case 2 (Legitimate Developer Portal):** `https://github.com`
  - *Extracted Verdict:* Legitimate (`+1`)
  - *Safety Probability:* `100.00%` | *Result:* PASS
- **Test Case 3 (Raw IP Phishing Simulation):** `http://192.168.1.1/paypal-account.php`
  - *Extracted Verdict:* Phishing (`-1`)
  - *Phishing Risk:* `99.97%` | *Result:* PASS
- **Test Case 4 (Brand Hyphen Spoofing):** `http://secure-appleid-update-login.servehttp.com`
  - *Extracted Verdict:* Phishing (`-1`)
  - *Phishing Risk:* `98.53%` | *Result:* PASS

---

## 7. CONCLUSION & FUTURE SCOPE
PhishShield Pro successfully replicates and improves upon the original `vaibhavbichave/Phishing-URL-Detection` repository by incorporating a production-grade UI, fault-tolerant offline heuristics, multi-model evaluation metrics, and a standardized REST API. 

**Future enhancements include:**
1. Integration of Deep Learning Transformers (e.g., Char-CNN, DistilBERT) for raw textual URL lexical sequence embedding.
2. Direct integration with Google Safe Browsing and PhishTank Live APIs for multi-layered hybrid defense.
3. Chromium browser extension for real-time click-time warning interception.
