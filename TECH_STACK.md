# Technical Stack – Scam Guard Project

## Overview

| Component | Technology | Why |
|-----------|------------|-----|
| **Runtime** | Node.js | JavaScript everywhere; runs server and allows same language for extensions |
| **Backend** | Express.js | Lightweight HTTP server; minimal setup for static site + visit logging |
| **Browser extensions** | Chrome Manifest V3 | Modern standard; works in Chrome, Edge, and other Chromium browsers |
| **Extensions language** | Vanilla JavaScript | No build step; fast load; runs in content script context without frameworks |
| **ML model** | Naive Bayes (Python-trained, JSON) | Runs client-side in browser; no TensorFlow; small model, fast inference |
| **Model training** | Python 3 | Scikit-learn–style implementation; trains on spam/ham data and exports JSON |
| **Data storage** | File system (visits.log, JSON) | No database; easy deployment; suitable for small traffic |

---

## 1. Node.js

**What it is:** JavaScript runtime built on Chrome's V8 engine.

**Why used:**
- Runs the backend server (`server.js`) to serve the site and log visits
- Same language as the browser extensions (JavaScript) for consistency
- Large ecosystem (`npm`) for dependencies
- Cross-platform (Windows, macOS, Linux)

---

## 2. Express.js

**What it is:** Minimal web framework for Node.js.

**Why used:**
- Simple HTTP server with few lines of code
- Static file serving (`express.static`) for the landing page
- Request logging middleware to record IP, user agent, etc.
- No database, auth, or complex routing needed
- Widely used and documented

---

## 3. Chrome Extensions (Manifest V3)

**What it is:** Browser extensions using the Manifest V3 format.

**Why used:**
- Content scripts can inject into Gmail, Outlook, WhatsApp Web
- Runs in the user’s browser; no server required for detection
- Manifest V3 is the current standard for Chrome/Edge
- `host_permissions` limits access to Gmail, Outlook, WhatsApp Web only

---

## 4. Vanilla JavaScript (No React/Vue/Angular)

**What it is:** Plain JavaScript without frameworks.

**Why used:**
- Content scripts have tight constraints; heavy frameworks add complexity
- Fast load and execution
- No build step (webpack, Vite, etc.)
- Direct DOM APIs (`querySelector`, `createElement`) are sufficient for warnings and banners

---

## 5. Content Scripts

**What it is:** JavaScript that runs in the context of web pages (e.g. mail.google.com).

**Why used:**
- Access to the page DOM (email body, chat messages)
- `MutationObserver` to detect new messages in real time
- Can read text and inject warning elements
- Runs only on allowed hosts (Gmail, Outlook, WhatsApp Web)

---

## 6. Naive Bayes Classifier

**What it is:** Probabilistic classifier that assumes word independence (bag-of-words).

**Why used:**
- Simple to implement in JavaScript
- Model is a JSON file with log probabilities; no heavy ML runtime
- Runs fully client-side (privacy-friendly)
- Sufficient for spam detection with enough training examples

---

## 7. Python (Training Script)

**What it is:** `train_spam_model.py` trains the Naive Bayes model.

**Why used:**
- Straightforward text preprocessing and tokenization
- Uses built-in modules (`json`, `math`, `re`, `collections`); no ML libs
- Outputs `spam_model.json` for the extension to load
- Training is a one-off step; users run it when retraining

---

## 8. JSON for Model Storage

**What it is:** `spam_model.json` with log priors and per-word log probabilities.

**Why used:**
- Human-readable and debuggable
- Loaded via `fetch()` in the extension
- No binary format or special parsing
- Small size for web delivery

---

## 9. File System (visits.log)

**What it is:** Append-only log file for visit data.

**Why used:**
- No database setup or configuration
- Easy to inspect and process with standard tools
- Each line is one JSON object
- Suitable for low to medium traffic

---

## 10. HTML5 + CSS3

**What it is:** Standard HTML and CSS for the landing page.

**Why used:**
- Single static page with no templating engine
- CSS in `<style>` keeps it self-contained
- Responsive layout with `viewport` meta tag

---

## File Structure Summary

```
scam_ai-main/
├── server.js              # Express server, visit logging
├── package.json           # Node dependencies (Express)
├── public/
│   └── index.html         # Scam awareness landing page
├── Whatsapp Extension/    # Chrome extension for WhatsApp Web
│   ├── manifest.json
│   └── whatsapp-content.js
├── Email Extension/       # Chrome extension for Gmail/Outlook
│   ├── manifest.json
│   ├── email-content.js
│   └── spam_model.json    # Pre-trained Naive Bayes model
└── train_spam_model.py    # Python script to train model
```
