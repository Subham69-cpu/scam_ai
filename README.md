# Scam Guard for Email

Browser extension that detects spam/scam emails using **pre-trained ML + rule-based** detection.

## ML Model

Uses a **Naive Bayes classifier** trained on:
- SMS Spam Collection (UCI) samples
- Advanced spam patterns: phishing, OTP scams, investment fraud, inheritance scams, romance scams
- Email-specific: CEO fraud, invoice fraud, tech support scams

## Retrain the Model

To retrain with more data (e.g., full SMS Spam dataset):

```bash
cd scam_ai-main
python train_spam_model.py
```

The script outputs `Email Extension/spam_model.json`. Edit `train_spam_model.py` to add more `(label, message)` tuples to `TRAINING_DATA`.

## Installation

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `Email Extension` folder
