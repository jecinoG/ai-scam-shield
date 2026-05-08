# AI Scam Shield

AI safety prototype for detecting AI-enabled fraud and social engineering attempts in WhatsApp-style messages common in Nigeria and West Africa.

Analyzes a text message and returns a risk score, risk level, fraud categories, and a plain-English explanation.

---

## Problem Statement

AI-enabled social engineering and scam messages delivered via WhatsApp and SMS remain a major and growing safety risk in Nigeria and West Africa. Common tactics include bank impersonation, fake investment pitches, OTP harvesting, and fake job offers — often mixed with urgency manipulation and written in English or Nigerian Pidgin. Most people have no tool to quickly check whether a message they received is likely a scam.

This project explores lightweight AI safety interventions for detecting and flagging such content in real time.

---

## How It Works

1. A message is submitted via POST request to `/analyze`
2. The **detector engine** (`detector.py`) scans the text against ~70 weighted regex patterns covering known fraud indicators
3. Matched signals are passed to the **risk classifier** (`risk_classifier.py`), which normalizes the cumulative weight into a 0–100 score and buckets it into low/medium/high
4. The API returns structured JSON with score, level, categories, and explanation

The system is intentionally rule-based at this early stage to prioritize interpretability, rapid iteration, and safety evaluation before introducing learned models. Rules are readable, auditable, and tunable without any ML infrastructure.
## Quick Demo

### Example Input
"Your Access Bank account has been suspended. Send your OTP immediately or your account will be closed."

### Example Output
- Risk Score: 87/100  
- Risk Level: High  
- Categories: bank_impersonation, otp_harvesting, urgency_manipulation  
- Explanation: Multiple high-confidence fraud patterns detected including OTP request and urgency based manipulation.

## AI Safety Relevance

This system is designed as a lightweight defensive tool against AI-assisted social engineering and fraud amplification. As generative models make scam messages more convincing, scalable, and multilingual, there is a growing need for simple, deployable detection systems that can operate in low-resource environments.

Unlike black-box detection systems, this prototype prioritizes interpretability, allowing users and researchers to understand which signals triggered a risk classification. This makes it useful for both practical fraud prevention and AI safety evaluation research.

The project focuses on early-stage detection of deceptive intent in real-world messaging contexts, particularly in underserved regions where formal fraud monitoring infrastructure is limited.
---

## Features

- Detects 10+ fraud categories including bank impersonation, OTP harvesting, fake investment, and romance scams
- Handles English and Nigerian Pidgin text
- Returns structured JSON — easy to integrate into bots, apps, or dashboards
- Batch endpoint for analyzing multiple messages at once
- ~70 weighted detection rules, tunable without code changes to core logic
- Evaluation script for sanity-checking detection across a sample dataset
- No external dependencies beyond FastAPI and uvicorn

---

## Detected Risk Categories (AI Safety Taxonomy)

| Category | Examples |
|---|---|
| `bank_impersonation` | Fake GTBank/Access/Zenith alerts |
| `government_impersonation` | Fake EFCC, CBN, NIMC messages |
| `otp_harvesting` | Requests for OTP, PIN, BVN, card details |
| `fake_investment` | Forex schemes, crypto doubling, guaranteed returns |
| `urgency_manipulation` | Act now, expires tonight, account will close |
| `fake_job_offer` | Work from home, registration fee jobs |
| `giveaway_lottery` | MTN/Airtel promos, you have won |
| `account_verification` | Reactivate account, verify details |
| `romance_scam` | Soldiers, diplomats, unsolicited money offers |
| `delivery_scam` | DHL/FedEx clearance fees |
| `payment_method_red_flag` | Bitcoin, gift card, Western Union requests |
| `information_control` | "Don't tell anyone", secrecy instructions |

---

## Project Structure

```
ai-scam-shield/
├── app.py                  # FastAPI app, routes
├── detector.py             # Pattern matching engine
├── risk_classifier.py      # Scoring and risk level logic
├── evaluate.py             # Batch evaluation / CLI tool
├── datasets/
│   └── scam_samples.csv    # 40 sample scam messages for testing
├── requirements.txt
└── README.md
```

---

## Setup

**Requirements:** Python 3.10+

```bash
git clone https://github.com/jecinoG/ai-scam-shield.git

pip install -r requirements.txt

# Start the API server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# Or simply:
python app.py
```

The API will be available at `http://localhost:8000`.

Interactive docs: `http://localhost:8000/docs`

---

## API Usage

### Single message analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"message": "Your Access Bank account has been suspended. Send your OTP immediately or your account will be closed."}'
```

Response:
```json
{
  "risk_score": 87,
  "risk_level": "high",
  "detected_categories": ["bank_impersonation", "otp_harvesting", "urgency_manipulation"],
  "explanation": "Multiple high-confidence fraud patterns detected. Triggered categories: bank_impersonation, otp_harvesting, urgency_manipulation. Top signals: Request for OTP or PIN; Nigerian bank name mentioned; Urgency phrase 'act now'.",
  "signal_breakdown": [...],
  "processing_time_ms": 1.2,
  "message_length": 102
}
```

### Batch analysis

```bash
curl -X POST http://localhost:8000/batch \
  -H "Content-Type: application/json" \
  -d '["message one here", "message two here"]'
```

---

## Evaluation

Run the detector against the bundled sample dataset:

```bash
python evaluate.py
```

Analyze a single message from the command line:

```bash
python evaluate.py --message "You have won ₦500,000 in the MTN promo. Claim now."

# With detailed signal breakdown:
python evaluate.py --message "..." --verbose
```

---

## Limitations

- **Rules are regex-based.** Novel phrasings that don't match any pattern will be missed. A scammer who avoids keywords can evade detection.
- **No ML model.** The system has no learned representation of scam language. It will miss paraphrased or lightly obfuscated messages.
- **English and Pidgin only.** Yoruba, Igbo, Hausa, and French messages are not covered.
- **No feedback loop.** There is no mechanism yet to learn from false positives/negatives in production.
- **Normalization is heuristic.** The score-to-100 mapping is calibrated against a small sample. Scores should be interpreted relatively, not as probabilities.
- **No rate limiting or authentication.** The API is wide open — do not expose to the internet without adding these.
- **No persistent logging.** Each analysis is stateless. There is no database of analyzed messages.
- **False positives are possible.** Some legitimate bank alert formats overlap with scam patterns. Always treat scores as advisory, not definitive.

---

## Future Improvements
## Project Status

This is an actively developed early-stage prototype. The current version includes a functioning API, weighted risk scoring engine, fraud classification framework, evaluation script, and a curated dataset of scam-style messages relevant to Nigeria and West Africa.

Current development is focused on improving detection robustness, expanding multilingual coverage, and evaluating lightweight approaches for scalable fraud detection in low-resource environments.

- Add a small trained text classifier (logistic regression or SVM on TF-IDF) as a second layer — rules + model ensemble would improve recall significantly
- Add Yoruba/Hausa/French pattern coverage
- Build a feedback endpoint to collect confirmed scam/legitimate labels from users
- Add proper rate limiting, API keys, and request logging
- Deploy on a small VPS with a simple web UI for non-technical users
- Fine-tune scoring weights using labelled dataset and grid search
- Add phone number pattern detection (fake NGN numbers, common scam number prefixes)
- Add URL reputation checking against known phishing databases

---

## License

MIT
