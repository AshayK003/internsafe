# internsafe — Internship Scam Checker for Freshers

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://internsafe.streamlit.app/)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-76%20passing-brightgreen)](#)

> **Deterministic, explainable, privacy-first** — Paste an internship post, get a clear RED/YELLOW/GREEN verdict with exact reasons. No AI, no tracking, no data stored.

---

## Why internsafe?

Freshers in India lose lakhs every year to internship scams: registration fees, certificate mills (CodSoft, Oasis Infobyte, Bharat Intern, Prodigy Infotech, Code Alpha, Bluestock), task-deposit schemes, and credential phishing. Existing advice is generic ("be careful"). **internsafe gives you a specific, auditable verdict.**

- 🔴 **RED** = Deal-breaker detected (payment asked, OTP requested, deposit to unlock tasks)
- 🟡 **YELLOW** = Strong warnings or insufficient verification (unrealistic earnings, domain mismatch, LinkedIn→WhatsApp)
- 🟢 **GREEN** = No red flags **and** verifiable employer signals (careers page, domain match, explicit no-fee)

> **GREEN ≠ Safe.** It means *no high-confidence scam indicators detected from what you provided*. Always verify independently.

---

## Try It

**Live:** https://internsafe.streamlit.app/  
*(Free tier — sleeps after 12h inactivity, cold start ~45s)*

### Quick Test Samples (one-click in app)
| Sample | Expected |
|--------|----------|
| Scam: Registration fee | 🔴 RED |
| Scam: Certificate fee (CodSoft) | 🔴 RED |
| Scam: Deposit to unlock tasks | 🔴 RED |
| Scam: OTP request | 🔴 RED |
| Legit: Microsoft (verified) | 🟢 GREEN |
| Legit: Startup (verified) | 🟢 GREEN |
| Warning: Too good to be true | 🟡 YELLOW |
| Warning: Email domain mismatch | 🟡 YELLOW |
| Adversarial: "NO fee" claim | 🟡 YELLOW |

---

## How It Works

**Deterministic rule engine** (stdlib only, ~300 lines) — no ML, no external API by default.

| Tier | Rules | Triggers |
|------|-------|----------|
| **Deal-breakers (HARD RED)** | 8 | Payment asked, registration/training/cert fee, deposit to unlock, withdrawal fee, gift card/crypto, OTP/password, govt recruitment via WhatsApp+pay |
| **Strong Warnings** | 12 | Unrealistic earnings (₹5000/day, 2hrs), urgency pressure, guaranteed selection, unexpected WhatsApp/Telegram, LinkedIn→WhatsApp, domain mismatch, bank/PAN/Aadhaar before offer, referral-heavy, repetitive tasks, vague role + high pay, missing employer details |
| **Context Signals** | 7 | WhatsApp/Telegram mention, generic email, remote vague, no interview |
| **Positive Verification** | 8 | Company website, email domain match, careers page, specific role details, recruiter identity, official portal, verified profile, explicit no-fee |

**Decision tree:**
```
HARD RED present? → RED
≥2 Strong Warnings? → YELLOW
1 Strong Warning + <3 Verifications? → YELLOW
No HARD/Strong + ≥2 Verifications? → GREEN
Else → YELLOW
```

**Negation-aware:** "NO registration fee", "never ask OTP" → correctly ignored (60-char context window + matched-text scan).

---

## Run Locally

```bash
git clone https://github.com/AshayK003/internsafe.git
cd internsafe
pip install -r requirements.txt
streamlit run app.py
```

**Requirements:** Python 3.10+, 200MB RAM. No GPU, no model downloads.

---

## Deploy Free (Streamlit Cloud)

1. Fork this repo
2. Go to [share.streamlit.io](https://share.streamlit.io) → Deploy from fork
3. (Optional) Settings → Secrets → add `HF_TOKEN` for Laya open-weights API fallback

```toml
# .streamlit/secrets.toml
HF_TOKEN = "hf_..."  # Get from huggingface.co/settings/tokens
```

---

## Architecture

```
app.py          # Streamlit UI (dark theme, sample chips, tabs)
rules.py        # Core engine: analyze(text, meta) → Result
scam.py         # Legacy compat (preserved)
test_rules.py   # 50 cases: legit/scam/adversarial/ambiguous/mill/edge
test_scam.py    # 26 legacy tests
blackbox_test.py # 9 end-to-end scenarios
```

**Stack:** Streamlit 1.57+, stdlib only (`re`, `dataclasses`, `typing`).  
**Optional:** `huggingface_hub` for Laya API (lazy-loaded, graceful fallback).

---

## Evidence Base

Rules mapped to official guidance:

| Source | Key Patterns Covered |
|--------|---------------------|
| **I4C / cybercrime.gov.in** | Upfront payment, unrealistic earnings, delayed/denied withdrawals, referral emphasis, personal/financial info collection |
| **AICTE National Internship Portal (Sep 2026)** | Organisations must never charge students any fee for applying, selection, or placement |
| **LinkedIn Safety** | Payment requests, early sensitive-info requests, pressure to move to WhatsApp/Telegram, vague postings, fast hiring, email/domain mismatch |
| **FTC** | Task scams: unexpected WhatsApp/text → vague work → deposit to continue/withdraw |

---

## Contributing

1. Fork → add test case to `test_rules.py` → PR
2. New rule = one tuple in `rules.py` (`_HARD_RED_RULES`, `_STRONG_WARN_RULES`, etc.)
3. Run `python test_rules.py` — all 50 must pass

---

## Privacy

- **No external calls** unless you add `HF_TOKEN`
- **No database, no logs, no tracking**
- Input processed in-memory per request only
- Runs entirely on your device / Streamlit Cloud container

---

## License

MIT — free for personal, educational, and commercial use.

---

## Disclaimer

**internsafe detects known red-flag patterns. It does not verify employers, conduct background checks, or guarantee legitimacy.** A GREEN result means *no high-confidence scam indicators were detected from the information you provided*. Always verify independently using the verification guide in the app.

---

**Built for freshers. Stay safe. 🛡️**