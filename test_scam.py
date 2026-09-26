"""One-file check: python test_scam.py. Stdlib only, no pytest."""
from scam import fuse, risk_to_verdict, score_rules

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name, extra)
    if not cond:
        fails.append(name)


# 1. advance-fee -> RED when user confirms money asked
r = score_rules("Pay Rs 1500 registration fee before offer", {"asked_money": "Yes"})
check("advance-fee RED", r["label"] == "advance-fee" and r["risk"] >= 0.8, str(r))

# 2. telegram task-scam -> RED
r = score_rules("Telegram task: like videos, Rs 5000 per day, work 2 hours daily")
check("task-scam RED", r["label"] == "task-scam" and r["risk"] >= 0.8, str(r))

# 3. otp + aadhaar -> YELLOW, info-harvest
r = score_rules("Share OTP and Aadhaar photo to confirm joining")
check("info-harvest YELLOW", r["label"] == "info-harvest" and 0.5 <= r["risk"] < 0.8, str(r))

# 4. no interview + whatsapp channel -> RED fake-offer
r = score_rules("Instant joining, no interview, ping on WhatsApp", {"channel": "WhatsApp"})
check("fake-offer RED", r["label"] == "fake-offer" and r["risk"] >= 0.8, str(r))

# 5. legit stays GREEN
r = score_rules("Software intern, onsite interview Koramangala, apply via careers@acme.in")
check("legit GREEN", r["label"] == "legit" and r["risk"] < 0.5, str(r))

# 6. empty input never crashes
r = score_rules("", {})
check("empty safe", r["risk"] < 0.5, str(r))

# 7. Hinglish caught
r = score_rules("Telegram par task hai, Rs 5000 per day milega")
check("hinglish YELLOW+", r["risk"] >= 0.5, str(r))

# 8. verdict boundaries
check("verdict RED", risk_to_verdict(0.8) == "RED")
check("verdict YELLOW", risk_to_verdict(0.5) == "YELLOW")
check("verdict GREEN", risk_to_verdict(0.49) == "GREEN")

# 9. fuse: None -> rules
rules = {"label": "legit", "risk": 0.05, "reasons": ["x"]}
check("fuse none", fuse(rules, None)["source"] == "rules")
# 10. fuse picks higher
hi = {"label": "advance-fee", "risk": 0.9, "reasons": ["y"]}
check("fuse laya wins", fuse(rules, hi)["source"] == "laya")
check("fuse rules wins", fuse(hi, rules)["risk"] == 0.9)

# 11. cert fee -> RED advance-fee
r = score_rules("Pay Rs 500 to download completion certificate")
check("cert-fee RED", r["label"] == "advance-fee" and r["risk"] >= 0.8, str(r))

# 12. instant selection confirmed -> RED fake-offer
r = score_rules("Selection is confirmed! No interview needed. Ping on WhatsApp", {"channel": "WhatsApp"})
check("instant-select RED", r["label"] == "fake-offer" and r["risk"] >= 0.8, str(r))

# 13. vague JD: multiple signals -> RED (multiple vague signals = high risk)
r = score_rules("Watch tutorials, read PDFs, copy paste data, add 50 people to group")
check("vague-jd RED", r["label"] == "vague-jd" and r["risk"] >= 0.8, str(r))

# 14. cert mill name -> YELLOW cert-mill (verify, not accuse)
r = score_rules("Join CodSoft internship, get certificate after Rs 199")
check("cert-mill YELLOW", r["label"] == "cert-mill" and 0.5 <= r["risk"] < 0.8, str(r))

# 15. legit with gmail stays GREEN verdict (email adds signal but risk stays low)
r = score_rules("Software intern, interview via Google Meet, apply at hr@gmail.com", {"email": "hr@gmail.com"})
check("gmail GREEN", r["risk"] < 0.5, str(r))

# 16. combined signals escalate
r = score_rules("Telegram task, Rs 5000/day, pay Rs 2000 registration, no interview", {"asked_money": "Yes", "channel": "Telegram"})
check("combined RED", r["risk"] >= 0.9, str(r))

print(f"\n{26 - len(fails)}/26 passed")
raise SystemExit(1 if fails else 0)
