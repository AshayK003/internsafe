"""internsafe core: stdlib-only rules + fuse. No torch, no network, Cloud-safe."""
import re

# (category, compiled regex, weight, human reason)
_PATTERNS = [
    ("advance-fee", re.compile(r"registra\w*\s*(fee|charge|amount)", re.I), 0.45, "asks registration fee"),
    ("advance-fee", re.compile(r"training\s*(fee|charge)", re.I), 0.45, "asks training fee"),
    ("advance-fee", re.compile(r"pay\s*(rs|₹|inr|\$)?\s*\d+.*(before|for).*(offer|join|training|regist)", re.I), 0.45, "asks payment before offer"),
    ("advance-fee", re.compile(r"(security|laptop|refundable)\s*deposit", re.I), 0.40, "asks deposit"),
    ("advance-fee", re.compile(r"(application|certificate|completion|offer)\s*(fee|charge|payment)", re.I), 0.75, "asks application/certificate fee"),
    ("advance-fee", re.compile(r"pay\s*(rs|₹|inr|\$)?\s*\d*.*(certificate|completion)", re.I), 0.75, "pay to get certificate"),
    ("fake-offer", re.compile(r"selection\s*(is\s*)?confirmed", re.I), 0.35, "instant 'selection confirmed'"),
    ("fake-offer", re.compile(r"direct\s*selection", re.I), 0.30, "direct selection, no assessment"),
    ("vague-jd", re.compile(r"watch.*tutorial", re.I), 0.30, "vague work: watch tutorials"),
    ("vague-jd", re.compile(r"read.*pdf", re.I), 0.25, "vague work: read PDFs"),
    ("vague-jd", re.compile(r"copy.?paste", re.I), 0.30, "vague work: copy-paste tasks"),
    ("vague-jd", re.compile(r"(add\s*\d*\s*(people|members|friends|strangers).{0,20}group|spam|forward.*message)", re.I), 0.30, "spam/add-people tasks"),
    ("cert-mill", re.compile(r"cod\s*soft|oasis\s*infobyte|bharat\s*intern|prodigy\s*infotech|code\s*alpha|bluestock", re.I), 0.50, "community-reported certificate-fee pattern — verify"),
    ("task-scam", re.compile(r"telegram", re.I), 0.35, "moves to Telegram"),
    ("task-scam", re.compile(r"(like|subscribe).*(video|youtube|channel)", re.I), 0.40, "like/subscribe tasks"),
    ("task-scam", re.compile(r"(rs|₹)\s*\d[\d,]*\s*(per day|/day|daily)", re.I), 0.35, "unrealistic per-day payout"),
    ("task-scam", re.compile(r"work\s*(only\s*)?(1|2)\s*(hrs|hours).*day", re.I), 0.25, "claims 1-2 hrs/day high pay"),
    ("info-harvest", re.compile(r"\botp\b", re.I), 0.40, "asks for OTP"),
    ("info-harvest", re.compile(r"aadha?ar", re.I), 0.30, "asks Aadhaar early"),
    ("info-harvest", re.compile(r"(bank\s*(account|detail)|pan\s*card).*(share|send|photo)", re.I), 0.35, "asks bank/PAN copy"),
    ("fake-offer", re.compile(r"(no|without)\s*interview", re.I), 0.35, "no interview"),
    ("fake-offer", re.compile(r"instant\s*offer", re.I), 0.35, "instant offer"),
    ("fake-offer", re.compile(r"(contact|ping|message|whatsapp).{0,20}whatsapp", re.I), 0.25, "WhatsApp-only contact"),
]

_PERSONAL_MAIL = re.compile(r"@(gmail|yahoo|outlook|hotmail|rediffmail)\.", re.I)
_STIPEND_NUM = re.compile(r"(rs|₹|inr)\s*([\d,]+)", re.I)


def risk_to_verdict(risk: float) -> str:
    if risk >= 0.8:
        return "RED"
    if risk >= 0.5:
        return "YELLOW"
    return "GREEN"


def score_rules(text: str, meta: dict | None = None) -> dict:
    """Pure function. text=post, meta={asked_money, channel, email}. Never raises on bad input."""
    meta = meta or {}
    t = (text or "").strip()
    cat_score: dict[str, float] = {}
    reasons: list[str] = []

    for cat, rx, w, reason in _PATTERNS:
        if rx.search(t):
            cat_score[cat] = cat_score.get(cat, 0.0) + w
            if reason not in reasons:
                reasons.append(reason)

    if (meta.get("asked_money") or "").lower() == "yes":
        cat_score["advance-fee"] = cat_score.get("advance-fee", 0.0) + 0.35
        reasons.append("you marked: asked for money")

    ch = (meta.get("channel") or "").lower()
    if ch in ("whatsapp", "telegram"):
        for c in ("fake-offer", "task-scam"):
            cat_score[c] = cat_score.get(c, 0.0) + 0.10
        reasons.append(f"contact via {ch}")

    email = (meta.get("email") or "").strip()
    if email and _PERSONAL_MAIL.search(email):
        cat_score["fake-offer"] = cat_score.get("fake-offer", 0.0) + 0.10
        reasons.append("personal email only")

    m = _STIPEND_NUM.search(t)
    if m:
        try:
            amt = int(m.group(2).replace(",", ""))
        except ValueError:
            amt = 0
        if amt >= 80000 and re.search(r"data entry|part.?time|2\s*(hrs|hours)", t, re.I):
            cat_score["fake-offer"] = cat_score.get("fake-offer", 0.0) + 0.20
            reasons.append(f"unrealistic stipend Rs {amt}")

    if not cat_score:
        return {"label": "legit", "risk": 0.05, "reasons": ["no scam patterns found"]}

    label = max(cat_score, key=cat_score.get)
    risk = round(min(0.98, 0.05 + sum(cat_score.values())), 2)
    return {"label": label, "risk": risk, "reasons": reasons[:5]}


def fuse(rules: dict, laya: dict | None) -> dict:
    """Pick higher risk. laya=None -> rules. Pure, no I/O."""
    if not laya:
        return {**rules, "source": "rules"}
    if laya.get("risk", 0) >= rules.get("risk", 0):
        out = {**laya, "source": "laya"}
        out.setdefault("reasons", ["flagged by open-weights model"])
        return out
    return {**rules, "source": "rules+laya-checked"}
