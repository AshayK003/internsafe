"""internsafe deterministic rule engine. Stdlib only. No ML, no network."""
import re
from dataclasses import dataclass
from typing import Literal

Verdict = Literal["RED", "YELLOW", "GREEN"]


@dataclass(slots=True)
class Hit:
    rule_id: str
    severity: Literal["HARD_RED", "STRONG_WARN", "WEAK_WARN", "VERIFY"]
    message: str
    evidence: str


@dataclass(slots=True)
class Result:
    verdict: Verdict
    hits: list[Hit]
    missing_info: list[str]
    summary: str


# --- negation-aware helpers ---

_NEGATION_WORDS = re.compile(
    r"\b(no|not|never|none|without|absolutely\s+no|doesn't\s+ask|don't\s+ask|"
    r"won't\s+ask|no\s+need|no\s+requirement|free\s+of\s+cost|zero\s+fee|"
    r"without\s+any\s+payment|no\s+charge)\b",
    re.I,
)


def _has_negation_near(text: str, match: re.Match, window: int = 60) -> bool:
    """True if negation word appears within `window` chars before OR after the match."""
    # Check before
    start = max(0, match.start() - window)
    context_before = text[start : match.start()]
    if _NEGATION_WORDS.search(context_before):
        return True
    # Check after (for patterns like "stipend ... no fee")
    end = min(len(text), match.end() + window)
    context_after = text[match.end() : end]
    return bool(_NEGATION_WORDS.search(context_after))


# --- HARD RED rules ---

_HARD_RED_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "R01",
        re.compile(r"(must|required|need\s+to)\s+pay.*(apply|application|regist)", re.I),
        "Payment required to apply",
    ),
    (
        "R02",
        re.compile(r"(registration|onboarding|verification|joining)\s*(fee|charge|amount|payment)", re.I),
        "Registration/onboarding/verification fee",
    ),
    (
        "R03",
        re.compile(r"(training|certificate|software|platform)\s*(fee|charge|payment|cost)", re.I),
        "Training/certificate/software fee to obtain internship",
    ),
    (
        "R04",
        re.compile(r"deposit.*(task|work|start|unlock)", re.I),
        "Deposit money to perform tasks",
    ),
    (
        "R05",
        re.compile(r"(withdraw|withdrawal|salary|stipend|earnings|payout).*(fee|charge|payment|deposit)", re.I),
        "Pay to withdraw salary/stipend/earnings",
    ),
    (
        "R06",
        re.compile(r"(gift\s*card|crypto|bitcoin|wire\s*transfer|upi|paytm|google\s*pay).*hiring", re.I),
        "Gift card/crypto/wire transfer requested for hiring",
    ),
    (
        "R07",
        re.compile(r"(send|share|give).*(otp|pin|password|authentication|secret)", re.I),
        "Asked for OTP/PIN/password/authentication secret",
    ),
    (
        "R08",
        re.compile(r"(government|official|company)\s+recruitment.*(whatsapp|telegram|unofficial).*pay", re.I),
        "Official recruitment via unofficial channel with payment request",
    ),
]

# --- STRONG WARNING rules ---

_STRONG_WARN_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "W01",
        re.compile(r"(earn|make|salary|stipend|income).*(rs|₹|inr|\$)\s*\d[\d,]*.*(1|2)\s*(hrs?|hours?|day)", re.I),
        "Unrealistic earnings with minimal hours",
    ),
    (
        "W02",
        re.compile(r"(today\s*only|limited\s*seats?|join\s*(in|within)\s*\d+\s*(min|hrs?|hours)|urgent|immediate|hurry)", re.I),
        "Urgency/pressure language",
    ),
    (
        "W03",
        re.compile(r"(guaranteed|sure|confirm|certain).*selection|guaranteed.*income|guaranteed.*job", re.I),
        "Guaranteed selection/income",
    ),
    (
        "W04",
        re.compile(r"(unexpected|unsolicited|out\s*of\s*blue).*(whatsapp|telegram).*(recruit|internship|job|offer)", re.I),
        "Unexpected WhatsApp/Telegram recruitment",
    ),
    (
        "W05",
        re.compile(r"linkedin.*(move|shift|switch|continue).*(whatsapp|telegram|external\s*form)", re.I),
        "Immediate move from LinkedIn to WhatsApp/external form",
    ),
    (
        "W06",
        re.compile(r"@(gmail|yahoo|outlook|hotmail|rediffmail)\.", re.I),
        "Generic recruiter email",
    ),
    (
        "W07",
        re.compile(r"", re.I),  # domain mismatch handled separately with company info
        "Company email domain mismatch",
    ),
    (
        "W08",
        re.compile(r"(bank\s*(account|detail|statement)|pan\s*card|aadhaar|passport|financial).*before.*(hiring|joining|offer)", re.I),
        "Financial/identity documents requested before formal hiring",
    ),
    (
        "W09",
        re.compile(r"(referral|refer\s*friend|commission|affiliate|network).*earn", re.I),
        "Referral/commission-heavy earnings",
    ),
    (
        "W10",
        re.compile(r"(like|rate|review|click|subscribe|rating|task).*repetitive|simple\s*task", re.I),
        "Repetitive rating/liking/task completion work",
    ),
    (
        "W11",
        re.compile(r"(vague|unspecified|flexible).*responsibilit(y|ies).*high.*(pay|stipend|salary)", re.I),
        "Vague responsibilities + unusually attractive compensation",
    ),
    
]

# --- WEAK WARNING rules ---

_WEAK_WARN_RULES: list[tuple[str, re.Pattern, str]] = [
    ("WK01", re.compile(r"whatsapp", re.I), "WhatsApp mentioned"),
    ("WK02", re.compile(r"telegram", re.I), "Telegram mentioned"),
    ("WK03", re.compile(r"urgent|immediate|hurry|asap", re.I), "Urgency language"),
    ("WK04", re.compile(r"@(gmail|yahoo|outlook|hotmail|rediffmail)\.", re.I), "Generic recruiter email"),
    ("WK05", re.compile(r"(work\s*from\s*home|remote).*flexible", re.I), "Remote with vague details"),
    ("WK06", re.compile(r"(no|without)\s*interview", re.I), "No interview mentioned"),
    ("WK07", re.compile(r"", re.I), "Incomplete employer details"),  # meta-dependent
]

# --- POSITIVE VERIFICATION rules ---

_VERIFY_RULES: list[tuple[str, re.Pattern, str]] = [
    ("V01", re.compile(r"", re.I), "Company has official website"),  # needs company info
    ("V02", re.compile(r"", re.I), "Email domain matches company website"),
    ("V03", re.compile(r"(careers|jobs)\.(?!.*(indeed|naukri|linkedin|monster|glassdoor|internshala))", re.I), "Role on company careers page"),
    ("V04", re.compile(r"(responsibilit(y|ies)|duration|location|eligibility|stipend).*(specified|clear|detailed)", re.I), "Specific role details"),
    ("V05", re.compile(r"", re.I), "Recruiter identity consistent with company"),
    ("V06", re.compile(r"(apply|application).*portal|careers\.", re.I), "Apply through official portal"),
    ("V07", re.compile(r"(linkedin|company)\s*(verified|verified\s*page|official\s*page)", re.I), "Verified company/recruiter profile"),
    ("V08", re.compile(r"(no|not|never|none|without).*(payment|fee|charge|pay|deposit)", re.I), "Explicitly no payment requested"),
]


def _check_rules(text: str, rules: list[tuple[str, re.Pattern, str]], severity: str, meta: dict | None = None) -> list[Hit]:
    """Run rules against text, respecting negation for payment/credential rules."""
    hits = []
    meta = meta or {}
    for rule_id, pattern, msg in rules:
        if not pattern.pattern:  # placeholder for meta-dependent rules
            continue
        for m in pattern.finditer(text):
            # negation check for payment/credential sensitive rules
            if severity in ("HARD_RED", "STRONG_WARN"):
                # Check negation before match
                if _has_negation_near(text, m):
                    continue
                # For HARD_RED payment patterns, also check if matched text contains negation
                if severity == "HARD_RED" and any(kw in rule_id for kw in ("R01", "R02", "R03", "R04", "R05", "R06")):
                    matched_text = m.group(0).lower()
                    if any(neg in matched_text for neg in ("no ", "not ", "never ", "without ", "free ", "zero ")):
                        continue
            hits.append(Hit(rule_id, severity, msg, text[max(0, m.start()-40):m.end()+40]))
    return hits


def _check_meta_hard_red(meta: dict | None) -> list[Hit]:
    """HARD RED rules that need meta fields."""
    if not meta:
        return []
    hits = []
    # R01-R06 covered by text patterns mostly, but explicit meta helps
    if meta.get("asked_money") == "Yes":
        hits.append(Hit("R01", "HARD_RED", "User confirmed: asked for money", meta.get("money_for", "")))
    if meta.get("money_for") and re.search(r"(registration|training|certificate|onboarding|verification|deposit|withdraw)", meta["money_for"], re.I):
        hits.append(Hit("R02", "HARD_RED", f"Money for: {meta['money_for']}", meta["money_for"]))
    if meta.get("payment_method") and re.search(r"(gift\s*card|crypto|wire|upi|paytm)", meta["payment_method"], re.I):
        hits.append(Hit("R06", "HARD_RED", f"Suspicious payment method: {meta['payment_method']}", meta["payment_method"]))
    if meta.get("documents_requested") and re.search(r"(password|otp|pin|bank.*detail|pan|aadhaar)", meta["documents_requested"], re.I):
        hits.append(Hit("R07", "HARD_RED", f"Sensitive docs requested: {meta['documents_requested']}", meta["documents_requested"]))
    return hits


def _domain_match(company: str, email_domain: str) -> bool:
    """Check if email domain matches company name (handles .io, .com, etc.)"""
    company_clean = company.replace(" ", "").replace(".", "").lower()
    domain_clean = email_domain.replace(".", "").lower()
    return company_clean == domain_clean or company_clean.startswith(domain_clean) or domain_clean.startswith(company_clean)


def _check_meta_strong_warn(meta: dict | None) -> list[Hit]:
    if not meta:
        return []
    hits = []
    if meta.get("channel") in ("WhatsApp", "Telegram") and meta.get("platform") == "LinkedIn":
        hits.append(Hit("W05", "STRONG_WARN", f"Moved from {meta['platform']} to {meta['channel']}", f"{meta['platform']} -> {meta['channel']}"))
    # W07: domain mismatch
    company = (meta.get("company") or "").strip().lower()
    email = (meta.get("email") or "").strip().lower()
    website = (meta.get("website") or "").strip().lower()
    if company and email and "@" in email:
        email_domain = email.split("@")[1].split(".")[0]
        if not _domain_match(company, email_domain) and email_domain not in ("gmail", "yahoo", "outlook", "hotmail"):
            hits.append(Hit("W07", "STRONG_WARN", f"Email domain '{email_domain}' doesn't match company '{company}'", f"{email} vs {company}"))
    return hits


def _check_meta_weak_warn(meta: dict | None) -> list[Hit]:
    if not meta:
        return []
    hits = []
    # WK07: incomplete details
    if not (meta.get("company") or meta.get("website") or meta.get("apply_url") or meta.get("role_details")):
        hits.append(Hit("WK07", "WEAK_WARN", "Missing: company, website, application URL, or role details", "incomplete employer info"))
    return hits


def _check_meta_verify(meta: dict | None) -> list[Hit]:
    if not meta:
        return []
    hits = []
    company = (meta.get("company") or "").strip()
    website = (meta.get("website") or "").strip()
    email = (meta.get("email") or "").strip()
    apply_url = (meta.get("apply_url") or "").strip()
    if company and website:
        hits.append(Hit("V01", "VERIFY", f"Company website provided: {website}", f"{company} -> {website}"))
    if company and email and "@" in email:
        email_domain = email.split("@")[1].split(".")[0]
        if company.replace(" ", "") == email_domain:
            hits.append(Hit("V02", "VERIFY", f"Email domain matches company", f"{email}"))
    if apply_url and "careers" in apply_url and not any(x in apply_url for x in ("indeed", "naukri", "linkedin", "monster", "glassdoor", "internshala")):
        hits.append(Hit("V03", "VERIFY", f"Application on company careers page", apply_url))
    if meta.get("role_details") and len(meta["role_details"]) > 30:
        hits.append(Hit("V04", "VERIFY", "Specific role details provided", meta["role_details"][:100]))
    if meta.get("recruiter_name") and company:
        hits.append(Hit("V05", "VERIFY", f"Recruiter name provided: {meta['recruiter_name']}", meta["recruiter_name"]))
    if meta.get("explicit_no_fee"):
        hits.append(Hit("V08", "VERIFY", "Explicitly states no fee", meta["explicit_no_fee"]))
    return hits


def analyze(text: str, meta: dict | None = None) -> Result:
    """Deterministic decision engine. Returns Result with verdict, hits, missing info."""
    meta = meta or {}
    t = (text or "").strip()

    hard_hits = _check_rules(t, _HARD_RED_RULES, "HARD_RED", meta) + _check_meta_hard_red(meta)
    strong_hits = _check_rules(t, _STRONG_WARN_RULES, "STRONG_WARN", meta) + _check_meta_strong_warn(meta)
    weak_hits = _check_rules(t, _WEAK_WARN_RULES, "WEAK_WARN", meta) + _check_meta_weak_warn(meta)
    verify_hits = _check_rules(t, _VERIFY_RULES, "VERIFY", meta) + _check_meta_verify(meta)

    all_hits = hard_hits + strong_hits + weak_hits + verify_hits

    # --- Decision tree ---
    if hard_hits:
        verdict: Verdict = "RED"
        summary = "High-confidence scam indicators detected. Do not proceed."
    elif strong_hits:
        # Multiple strong warnings = YELLOW
        if len(strong_hits) >= 2:
            verdict = "YELLOW"
            summary = "Multiple strong warning signals. Insufficient evidence of legitimacy."
        else:
            # Single strong warning, check verification
            if verify_hits and len(verify_hits) >= 3:
                verdict = "GREEN"
                summary = "No high-confidence scam indicators detected from the information provided. This does not verify the employer or guarantee legitimacy."
            else:
                verdict = "YELLOW"
                summary = "Strong warning signal present. Verify employer independently."
    else:
        # No hard red, no strong warns
        # Count only meta-based verify hits for GREEN (text-only patterns like V06/V08 can be faked)
        meta_verify = [h for h in verify_hits if h.rule_id in ("V01", "V02", "V03", "V04", "V05", "V07")]
        if meta_verify and len(meta_verify) >= 2:
            verdict = "GREEN"
            summary = "No high-confidence scam indicators detected from the information provided. This does not verify the employer or guarantee legitimacy."
        else:
            verdict = "YELLOW"
            summary = "Insufficient evidence to establish legitimacy. Verify before proceeding."

    # Missing info hints
    missing = []
    if not meta.get("company"):
        missing.append("Company name")
    if not meta.get("website"):
        missing.append("Company website")
    if not meta.get("apply_url"):
        missing.append("Application URL")
    if not meta.get("role_details"):
        missing.append("Role details (responsibilities, duration, location)")

    return Result(verdict=verdict, hits=all_hits, missing_info=missing, summary=summary)


# --- quick self-test ---

if __name__ == "__main__":
    # Smoke tests
    tests = [
        ("Pay Rs 500 registration fee", {}, "RED"),
        ("No registration fee required", {}, "YELLOW"),
        ("Earn Rs 5000/day 2 hours work", {}, "YELLOW"),
        ("Microsoft internship, apply at careers.microsoft.com, no fee", {"company": "Microsoft", "website": "microsoft.com", "apply_url": "careers.microsoft.com", "explicit_no_fee": "no application fee"}, "GREEN"),
        ("Telegram task, deposit 1000 to unlock", {}, "RED"),
    ]
    for txt, m, exp in tests:
        r = analyze(txt, m)
        print(f"{'PASS' if r.verdict == exp else 'FAIL'} | {exp} -> {r.verdict} | {txt[:60]}")
        for h in r.hits:
            print(f"  {h.severity} {h.rule_id}: {h.message}")