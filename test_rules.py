"""Comprehensive test suite for internsafe deterministic rule engine.
Run: python test_rules.py
"""
from rules import analyze, Hit, Result

fails = []


def check(name: str, text: str, meta: dict, expected: str, exp_hits_contains: list[str] | None = None):
    global fails
    r: Result = analyze(text, meta)
    passed = r.verdict == expected
    if exp_hits_contains:
        hit_ids = [h.rule_id for h in r.hits]
        for exp_id in exp_hits_contains:
            if exp_id not in hit_ids:
                passed = False
                break
    status = "PASS" if passed else "FAIL"
    print(f"{status} {name} -> {r.verdict} (exp {expected})")
    if not passed:
        fails.append(f"{name}: got {r.verdict}, exp {expected} | hits: {[h.rule_id for h in r.hits]}")
        for h in r.hits:
            print(f"  {h.severity} {h.rule_id}: {h.message}")


# ============================================================
# LEGITIMATE INTERNSHIPS (should be GREEN with sufficient meta)
# ============================================================
legit_meta = {
    "company": "Microsoft",
    "website": "microsoft.com",
    "apply_url": "careers.microsoft.com",
    "email": "hr@microsoft.com",
    "role_details": "3 months, Bangalore, backend development, Rs 80k/month, mentorship",
    "recruiter_name": "Priya Sharma",
    "channel": "Email",
    "platform": "Company site",
}

check("legit_microsoft_full", "Microsoft Software Engineering Intern. Apply at careers.microsoft.com. No application fee. 3 months Bangalore Rs 80k/month.", legit_meta, "GREEN")
check("legit_google_full", "Google STEP Intern. Apply via careers.google.com. No fee. 12 weeks Mountain View.", {"company": "Google", "website": "google.com", "apply_url": "careers.google.com", "email": "recruiting@google.com", "role_details": "12 weeks, Mountain View, ML research", "channel": "Email", "platform": "Company site"}, "GREEN")
check("legit_startup_full", "Startup.io Backend Intern. Apply at startup.io/careers. No fee. 6 months remote Rs 40k.", {"company": "Startup.io", "website": "startup.io", "apply_url": "startup.io/careers", "email": "jobs@startup.io", "role_details": "6 months remote, Node.js, Rs 40k/month", "channel": "Email", "platform": "Company site"}, "GREEN")
check("legit_naukri_redirect", "TCS Internship. Apply on TCS careers portal. No registration fee. 6 months Pune.", {"company": "TCS", "website": "tcs.com", "apply_url": "careers.tcs.com", "email": "hr@tcs.com", "role_details": "6 months Pune, Java development", "channel": "Email", "platform": "Naukri"}, "GREEN")

# Legit with minimal meta (should be YELLOW - insufficient verification)
check("legit_minimal_meta", "Software intern, interview via Google Meet, apply at hr@company.com", {"email": "hr@company.com"}, "YELLOW")
check("legit_text_only", "Software intern, onsite interview, apply via careers portal, no fee", {}, "YELLOW")

# ============================================================
# OBVIOUS SCAMS (should be RED)
# ============================================================
check("scam_reg_fee", "Pay Rs 1500 registration fee before offer", {"asked_money": "Yes", "money_for": "registration fee"}, "RED", ["R01", "R02"])
check("scam_training_fee", "Training fee Rs 5000 required to join", {"asked_money": "Yes", "money_for": "training fee"}, "RED", ["R02"])
check("scam_cert_fee", "Pay Rs 500 to download completion certificate", {"asked_money": "Yes", "money_for": "certificate fee"}, "RED", ["R02"])
check("scam_deposit_tasks", "Deposit Rs 1000 to unlock premium tasks", {"asked_money": "Yes", "money_for": "deposit for tasks"}, "RED", ["R04"])
check("scam_withdrawal_fee", "Pay Rs 200 withdrawal fee to get your stipend", {"asked_money": "Yes", "money_for": "withdrawal fee"}, "RED", ["R05"])
check("scam_gift_card", "Send Amazon gift card for verification", {"asked_money": "Yes", "money_for": "gift card", "payment_method": "gift card"}, "RED", ["R06"])
check("scam_otp", "Share OTP to verify your account", {"documents_requested": "OTP"}, "RED", ["R07"])
check("scam_password", "Send your password for background check", {"documents_requested": "password"}, "RED", ["R07"])
check("scam_govt_whatsapp_pay", "Government recruitment via WhatsApp, pay Rs 999", {"channel": "WhatsApp", "asked_money": "Yes", "money_for": "verification fee"}, "RED", ["R08"])
check("scam_task_deposit", "Earn Rs 5000/day rating products. Deposit Rs 1000 to unlock premium tasks.", {}, "RED", ["R04"])
check("scam_codsoft", "Join CodSoft internship, get certificate after Rs 199", {"asked_money": "Yes", "money_for": "certificate"}, "RED", ["R02"])
check("scam_oasis", "Oasis Infobyte internship, pay Rs 299 for certificate", {"asked_money": "Yes", "money_for": "certificate"}, "RED", ["R02"])
check("scam_bharat_intern", "Bharat Intern, certificate fee Rs 499", {"asked_money": "Yes", "money_for": "certificate fee"}, "RED", ["R02"])

# ============================================================
# ADVERSARIAL CASES (negation handling)
# ============================================================
check("adv_no_reg_fee", "There is absolutely NO registration fee. Apply today.", {}, "YELLOW")
check("adv_never_ask_otp", "We never ask for OTP or password. Legitimate company.", {}, "YELLOW")
check("adv_no_payment_required", "No payment required at any stage. Free application.", {}, "YELLOW")
check("adv_company_no_fee", "Company does not charge any registration or training fees.", {}, "YELLOW")
check("adv_free_internship", "Free internship, no hidden costs, no certificate fee.", {}, "YELLOW")

# ============================================================
# STRONG WARNING CASES (should be YELLOW)
# ============================================================
check("warn_unrealistic_earnings", "Earn Rs 5000 per day working 2 hours daily from home", {}, "YELLOW")
check("warn_urgency", "Limited seats! Join today only! Offer expires in 2 hours!", {}, "YELLOW")
check("warn_guaranteed", "Guaranteed selection! 100% job assurance!", {}, "YELLOW")
check("warn_unexpected_wa", "Unexpected WhatsApp message offering high-paying internship", {}, "YELLOW")
check("warn_linkedin_to_wa", "Saw on LinkedIn, they asked to continue on WhatsApp", {"platform": "LinkedIn", "channel": "WhatsApp"}, "YELLOW")
check("warn_domain_mismatch", "", {"company": "Microsoft", "email": "microsoft.hr@gmail.com"}, "YELLOW")
# Bank details early - per research this IS a HARD RED (R07), so RED is correct
check("warn_bank_details_early", "Send bank account details and PAN before offer letter", {"documents_requested": "bank account details, PAN"}, "RED", ["R07", "W08"])
check("warn_referral_heavy", "Refer 10 friends and earn Rs 50000/month commission", {}, "YELLOW")
check("warn_repetitive_tasks", "Simple task: like and rate videos all day, repetitive work", {}, "YELLOW")
check("warn_vague_high_pay", "Vague responsibilities, flexible work, Rs 1 lakh per month", {}, "YELLOW")
check("warn_no_details", "Internship available, high stipend, work from home", {}, "YELLOW")

# ============================================================
# AMBIGUOUS / BORDERLINE CASES
# ============================================================
check("ambig_whatsapp_legit", "After applying on careers portal, shortlisted candidates get WhatsApp for interview scheduling", {"platform": "Company site", "channel": "WhatsApp"}, "YELLOW")
check("ambig_gmail_small_co", "Startup internship, apply at hr@startup.io", {"company": "Startup.io", "email": "hr@gmail.com"}, "YELLOW")
check("ambig_high_stipend_real", "Quantitative Research Intern, Rs 1.5L/month, PhD required, apply at careers.janestreet.com", {"company": "Jane Street", "website": "janestreet.com", "apply_url": "careers.janestreet.com", "email": "recruiting@janestreet.com", "role_details": "PhD required, quantitative research, 3 months NYC", "channel": "Email", "platform": "Company site"}, "GREEN")
check("ambig_remote_clear", "Remote internship, specific role: React frontend, 6 months, Rs 60k, apply at company.com/careers", {"company": "Company", "website": "company.com", "apply_url": "company.com/careers", "email": "hr@company.com", "role_details": "React frontend, 6 months remote, Rs 60k/month", "channel": "Email", "platform": "Company site"}, "GREEN")

# ============================================================
# CERTIFICATE MILL SPECIFIC
# ============================================================
check("mill_codsoft", "CodSoft Python internship, certificate after Rs 199", {"asked_money": "Yes", "money_for": "certificate"}, "RED", ["R02"])
check("mill_oasis", "Oasis Infobyte web dev, pay Rs 299 for completion certificate", {"asked_money": "Yes", "money_for": "completion certificate"}, "RED", ["R02"])
check("mill_prodigy", "Prodigy Infotech data science, certificate fee Rs 499", {"asked_money": "Yes", "money_for": "certificate fee"}, "RED", ["R02"])
check("mill_bluestock", "Bluestock marketing intern, get certified for Rs 99", {"asked_money": "Yes", "money_for": "certified"}, "RED")

# ============================================================
# EDGE CASES
# ============================================================
check("edge_empty", "", {}, "YELLOW")
check("edge_only_verify", "No fee, apply at careers.realcompany.com", {"company": "RealCompany", "website": "realcompany.com", "apply_url": "careers.realcompany.com", "email": "hr@realcompany.com", "role_details": "Software intern 3 months"}, "GREEN")
# Strong warn overcome: "Earn high stipend" triggers W01 but with 4 verify hits should be GREEN
check("edge_strong_warn_overcome", "Earn high stipend! But apply at careers.microsoft.com, no fee, specific role", {"company": "Microsoft", "website": "microsoft.com", "apply_url": "careers.microsoft.com", "email": "hr@microsoft.com", "role_details": "Specific role details here", "channel": "Email", "platform": "Company site"}, "GREEN")

check("reg_v02_case_insensitive", "Join us!", {"company": "Microsoft", "website": "microsoft.com", "email": "hr@microsoft.com"}, "GREEN", ["V02"])
check("reg_wk04_removed", "Email at hr@gmail.com", {}, "YELLOW")
check("reg_negation_before_only", "No fee for registration fee required", {}, "YELLOW")


# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*50}")
print(f"Total failures: {len(fails)}")
if fails:
    for f in fails:
        print(f"  FAIL: {f}")
    raise SystemExit(1)
else:
    print("ALL TESTS PASSED")
    raise SystemExit(0)