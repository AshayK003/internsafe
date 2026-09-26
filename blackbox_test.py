"""Black-box test: simulate real user inputs through the rule engine."""
from rules import analyze

tests = [
    # Scam: registration fee
    ("Pay Rs 1500 registration fee to confirm internship", {"asked_money": "Yes", "money_for": "registration fee"}),
    # Scam: certificate mill
    ("CodSoft Python internship, certificate after Rs 199", {"asked_money": "Yes", "money_for": "certificate"}),
    # Scam: task deposit
    ("Earn Rs 5000/day rating products. Deposit 1000 to unlock.", {}),
    # Scam: OTP request
    ("Share OTP for verification", {"documents_requested": "OTP"}),
    # Legit with full meta
    ("Microsoft SWE Intern. Apply at careers.microsoft.com. No fee. 3 months Bangalore Rs 80k.",
     {"company": "Microsoft", "website": "microsoft.com", "apply_url": "careers.microsoft.com", "email": "hr@microsoft.com", "role_details": "3 months Bangalore backend Rs 80k", "channel": "Email", "platform": "Company site"}),
    # Legit minimal
    ("Software intern, interview via Meet, apply at hr@company.com", {"email": "hr@company.com"}),
    # Adversarial: negation
    ("There is absolutely NO registration fee. Apply today.", {}),
    # Warning: unrealistic earnings
    ("Earn Rs 5000 per day working 2 hours daily from home", {}),
    # Warning: domain mismatch
    ("", {"company": "Microsoft", "email": "microsoft.hr@gmail.com"}),
]

print("=" * 60)
print("BLACK-BOX TEST RESULTS")
print("=" * 60)

for i, (text, meta) in enumerate(tests, 1):
    r = analyze(text, meta)
    print(f"\nTest {i}: {r.verdict}")
    print(f"  Input: {text[:80] if text else '(meta only)'}")
    print(f"  Summary: {r.summary}")
    if r.hits:
        for h in r.hits:
            print(f"  -> {h.rule_id} [{h.severity}]: {h.message}")
    if r.missing_info:
        print(f"  Missing: {r.missing_info}")

print("\n" + "=" * 60)
print("All black-box tests executed.")
print("=" * 60)