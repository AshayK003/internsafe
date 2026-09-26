"""internsafe - clean UI for internship scam detection."""
import streamlit as st

from rules import Hit, Result, analyze


# --- Page config ---
st.set_page_config(
    page_title="internsafe — Internship Scam Checker",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# --- Custom CSS ---
st.markdown("""
<style>
/* Dark theme - black background, white text */
:root {
    --bg-primary: #000000;
    --bg-secondary: #111111;
    --bg-card: #1a1a1a;
    --bg-input: #0d0d0d;
    --border-color: #333333;
    --text-primary: #ffffff;
    --text-secondary: #e5e5e5;
    --text-muted: #a3a3a3;
    --accent-red: #ef4444;
    --accent-yellow: #f59e0b;
    --accent-green: #22c55e;
    --accent-blue: #3b82f6;
}

/* Global */
.main .block-container {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
}
.stApp {
    background-color: var(--bg-primary) !important;
}

/* Verdict cards */
.verdict-red { background: #1a0000 !important; border-left: 4px solid var(--accent-red); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; color: var(--text-primary) !important; }
.verdict-yellow { background: #1a1300 !important; border-left: 4px solid var(--accent-yellow); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; color: var(--text-primary) !important; }
.verdict-green { background: #001a00 !important; border-left: 4px solid var(--accent-green); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; color: var(--text-primary) !important; }
.verdict-title { font-weight: 600; font-size: 1.1rem; margin-bottom: 0.25rem; color: var(--text-primary) !important; }
.verdict-summary { color: var(--text-secondary) !important; font-size: 0.95rem; }

/* Reason items */
.reason-item { background: var(--bg-card) !important; border: 1px solid var(--border-color); border-radius: 0.375rem; padding: 0.75rem; margin: 0.5rem 0; color: var(--text-primary) !important; }
.reason-label { font-weight: 500; color: var(--text-primary) !important; }
.reason-evidence { color: var(--text-muted) !important; font-size: 0.875rem; margin-top: 0.25rem; font-family: monospace; }

/* Section headers */
.section-header { font-weight: 600; color: var(--text-primary) !important; margin-top: 1.5rem; margin-bottom: 0.5rem; }

/* Hide streamlit branding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Buttons */
.stButton > button {
    color: var(--text-primary) !important;
    background-color: var(--bg-input) !important;
    border: 1px solid var(--border-color) !important;
}
.stButton > button:hover {
    background-color: var(--bg-secondary) !important;
    border-color: #444 !important;
}
.stButton > button:focus {
    box-shadow: 0 0 0 2px var(--accent-blue) !important;
}
.stButton > button[kind="primary"] {
    background-color: var(--accent-blue) !important;
    border-color: var(--accent-blue) !important;
    color: white !important;
}

/* Text area and inputs */
.stTextArea textarea, .stTextInput input {
    color: var(--text-primary) !important;
    background-color: var(--bg-input) !important;
    border: 1px solid var(--border-color) !important;
    caret-color: var(--text-primary) !important;
}
.stTextArea textarea::placeholder, .stTextInput input::placeholder {
    color: var(--text-muted) !important;
}

/* Segmented control */
[data-baseweb="segmented-control"] {
    background-color: var(--bg-input) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 0.5rem !important;
}
[data-baseweb="segmented-control"] [role="button"] {
    color: var(--text-secondary) !important;
    background-color: transparent !important;
}
[data-baseweb="segmented-control"] [role="button"][aria-selected="true"] {
    background-color: var(--accent-blue) !important;
    color: white !important;
}

/* Expander */
.streamlit-expanderHeader {
    color: var(--text-primary) !important;
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border-color) !important;
}
.streamlit-expanderContent {
    color: var(--text-primary) !important;
    background-color: var(--bg-primary) !important;
    border: 1px solid var(--border-color) !important;
    border-top: none !important;
}

/* Tabs */
[data-baseweb="tab-list"] {
    background-color: var(--bg-secondary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 0.5rem !important;
}
[data-baseweb="tab"] {
    color: var(--text-secondary) !important;
}
[data-baseweb="tab"][aria-selected="true"] {
    color: var(--text-primary) !important;
    background-color: var(--bg-card) !important;
}

/* Markdown text */
.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span, .stMarkdown div {
    color: var(--text-primary) !important;
}
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
    color: var(--text-primary) !important;
}

/* Label text */
label, .stSelectbox label, .stTextInput label, .stTextArea label, .stSegmentedControl label {
    color: var(--text-primary) !important;
}

/* Divider */
hr {
    border-color: var(--border-color) !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #555; }
</style>
""", unsafe_allow_html=True)


# --- Sample data (simplified labels) ---
SAMPLES = {
    "Scam: Registration fee": {
        "text": "Pay Rs 1500 registration fee to confirm your internship. Send to UPI ID.",
        "meta": {"asked_money": "Yes", "money_for": "registration fee", "payment_method": "UPI"},
        "tag": "red",
    },
    "Scam: Certificate fee (CodSoft)": {
        "text": "CodSoft Python internship. Get certificate after paying Rs 199.",
        "meta": {"asked_money": "Yes", "money_for": "certificate fee"},
        "tag": "red",
    },
    "Scam: Deposit to unlock tasks": {
        "text": "Earn Rs 5000/day rating products. Deposit Rs 1000 to unlock premium tasks.",
        "meta": {},
        "tag": "red",
    },
    "Scam: OTP request": {
        "text": "Share OTP for verification before we send offer letter.",
        "meta": {"documents_requested": "OTP"},
        "tag": "red",
    },
    "Legit: Microsoft (verified)": {
        "text": "Microsoft Software Engineering Intern. Apply at careers.microsoft.com. No application fee. 3 months, Bangalore, Rs 80k/month.",
        "meta": {"company": "Microsoft", "website": "microsoft.com", "apply_url": "careers.microsoft.com", "email": "hr@microsoft.com", "role_details": "3 months, Bangalore, backend development, Rs 80k/month, mentorship", "channel": "Email", "platform": "Company site"},
        "tag": "green",
    },
    "Legit: Startup (verified)": {
        "text": "Startup.io Backend Intern. Apply at startup.io/careers. No fee. 6 months remote Rs 40k.",
        "meta": {"company": "Startup.io", "website": "startup.io", "apply_url": "startup.io/careers", "email": "jobs@startup.io", "role_details": "6 months remote, Node.js, Rs 40k/month", "channel": "Email", "platform": "Company site"},
        "tag": "green",
    },
    "Warning: Too good to be true": {
        "text": "Earn Rs 5000 per day working 2 hours daily from home. No experience needed.",
        "meta": {},
        "tag": "yellow",
    },
    "Warning: Email domain mismatch": {
        "text": "Join our team! Great opportunity.",
        "meta": {"company": "Microsoft", "email": "microsoft.hr@gmail.com"},
        "tag": "yellow",
    },
    "Adversarial: Claims no fee": {
        "text": "There is absolutely NO registration fee. Apply today for free internship.",
        "meta": {},
        "tag": "yellow",
    },
    "Warning: LinkedIn to WhatsApp": {
        "text": "Saw on LinkedIn, they asked to continue on WhatsApp for interview.",
        "meta": {"platform": "LinkedIn", "channel": "WhatsApp"},
        "tag": "yellow",
    },
}


def load_sample(key: str):
    sample = SAMPLES[key]
    st.session_state["sample_text"] = sample["text"]
    st.session_state["sample_meta"] = sample["meta"]


def verdict_card(verdict: str, summary: str):
    """Render a clean verdict card."""
    if verdict == "RED":
        cls, icon, title = "verdict-red", "🔴", "High Risk — Likely Scam"
    elif verdict == "YELLOW":
        cls, icon, title = "verdict-yellow", "🟡", "Caution — Verify Before Proceeding"
    else:
        cls, icon, title = "verdict-green", "🟢", "Low Risk — No Clear Red Flags"

    st.markdown(f"""
    <div class="{cls}">
        <div class="verdict-title">{icon} {title}</div>
        <div class="verdict-summary">{summary}</div>
    </div>
    """, unsafe_allow_html=True)


def reason_card(label: str, evidence: str):
    """Render a single reason item."""
    st.markdown(f"""
    <div class="reason-item">
        <div class="reason-label">{label}</div>
        <div class="reason-evidence">"{evidence}"</div>
    </div>
    """, unsafe_allow_html=True)


# --- Header ---
st.title("🛡️ internsafe")
st.markdown("*Check an internship offer for red flags. Paste the post, get a clear verdict.*")

# --- Quick samples (compact chips) ---
with st.expander("💡 Try a sample", expanded=False):
    cols = st.columns(2)
    for i, (name, data) in enumerate(SAMPLES.items()):
        with cols[i % 2]:
            tag_class = f"sample-{data['tag']}"
            if st.button(name, key=f"sample_{i}", use_container_width=True):
                load_sample(name)
                st.rerun()

st.divider()

# --- Input: Post text ---
st.subheader("Internship Post / Message")
text = st.text_area(
    "",
    height=140,
    placeholder=(
        "Paste the LinkedIn post, WhatsApp message, or job description here...\n\n"
        "Example: 'Microsoft SWE Intern. Apply at careers.microsoft.com. No fee. 3 months, Bangalore, Rs 80k/month.'"
    ),
    value=st.session_state.get("sample_text", ""),
    label_visibility="collapsed",
)

# --- Optional verification details ---
sample_meta = st.session_state.get("sample_meta", {})
def get_sample(key, default=""):
    return sample_meta.get(key, default)

with st.expander("Add company details (optional — improves accuracy)", expanded=False):
    c1, c2 = st.columns(2)
    with c1:
        company = st.text_input("Company name", value=get_sample("company"), placeholder="Microsoft")
        website = st.text_input("Company website", value=get_sample("website"), placeholder="microsoft.com")
        apply_url = st.text_input("Application URL", value=get_sample("apply_url"), placeholder="careers.microsoft.com")
    with c2:
        email = st.text_input("Recruiter email", value=get_sample("email"), placeholder="hr@microsoft.com")
        role_details = st.text_area(
            "Role details", value=get_sample("role_details"),
            placeholder="Duration, location, stipend, responsibilities...",
            height=80,
        )
        recruiter_name = st.text_input("Recruiter name (if known)", value=get_sample("recruiter_name"), placeholder="Priya Sharma")

st.divider()

# --- Red-flag signals ---
st.subheader("What happened? (Check all that apply)")

col1, col2 = st.columns(2)
with col1:
    asked = st.segmented_control(
        "Asked for money?",
        options=["No", "Yes"],
        default=get_sample("asked_money", "No"),
    )
with col2:
    channel = st.segmented_control(
        "Contact method",
        options=["LinkedIn", "WhatsApp", "Telegram", "Email", "Other"],
        default=get_sample("channel", "LinkedIn"),
    )

money_for = ""
payment_method = ""
if asked == "Yes":
    c3, c4 = st.columns(2)
    with c3:
        money_for = st.text_input("What for?", value=get_sample("money_for"), placeholder="registration fee, training fee, certificate fee, deposit...")
    with c4:
        payment_method = st.text_input("Payment method", value=get_sample("payment_method"), placeholder="UPI, bank transfer, gift card, crypto...")

platform = st.segmented_control(
    "Where did you first see it?",
    options=["LinkedIn", "Internshala", "Naukri", "Company site", "Other"],
    default=get_sample("platform", "LinkedIn"),
)

documents = st.text_input("Documents requested", value=get_sample("documents_requested"), placeholder="Aadhaar, PAN, bank details, passport, OTP...")

st.divider()

# --- Analyze ---
if st.button("🔍 Check for Red Flags", width="stretch", type="primary"):
    if not (text or "").strip():
        st.warning("Please paste the internship post first.")
        st.stop()

    meta = {
        "asked_money": asked,
        "money_for": money_for,
        "payment_method": payment_method,
        "channel": channel,
        "platform": platform,
        "email": email,
        "company": company,
        "website": website,
        "apply_url": apply_url,
        "role_details": role_details,
        "recruiter_name": recruiter_name,
        "documents_requested": documents,
        "explicit_no_fee": "no fee" if "no fee" in text.lower() or "no payment" in text.lower() else "",
    }

    result: Result = analyze(text, meta)

    # --- Verdict ---
    verdict_card(result.verdict, result.summary)

    # --- Reasons (plain language) ---
    with st.expander("Why this result?", expanded=True):
        # Group by severity with friendly labels
        groups = {
            "🔴 **Deal-breakers** (any one = High Risk)": [h for h in result.hits if h.severity == "HARD_RED"],
            "🟠 **Strong warnings**": [h for h in result.hits if h.severity == "STRONG_WARN"],
            "🟡 **Context signals**": [h for h in result.hits if h.severity == "WEAK_WARN"],
            "🟢 **Positive signs**": [h for h in result.hits if h.severity == "VERIFY"],
        }

        any_hits = False
        for group_title, hits in groups.items():
            if hits:
                any_hits = True
                st.markdown(f"**{group_title}**")
                for h in hits:
                    reason_card(h.message, h.evidence)
        if not any_hits:
            st.info("No specific patterns matched from the information provided.")

    # --- Missing info ---
    if result.missing_info:
        with st.expander("Add these details for a more accurate check", expanded=False):
            for m in result.missing_info:
                st.markdown(f"- {m}")

    st.divider()

    # --- Verification guide ---
    st.subheader("How to verify independently")
    tabs = st.tabs(["Company", "Domain", "Communication", "Golden Rules"])

    with tabs[0]:
        st.markdown("""
        - Search the company on **LinkedIn** — real employees, complete history, verified badge?
        - Check **Glassdoor** / **AmbitionBox** for reviews
        - Search Reddit/Quora for "[company] internship scam"
        - Verify the company has a real website (not just a LinkedIn page)
        """)
    with tabs[1]:
        st.markdown("""
        - Paste the website in **who.is** or **ICANN Lookup**
        - Domain created **less than 6 months ago**? Major red flag
        - Does the domain match the company name exactly?
        - Free subdomain (wordpress, wix, blogspot)? Be careful
        """)
    with tabs[2]:
        st.markdown("""
        - Official email uses **company domain** (not @gmail, @yahoo, @outlook)
        - Hiring happens on company portal or official email — not WhatsApp/Telegram
        - If they moved you from LinkedIn to WhatsApp instantly — verify independently
        """)
    with tabs[3]:
        st.markdown("""
        - **Never pay** to apply, join, train, or download a certificate
        - Legit companies don't ask for OTP, Aadhaar, or bank details before an offer
        - "Guaranteed selection" or "earn ₹5000/day for 2 hours work" = scam
        - **Low Risk ≠ Safe** — this tool only checks for known red flags
        """)

# --- Footer ---
st.markdown("---")
st.caption("internsafe • Deterministic rule engine • No AI, no tracking, no data stored • Based on I4C, AICTE, FTC, LinkedIn guidance")