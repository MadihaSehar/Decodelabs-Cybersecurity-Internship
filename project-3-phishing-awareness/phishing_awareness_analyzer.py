"""
DecodeLabs Cyber Security Industrial Training Kit
Project 3: Phishing Awareness Analysis

Goal: Analyze sample emails/messages to identify phishing attempts —
spot suspicious links/keywords, list red flags, and explain why a
message is unsafe.

Key Skills demoed: threat analysis, awareness of cyber attacks,
security thinking.

This tool does NOT send, click, or interact with anything. It is a
purely defensive/analytical triage helper: given the text of a message
(sender, subject, body), it flags known phishing indicators and
returns a Safe / Suspicious / Malicious verdict, following the
Pause -> Verify -> Report triage model from the training material.
"""

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Reference data: known phishing indicators
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "verify your account",
    "account will be locked", "account suspended", "expires in",
    "final notice", "within 24 hours", "immediate action required",
    "confirm your identity", "unusual activity", "unauthorized access",
]

AUTHORITY_KEYWORDS = [
    "ceo", "director", "it security", "law enforcement", "irs",
    "government", "compliance department", "strictly confidential",
    "do not discuss", "bypass standard procedure",
]

SENSITIVE_INFO_REQUESTS = [
    "password", "otp", "one-time code", "verification code", "ssn",
    "social security", "credit card", "cvv", "pin number",
    "wire transfer", "bank details", "login credentials",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "hello user",
]

SUSPICIOUS_LINK_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co/", r"goo\.gl",     # URL shorteners
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",                  # raw IP address links
    r"[a-z0-9-]+\.[a-z]{2,}\.[a-z0-9-]+\.[a-z]{2,}",        # nested/lookalike subdomains
]

LOOKALIKE_SUBSTITUTIONS = {
    "0": "o", "1": "l", "5": "s", "@": "a", "vv": "w",
}

COMMON_BRANDS = [
    "paypal", "amazon", "microsoft", "google", "apple", "netflix",
    "bank", "linkedin",
]

DANGEROUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".js", ".vbs", ".iso", ".bat", ".jar", ".hta",
]


@dataclass
class TriageResult:
    verdict: str = "Safe"                  # Safe | Suspicious | Malicious
    score: int = 0
    red_flags: list = field(default_factory=list)
    action: str = "Close"                  # Close | Warn User | Block & Escalate


def _find_matches(text: str, phrases: list) -> list:
    """
    Case-insensitive phrase search using word boundaries, so 'urgent'
    doesn't match inside 'non-urgent'. Negated phrases like 'no immediate
    action' or 'not urgent' are skipped to avoid false positives on
    legitimate messages.
    """
    text_lower = text.lower()
    matches = []
    for phrase in phrases:
        pattern = r"(?<!non-)(?<!non )(?<!not )\b" + re.escape(phrase) + r"\b"
        if re.search(pattern, text_lower):
            matches.append(phrase)
    return matches


def _check_suspicious_links(body: str) -> list:
    found = []
    for pattern in SUSPICIOUS_LINK_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            found.append(f"Suspicious link pattern detected: matches '{pattern}'")
    return found


def _check_lookalike_domain(sender_domain: str) -> list:
    """Very simple heuristic: flag brand names combined with extra
    words/hyphens/typosquat-style character substitutions in the domain."""
    flags = []
    domain_lower = sender_domain.lower()
    for brand in COMMON_BRANDS:
        if brand in domain_lower and domain_lower != f"{brand}.com":
            flags.append(
                f"Possible brand impersonation / lookalike domain: '{sender_domain}' "
                f"references '{brand}' but is not the official domain."
            )
    for char, lookalike in LOOKALIKE_SUBSTITUTIONS.items():
        if char in domain_lower:
            flags.append(
                f"Domain contains a character substitution ('{char}') often used "
                f"in typosquatting/homoglyph attacks: '{sender_domain}'"
            )
            break
    return flags


def _check_sender_display_mismatch(display_name: str, sender_email: str) -> list:
    """Flags cases where the friendly display name implies an internal/
    trusted identity but the actual email domain looks external."""
    flags = []
    if "@" not in sender_email:
        return flags
    domain = sender_email.split("@")[-1].lower()
    free_mail_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    trusted_titles = ["ceo", "director", "manager", "support", "admin", "hr", "it"]

    if any(title in display_name.lower() for title in trusted_titles) and domain in free_mail_providers:
        flags.append(
            f"Display-name spoofing: sender shows as '{display_name}' (implies authority) "
            f"but the email address uses a free/public domain ('{domain}')."
        )
    return flags


def analyze_message(
    subject: str = "",
    display_name: str = "",
    sender_email: str = "",
    body: str = "",
    attachments: list = None,
) -> TriageResult:
    """
    Run a full phishing triage on a message and return a TriageResult
    with a verdict, score, list of red flags, and recommended action.
    """
    attachments = attachments or []
    result = TriageResult()
    full_text = f"{subject}\n{body}"

    # 1. Urgency / pressure tactics
    urgency_hits = _find_matches(full_text, URGENCY_KEYWORDS)
    if urgency_hits:
        result.red_flags.append(f"Urgency/pressure language: {', '.join(urgency_hits)}")
        result.score += 2

    # 2. Authority impersonation
    authority_hits = _find_matches(full_text, AUTHORITY_KEYWORDS)
    if authority_hits:
        result.red_flags.append(f"Authority impersonation language: {', '.join(authority_hits)}")
        result.score += 2

    # 3. Requests for sensitive information
    sensitive_hits = _find_matches(full_text, SENSITIVE_INFO_REQUESTS)
    if sensitive_hits:
        result.red_flags.append(f"Requests sensitive info: {', '.join(sensitive_hits)}")
        result.score += 3

    # 4. Generic greeting (mass phishing indicator)
    greeting_hits = _find_matches(full_text, GENERIC_GREETINGS)
    if greeting_hits:
        result.red_flags.append(f"Generic greeting (mass-phishing signal): {', '.join(greeting_hits)}")
        result.score += 1

    # 5. Suspicious links
    link_flags = _check_suspicious_links(body)
    if link_flags:
        result.red_flags.extend(link_flags)
        result.score += 3

    # 6. Sender domain lookalike / typosquatting
    if sender_email:
        domain = sender_email.split("@")[-1] if "@" in sender_email else sender_email
        domain_flags = _check_lookalike_domain(domain)
        if domain_flags:
            result.red_flags.extend(domain_flags)
            result.score += 3

    # 7. Display-name spoofing
    mismatch_flags = _check_sender_display_mismatch(display_name, sender_email)
    if mismatch_flags:
        result.red_flags.extend(mismatch_flags)
        result.score += 3

    # 8. Dangerous attachments
    for att in attachments:
        if any(att.lower().endswith(ext) for ext in DANGEROUS_ATTACHMENT_EXTENSIONS):
            result.red_flags.append(f"Dangerous attachment type: '{att}'")
            result.score += 3

    # --- Verdict logic ---
    if result.score == 0:
        result.verdict = "Safe"
        result.action = "Close"
    elif result.score <= 4:
        result.verdict = "Suspicious"
        result.action = "Warn User"
    else:
        result.verdict = "Malicious"
        result.action = "Block & Escalate"

    if not result.red_flags:
        result.red_flags.append("No known phishing indicators detected.")

    return result


def print_report(label: str, result: TriageResult) -> None:
    print("\n" + "=" * 55)
    print(f"Phishing Triage Report: {label}")
    print("=" * 55)
    print(f"Verdict        : {result.verdict}")
    print(f"Risk score     : {result.score}")
    print(f"Recommended action: {result.action}")
    print("-" * 55)
    print("Red flags found:")
    for flag in result.red_flags:
        print(f"  • {flag}")
    print("=" * 55 + "\n")


# ---------------------------------------------------------------------------
# Sample messages for demonstration (based on common real-world patterns
# described in the training material — not real emails)
# ---------------------------------------------------------------------------

SAMPLE_MESSAGES = [
    {
        "label": "Sample 1 - Fake IT password reset",
        "subject": "Mandatory: Password expires in 24 hrs",
        "display_name": "IT Security",
        "sender_email": "support@logins-updates.com",
        "body": (
            "Dear Customer, your password will expire immediately. "
            "Click here to verify your account and avoid account suspended status: "
            "http://bit.ly/reset-now"
        ),
        "attachments": ["Security_Update_2024.iso"],
    },
    {
        "label": "Sample 2 - CEO wire transfer (BEC)",
        "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "display_name": "CEO Name",
        "sender_email": "ceo.urgent@gmail.com",
        "body": (
            "URGENT: Process the attached wire transfer instruction immediately. "
            "This is strictly confidential. Do not discuss with anyone. "
            "Bypass standard procedure."
        ),
        "attachments": [],
    },
    {
        "label": "Sample 3 - Legitimate internal email",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "display_name": "Sarah Lee",
        "sender_email": "sarah.lee@decodelabs.tech",
        "body": (
            "Hi Team,\n\nPlease review the attached project status for Q3 at your "
            "earliest convenience. No immediate action is required.\n\nThanks, Sarah."
        ),
        "attachments": ["Q3_Status.pdf"],
    },
]


if __name__ == "__main__":
    print("=== DecodeLabs Phishing Awareness Analyzer ===\n")
    print("1. Run built-in sample messages")
    print("2. Analyze your own message")
    choice = input("Choose an option (1 or 2): ").strip()

    if choice == "2":
        subject = input("Subject line: ")
        display_name = input("Sender display name (e.g. 'IT Security'): ")
        sender_email = input("Sender email address: ")
        print("Paste the message body, then press Enter twice to finish:")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        body = "\n".join(lines)
        attachments_raw = input("Attachment filenames, comma-separated (or leave blank): ")
        attachments = [a.strip() for a in attachments_raw.split(",") if a.strip()]

        result = analyze_message(subject, display_name, sender_email, body, attachments)
        print_report("Your Message", result)
    else:
        for sample in SAMPLE_MESSAGES:
            result = analyze_message(
                subject=sample["subject"],
                display_name=sample["display_name"],
                sender_email=sample["sender_email"],
                body=sample["body"],
                attachments=sample["attachments"],
            )
            print_report(sample["label"], result)
