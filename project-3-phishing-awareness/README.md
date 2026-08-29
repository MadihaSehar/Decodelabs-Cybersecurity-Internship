# Project 3: Phishing Awareness Analysis 🎣⚠️

Part of the **DecodeLabs Cyber Security Industrial Training Kit**.

## 📌 Project Overview
The **Phishing Awareness Analyzer** is a defensive triage helper designed to analyze email and message artifacts to spot social engineering, phishing, and Business Email Compromise (BEC) tactics.

It follows the **Pause ➔ Verify ➔ Report** security model to flag suspicious patterns, assign a risk score, and return a clear action recommendation.

---

## 🔍 Phishing Indicators Analyzed
The triage engine screens messages across 8 key risk vectors:

1. **Urgency & Fear Tactics**: Flags high-pressure keywords like `immediately`, `account suspended`, `verify within 24 hours`.
2. **Authority Impersonation**: Detects terms like `CEO`, `IT Security`, `Government`, `Strictly Confidential`.
3. **Sensitive Info Requests**: Checks for requests for `password`, `OTP`, `credit card`, `wire transfer`, `login credentials`.
4. **Generic Greetings**: Identifies mass phishing signatures like `Dear Customer`, `Dear Account Holder`.
5. **Suspicious Link Patterns**: Scans for URL shorteners (`bit.ly`, `tinyurl`), raw IP addresses, and multi-subdomain links.
6. **Brand Impersonation & Typosquatting**: Checks domain names against known brands and homoglyph substitutions (`0` for `o`, `@` for `a`).
7. **Display-Name Spoofing**: Identifies executive/authority display names sending from free public domains (e.g. `gmail.com`).
8. **Dangerous Attachment Extensions**: Scans for hazardous file types like `.exe`, `.iso`, `.js`, `.vbs`, `.scr`.

---

## 🚦 Triage Scoring & Actions

| Score | Verdict | Recommended Action | Description |
|---|---|---|---|
| **0** | 🟢 **Safe** | `Close` | No phishing indicators detected. |
| **1 - 4** | 🟡 **Suspicious** | `Warn User` | Moderate indicators present. Exercise caution. |
| **5+** | 🛑 **Malicious** | `Block & Escalate` | High-confidence phishing/BEC attempt detected. |

---

## 🛠️ Key Skills Demonstrated
- Regex pattern matching & text triage logic.
- Threat modeling & phishing vector classification.
- Defensive SOC/Email Incident Triage principles.

---

## 🚀 How to Run

1. Open your terminal or command prompt.
2. Navigate to the project directory:
   ```bash
   cd project-3-phishing-awareness
   ```
3. Run the Python script:
   ```bash
   python phishing_awareness_analyzer.py
   ```
4. Choose `1` to test built-in sample phishing/BEC emails, or `2` to analyze a custom email message.

---

## 📊 Sample Output
```text
=======================================================
Phishing Triage Report: Sample 1 - Fake IT password reset
=======================================================
Verdict        : Malicious
Risk score     : 14
Recommended action: Block & Escalate
-------------------------------------------------------
Red flags found:
  • Urgency/pressure language: immediately, account suspended, expires in
  • Authority impersonation language: it security
  • Requests sensitive info: password
  • Generic greeting (mass-phishing signal): dear customer
  • Suspicious link pattern detected: matches 'bit\.ly'
  • Possible brand impersonation / lookalike domain: 'logins-updates.com'
  • Dangerous attachment type: 'Security_Update_2024.iso'
=======================================================
```
