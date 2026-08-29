# Project 1: Password Strength Checker 🔒

Part of the **DecodeLabs Cyber Security Industrial Training Kit**.

## 📌 Project Overview
The **Password Strength Checker** is a Python utility designed to evaluate the strength and security level of user-supplied passwords. It evaluates passwords based on character length, diversity (uppercase, lowercase, digits, symbols), and checks against a blocklist of commonly breached passwords.

---

## ✨ Features
- **Leaked Password Blocklist**: Instantly flags extremely common or leaked passwords (e.g., `password`, `123456`, `qwerty`).
- **Character Variety Analysis**: Verifies presence of Uppercase (`A-Z`), Lowercase (`a-z`), Digits (`0-9`), and Symbols (`!@#$%^&*`).
- **Dynamic Rating System**: Classifies passwords into **WEAK**, **MEDIUM**, or **STRONG**:
  - 🛑 **Weak**: Length < 8 or variety score ≤ 1 (or listed on common leak lists).
  - 🟡 **Medium**: Length ≥ 8 and variety score ≥ 3.
  - 🟢 **Strong**: Length ≥ 12 and variety score == 4 (all character sets used).
- **Actionable Security Feedback**: Returns human-readable suggestions to improve password complexity.

---

## 🛠️ Key Skills Demonstrated
- Python string manipulation (`any()`, `string.punctuation`, case checks).
- Dictionary data structures & conditional evaluation.
- Security best practices (Password policy enforcement & Breach list screening).

---

## 🚀 How to Run

1. Open your terminal or command prompt.
2. Navigate to the project directory:
   ```bash
   cd project-1-password-checker
   ```
3. Run the Python script:
   ```bash
   python password_strength_checker.py
   ```
4. Enter any password to check its strength report, or type `quit` to exit.

---

RESULT:
<img width="1214" height="458" alt="image" src="https://github.com/user-attachments/assets/c6cef7c8-78b2-4e32-b9ca-1c3324479ad7" />








=============================================
```
