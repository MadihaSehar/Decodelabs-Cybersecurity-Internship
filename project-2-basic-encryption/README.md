# Project 2: Basic Encryption & Decryption 🔐

Part of the **DecodeLabs Cyber Security Industrial Training Kit**.

## 📌 Project Overview
This project implements reversible classic cryptographic techniques (Caesar Cipher & Vigenère Cipher) in Python. The goal is to demonstrate fundamental data confidentiality concepts, key-based symmetric encryption, and string transformation algorithms.

---

## 📐 Mathematical Foundations

### 1. Caesar Cipher (Fixed Shift Key)
Mathematical formula for shift key $n$ and character position $x \in [0, 25]$:
- **Encryption**: $E_n(x) = (x + n) \pmod{26}$
- **Decryption**: $D_n(x) = (x - n) \pmod{26}$

### 2. Vigenère Cipher (Keyword-based Polyalphabetic Cipher)
Enhances security by shifting each character using the positional value of a repeating keyword:
- **Encryption**: $E_K(x_i) = (x_i + k_i) \pmod{26}$
- **Decryption**: $D_K(c_i) = (c_i - k_i) \pmod{26}$

---

## ✨ Features
- **Case Preservation**: Retains uppercase (`A-Z`) and lowercase (`a-z`) casing during encryption and decryption.
- **Edge Case Protection**: Spaces, numbers (`0-9`), and punctuation symbols remain intact.
- **Dual Cipher Modes**:
  1. **Caesar Cipher**: Standard single shift key (1-25).
  2. **Vigenère Cipher (Bonus)**: Keyword-based polyalphabetic encryption.
- **Round-Trip Validation**: Verifies that decrypted text matches the original input message exactly.

---

## 🛠️ Key Skills Demonstrated
- Symmetric key encryption concepts & modular arithmetic (`% 26`).
- ASCII char-to-integer conversions using `ord()` and `chr()`.
- Error handling and input validation in interactive CLI apps.

---

## 🚀 How to Run

1. Open your terminal or command prompt.
2. Navigate to the project directory:
   ```bash
   cd project-2-basic-encryption
   ```
3. Run the Python script:
   ```bash
   python basic_encryption.py
   ```
4. Select option `1` for Caesar Cipher or option `2` for Vigenère Cipher.

---


Result:
<img width="1293" height="454" alt="image" src="https://github.com/user-attachments/assets/59a4464d-1f3c-4606-a48b-f93fad1196b4" />
