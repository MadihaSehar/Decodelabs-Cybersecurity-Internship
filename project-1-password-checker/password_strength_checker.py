"""
DecodeLabs Cyber Security Industrial Training Kit
Project 1: Password Strength Checker

Goal: Evaluate whether a password is WEAK, MEDIUM, or STRONG
based on length and character variety (uppercase, digits, symbols).

Key Skills demoed: string handling, conditional logic, security basics.
"""

import string

# A tiny sample of extremely common leaked passwords, just to demonstrate
# the "blocklist" idea mentioned in the brief. In a real system this would
# be backed by a proper breached-password list (e.g. Have I Been Pwned).
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "letmein", "iloveyou",
}


def check_password_strength(password: str) -> dict:
    """
    Analyze a password and return a dict with:
      - length
      - has_upper, has_lower, has_digit, has_symbol
      - is_common (found in a leaked-password list)
      - strength: "Weak" | "Medium" | "Strong"
      - feedback: list of human-readable suggestions
    """
    feedback = []

    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)
    is_common = password.lower() in COMMON_PASSWORDS

    # --- Immediate disqualifiers ---
    if is_common:
        feedback.append("This password appears on common leaked-password lists. Avoid it entirely.")
        return {
            "length": length, "has_upper": has_upper, "has_lower": has_lower,
            "has_digit": has_digit, "has_symbol": has_symbol,
            "is_common": is_common, "strength": "Weak", "feedback": feedback,
        }

    if length < 8:
        feedback.append("Too short: use at least 8 characters (12+ is better).")

    # --- Character variety checks ---
    variety_score = sum([has_upper, has_lower, has_digit, has_symbol])

    if not has_upper:
        feedback.append("Add at least one uppercase letter (A-Z).")
    if not has_lower:
        feedback.append("Add at least one lowercase letter (a-z).")
    if not has_digit:
        feedback.append("Add at least one number (0-9).")
    if not has_symbol:
        feedback.append("Add at least one symbol (e.g. !@#$%^&*).")

    # --- Scoring logic (Weak / Medium / Strong) ---
    if length < 8 or variety_score <= 1:
        strength = "Weak"
    elif length >= 12 and variety_score == 4:
        strength = "Strong"
    elif length >= 8 and variety_score >= 3:
        strength = "Medium"
    else:
        strength = "Weak"

    if not feedback:
        feedback.append("Looks good! No issues detected.")

    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_common": is_common,
        "strength": strength,
        "feedback": feedback,
    }


def print_report(password: str) -> None:
    result = check_password_strength(password)

    print("\n" + "=" * 45)
    print(f"Password Strength Report")
    print("=" * 45)
    print(f"Length            : {result['length']}")
    print(f"Uppercase letter  : {'Yes' if result['has_upper'] else 'No'}")
    print(f"Lowercase letter  : {'Yes' if result['has_lower'] else 'No'}")
    print(f"Digit             : {'Yes' if result['has_digit'] else 'No'}")
    print(f"Symbol            : {'Yes' if result['has_symbol'] else 'No'}")
    print(f"Common/leaked     : {'Yes ⚠' if result['is_common'] else 'No'}")
    print("-" * 45)
    print(f"STRENGTH: {result['strength'].upper()}")
    print("-" * 45)
    print("Feedback:")
    for tip in result["feedback"]:
        print(f"  • {tip}")
    print("=" * 45 + "\n")


if __name__ == "__main__":
    print("=== DecodeLabs Password Strength Checker ===")
    print("(Type 'quit' to exit)\n")

    while True:
        pwd = input("Enter a password to check: ")
        if pwd.lower() == "quit":
            print("Goodbye!")
            break
        print_report(pwd)
