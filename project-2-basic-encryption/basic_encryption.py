"""
DecodeLabs Cyber Security Industrial Training Kit
Project 2: Basic Encryption & Decryption

Goal: Implement a simple, reversible encryption technique (Caesar cipher)
that protects data confidentiality using pure mathematical/programmatic logic.

Key Skills demoed: encryption concepts, logic building, data protection basics.

Core math (from the brief):
    Encrypt: E_n(x) = (x + n) % 26
    Decrypt: D_n(x) = (x - n) % 26
where x = character's position in the alphabet, n = shift key.
"""

import string


def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypt `text` using a Caesar cipher with the given `shift` (key).
    Preserves case, and leaves non-alphabetic characters (spaces,
    punctuation, digits) untouched — these are the "edge cases" the
    brief calls out.
    """
    result = []
    for char in text:
        if char.isupper():
            base = ord('A')
            new_char = chr((ord(char) - base + shift) % 26 + base)
        elif char.islower():
            base = ord('a')
            new_char = chr((ord(char) - base + shift) % 26 + base)
        else:
            new_char = char  # spaces, punctuation, digits pass through
        result.append(new_char)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """
    Decrypt text that was encrypted with caesar_encrypt using the same shift.
    Symmetric encryption: the same key locks and unlocks, just applied
    in reverse (a negative shift undoes a positive one).
    """
    return caesar_encrypt(text, -shift)


# --- Bonus: Vigenère cipher (mentioned in the brief as a stretch goal) ---
# Instead of one fixed shift, each letter of the message is shifted by
# the corresponding letter of a repeating keyword, making frequency
# analysis much harder than plain Caesar.

def vigenere_encrypt(text: str, keyword: str) -> str:
    keyword = keyword.upper()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(keyword[key_index % len(keyword)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def vigenere_decrypt(text: str, keyword: str) -> str:
    keyword = keyword.upper()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(keyword[key_index % len(keyword)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def run_caesar_demo() -> None:
    message = input("Enter the text to encrypt: ")

    while True:
        try:
            shift = int(input("Enter a shift key (1-25): "))
            if 1 <= shift <= 25:
                break
            print("Please enter a number between 1 and 25.")
        except ValueError:
            print("Please enter a valid whole number.")

    encrypted = caesar_encrypt(message, shift)
    decrypted = caesar_decrypt(encrypted, shift)

    print("\n" + "=" * 45)
    print("Caesar Cipher Result")
    print("=" * 45)
    print(f"Original text   : {message}")
    print(f"Shift key       : {shift}")
    print(f"Encrypted text  : {encrypted}")
    print(f"Decrypted text  : {decrypted}")
    print(f"Round-trip OK?  : {decrypted == message}")
    print("=" * 45 + "\n")


def run_vigenere_demo() -> None:
    message = input("Enter the text to encrypt: ")
    keyword = input("Enter a keyword (letters only): ").strip()
    while not keyword.isalpha():
        keyword = input("Keyword must be letters only. Try again: ").strip()

    encrypted = vigenere_encrypt(message, keyword)
    decrypted = vigenere_decrypt(encrypted, keyword)

    print("\n" + "=" * 45)
    print("Vigenère Cipher Result")
    print("=" * 45)
    print(f"Original text   : {message}")
    print(f"Keyword         : {keyword}")
    print(f"Encrypted text  : {encrypted}")
    print(f"Decrypted text  : {decrypted}")
    print(f"Round-trip OK?  : {decrypted == message}")
    print("=" * 45 + "\n")


if __name__ == "__main__":
    print("=== DecodeLabs Encryption & Decryption Tool ===")
    print("1. Caesar Cipher (fixed shift key)")
    print("2. Vigenère Cipher (keyword-based, bonus)")

    choice = input("Choose an option (1 or 2): ").strip()
    if choice == "2":
        run_vigenere_demo()
    else:
        run_caesar_demo()
