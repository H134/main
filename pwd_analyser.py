"""PWD ANALYSER"""

import math


def score_password(password):
    """
    Analyzes the password and returns a dictionary with length,
    entropy, scaled score, and a text verdict.
    """
    length = len(password)
    if length == 0:
        return {"length": 0, "entropy": 0, "score": 0, "verdict": "Very Weak"}

    # Determine character pool size (charset) based on characters used
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    # Check for special characters/symbols
    has_special = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        # Standard ASCII special characters
        pool_size += 33

    # Calculate Shannon Entropy: E = L * log2(R)
    entropy = length * math.log2(pool_size)

    # Calculate a score out of 100 based on standard entropy thresholds
    # 80+ bits of entropy is generally considered very strong for passwords
    score = min(100, int((entropy / 80) * 100))

    # Determine verdict based on score
    if score < 40:
        verdict = "Weak"
    elif score < 70:
        verdict = "Moderate"
    else:
        verdict = "Strong"

    return {
        "entropy": round(entropy, 2),
        "score": score,
        "verdict": verdict,
        "length": length,
    }


def main():
    """Main function to run the password strength checker interface."""
    print("🔒 Password Strength Checker 🔒")
    password = input("Enter a password to check: ")

    result = score_password(password)
    print("\n--- Password Analysis ---")
    print(f"Length:  {result['length']}")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Score:   {result['score']} / 100")
    print(f"Verdict: {result['verdict']}")


if __name__ == "__main__":
    main()
