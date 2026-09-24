import re
import random
import string
import sqlite3
import hashlib

# --- DATABASE SETUP (Optional Feature) ---
# Create a local database to store and check against old/reused passwords
def init_db():
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def is_password_reused(username, password):
    """Hashes the password and checks if it exists in the database history."""
    # Using SHA-256 for secure cryptographic comparison
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM password_history WHERE username=? AND password_hash=?", (username, hashed_pwd))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def save_password(username, password):
    """Saves the hashed password to history."""
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO password_history (username, password_hash) VALUES (?, ?)", (username, hashed_pwd))
    conn.commit()
    conn.close()


# --- STRENGTH ANALYZER CORE ---
def analyze_password(password):
    """Evaluates password length, complexity, and uniqueness."""
    score = 0
    feedback = []

    # 1. Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("• Consider making it longer (12+ characters is ideal).")
    else:
        feedback.append("• Critical: Password is too short (minimum 8 characters).")

    # 2. Complexity Checks
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("• Missing uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("• Missing lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("• Missing numerical digits.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("• Missing special characters.")

    # 3. Uniqueness Check (Basic pattern repetition check)
    if len(set(password)) < len(password) / 2:
        feedback.append("• Contains too many repeating characters (low uniqueness).")
        score = max(0, score - 1)

    # Determine Rating
    if score >= 5 and len(password) >= 12:
        rating = "STRONG 🔥"
    elif score >= 4:
        rating = "MEDIUM ⚠️"
    else:
        rating = "WEAK ❌"

    return rating, feedback


# --- ALTERNATIVE GENERATOR ---
def generate_strong_alternative(length=14):
    """Suggests a strong, compliant random alternative."""
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = "".join(random.choice(all_chars) for _ in range(length))
        # Ensure it meets strong criteria before returning
        rating, _ = analyze_password(password)
        if rating == "STRONG 🔥":
            return password


# --- MAIN RUNNER ---
def main():
    init_db()
    print("=== PASSWORD STRENGTH ANALYZER ===")
    username = input("Enter your username: ").strip()
    password = input("Enter password to evaluate: ").strip()

    if not password:
        print("Password cannot be empty.")
        return

    # Check for reuse
    if is_password_reused(username, password):
        print("\n[!] ALERT: This password has been used before. Choose a unique one!")
    else:
        # Analyze Strength
        rating, feedback = analyze_password(password)
        print(f"\nPassword Rating: {rating}")
        
        if feedback:
            print("\nSuggestions for improvement:")
            for line in feedback:
                print(line)
        
        if rating != "STRONG 🔥":
            print(f"\nSuggested Alternative: {generate_strong_alternative()}")
        else:
            save_password(username, password)
            print("\n[+] Success: Password meets standards and was saved securely.")

if __name__ == "__main__":
    main()
