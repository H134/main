import os
import sys
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

def create_sample_dataset(file_path):
    """Generates a sample CSV file if no dataset is provided by the user."""
    sample_data = {
        'text': [
            "URGENT: Your bank account is locked! Click here to reset your password immediately.",
            "Hey, are we still meeting up for lunch today at the cafeteria?",
            "Dear customer, you won a $1,000 Amazon gift card! Claim your prize now at this link.",
            "Please review the attached project proposal details and send your feedback by Friday.",
            "OFFICIAL NOTICE: Verify your account credentials now to avoid service suspension.",
            "Don't forget that the monthly team sync meeting starts tomorrow at 10 AM.",
            "Get rich quick! Click to invest in this exclusive crypto token option today!",
            "Thanks for submitting the report. The formatting looks perfect."
        ],
        'label': ['Phishing', 'Safe', 'Phishing', 'Safe', 'Phishing', 'Safe', 'Phishing', 'Safe']
    }
    df = pd.DataFrame(sample_data)
    df.to_csv(file_path, index=False)
    print(f"[+] Sample dataset automatically created at: '{file_path}'\n")

def main():
    csv_file = "spam.csv"

    # Step 1: Dataset Check & Loading
    if not os.path.exists(csv_file):
        print(f"[-] '{csv_file}' not found. Generating a synthetic dataset for testing...")
        create_sample_dataset(csv_file)

    try:
        data = pd.read_csv(csv_file)
    except Exception as e:
        print(f"[-] Error reading CSV file: {e}")
        sys.exit(1)

    # Validate column structures
    if 'text' not in data.columns or 'label' not in data.columns:
        print("[-] Error: Dataset must contain 'text' and 'label' columns.")
        sys.exit(1)

    X = data['text']
    y = data['label']

    # Step 2: Split Data into Training and Testing Sets (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Step 3: Feature Extraction (TF-IDF Vectorization)
    # Converts raw email string data into numeric values based on word importance
    vectorizer = TfidfVectorizer(stop_words='english', lowercase=True)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    # Step 4: Model Training (Multinomial Naive Bayes Classifier)
    print("[+] Training Phishing Detection Model...")
    model = MultinomialNB()
    model.fit(X_train_tfidf, y_train)
    print("[+] Model training successfully complete.\n")

    # Step 5: Model Evaluation
    y_pred = model.predict(X_test_tfidf)
    
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred, labels=model.classes_)
    
    # Format and display metric output reports cleanly
    print("=" * 55)
    print("               MODEL PERFORMANCE REPORT                ")
    print("=" * 55)
    print(f"Overall Model Accuracy: {accuracy * 100:.2f}%")
    print("-" * 55)
    print("Confusion Matrix:")
    
    # Turn confusion matrix into a clean, labeled DataFrame for scannability
    cm_df = pd.DataFrame(
        conf_matrix, 
        index=[f"Actual {cls}" for cls in model.classes_], 
        columns=[f"Predicted {cls}" for cls in model.classes_]
    )
    print(cm_df)
    print("-" * 55)
    print("Detailed Classification Statistics:")
    print(classification_report(y_test, y_pred))
    print("=" * 55 + "\n")

    # Step 6: Live Interactive Testing Playground
    print("--- Live Email Classifier Tool ---")
    print("Type an email body below to test the model (or type 'exit' to quit):")
    
    while True:
        try:
            user_input = input("\nEnter Email Text: ").strip()
            if user_input.lower() == 'exit' or not user_input:
                print("Exiting Classifier Tool. Goodbye!")
                break
                
            # Vectorize and evaluate user text sample input values
            sample_vector = vectorizer.transform([user_input])
            prediction = model.predict(sample_vector)[0]
            probabilities = model.predict_proba(sample_vector)[0]
            max_prob = max(probabilities) * 100

            print(f"-> Classification Decision : **{prediction.upper()}** ({max_prob:.1f}% confidence)")
        except KeyboardInterrupt:
            print("\nExiting Classifier Tool. Goodbye!")
            break

if __name__ == "__main__":
    main()
