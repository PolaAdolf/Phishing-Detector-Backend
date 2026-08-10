import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

# Add parent and src directory to python path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.preprocessing import URLPreprocessor, clean_url
from src.model import build_phishing_model

def get_file_path(filename):
    """Checks for file in data/ subdirectory first, then root directory."""
    path_in_data = os.path.join(BASE_DIR, "data", filename)
    path_in_root = os.path.join(BASE_DIR, filename)
    if os.path.exists(path_in_data):
        return path_in_data
    elif os.path.exists(path_in_root):
        return path_in_root
    return None

def load_and_merge_datasets():
    dfs = []

    # 1. Dataset 1: phishing_site_urls.csv
    file1 = get_file_path("phishing_site_urls.csv")
    if file1:
        print(f"Loading dataset from {file1}...")
        df1 = pd.read_csv(file1)
        df1 = df1.rename(columns={'URL': 'url', 'url': 'url', 'Label': 'label', 'label': 'label'})
        if 'url' in df1.columns and 'label' in df1.columns:
            df1['target'] = df1['label'].apply(lambda x: 1 if str(x).lower() in ['bad', 'phishing', '1', 'malicious'] else 0)
            dfs.append(df1[['url', 'target']])

    # 2. Dataset 2: URL dataset.csv
    file2 = get_file_path("URL dataset.csv")
    if file2:
        print(f"Loading dataset from {file2}...")
        df2 = pd.read_csv(file2)
        df2 = df2.rename(columns={'URL': 'url', 'url': 'url', 'type': 'label', 'Type': 'label'})
        if 'url' in df2.columns and 'label' in df2.columns:
            df2['target'] = df2['label'].apply(lambda x: 1 if str(x).lower() in ['bad', 'phishing', '1', 'malicious'] else 0)
            dfs.append(df2[['url', 'target']])

    # 3. Dataset 3: Phishing URLs.csv
    file3 = get_file_path("Phishing URLs.csv")
    if file3:
        print(f"Loading dataset from {file3}...")
        df3 = pd.read_csv(file3)
        url_col = [c for c in df3.columns if 'url' in c.lower() or 'link' in c.lower()]
        if url_col:
            df3 = df3.rename(columns={url_col[0]: 'url'})
            df3['target'] = 1  # All entries in Phishing URLs are malicious
            dfs.append(df3[['url', 'target']])

    if not dfs:
        raise FileNotFoundError("No dataset CSV files found in 'data/' or project root directory!")

    merged_df = pd.concat(dfs, ignore_index=True)
    merged_df = merged_df.dropna(subset=['url', 'target'])
    merged_df['url'] = merged_df['url'].astype(str)
    merged_df['cleaned_url'] = merged_df['url'].apply(clean_url)
    merged_df = merged_df.drop_duplicates(subset=['cleaned_url'])

    print(f"\nTotal Unique Cleaned URLs: {len(merged_df)}")
    print("Class distribution:")
    print(merged_df['target'].value_counts())

    return merged_df

def train():
    merged_df = load_and_merge_datasets()

    # Sample up to 80,000 samples for fast, high-accuracy training
    sample_size = min(80000, len(merged_df))
    df_sample = merged_df.sample(n=sample_size, random_state=42)
    print(f"\nTraining on dataset sample size: {len(df_sample)}")

    urls = df_sample['cleaned_url'].tolist()
    labels = df_sample['target'].tolist()

    # Preprocessing
    print("\nExtracting character features & tokenizing...")
    preprocessor = URLPreprocessor(max_len=150)
    preprocessor.fit(urls)
    X = preprocessor.transform(urls)
    y = np.asarray(labels, dtype=np.float32)

    # Train / Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    vocab_size = len(preprocessor.tokenizer.word_index) + 1
    print(f"Vocabulary size: {vocab_size}")

    # Build 1D-CNN Model
    print("Building 1D-CNN Model architecture...")
    model = build_phishing_model(vocab_size=vocab_size, max_len=150)

    print("\nStarting 1D-CNN Deep Learning model training...")
    model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=5,
        batch_size=128
    )

    # Evaluation
    print("\nEvaluating model on test dataset...")
    y_pred_proba = model.predict(X_test, batch_size=128)
    y_pred = (y_pred_proba > 0.5).astype(int)

    acc = accuracy_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n=== Model Evaluation Metrics ===")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Save artifacts
    models_dir = os.path.join(BASE_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)

    keras_model_path = os.path.join(models_dir, "phishing_model.keras")
    h5_model_path = os.path.join(models_dir, "phishing_model.h5")
    tokenizer_path = os.path.join(models_dir, "tokenizer.json")

    print("\nSaving model and tokenizer artifacts...")
    model.save(keras_model_path)
    model.save(h5_model_path)
    preprocessor.save_tokenizer(tokenizer_path)

    print(f"SUCCESS: Model saved to '{keras_model_path}' and '{h5_model_path}'!")
    print(f"SUCCESS: Tokenizer saved to '{tokenizer_path}'!")

if __name__ == "__main__":
    train()