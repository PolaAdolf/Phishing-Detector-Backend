import re
import json
import numpy as np
from tensorflow.keras.preprocessing.text import Tokenizer, tokenizer_from_json
from tensorflow.keras.preprocessing.sequence import pad_sequences

def clean_url(url: str) -> str:
    """
    Cleans and normalizes URL for character-level feature extraction.
    Removes scheme (http://, https://) and leading www. while preserving domain and path structure.
    """
    url = url.lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url

class URLPreprocessor:
    def __init__(self, max_len=150):
        self.max_len = max_len
        self.tokenizer = Tokenizer(char_level=True, lower=True)

    def fit(self, urls):
        cleaned_urls = [clean_url(u) for u in urls]
        self.tokenizer.fit_on_texts(cleaned_urls)

    def transform(self, urls):
        cleaned_urls = [clean_url(u) for u in urls]
        sequences = self.tokenizer.texts_to_sequences(cleaned_urls)
        padded = pad_sequences(sequences, maxlen=self.max_len, padding='post', truncating='post')
        return np.asarray(padded, dtype=np.float32)

    def save_tokenizer(self, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.tokenizer.to_json())

    def load_tokenizer(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            self.tokenizer = tokenizer_from_json(f.read())