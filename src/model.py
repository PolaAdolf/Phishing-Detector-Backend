from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout

def build_phishing_model(vocab_size, max_len=150):
    """
    Builds a 1D Convolutional Neural Network (1D-CNN) for Character-Level Phishing URL Detection.
    Based on MDPI research paper architecture specs.
    """
    model = Sequential([
        Input(shape=(max_len,)),
        Embedding(input_dim=vocab_size, output_dim=32),
        Conv1D(filters=64, kernel_size=5, activation='relu'),
        GlobalMaxPooling1D(),
        Dense(units=64, activation='relu'),
        Dropout(0.3),
        Dense(units=1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    return model