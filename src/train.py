import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from preprocessing import URLPreprocessor
from model import build_phishing_model

# 1. قراءة البيانات من ملف الـ CSV
print("جاري تحميل البيانات من phishing_site_urls.csv ...")
# تأكد إن مسار الملف صحيح (لو الملف بره فولدر src، المسار هيكون كالتالي)
df = pd.read_csv("phishing_site_urls.csv")

# 2. تنظيف وتحضير البيانات
print("جاري تجهيز البيانات...")
# تحويل عمود الـ Label إلى 1 للروابط الخبيثة (bad) و 0 للروابط السليمة (good)
df['target'] = df['Label'].map({'bad': 1, 'good': 0})

# مسح أي صفوف فارغة إن وجدت
df = df.dropna(subset=['URL', 'target'])

urls = df['URL'].tolist()
labels = df['target'].tolist()

# 3. المعالجة المسبقة للروابط
print("جاري تحويل الروابط لأرقام (Tokenization & Padding)...")
preprocessor = URLPreprocessor(max_len=150)
preprocessor.fit(urls)
X = preprocessor.transform(urls)
y = np.asarray(labels, dtype=np.float32)

# 4. تقسيم البيانات وتدريب الموديل
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

vocab_size = len(preprocessor.tokenizer.word_index) + 1
model = build_phishing_model(vocab_size=vocab_size, max_len=150)

print(f"بدء تدريب الموديل على {len(urls)} رابط حقيقي...")
model.fit(
    X_train, y_train,
    validation_data=(X_test, y_test),
    epochs=5,        # 5 دورات كافية جداً مع الداتا الكبيرة
    batch_size=64    # نكبر الـ Batch عشان الداتا كبيرة والتدريب يخلص أسرع
)

# 5. حفظ الموديل والـ Tokenizer
MODELS_DIR = "models"
os.makedirs(MODELS_DIR, exist_ok=True)
model.save(os.path.join(MODELS_DIR, "phishing_model.h5"))
preprocessor.save_tokenizer(os.path.join(MODELS_DIR, "tokenizer.json"))

print("\nتم التدريب على الداتا الحقيقية وحفظ الموديل بنجاح!")