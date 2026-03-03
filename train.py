import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

print("1. Đang đọc dữ liệu...")
# Lưu ý: Copy file dataset_final_BTL.csv để cùng thư mục với file này nhé
df = pd.read_csv("dataset_BTL_hoan_chinh.csv")

# Đảm bảo dữ liệu là dạng chuỗi
df['payload'] = df['payload'].astype(str)
X = df['payload']
y = df['label']

print("2. Đang trích xuất đặc trưng (TF-IDF N-Gram)...")
# Đây là phần "Khai phá dữ liệu" chuẩn bài Karthik
vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=10000)
X_vectorized = vectorizer.fit_transform(X)

print("3. Đang huấn luyện Mô hình (Random Forest)...")
X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Đánh giá nhanh
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Đã train xong! Độ chính xác (Accuracy): {acc * 100:.2f}%")

print("4. Đang lưu mô hình để làm Demo...")
# Lưu model và vectorizer ra file để file giao diện (app.py) gọi lên dùng
joblib.dump(model, 'rf_model.pkl')
joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')
print("🎉 Hoàn tất! Đã sinh ra 2 file .pkl")