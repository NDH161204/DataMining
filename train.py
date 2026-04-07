import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack, csr_matrix
import urllib.parse
import time
import pickle

print("🚀 ĐANG KHỞI ĐỘNG HỆ THỐNG AI)...\n")

# --- 1. ĐỌC VÀ TIỀN XỬ LÝ DỮ LIỆU ---
ten_file = "dataset_BTL_hoan_chinh.csv"
print(f"⏳ Đang nạp dữ liệu từ {ten_file}...")
df = pd.read_csv(ten_file)
df['payload'] = df['payload'].fillna('').astype(str)

print("🔍 Đang Giải mã URL và Chuyển về chữ thường (Lowercase) để chống Bypass...")
# Giải mã %20, %3C...
df['payload'] = df['payload'].apply(lambda x: urllib.parse.unquote(x))
# 💡 CẢI TIẾN 1: Chuyển toàn bộ về chữ thường
df['payload'] = df['payload'].str.lower()

# --- 2. KỸ NGHỆ ĐẶC TRƯNG (6 FEATURES) ---
print("⚙️ Đang trích xuất 6 Đặc trưng thủ công (Thêm đếm dấu gạch chéo /)...")
df['length'] = df['payload'].apply(len)
df['special_chars'] = df['payload'].apply(lambda x: sum(x.count(c) for c in "<>'\"=()/%;"))
df['special_ratio'] = df['special_chars'] / (df['length'] + 1)
df['digit_count'] = df['payload'].apply(lambda x: sum(c.isdigit() for c in x))

# Không cần .lower() ở đây nữa vì payload đã được lower() ở trên
keywords = ["select", "union", "script", "alert", "drop", "../", "etc/passwd", "cmd.exe"]
df['keyword_count'] = df['payload'].apply(lambda x: sum(k in x for k in keywords))

# 💡 CẢI TIẾN 2: Đặc trị Path Traversal (Đếm số lượng dấu /)
df['slash_count'] = df['payload'].apply(lambda x: x.count('/'))

X_text = df['payload']
# Thêm slash_count vào ma trận đặc trưng
X_features = df[['length', 'special_chars', 'special_ratio', 'digit_count', 'keyword_count', 'slash_count']].values 
y = df['label']

# --- 3. CHIA TẬP DỮ LIỆU ---
X_train_text, X_test_text, X_train_feat, X_test_feat, y_train, y_test = train_test_split(
    X_text, X_features, y, test_size=0.2, random_state=42, stratify=y
)

# --- 4. CHUẨN HÓA (STANDARD SCALER) ---
print("⚖️ Đang chuẩn hóa (Standard Scaler) các đặc trưng số...")
scaler = StandardScaler()
X_train_feat_scaled = scaler.fit_transform(X_train_feat)
X_test_feat_scaled = scaler.transform(X_test_feat)

# --- 5. TRÍCH XUẤT TF-IDF & GỘP MA TRẬN ---
print("🧠 Đang băm dữ liệu văn bản với TF-IDF...")
vectorizer = TfidfVectorizer(max_features=10000, analyzer='char', ngram_range=(2, 4)) 
X_train_tfidf = vectorizer.fit_transform(X_train_text)
X_test_tfidf = vectorizer.transform(X_test_text)

print("🔗 Đang dung hợp TF-IDF và Đặc trưng...")
X_train_final = hstack([X_train_tfidf, csr_matrix(X_train_feat_scaled)])
X_test_final = hstack([X_test_tfidf, csr_matrix(X_test_feat_scaled)])

# --- 6. SÀN ĐẤU MÔ HÌNH ---
print("\n⚔️ BẮT ĐẦU SÀN ĐẤU SO SÁNH...\n")

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight={0: 1.5, 1: 1.0})
}

best_model = None
best_f1 = 0
best_model_name = ""

print(f"{'Tên Mô hình':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Thời gian'}")
print("-" * 85)

for name, clf in models.items():
    start_time = time.time()
    clf.fit(X_train_final, y_train)
    train_time = time.time() - start_time
    
    y_pred = clf.predict(X_test_final)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"{name:<20} | {acc*100:>8.2f}% | {prec*100:>8.2f}% | {rec*100:>8.2f}% | {f1*100:>8.2f}% | {train_time:>5.2f}s")
    
    if f1 > best_f1:
        best_f1 = f1
        best_model = clf
        best_model_name = name

print("-" * 85)
print(f"🏆 QUÁN QUÂN THEO F1-SCORE: {best_model_name}\n")

# --- 7. KIỂM ĐỊNH CHÉO (CROSS-VALIDATION) ---
print("🔄 ĐANG KIỂM ĐỊNH CHÉO (5-FOLD CROSS VALIDATION) CHO QUÁN QUÂN...")
# 💡 CẢI TIẾN 3: Dùng models[best_model_name] thay vì best_model đã fit
cv_scores = cross_val_score(models[best_model_name], X_train_final, y_train, cv=5, scoring='f1', n_jobs=-1)
print(f"👉 Điểm F1 từng nếp gấp: {[f'{score*100:.2f}%' for score in cv_scores]}")
print(f"👉 Trung bình F1 (CV): {cv_scores.mean()*100:.2f}% (Độ lệch chuẩn: ±{cv_scores.std()*100:.2f}%)\n")

# --- 8. MA TRẬN NHẦM LẪN ---
print(f"📊 MA TRẬN NHẦM LẪN ({best_model_name}):")
y_pred_best = best_model.predict(X_test_final)
cm = confusion_matrix(y_test, y_pred_best)
print(f"TN (Sạch)      : {cm[0][0]} | FP (Chặn nhầm) : {cm[0][1]}")
print(f"FN (Bỏ lọt)    : {cm[1][0]} | TP (Bắt trúng) : {cm[1][1]}\n")

# --- 9. LƯU NÃO BỘ AI ---
with open("model_rf.pkl", "wb") as f:
    pickle.dump(best_model, f)
with open("tfidf.pkl", "wb") as f:
    pickle.dump(vectorizer, f)
with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

print("✅ Đã xuất xưởng hệ thống hoàn chỉnh. Sẵn sàng tích hợp Web!")