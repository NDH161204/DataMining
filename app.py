import streamlit as st
import joblib

# 1. Cấu hình trang Web
st.set_page_config(page_title="WAF AI Demo", page_icon="🛡️")
st.title("🛡️ Hệ thống Phát hiện Tấn công Web (WAF-AI)")
st.markdown("**Bài Tập Lớn môn Khai Phá Dữ Liệu | ATTT - KMA**")
st.write("---")

# 2. Tải "não bộ" (Model) lên
@st.cache_resource # Lệnh này giúp model chỉ cần load 1 lần cho nhẹ web
def load_model():
    model = joblib.load('rf_model.pkl')
    vectorizer = joblib.load('tfidf_vectorizer.pkl')
    return model, vectorizer

try:
    model, vectorizer = load_model()
except Exception as e:
    st.error("⚠️ Chưa tìm thấy file mô hình. Vui lòng chạy file `train.py` trước!")
    st.stop()

# 3. Vẽ giao diện chính
st.subheader("Kiểm tra HTTP Request / Payload")
user_input = st.text_area("Nhập chuỗi cần kiểm tra vào đây (Ví dụ: ' OR 1=1 --, <script>alert(1)</script>, hoặc /home/index.php):", height=150)

# Nút bấm
if st.button("🔍 Quét An Toàn", type="primary"):
    if user_input.strip() == "":
        st.warning("Vui lòng nhập dữ liệu trước khi quét!")
    else:
        # Bước 4: Khai phá dữ liệu trên chuỗi người dùng nhập
        # Biến chữ thành số y hệt như lúc train
        input_vectorized = vectorizer.transform([user_input])
        
        # Dự đoán
        prediction = model.predict(input_vectorized)[0]
        
        # In kết quả hoành tráng
        st.write("---")
        st.subheader("Kết quả phân tích:")
        
        if prediction == 1:
            st.error("🚨 CẢNH BÁO: Phát hiện dấu hiệu Tấn Công (Malicious)!")
            st.write("Mô hình nhận diện đây là một payload độc hại (SQLi / XSS).")
        else:
            st.success("✅ AN TOÀN: Không phát hiện bất thường (Normal).")
            st.write("Đường dẫn / Request này có vẻ hợp lệ.")