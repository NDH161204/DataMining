import streamlit as st
import pickle
import numpy as np
import urllib.parse
from scipy.sparse import hstack, csr_matrix

# --- CẤU HÌNH TRANG ---
st.set_page_config(page_title="Hệ thống Phát hiện Tấn công Web", page_icon="🛡️")

# --- 1. TẢI MÔ HÌNH, VECTORIZER VÀ SCALER ---
@st.cache_resource
def load_model():
    with open("model_rf.pkl", "rb") as f:
        model = pickle.load(f)
    with open("tfidf.pkl", "rb") as f:
        vectorizer = pickle.load(f)
    with open("scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, vectorizer, scaler

try:
    model, vectorizer, scaler = load_model()
except Exception as e:
    st.error("⚠️ Không tìm thấy file mô hình. Vui lòng kiểm tra lại!")
    st.stop()

# --- 2. HÀM KỸ NGHỆ ĐẶC TRƯNG ---
def full_decode(payload):
    """Hàm giải mã đa tầng (Iterative Decoding)"""
    decoded = urllib.parse.unquote(payload)
    while decoded != payload:
        payload = decoded
        decoded = urllib.parse.unquote(payload)
    return decoded

def extract_features(payload):
    decoded_payload = full_decode(payload)
    processed_payload = decoded_payload.lower()
    
    length = len(processed_payload)
    special_chars = sum(processed_payload.count(c) for c in "<>'\"=()/%;")
    special_ratio = special_chars / (length + 1)
    digit_count = sum(c.isdigit() for c in processed_payload)
    
    keywords = ["select", "union", "script", "alert", "drop", "../", "etc/passwd", "cmd.exe"]
    keyword_count = sum(k in processed_payload for k in keywords) 
    slash_count = processed_payload.count('/')
    
    return [length, special_chars, special_ratio, digit_count, keyword_count, slash_count], processed_payload

# --- 3. GIAO DIỆN CHÍNH ---
st.title("🛡️ WAF-AI: Web Application Firewall")
st.markdown("**Hệ thống phân tích Payload với Multi-level Threshold**")
st.markdown("---")

st.subheader("Kiểm tra HTTP Request / Payload")
payload_input = st.text_area(
    "Nhập chuỗi cần kiểm tra vào đây:", 
    height=150
)

if st.button("🔍 Phân tích Payload"):
    if payload_input.strip() == "":
        st.warning("Vui lòng nhập chuỗi payload để kiểm tra!")
    else:
        # Bước A: Rút trích đặc trưng
        raw_features, processed_payload = extract_features(payload_input)
        
        # Bước B: Chuẩn hóa
        features_array = np.array([raw_features])
        scaled_features = scaler.transform(features_array)
        
        # Bước C: Băm từ khóa
        payload_tfidf = vectorizer.transform([processed_payload])
        
        # Bước D: Gộp ma trận
        payload_final = hstack([payload_tfidf, csr_matrix(scaled_features)])
        
        # Bước E: AI dự đoán xác suất
        probabilities = model.predict_proba(payload_final)[0]
        prob_score = probabilities[1] 
        
        # --- 4. CƠ CHẾ QUYẾT ĐỊNH 3 MỨC (MULTI-LEVEL THRESHOLD) ---
        st.markdown("---")
        st.subheader("Báo cáo Quyết định (Action Log):")
        
        if payload_input != processed_payload:
            st.info(f"**Chuỗi thực tế sau khi Decode:** `{processed_payload}`")
        
        # Phân loại hành động
        if prob_score >= 0.85:
            st.error(f"🔴 ACTION: BLOCK (Chặn lập tức)")
            st.write(f"**Trạng thái:** Tấn công rõ ràng (Malicious)")
            st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")
            
        elif prob_score >= 0.65:
            st.warning(f"🟡 ACTION: SUSPICIOUS (Ghi Log & Giám sát)")
            st.write(f"**Trạng thái:** Hành vi đáng ngờ, cần theo dõi thêm.")
            st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")
            st.write("*Chú thích: Payload có chứa các đặc trưng nhạy cảm nhưng chưa đủ bằng chứng cấu thành mã độc hoàn chỉnh.*")
            
        else:
            st.success(f"🟢 ACTION: ALLOW (Cho phép đi qua)")
            st.write(f"**Trạng thái:** Yêu cầu hợp lệ (Normal)")
            st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")