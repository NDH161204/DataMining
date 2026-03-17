import streamlit as st
import pickle
import numpy as np
import urllib.parse
import re
from scipy.sparse import hstack, csr_matrix

# --- CẤU HÌNH TRANG ---
st.set_page_config(page_title="Hệ thống Phát hiện Tấn công Web", page_icon="🛡️")

# --- 1. TẢI MÔ HÌNH VÀ SCALER ---
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
    st.error("⚠️ Lỗi tải mô hình!")
    st.stop()

# --- 2. CÁC HÀM TIỀN XỬ LÝ VÀ LUẬT (CHỐT 0 & CHỐT 1) ---
def full_decode(payload):
    decoded = urllib.parse.unquote(payload)
    while decoded != payload:
        payload = decoded
        decoded = urllib.parse.unquote(payload)
    return decoded

def check_whitelist(payload):
    """CHỐT 0: Bộ lọc Ngoại lệ theo Ngữ cảnh (Endpoint Whitelisting)"""
    # Nếu payload bắt đầu bằng các endpoint đặc thù, ta cho phép qua luôn
    if payload.startswith("/api/config"):
        return True, "Endpoint API được phép nhận định dạng JSON."
    if payload.startswith("/math/solve"):
        return True, "Endpoint Toán học được phép chứa công thức và ký tự đặc biệt."
    if payload.startswith("/support"):
        return True, "Endpoint Hỗ trợ Kỹ thuật được phép chứa từ khóa lập trình."
    return False, ""

def check_signatures(payload):
    """CHỐT 1: Bộ quét Luật tĩnh (Signature-based) để chặn ngay mã độc"""
    if "{{" in payload and "}}" in payload:
        return True, "Phát hiện mã độc SSTI (Template Injection)"
    
    clean_payload = re.sub(r'[\s\(\)\+/\*]', '', payload)
    if "unionselect" in clean_payload:
        return True, "Phát hiện SQLi (Kỹ thuật băm từ khóa Union Select)"
    if "etc/passwd" in clean_payload or "cmd.exe" in clean_payload:
        return True, "Phát hiện Path Traversal / CMDi"
        
    return False, ""

# --- 3. HÀM TRÍCH XUẤT ĐẶC TRƯNG CHO AI (CHỐT 2) ---
def extract_features_for_ai(processed_payload):
    length = len(processed_payload)
    special_chars = sum(processed_payload.count(c) for c in "<>'\"=()/%;")
    special_ratio = special_chars / (length + 1)
    digit_count = sum(c.isdigit() for c in processed_payload)
    
    keywords = ["select", "union", "script", "alert", "drop", "../", "etc/passwd", "cmd.exe"]
    keyword_count = sum(k in processed_payload for k in keywords) 
    slash_count = processed_payload.count('/')
    
    return [length, special_chars, special_ratio, digit_count, keyword_count, slash_count]

# --- 4. GIAO DIỆN CHÍNH ---
st.title("🛡️ WAF-AI: Tường Lửa Web Đa Tầng")
st.markdown("**Kiến trúc: [Chốt 0] Ngoại lệ $\\rightarrow$ [Chốt 1] Luật tĩnh $\\rightarrow$ [Chốt 2] AI Engine**")
st.markdown("---")

payload_input = st.text_area("Nhập chuỗi HTTP Request cần kiểm tra:", height=150)

if st.button("🔍 Phân tích Payload"):
    if payload_input.strip() == "":
        st.warning("Vui lòng nhập chuỗi payload!")
    else:
        # Tiền xử lý chung
        processed_payload = full_decode(payload_input).lower()
        processed_payload = re.sub(r'\s+', ' ', processed_payload)
        
        st.markdown("---")
        st.subheader("Báo cáo Quyết định (Action Log):")
        if payload_input != processed_payload:
            st.info(f"**Chuỗi sau khi Decode & Lowercase:** `{processed_payload}`")
            
        # ==========================================
        # 🟢 CHỐT 0: KIỂM TRA LUẬT NGOẠI LỆ (WHITELIST)
        # ==========================================
        is_whitelisted, wl_reason = check_whitelist(processed_payload)
        
        if is_whitelisted:
            st.success(f"🟢 ACTION: ALLOW (Bypass bởi Whitelist)")
            st.write(f"**Trạng thái:** Yêu cầu hợp lệ theo ngữ cảnh (Context-Aware)")
            st.write(f"**Lý do:** {wl_reason}")
            
        else:
            # ==========================================
            # 🔴 CHỐT 1: KIỂM TRA LUẬT TĨNH (BLACKLIST)
            # ==========================================
            is_sig_match, sig_reason = check_signatures(processed_payload)
            
            if is_sig_match:
                st.error(f"🔴 ACTION: BLOCK (Chặn bởi Rule-based Engine)")
                st.write(f"**Trạng thái:** Tấn công rõ ràng (Malicious)")
                st.write(f"**Lý do:** {sig_reason}")
                
            else:
                # ==========================================
                # 🧠 CHỐT 2: ĐƯA QUA AI (RANDOM FOREST)
                # ==========================================
                raw_features = extract_features_for_ai(processed_payload)
                scaled_features = scaler.transform(np.array([raw_features]))
                payload_tfidf = vectorizer.transform([processed_payload])
                payload_final = hstack([payload_tfidf, csr_matrix(scaled_features)])
                
                prob_score = model.predict_proba(payload_final)[0][1]
                
                if prob_score >= 0.85:
                    st.error(f"🔴 ACTION: BLOCK (Chặn bởi AI Engine)")
                    st.write(f"**Trạng thái:** Tấn công rõ ràng (Malicious)")
                    st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")
                    
                elif prob_score >= 0.65:
                    st.warning(f"🟡 ACTION: SUSPICIOUS (Ghi Log & Giám sát bởi AI)")
                    st.write(f"**Trạng thái:** Hành vi đáng ngờ, cần theo dõi thêm.")
                    st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")
                    
                else:
                    st.success(f"🟢 ACTION: ALLOW (Cho phép đi qua)")
                    st.write(f"**Trạng thái:** Yêu cầu hợp lệ (Normal)")
                    st.write(f"**Điểm rủi ro (Risk Score): {prob_score*100:.2f}%**")