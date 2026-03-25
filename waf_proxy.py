from flask import Flask, request, Response
import requests as req
import pickle
import numpy as np
import urllib.parse
import re
from scipy.sparse import hstack, csr_matrix

app = Flask(__name__)
TARGET_URL = "http://localhost:5050" # Địa chỉ của Web Nạn nhân

# --- 1. TẢI MÔ HÌNH ---
with open("model_rf.pkl", "rb") as f:
    model = pickle.load(f)
with open("tfidf.pkl", "rb") as f:
    vectorizer = pickle.load(f)
with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

# --- 2. CÁC HÀM LOGIC WAF (CHỐT 0, 1, 2) ---
def check_whitelist(payload):
    # CHỈ bỏ qua trang chủ và logo để tránh False Positive. 
    # Tuyệt đối không thả cửa cho /api/ nữa!
    if payload == "/" or payload == "/?" or payload.startswith("/favicon.ico"):
        return True
    return False

def check_signatures(payload):
    if "{{" in payload and "}}" in payload: return True
    clean_payload = re.sub(r'[\s\(\)\+/\*]', '', payload)
    if "unionselect" in clean_payload or "etc/passwd" in clean_payload: return True
    return False

def extract_features_for_ai(payload):
    length = len(payload)
    special_chars = sum(payload.count(c) for c in "<>'\"=()/%;")
    special_ratio = special_chars / (length + 1)
    digit_count = sum(c.isdigit() for c in payload)
    keywords = ["select", "union", "script", "alert", "drop", "../", "etc/passwd", "cmd.exe"]
    keyword_count = sum(k in payload for k in keywords) 
    slash_count = payload.count('/')
    return [length, special_chars, special_ratio, digit_count, keyword_count, slash_count]

def is_malicious(raw_payload):
    # Tiền xử lý
    payload = urllib.parse.unquote(raw_payload).lower()
    payload = re.sub(r'\s+', ' ', payload)
    
    # Chốt 0: Whitelist
    if check_whitelist(payload): return False, "Bypass Whitelist"
    
    # Chốt 1: Luật tĩnh
    if check_signatures(payload): return True, "Bị chặn bởi Chốt 1 (Luật tĩnh)"
    
    # Chốt 2: AI Engine
    raw_features = extract_features_for_ai(payload)
    scaled_features = scaler.transform(np.array([raw_features]))
    payload_tfidf = vectorizer.transform([payload])
    payload_final = hstack([payload_tfidf, csr_matrix(scaled_features)])
    
    prob_score = model.predict_proba(payload_final)[0][1]
    if prob_score >= 0.65: # Chặn luôn cả Suspicious (65%) và Block (85%)
        return True, f"Bị chặn bởi AI Engine (Rủi ro: {prob_score*100:.2f}%)"
    
    return False, "An toàn"

# --- 3. LUỒNG PROXY CHÍNH (Đã nâng cấp quét GET, POST, PUT, DELETE) ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # 1. Lấy dữ liệu từ URL
    full_payload = request.full_path 
    
    # 2. Rút ruột dữ liệu ẩn bên trong Body (POST/PUT Request)
    body_data = request.get_data(as_text=True)
    if body_data:
        full_payload = full_payload + " " + body_data
        
    # 3. [ĐÃ TẠM KHÓA] Lấy cả thông tin HTTP Headers 
    # Tắt đi để tránh lỗi Data Drift khi truy cập bằng trình duyệt Chrome/Safari
    # headers_data = " ".join([f"{v}" for k, v in request.headers.items() if k.lower() != 'host'])
    # full_payload = full_payload + " " + headers_data
        
    # QUÉT WAF TOÀN DIỆN
    is_attack, reason = is_malicious(full_payload)
    
    if is_attack:
        print(f"🔴 [WAF BLOCKED]: {request.method} {request.full_path} -> Lý do: {reason}")
        return f"""
        <div style="text-align:center; font-family:sans-serif; margin-top:50px;">
            <h1 style="color:red; font-size: 50px;">⛔ 403 FORBIDDEN</h1>
            <h2>Yêu cầu của bạn đã bị WAF-AI chặn!</h2>
            <p>Phát hiện dấu hiệu tấn công mạng.</p>
            <p style="color:gray;"><i>Chi tiết: {reason}</i></p>
        </div>
        """, 403
        
    else:
        print(f"🟢 [WAF ALLOWED]: {request.method} {request.full_path}")
        target_url = f"{TARGET_URL}{request.full_path}" 
        
        # Lọc bỏ header Host
        headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
        
        # Gửi request hộ người dùng
        resp = req.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        # Trả kết quả từ web đích
        resp_headers = [(name, value) for name, value in resp.headers.items()]
        return Response(resp.content, resp.status_code, resp_headers)

if __name__ == '__main__':
    # WAF Proxy đứng gác ở cổng 8080
    app.run(port=8080, debug=True)