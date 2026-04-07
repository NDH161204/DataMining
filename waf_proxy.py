from flask import Flask, request, Response
import requests as req
import pickle
import numpy as np
import urllib.parse
import re
from scipy.sparse import hstack, csr_matrix

app = Flask(__name__)
TARGET_URL = "http://localhost:5050"  # Địa chỉ của Web Nạn nhân (Backend)

# ==========================================
# 1. TẢI MÔ HÌNH VÀ CÁC BỘ TIỀN XỬ LÝ AI
# ==========================================
with open("model_rf.pkl", "rb") as f:
    model = pickle.load(f)

with open("tfidf.pkl", "rb") as f:
    vectorizer = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)


# ==========================================
# 2. CÁC HÀM LOGIC CỦA TƯỜNG LỬA (WAF ENGINE)
# ==========================================

# 🟢 CHỐT 0: Whitelist theo Context (PATH)
def check_whitelist(path):
    # LƯU Ý BẢO VỆ ĐỒ ÁN: Đã gỡ bỏ "/" khỏi danh sách trắng. 
    # Vì nếu để "/", hacker có thể giấu mã độc vào Header và đánh thẳng vào trang chủ.
    if path.startswith("/favicon.ico"):
        return True
    if path.startswith("/diendan/bai-viet"):
        return True
    return False


# 🔴 CHỐT 1: Luật tĩnh (Rule-based / Signatures)
def check_signatures(payload):
    # 1. Bắt Server-Side Template Injection (SSTI)
    if "{{" in payload and "}}" in payload:
        return True

    # 2. Bắt Path Traversal và Command Injection
    # LƯU Ý: Phải bắt các lỗ hổng chứa dấu "/" ở đây TRƯỚC KHI bị hàm Regex bên dưới gọt mất!
    if "etc/passwd" in payload or "cmd.exe" in payload:
        return True

    # 3. Bắt SQL Injection nâng cao
    # Gọt sạch khoảng trắng, dấu ngoặc, dấu cộng để ép mã độc lẩn trốn hiện nguyên hình
    clean_payload = re.sub(r'[\s\(\)\+/\*]', '', payload)
    if "unionselect" in clean_payload:
        return True

    return False


# 🧠 CHỐT 2: Trích xuất đặc trưng cho AI Engine
def extract_features_for_ai(payload):
    length = len(payload)
    # Đếm số lượng ký tự đặc biệt - Đặc trưng sống còn để bắt XSS và SQLi
    special_chars = sum(payload.count(c) for c in "<>'\"=()/%;")
    special_ratio = special_chars / (length + 1)
    digit_count = sum(c.isdigit() for c in payload)

    # Đếm các từ khóa nhạy cảm
    keywords = ["select", "union", "script", "alert", "drop", "../", "etc/passwd", "cmd.exe"]
    keyword_count = sum(k in payload for k in keywords)

    slash_count = payload.count('/')

    return [length, special_chars, special_ratio, digit_count, keyword_count, slash_count]


# ⚙️ HÀM ĐIỀU PHỐI CHUNG: Kiểm tra xem Request có độc hại không
def is_malicious(path, raw_payload):
    # --- Tiền xử lý (Preprocessing) ---
    payload = urllib.parse.unquote(raw_payload)
    payload = urllib.parse.unquote(payload)  # Decode 2 lần để chống kỹ thuật Double URL-Encode
    payload = payload.lower()
    payload = re.sub(r'\s+', ' ', payload)   # Gom nhiều khoảng trắng thành 1

    # --- Đi qua 3 chốt chặn ---
    # Chốt 0 kiểm tra đường dẫn gốc (path)
    if check_whitelist(path):
        return False, "Bypass Whitelist"

    # Chốt 1 và Chốt 2 kiểm tra toàn bộ gói tin (payload)
    if check_signatures(payload):
        return True, "Bị chặn bởi Chốt 1 (Luật tĩnh)"

    # AI Engine tính toán rủi ro
    raw_features = extract_features_for_ai(payload)
    scaled_features = scaler.transform(np.array([raw_features]))
    payload_tfidf = vectorizer.transform([payload])
    
    # Ghép ma trận đặc trưng số và ma trận TF-IDF
    payload_final = hstack([payload_tfidf, csr_matrix(scaled_features)])

    # Lấy xác suất rơi vào Nhãn 1 (Mã độc)
    prob_score = model.predict_proba(payload_final)[0][1]

    # Ngưỡng (Threshold) chặn: >= 65% là tiêu diệt
    if prob_score >= 0.65:
        return True, f"Bị chặn bởi AI Engine (Risk: {prob_score*100:.2f}%)"

    return False, "An toàn"


# ==========================================
# 3. LUỒNG REVERSE PROXY CHÍNH
# ==========================================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):

    # --- BƯỚC 1: GOM DỮ LIỆU TỪ URL ---
    full_payload = request.full_path

    # --- BƯỚC 2: GOM DỮ LIỆU TỪ BODY (Dành cho POST/PUT) ---
    body_data = request.get_data(as_text=True)
    if body_data:
        full_payload += " " + body_data

    # --- 3. HEADER (CÓ CHỌN LỌC VÀ THÔNG MINH) ---
    # Trình duyệt thật luôn có chữ 'Mozilla'. Các tool hack (như curl, sqlmap) thì không.
    user_agent = str(request.headers.get('User-Agent', ''))
    
    # CHỈ ghép User-Agent vào cho AI quét nếu phát hiện nghi vấn:
    # 1. Dùng tool tự động (Mất chữ Mozilla)
    # 2. Cố tình chèn Directory Traversal (../) hoặc lệnh cấm
    if "Mozilla" not in user_agent or "../" in user_agent or "passwd" in user_agent.lower():
        full_payload += " " + user_agent
    # --- BƯỚC 4: ĐƯA VÀO WAF QUÉT ---
    # Truyền riêng rẽ 'request.path' cho Whitelist và 'full_payload' cho các luật kiểm tra
    is_attack, reason = is_malicious(request.path, full_payload)

    if is_attack:
        print(f"🔴 [WAF BLOCKED]: {request.method} {request.full_path} -> {reason}")
        return f"""
        <div style="text-align:center; font-family:sans-serif; margin-top:50px;">
            <h1 style="color:red; font-size: 50px;">⛔ 403 FORBIDDEN</h1>
            <h2>Yêu cầu của bạn đã bị WAF-AI chặn!</h2>
            <p>Phát hiện dấu hiệu tấn công mạng.</p>
            <p style="color:gray;"><i>Chi tiết: {reason}</i></p>
        </div>
        """, 403

    # --- BƯỚC 5: NẾU AN TOÀN -> CHUYỂN TIẾP CHO BACKEND (CỔNG 5050) ---
    print(f"🟢 [WAF ALLOWED]: {request.method} {request.full_path}")

    target_url = f"{TARGET_URL}{request.full_path}"

    # Lọc bỏ header Host mặc định
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() != 'host'
    }

    # 🔥 MẬT KHẨU NGẦM (SECRET KEY) 🔥
    # Đóng dấu xác nhận gói tin này đã đi qua WAF, giúp Backend chặn các luồng đi vòng (Direct-to-Origin Bypass)
    headers['X-WAF-Secret-Key'] = 'KMA_SIEUCAP_BIMAT_123!@#'

    # WAF đóng vai trò Client, gửi request sang Backend
    resp = req.request(
        method=request.method,
        url=target_url,
        headers=headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    # Lấy kết quả từ Backend trả ngược lại cho người dùng
    resp_headers = [(name, value) for name, value in resp.headers.items()]
    return Response(resp.content, resp.status_code, resp_headers)


# ==========================================
# 4. CHẠY MÁY CHỦ
# ==========================================
if __name__ == '__main__':
    # Bật Tường lửa đứng gác ở cổng 8080
    app.run(port=8080, debug=True)