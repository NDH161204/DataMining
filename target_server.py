from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    # 1. Ổ KHÓA BÍ MẬT: Kiểm tra xem có đúng là WAF cõng vào không?
    secret_key = request.headers.get('X-WAF-Secret-Key')
    if secret_key != 'KMA_SIEUCAP_BIMAT_123!@#':
        # Nếu tự ý chui vào cổng 5050 mà không có chìa khóa -> Đuổi cổ ngay!
        return """
        <div style="text-align:center; font-family:sans-serif; margin-top:50px;">
            <h1 style='color:red; font-size: 50px;'>⛔ CẢNH BÁO XÂM NHẬP TRÁI PHÉP</h1>
            <h2>Bạn đang cố tình truy cập trực tiếp vào hệ thống Backend (Cổng 5050).</h2>
            <p>Lỗ hổng Direct-to-Origin Bypass đã bị chặn!</p>
            <p>Vui lòng đi qua cổng Tường lửa WAF ở port 8080!</p>
        </div>
        """, 403

    # 2. NẾU CÓ CHÌA KHÓA CỦA WAF -> Mở cửa đón khách bình thường
    return f"""
    <div style="font-family:sans-serif; padding: 20px;">
        <h2>🟢 ĐÂY LÀ TRANG WEB ĐÍCH</h2>
        <p>Bạn đã truy cập thành công vào: <b>/{path}</b></p>
        <p>Phương thức: <b>{request.method}</b></p>
        <p>Dữ liệu gửi kèm: <b>{request.get_data(as_text=True)}</b></p>
        <p style='color: green;'><i>Nếu bạn thấy dòng này, nghĩa là WAF đã quét an toàn và đóng dấu cho phép Request đi qua!</i></p>
    </div>
    """

if __name__ == '__main__':
    # Web đích chạy ở cổng 5050
    app.run(port=5050, debug=True)