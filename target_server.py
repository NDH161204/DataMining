from flask import Flask, request

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST','PUT', 'DELETE'])
def catch_all(path):
    # Trang web ngây thơ này sẽ in ra mọi thứ người dùng gửi tới
    return f"""
    <h2>🟢 ĐÂY LÀ TRANG WEB ĐÍCH</h2>
    <p>Bạn đã truy cập thành công vào: <b>/{path}</b></p>
    <p>Dữ liệu gửi kèm: <b>{request.query_string.decode('utf-8')}</b></p>
    <p style='color: green;'><i>Nếu bạn thấy dòng này, nghĩa là WAF đã cho phép Request đi qua!</i></p>
    """

if __name__ == '__main__':
    # Chạy ở cổng 5050
    app.run(port=5050, debug=True)