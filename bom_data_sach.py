import random
import string

print("💉 Đang tiêm URL thực tế (chứa &, =, ?, và chuỗi ngẫu nhiên) vào Normal Data...")

with open('normal.txt', 'a', encoding='utf-8') as f:
    for _ in range(1500): # Bơm 1500 dòng x 4 loại = 6000 link sạch
        # 1. Link chứa tham số tìm kiếm phức tạp
        f.write(f"/search?q=iphone+14+pro+max&sort=price_asc\n")
        
        # 2. Link chứa ID là số nguyên
        so_id = random.randint(100, 999999)
        f.write(f"/product?id={so_id}&utm_source=facebook&campaign=sale\n")
        f.write(f"/login?redirect_url=/dashboard/user/{so_id}\n")
        
        # 3. Link chứa ID ngẫu nhiên kiểu flashscore (chữ hoa, chữ thường, số)
        ky_tu = string.ascii_letters + string.digits
        chuoi_id = ''.join(random.choice(ky_tu) for _ in range(8))
        f.write(f"/team/verona/{chuoi_id}/statistics\n")
        f.write(f"/api/v1/auth?token={chuoi_id}\n")

print("✅ Bơm xong 6000 URL sạch! Hãy chuyển sang bước gộp data.")