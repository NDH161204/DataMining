import pandas as pd

print("🚀 ĐANG TRỘN DỮ LIỆU TỪ 3 FILE TXT...")

def doc_txt(ten_file, nhan):
    try:
        # errors='ignore' giúp bỏ qua các ký tự mã hóa lỗi của hacker
        with open(ten_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip() != ""]
        df = pd.DataFrame({'payload': lines, 'label': nhan})
        print(f"✅ Đã đọc {len(df)} dòng từ {ten_file}")
        return df
    except Exception as e:
        print(f"❌ Lỗi đọc file {ten_file}: {e}")
        return pd.DataFrame()

# 1. Đọc và gán nhãn
df_sqli = doc_txt('sqli.txt', 1)
df_xss = doc_txt('xss.txt', 1)
df_normal = doc_txt('normal.txt', 0)

# 2. Gộp lại
df_tong = pd.concat([df_sqli, df_xss, df_normal], ignore_index=True)

# 3. Làm sạch: Xóa trùng lặp & Xáo trộn ngẫu nhiên
df_tong.drop_duplicates(subset=['payload'], inplace=True)
df_tong = df_tong.sample(frac=1, random_state=42).reset_index(drop=True)

# 4. Xuất file cho AI học
ten_file_xuat = 'dataset_BTL_hoan_chinh.csv'
df_tong.to_csv(ten_file_xuat, index=False)

print("\n📊 THỐNG KÊ DATASET MỚI NHẤT:")
print(df_tong['label'].value_counts())
print(f"💾 Đã lưu thành công file: {ten_file_xuat}")