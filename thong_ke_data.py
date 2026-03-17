import pandas as pd
import os

print("🔍 ĐANG PHÂN TÍCH THÀNH PHẦN CHI TIẾT (PHIÊN BẢN CHUẨN)...\n")

# 1. Đọc dữ liệu tự tạo
def doc_txt_chitiet(ten_file, ten_loai):
    if not os.path.exists(ten_file):
        return pd.DataFrame()
    with open(ten_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip() != ""]
    return pd.DataFrame({'payload': lines, 'loai_chi_tiet': ten_loai})

df_sqli_txt = doc_txt_chitiet('sqli.txt', 'sqli (PayloadBox)')
df_xss_txt = doc_txt_chitiet('xss.txt', 'xss (PayloadBox)')
df_cmdi_txt = doc_txt_chitiet('cmdi.txt', 'cmdi (PayloadBox)')
df_normal_txt = doc_txt_chitiet('normal.txt', 'normal (Tự sinh)')

# 2. Đọc file Morzeux (Sửa lỗi chọn nhầm cột)
df_morzeux = pd.DataFrame()
if os.path.exists('payload_full.csv'):
    # Dùng header=0 để báo cho máy tính biết dòng đầu tiên là tiêu đề, không phải dữ liệu
    temp_df = pd.read_csv('payload_full.csv', header=0, names=['payload', 'length', 'attack_type', 'label'], engine='python', on_bad_lines='skip')
    
    df_morzeux['payload'] = temp_df['payload'].astype(str)
    
    # BÍ QUYẾT: Lấy cột 'attack_type' để có tên chi tiết (sqli, xss, cmdi...)
    # Nếu dữ liệu sạch mà cột này bị trống (NaN), tự động điền chữ 'norm'
    attack_types = temp_df['attack_type'].fillna('norm').astype(str).str.strip().str.lower()
    df_morzeux['loai_chi_tiet'] = attack_types + " (Morzeux)"

# 3. Gộp và xóa trùng lặp
df_tong = pd.concat([df_sqli_txt, df_xss_txt,df_cmdi_txt, df_normal_txt, df_morzeux], ignore_index=True)
df_tong.drop_duplicates(subset=['payload'], inplace=True)

# 4. IN THỐNG KÊ CHI TIẾT
print("📊 BẢNG THỐNG KÊ CHI TIẾT TỪNG LOẠI PAYLOAD:")
print(df_tong['loai_chi_tiet'].value_counts())

# 5. Lưu lại file để Train (Chỉ giữ 0 và 1)
def phien_dich_nhan(ten_loai):
    if 'norm' in ten_loai: 
        return 0 # Normal
    return 1 # Tấn công (Bất kể là SQLi, XSS hay CMDi)

df_tong['label'] = df_tong['loai_chi_tiet'].apply(phien_dich_nhan)
df_train = df_tong[['payload', 'label']]
df_train.to_csv('dataset_BTL_hoan_chinh.csv', index=False)

print("\n✅ Đã lưu file train: dataset_BTL_hoan_chinh.csv")