import pandas as pd
import os

print("🚀 ĐANG TRỘN DỮ LIỆU TỪ 4 FILE TXT VÀ BỘ CHUẨN MORZEUX...")

def doc_txt(ten_file, nhan):
    try:
        # errors='ignore' giúp bỏ qua các ký tự mã hóa lỗi của hacker
        with open(ten_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip() != ""]
        df = pd.DataFrame({'payload': lines, 'label': nhan})
        print(f"✅ Đã đọc {len(df):>6} dòng từ {ten_file}")
        return df
    except Exception as e:
        print(f"⚠️ Bỏ qua file {ten_file} (Chưa tải hoặc lỗi: {e})")
        return pd.DataFrame()

# 1. Đọc và gán nhãn từ các file của PayloadBox
df_sqli = doc_txt('sqli.txt', 1)
df_xss = doc_txt('xss.txt', 1)
df_cmdi = doc_txt('cmdi.txt', 1)  
df_normal = doc_txt('normal.txt', 0)

# ========================================================
# 2. ĐỌC THÊM DATASET CỦA MORZEUX (payload_full.csv)
# ========================================================
df_morzeux = pd.DataFrame()
if os.path.exists('payload_full.csv'):
    try:
        # Dùng header=None để đọc thẳng dữ liệu, cột đầu là payload, cột cuối là nhãn
        temp_df = pd.read_csv('payload_full.csv', header=None, engine='python', on_bad_lines='skip')
        
        df_morzeux = pd.DataFrame()
        df_morzeux['payload'] = temp_df[0].astype(str)
        
        # Nhãn của Morzeux là dạng chữ ('norm', 'sqli',...). Ta phiên dịch sang 0 và 1.
        cot_cuoi = temp_df.columns[-1]
        df_morzeux['label'] = temp_df[cot_cuoi].apply(lambda x: 0 if str(x).strip().lower() == 'norm' else 1)
        
        print(f"✅ Đã đọc {len(df_morzeux):>6} dòng từ payload_full.csv (Morzeux)")
    except Exception as e:
        print(f"❌ Lỗi khi đọc file Morzeux: {e}")
else:
    print("⚠️ Không tìm thấy file 'payload_full.csv'. Vẫn tiếp tục gộp các file TXT.")
# ========================================================

# 3. Gộp lại tất cả các nguồn (ĐÃ NHÉT df_cmdi VÀO NỒI LẨU)
df_tong = pd.concat([df_sqli, df_xss, df_cmdi, df_normal, df_morzeux], ignore_index=True)

# 4. Làm sạch: Xóa trùng lặp & Xáo trộn ngẫu nhiên
truoc_khi_xoa = len(df_tong)
df_tong.drop_duplicates(subset=['payload'], inplace=True)
df_tong = df_tong.sample(frac=1, random_state=42).reset_index(drop=True)
sau_khi_xoa = len(df_tong)

print(f"\n💥 Đã quét và tiêu diệt {truoc_khi_xoa - sau_khi_xoa} dòng bị trùng lặp!")

# 5. Xuất file cho AI học
ten_file_xuat = 'dataset_BTL_hoan_chinh.csv'
df_tong.to_csv(ten_file_xuat, index=False)

print("\n📊 THỐNG KÊ DATASET MỚI NHẤT:")
print(df_tong['label'].value_counts())
print(f"💾 Đã lưu thành công file: {ten_file_xuat}")