# MTProxy User Management & Monitoring

Bộ công cụ quản lý và giám sát người dùng cho MTProxy.

## 📁 Files

- `manage_users.py` - Quản lý users (thêm/xóa/liệt kê)
- `monitor.py` - Giám sát connections real-time
- `analyze_logs.py` - Phân tích logs để phát hiện chia sẻ tài khoản
- `config.py` - File cấu hình MTProxy

## 🚀 Cách sử dụng

### 1. Quản lý Users (`manage_users.py`)

#### Thêm user mới:

```bash
python3 manage_users.py add username
```

Ví dụ:

```bash
python3 manage_users.py add john
python3 manage_users.py add alice
```

#### Liệt kê tất cả users:

```bash
python3 manage_users.py list
```

#### Xóa user:

```bash
python3 manage_users.py remove username
```

### 2. Giám sát Real-time (`monitor.py`)

#### Kiểm tra connections hiện tại:

```bash
python3 monitor.py
```

#### Giám sát liên tục:

```bash
python3 monitor.py --continuous
```

#### Giám sát với interval tùy chỉnh:

```bash
python3 monitor.py --continuous --interval 10  # Kiểm tra mỗi 10 giây
```

#### Export dữ liệu monitoring:

```bash
python3 monitor.py --export
```

### 3. Phân tích Logs (`analyze_logs.py`)

#### Phân tích logs Docker Compose:

```bash
python3 analyze_logs.py --compose
```

#### Phân tích logs Docker container:

```bash
python3 analyze_logs.py --container mtprotoproxy
```

#### Phân tích nhiều dòng logs hơn:

```bash
python3 analyze_logs.py --compose --lines 5000
```

#### Export kết quả phân tích:

```bash
python3 analyze_logs.py --compose --export
```

## 📊 Monitoring Features

### Real-time Monitoring

- Số connections đang hoạt động
- Số users unique (theo IP)
- Connections theo từng IP
- Phát hiện hoạt động đáng ngờ

### Log Analysis

- Phân tích patterns kết nối của từng user
- Phát hiện chia sẻ tài khoản:
  - Multiple IPs cho cùng 1 user
  - Connections đồng thời từ IPs khác nhau
  - Tần suất kết nối bất thường
- Scoring system để đánh giá mức độ nghi ngờ

### Suspicious Activity Detection

#### Điểm nghi ngờ (Suspicious Score):

- **0-10**: ✅ LOW RISK - Sử dụng bình thường
- **11-30**: ⚠️ MEDIUM RISK - Cần theo dõi
- **31-100**: 🚨 HIGH RISK - Có thể đang chia sẻ tài khoản

#### Các yếu tố tăng điểm nghi ngờ:

- Sử dụng nhiều IPs khác nhau (+10 điểm/IP)
- Connections đồng thời từ IPs khác nhau (+50 điểm/lần)
- Tần suất kết nối cao (+2 điểm/connection trên 20)

## 🔧 Setup

### Cấp quyền thực thi:

```bash
chmod +x manage_users.py monitor.py analyze_logs.py
```

### Dependencies:

Các scripts sử dụng Python standard library, không cần cài thêm packages.

## 📝 Examples

### Workflow thông thường:

1. **Thêm user mới:**

```bash
python3 manage_users.py add customer1
# Output: User 'customer1' added successfully!
# Secret: a1b2c3d4e5f6789012345678901234567890abcd
# Connection string: tg://customer1@your-server-ip:443?secret=a1b2c3d4e5f6789012345678901234567890abcd
```

2. **Kiểm tra connections:**

```bash
python3 monitor.py
# Output:
# 🔍 MTProxy Monitor - 2024-01-15 14:30:25
# ========================================
# 📊 Total active connections: 3
# 👥 Unique users (IPs): 2
#
# 📋 Connections by IP:
#   ✅ 192.168.1.100: 1 connection(s)
#   ⚠️ 10.0.0.50: 2 connection(s)
```

3. **Phân tích logs để phát hiện chia sẻ:**

```bash
python3 analyze_logs.py --compose
# Output:
# 📊 MTProxy Log Analysis - 2024-01-15 14:35:10
# ================================================
#
# 👤 User: customer1
#    📈 Total connections: 25
#    🌐 Unique IPs: 4
#    ⚠️ Suspicious score: 45/100
#    🚨 HIGH RISK - Potential account sharing!
#    📍 IPs used: 192.168.1.100, 10.0.0.50, 172.16.0.10, 203.0.113.5
#    🔄 Simultaneous connections from different IPs: 2
```

## ⚠️ Lưu ý

1. **Permissions**: Scripts cần quyền đọc `config.py` và quyền chạy Docker commands
2. **Docker**: Đảm bảo Docker/Docker Compose đang chạy để monitoring hoạt động
3. **Logs**: MTProxy cần được cấu hình để ghi logs chi tiết
4. **Security**: Giữ bí mật các secrets được tạo ra

## 🔍 Troubleshooting

### Không tìm thấy connections:

- Kiểm tra MTProxy có đang chạy không
- Kiểm tra port 443 có đang được sử dụng không
- Thử với `sudo` nếu cần thiết

### Không parse được logs:

- Kiểm tra tên container/service Docker
- Đảm bảo có quyền đọc Docker logs
- Thử tăng số dòng logs với `--lines`

### Script không chạy:

- Kiểm tra Python 3 đã được cài đặt
- Kiểm tra quyền thực thi file
- Kiểm tra `config.py` có tồn tại không
