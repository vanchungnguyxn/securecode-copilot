import { Helmet } from "react-helmet-async";

export default function Privacy() {
  return (
    <div className="mx-auto max-w-3xl px-4 sm:px-6 py-16">
      <Helmet>
        <title>Chính sách bảo mật · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-3xl font-semibold">Chính sách bảo mật</h1>
      <p className="mt-2 text-sm text-muted">Cập nhật: tháng 8/2026</p>
      <div className="mt-8 space-y-4 text-sm text-muted leading-relaxed">
        <p>
          Chúng tôi thu thập thông tin tài khoản (email, họ tên) và dữ liệu sử dụng (lượt phân tích, gói) để vận hành
          dịch vụ. Source code gửi lên được xử lý để quét lỗ hổng và có thể lưu theo chính sách gói của bạn.
        </p>
        <p>
          Token JWT lưu trên thiết bị của bạn. Không chia sẻ mật khẩu. Bạn có thể yêu cầu xóa lịch sử phân tích trong
          Cài đặt.
        </p>
        <p>
          Liên hệ về dữ liệu cá nhân: privacy@securecode.local. Chính sách này có thể cập nhật; thay đổi lớn sẽ được
          thông báo trên trang.
        </p>
      </div>
    </div>
  );
}
