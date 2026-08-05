import { Helmet } from "react-helmet-async";
import { Link } from "react-router-dom";

export default function Docs() {
  return (
    <div className="mx-auto max-w-3xl px-4 sm:px-6 py-16">
      <Helmet>
        <title>Tài liệu · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-3xl font-semibold tracking-tight">Tài liệu nhanh</h1>
      <p className="mt-3 text-muted leading-relaxed">
        Hướng dẫn ngắn để bắt đầu. API dùng prefix{" "}
        <code className="font-mono text-sm bg-bg px-1.5 py-0.5 rounded border border-border">/api/v1</code>.
      </p>

      <h2 className="mt-10 text-xl font-semibold">1. Đăng ký & đăng nhập</h2>
      <p className="mt-2 text-sm text-muted leading-relaxed">
        Tạo tài khoản Free tại{" "}
        <Link to="/register" className="text-primary hover:underline">
          /register
        </Link>
        . JWT được lưu local và gửi kèm mọi request app.
      </p>

      <h2 className="mt-8 text-xl font-semibold">2. Phân tích code</h2>
      <p className="mt-2 text-sm text-muted leading-relaxed">
        Vào Phân tích, dán code hoặc chọn sample, bấm Quét. Mỗi lần quét trừ 1 lượt quota. Chọn finding để
        lazy-load explain/fix.
      </p>

      <h2 className="mt-8 text-xl font-semibold">3. Lịch sử & báo cáo</h2>
      <p className="mt-2 text-sm text-muted leading-relaxed">
        Xem lại phân tích đã lưu, lọc theo ngôn ngữ, xuất JSON. Báo cáo PDF hiện là stub (mock).
      </p>

      <h2 className="mt-8 text-xl font-semibold">4. Nâng cấp gói</h2>
      <p className="mt-2 text-sm text-muted leading-relaxed">
        Trang Billing hỗ trợ checkout mock — tiện cho demo. Production sẽ nối cổng thanh toán thật.
      </p>

      <div className="mt-10 rounded-xl border border-border bg-surface p-4 text-sm text-muted">
        Tài khoản seed (dev):{" "}
        <code className="font-mono text-fg">admin@securecode.local</code> / Admin123! · free@ · pro@ · team@
      </div>
    </div>
  );
}
