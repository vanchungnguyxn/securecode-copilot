import { Helmet } from "react-helmet-async";

export default function Terms() {
  return (
    <div className="mx-auto max-w-3xl px-4 sm:px-6 py-16">
      <Helmet>
        <title>Điều khoản sử dụng · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-3xl font-semibold">Điều khoản sử dụng</h1>
      <p className="mt-2 text-sm text-muted">Cập nhật: tháng 8/2026</p>
      <div className="mt-8 space-y-4 text-sm text-muted leading-relaxed">
        <p>
          Bằng việc đăng ký hoặc sử dụng SecureCode Copilot, bạn đồng ý sử dụng dịch vụ đúng mục đích, không lạm dụng
          API, và không upload mã độc hại nhằm tấn công hệ thống khác.
        </p>
        <p>
          Kết quả phân tích và đề xuất bản vá mang tính hỗ trợ. Bạn chịu trách nhiệm review trước khi áp dụng vào mã
          nguồn production.
        </p>
        <p>
          Gói Free/Pro/Team có hạn mức dùng. Chúng tôi có thể tạm khóa tài khoản vi phạm hoặc gây quá tải. Gói
          Enterprise theo hợp đồng riêng.
        </p>
      </div>
    </div>
  );
}
