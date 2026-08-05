import { Helmet } from "react-helmet-async";

export default function About() {
  return (
    <div className="mx-auto max-w-3xl px-4 sm:px-6 py-16">
      <Helmet>
        <title>Về chúng tôi · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-3xl font-semibold tracking-tight">Về SecureCode Copilot</h1>
      <p className="mt-4 text-muted leading-relaxed">
        SecureCode Copilot là nền tảng hỗ trợ lập trình viên phát hiện và xử lý lỗ hổng bảo mật sớm trong vòng đời
        phát triển. Chúng tôi kết hợp phân tích tĩnh theo rule với mô hình AI local (CodeBERT / CodeT5) để vừa bắt
        được pattern nguy hiểm vừa giảm báo sai.
      </p>
      <p className="mt-4 text-muted leading-relaxed">
        Mục tiêu: giúp team ship nhanh hơn mà không bỏ qua security review — với giao diện tiếng Việt, quota minh
        bạch và đường nâng cấp rõ ràng từ Free đến Enterprise.
      </p>
    </div>
  );
}
