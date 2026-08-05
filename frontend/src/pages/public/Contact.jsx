import { useState } from "react";
import { Helmet } from "react-helmet-async";
import { Button } from "../../components/ui/Button";
import { Input, Textarea } from "../../components/ui/Input";
import { useToast } from "../../components/ui/Toast";

export default function Contact() {
  const { toast } = useToast();
  const [sent, setSent] = useState(false);

  function onSubmit(e) {
    e.preventDefault();
    setSent(true);
    toast("Đã ghi nhận — chúng tôi sẽ phản hồi sớm (mock).", { variant: "success" });
  }

  return (
    <div className="mx-auto max-w-lg px-4 sm:px-6 py-16">
      <Helmet>
        <title>Liên hệ · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-3xl font-semibold tracking-tight">Liên hệ</h1>
      <p className="mt-3 text-muted text-sm">
        Hỗ trợ sản phẩm, Enterprise, hoặc phản hồi — gửi form bên dưới.
      </p>
      <form onSubmit={onSubmit} className="mt-8 space-y-4">
        <Input name="name" label="Họ tên" required placeholder="Nguyễn Văn A" />
        <Input name="email" type="email" label="Email" required placeholder="you@company.com" />
        <Textarea name="message" label="Nội dung" required placeholder="Tôi muốn tư vấn gói Enterprise…" />
        <Button type="submit" disabled={sent}>
          {sent ? "Đã gửi" : "Gửi tin nhắn"}
        </Button>
      </form>
      <p className="mt-6 text-sm text-muted">
        Email:{" "}
        <a href="mailto:hello@securecode.local" className="text-primary hover:underline">
          hello@securecode.local
        </a>
      </p>
    </div>
  );
}
