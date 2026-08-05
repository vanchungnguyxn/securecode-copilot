import { Helmet } from "react-helmet-async";
import { Shield, Brain, Wrench, History, FileJson, Gauge } from "lucide-react";
import { Card } from "../../components/ui/Card";
import { FadeIn, Stagger, StaggerItem } from "../../components/ui/Motion";

const items = [
  { icon: Shield, t: "Hybrid SAST", d: "Rules bắt CVE/CWE phổ biến; ML hỗ trợ đánh giá confidence." },
  { icon: Brain, t: "Giải thích thông minh", d: "Tóm tắt vì sao vulnerable, impact và kịch bản tấn bằng tiếng Việt." },
  { icon: Wrench, t: "Đề xuất bản vá", d: "Snippet an toàn + apply vào editor; copy hoặc export JSON." },
  { icon: History, t: "Lịch sử phân tích", d: "Tra cứu theo project, language, severity — theo hạn mức gói." },
  { icon: FileJson, t: "Báo cáo", d: "Tổng hợp severity, xuất JSON; PDF stub sẵn cho bản sau." },
  { icon: Gauge, t: "Quota & billing", d: "Theo dõi usage, checkout mock hoặc nâng gói Pro/Team." },
];

export default function Features() {
  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
      <Helmet>
        <title>Tính năng · SecureCode Copilot</title>
      </Helmet>
      <FadeIn>
        <p className="section-kicker">Sản phẩm</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-tight">Tính năng</h1>
        <p className="mt-4 text-muted max-w-2xl leading-relaxed">
          Một workspace duy nhất để quét, hiểu lỗ hổng và vá — không nhảy giữa mười tool khác nhau.
        </p>
      </FadeIn>
      <Stagger className="mt-14 grid sm:grid-cols-2 lg:grid-cols-3 gap-4" delay={0.05}>
        {items.map((i) => (
          <StaggerItem key={i.t}>
            <Card hover className="p-6 h-full">
              <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <i.icon className="h-[18px] w-[18px]" />
              </span>
              <h2 className="mt-4 font-semibold tracking-tight">{i.t}</h2>
              <p className="mt-2 text-sm text-muted leading-relaxed">{i.d}</p>
            </Card>
          </StaggerItem>
        ))}
      </Stagger>
    </div>
  );
}
