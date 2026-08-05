import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { ArrowRight, Check, Shield, Zap, FileCode2, GitBranch } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { Card, CardContent } from "../../components/ui/Card";
import { FadeIn, Stagger, StaggerItem } from "../../components/ui/Motion";

const features = [
  {
    icon: Shield,
    title: "Hybrid detect",
    body: "Rule SAST bắt pattern quen thuộc; CodeBERT lọc báo sai để giảm nhiễu.",
  },
  {
    icon: FileCode2,
    title: "Explain & Fix",
    body: "Giải thích CWE/OWASP bằng tiếng Việt và đề xuất bản vá có thể apply.",
  },
  {
    icon: GitBranch,
    title: "File · GitHub · ZIP",
    body: "Quét snippet, repo GitHub hoặc archive ZIP — findings kèm explain/fix theo ngữ cảnh.",
  },
  {
    icon: Zap,
    title: "Quota rõ ràng",
    body: "Biết còn bao nhiêu lượt trong tháng. Nâng cấp khi cần — không bất ngờ.",
  },
];

const langsOk = ["Python", "JavaScript", "Java", "C", "C++"];
const langsSoon = ["C#", "PHP", "Go", "TypeScript"];

const faqs = [
  {
    q: "SecureCode Copilot có thay thế review bảo mật không?",
    a: "Không. Đây là công cụ hỗ trợ — luôn đọc kết quả và review trước khi merge.",
  },
  {
    q: "Code của tôi có bị lưu không?",
    a: "Phân tích trong tài khoản được lưu theo gói để xem lại lịch sử. Gói Enterprise có tùy chọn không lưu source.",
  },
  {
    q: "Dùng thử như thế nào?",
    a: "Đăng ký Free — 5 lượt/tháng. Không cần thẻ tín dụng.",
  },
];

export default function Landing() {
  return (
    <>
      <Helmet>
        <title>SecureCode Copilot — Bảo mật code trước khi ship</title>
        <meta
          name="description"
          content="Phát hiện lỗ hổng, giải thích CWE và đề xuất bản vá bằng AI hybrid. Dùng thử miễn phí."
        />
      </Helmet>

      {/* Full-bleed hero — brand first, one CTA group, dominant visual */}
      <section className="hero-plane border-b border-border">
        <div className="relative z-10 mx-auto max-w-6xl px-4 sm:px-6 pt-20 pb-24 lg:pt-28 lg:pb-32">
          <div className="grid lg:grid-cols-[1.05fr_0.95fr] gap-14 lg:gap-16 items-center">
            <FadeIn>
              <p className="text-3xl sm:text-4xl lg:text-[2.75rem] font-bold tracking-tight text-fg leading-none">
                SecureCode Copilot
              </p>
              <h1 className="mt-5 text-2xl sm:text-3xl lg:text-[2.15rem] font-semibold tracking-tight text-fg/90 leading-snug max-w-lg">
                Bảo mật code trước khi ship.
              </h1>
              <p className="mt-4 text-muted text-base sm:text-lg max-w-md leading-relaxed">
                Phát hiện lỗ hổng, giải thích CWE, đề xuất bản vá — hybrid rule + AI local.
              </p>
              <div className="mt-9 flex flex-wrap gap-3">
                <Link to="/register">
                  <Button size="lg">
                    Dùng thử miễn phí <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
                <Link to="/pricing">
                  <Button size="lg" variant="secondary">
                    Xem bảng giá
                  </Button>
                </Link>
              </div>
            </FadeIn>

            <FadeIn delay={0.12} className="relative">
              <div className="float-soft relative">
                <div className="scan-sweep relative rounded-xl border border-border/80 bg-[#0b1220] overflow-hidden shadow-[0_24px_80px_-28px_rgba(55,48,163,0.55)]">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-white/8 text-xs text-white/45 font-mono bg-white/[0.03]">
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-400/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-teal-400/80" />
                    <span className="ml-2">workspace · hybrid scan</span>
                    <span className="ml-auto text-teal-300/80">3 findings</span>
                  </div>
                  <div className="grid sm:grid-cols-[1.1fr_0.9fr]">
                    <pre className="p-4 sm:p-5 text-[11px] sm:text-[12px] leading-relaxed text-slate-300/95 font-mono overflow-x-auto border-b sm:border-b-0 sm:border-r border-white/8">{`# vulnerable
q = f"SELECT * FROM users
      WHERE id = {uid}"

# → SQLi · high · CWE-89
cursor.execute(
  "SELECT * FROM users WHERE id=?",
  (uid,),
)`}</pre>
                    <div className="p-4 space-y-2.5 bg-[#080e18]">
                      {[
                        { sev: "HIGH", t: "SQL Injection", m: "CWE-89 · L2" },
                        { sev: "HIGH", t: "Command Injection", m: "CWE-78 · L10" },
                        { sev: "MED", t: "Hardcoded Secret", m: "CWE-798 · L3" },
                      ].map((r) => (
                        <div
                          key={r.t}
                          className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[11px] font-medium text-slate-100">{r.t}</span>
                            <span className="text-[9px] font-semibold tracking-wide text-rose-300/90">
                              {r.sev}
                            </span>
                          </div>
                          <p className="text-[10px] font-mono text-slate-500 mt-1">{r.m}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </FadeIn>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
        <FadeIn once>
          <p className="section-kicker">Tin cậy</p>
          <h2 className="mt-3 text-2xl sm:text-3xl font-semibold tracking-tight">
            Xây cho đội ngũ ship nhanh, không bỏ qua bảo mật.
          </h2>
          <p className="mt-3 text-muted max-w-xl leading-relaxed">
            Dành cho developer, security champion và team nhỏ cần feedback lỗ hổng ngay trong vòng dev.
          </p>
        </FadeIn>
        <Stagger className="mt-10 grid sm:grid-cols-3 gap-4" delay={0.05}>
          {["Giảm báo sai nhờ Anti-FP", "Giải thích tiếng Việt", "Apply fix một click"].map((t) => (
            <StaggerItem key={t}>
              <div className="glass-panel rounded-xl px-4 py-4 flex items-start gap-3 text-sm surface-hover">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-success/10 text-success">
                  <Check className="h-3.5 w-3.5" />
                </span>
                <span className="text-fg/90 leading-snug">{t}</span>
              </div>
            </StaggerItem>
          ))}
        </Stagger>
      </section>

      <section className="border-y border-border bg-surface/55">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
          <FadeIn once>
            <p className="section-kicker">Pipeline</p>
            <h2 className="mt-3 text-2xl sm:text-3xl font-semibold tracking-tight">Ba bước. Một dòng chảy.</h2>
          </FadeIn>
          <Stagger className="mt-12 grid md:grid-cols-3 gap-8 md:gap-10" delay={0.05}>
            {[
              { n: "01", t: "Quét", d: "Dán code, GitHub URL hoặc ZIP — nhận findings theo mức độ nghiêm trọng." },
              { n: "02", t: "Hybrid detect", d: "Rules + CodeBERT ngưỡng Anti-FP để giảm báo ảo." },
              { n: "03", t: "Explain & Fix", d: "CodeT5 sinh giải thích và patch; apply vào editor khi chọn finding." },
            ].map((s) => (
              <StaggerItem key={s.n}>
                <span className="font-mono text-primary/90 text-sm tracking-wide">{s.n}</span>
                <h3 className="mt-3 font-semibold text-lg tracking-tight">{s.t}</h3>
                <p className="mt-2 text-sm text-muted leading-relaxed">{s.d}</p>
              </StaggerItem>
            ))}
          </Stagger>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
        <FadeIn once>
          <p className="section-kicker">Tính năng</p>
          <h2 className="mt-3 text-2xl sm:text-3xl font-semibold tracking-tight">
            Đủ để ship an toàn hơn mỗi ngày.
          </h2>
        </FadeIn>
        <Stagger className="mt-10 grid sm:grid-cols-2 gap-4" delay={0.04}>
          {features.map((f) => (
            <StaggerItem key={f.title}>
              <Card hover className="p-6 h-full">
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <f.icon className="h-4.5 w-4.5 h-[18px] w-[18px]" />
                </span>
                <h3 className="mt-4 font-semibold tracking-tight">{f.title}</h3>
                <p className="mt-2 text-sm text-muted leading-relaxed">{f.body}</p>
              </Card>
            </StaggerItem>
          ))}
        </Stagger>
      </section>

      <section className="border-y border-border bg-surface/40">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
          <FadeIn once>
            <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Ngôn ngữ hỗ trợ</h2>
            <p className="mt-3 text-muted text-sm">Coverage mở rộng theo từng giai đoạn.</p>
          </FadeIn>
          <div className="mt-8 flex flex-wrap gap-2.5">
            {langsOk.map((l) => (
              <span
                key={l}
                className="rounded-lg border border-success/25 bg-success/10 px-3.5 py-2 text-sm text-success"
              >
                {l} · Đang hỗ trợ
              </span>
            ))}
            {langsSoon.map((l) => (
              <span key={l} className="rounded-lg border border-border bg-surface/60 px-3.5 py-2 text-sm text-muted">
                {l} · Đang mở rộng
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
        <FadeIn once>
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Kết quả demo</h2>
          <p className="mt-3 text-muted text-sm">Findings + severity + CWE trong một workspace.</p>
        </FadeIn>
        <Card className="mt-8 overflow-hidden" hover>
          <CardContent className="p-0">
            <div className="grid sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-border">
              {[
                { sev: "high", title: "SQL Injection", meta: "CWE-89 · L6" },
                { sev: "high", title: "Command Injection", meta: "CWE-78 · L10" },
                { sev: "medium", title: "Hardcoded Secret", meta: "CWE-798 · L3" },
              ].map((r) => (
                <div key={r.title} className="p-5 hover:bg-fg/[0.02] transition-colors">
                  <span className="text-[10px] uppercase tracking-wider font-semibold text-danger">{r.sev}</span>
                  <p className="font-medium mt-1.5 tracking-tight">{r.title}</p>
                  <p className="text-xs text-muted font-mono mt-1">{r.meta}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </section>

      <section className="border-y border-border bg-surface/55">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <FadeIn once>
              <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Bắt đầu từ Free</h2>
              <p className="mt-3 text-muted text-sm">Nâng Pro khi cần thêm quota và lịch sử.</p>
            </FadeIn>
            <Link to="/pricing">
              <Button variant="secondary">Chi tiết bảng giá</Button>
            </Link>
          </div>
          <Stagger className="mt-10 grid sm:grid-cols-3 gap-4" delay={0.04}>
            {[
              { name: "Free", price: "0đ", note: "5 lượt / tháng" },
              { name: "Pro", price: "149.000đ", note: "100 lượt / tháng · phổ biến", hot: true },
              { name: "Team", price: "499.000đ", note: "500 lượt · tới 5 thành viên" },
            ].map((p) => (
              <StaggerItem key={p.name}>
                <Card hover className={cnPlan(p.hot)}>
                  <p className="font-semibold tracking-tight">{p.name}</p>
                  <p className="mt-3 text-2xl font-bold tracking-tight">{p.price}</p>
                  <p className="text-sm text-muted mt-1.5">{p.note}</p>
                </Card>
              </StaggerItem>
            ))}
          </Stagger>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
        <FadeIn once>
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Câu hỏi thường gặp</h2>
        </FadeIn>
        <div className="mt-10 space-y-3 max-w-2xl">
          {faqs.map((f) => (
            <details
              key={f.q}
              className="group rounded-xl border border-border bg-surface px-5 py-4 open:border-primary/25 transition-colors"
            >
              <summary className="cursor-pointer font-medium list-none flex justify-between gap-3 items-start">
                <span>{f.q}</span>
                <span className="text-muted text-lg leading-none transition-transform group-open:rotate-45">+</span>
              </summary>
              <p className="mt-3 text-sm text-muted leading-relaxed pr-6">{f.a}</p>
            </details>
          ))}
        </div>
      </section>

      <section className="relative border-t border-border overflow-hidden">
        <div className="absolute inset-0 hero-plane opacity-60 pointer-events-none" aria-hidden />
        <div className="relative mx-auto max-w-6xl px-4 sm:px-6 py-20 text-center">
          <FadeIn once>
            <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">Sẵn sàng quét code đầu tiên?</h2>
            <p className="mt-3 text-muted">Tạo tài khoản Free — không cần thẻ.</p>
            <Link to="/register" className="inline-block mt-8">
              <Button size="lg">
                Đăng ký ngay <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <p className="mt-10 text-xs text-muted max-w-lg mx-auto leading-relaxed">
              Lưu ý: kết quả từ AI mang tính hỗ trợ. Luôn verify bản vá và tuân thủ quy trình bảo mật của tổ chức bạn.
            </p>
          </FadeIn>
        </div>
      </section>
    </>
  );
}

function cnPlan(hot) {
  return hot
    ? "p-6 border-primary/40 ring-1 ring-primary/20 bg-primary/[0.03]"
    : "p-6";
}
