import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Check } from "lucide-react";
import { api } from "../../lib/api";
import { formatVnd, cn } from "../../lib/utils";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { Skeleton } from "../../components/ui/Skeleton";

export default function Pricing() {
  const [plans, setPlans] = useState([]);
  const [yearly, setYearly] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .plans()
      .then(setPlans)
      .catch(() => setPlans([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6 py-20">
      <Helmet>
        <title>Bảng giá · SecureCode Copilot</title>
      </Helmet>
      <div className="text-center max-w-2xl mx-auto">
        <p className="section-kicker">Pricing</p>
        <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-tight">Bảng giá rõ ràng</h1>
        <p className="mt-4 text-muted leading-relaxed">Chọn gói phù hợp — nâng cấp khi cần thêm lượt phân tích.</p>
        <div className="mt-8 inline-flex items-center gap-1 rounded-xl border border-border bg-surface/80 p-1 text-sm shadow-sm">
          <button
            type="button"
            className={cn(
              "rounded-lg px-4 py-2 transition-all duration-200",
              !yearly && "bg-primary text-primary-fg shadow-sm"
            )}
            onClick={() => setYearly(false)}
          >
            Theo tháng
          </button>
          <button
            type="button"
            className={cn(
              "rounded-lg px-4 py-2 transition-all duration-200",
              yearly && "bg-primary text-primary-fg shadow-sm"
            )}
            onClick={() => setYearly(true)}
          >
            Theo năm <span className="text-xs opacity-85">−17%</span>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="mt-12 grid md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-72" />
          ))}
        </div>
      ) : (
        <div className="mt-12 grid md:grid-cols-2 lg:grid-cols-4 gap-4">
          {plans.map((p) => {
            const price = yearly ? p.price_yearly_vnd : p.price_monthly_vnd;
            return (
              <Card
                key={p.code}
                hover
                className={cn("p-6 flex flex-col", p.popular && "border-primary/40 ring-1 ring-primary/25 bg-primary/[0.03]")}
              >
                <div className="flex items-center justify-between gap-2">
                  <h2 className="font-semibold text-lg">{p.name}</h2>
                  {p.popular ? <Badge variant="primary">Phổ biến</Badge> : null}
                </div>
                <p className="mt-1 text-sm text-muted min-h-[40px]">{p.description}</p>
                <p className="mt-4 text-2xl font-bold tracking-tight">
                  {p.contact_only ? "Liên hệ" : price === 0 ? "Miễn phí" : formatVnd(price)}
                </p>
                <p className="text-xs text-muted mt-1">
                  {p.contact_only
                    ? "Enterprise tùy chỉnh"
                    : yearly
                      ? "thanh toán năm"
                      : p.price_monthly_vnd === 0
                        ? "mãi mãi"
                        : "/ tháng"}
                </p>
                <ul className="mt-4 space-y-2 text-sm text-muted flex-1">
                  {(p.features || []).slice(0, 6).map((f) => (
                    <li key={f} className="flex gap-2">
                      <Check className="h-4 w-4 text-success shrink-0 mt-0.5" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <Link to={p.contact_only ? "/contact" : "/register"} className="mt-6 block">
                  <Button variant={p.popular ? "primary" : "secondary"} className="w-full">
                    {p.contact_only ? "Liên hệ tư vấn" : p.code === "free" ? "Bắt đầu Free" : "Chọn gói"}
                  </Button>
                </Link>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
