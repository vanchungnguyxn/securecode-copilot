import { useEffect, useState } from "react";
import { Helmet } from "react-helmet-async";
import { Check } from "lucide-react";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { formatVnd, formatDate, cn } from "../../lib/utils";
import { Button } from "../../components/ui/Button";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/Card";
import { Badge } from "../../components/ui/Badge";
import { QuotaBar } from "../../components/ui/QuotaBar";
import { Skeleton } from "../../components/ui/Skeleton";
import { useToast } from "../../components/ui/Toast";

export default function Billing() {
  const { user, refresh, setUser } = useAuth();
  const { toast } = useToast();
  const [plans, setPlans] = useState([]);
  const [payments, setPayments] = useState([]);
  const [yearly, setYearly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(null);

  useEffect(() => {
    Promise.all([api.plans(), api.payments().catch(() => [])])
      .then(([p, pay]) => {
        setPlans(p);
        setPayments(pay);
      })
      .finally(() => setLoading(false));
  }, []);

  async function checkout(planCode) {
    setBusy(planCode);
    try {
      const out = await api.checkout({
        plan_code: planCode,
        billing_cycle: yearly ? "yearly" : "monthly",
      });
      const updated = await api.mockPay({ transaction_id: out.transaction_id });
      if (updated) setUser(updated);
      else await refresh();
      const pay = await api.payments();
      setPayments(pay);
      toast("Thanh toán mock thành công — gói đã cập nhật", { variant: "success" });
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Checkout thất bại", { variant: "danger" });
    } finally {
      setBusy(null);
    }
  }

  async function cancel() {
    if (!confirm("Hủy đăng ký và về Free?")) return;
    try {
      await api.cancelSubscription();
      await refresh();
      toast("Đã hủy — về gói Free");
    } catch (e) {
      toast(e.message, { variant: "danger" });
    }
  }

  return (
    <div>
      <Helmet>
        <title>Thanh toán · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-2xl font-semibold tracking-tight">Thanh toán & gói</h1>
      <p className="text-sm text-muted mt-1">Checkout mock — dùng cho demo SaaS</p>

      <Card className="mt-6 p-5">
        <div className="flex flex-wrap gap-6 justify-between">
          <div>
            <p className="text-xs text-muted">Gói hiện tại</p>
            <p className="text-xl font-semibold mt-1 capitalize">{user?.plan_name || user?.plan_code}</p>
            <Badge className="mt-2">{user?.subscription_status}</Badge>
          </div>
          <div className="w-56">
            <p className="text-xs text-muted mb-2">Usage</p>
            <QuotaBar used={user?.used_this_month || 0} limit={user?.monthly_limit || 0} />
          </div>
          {user?.plan_code && user.plan_code !== "free" ? (
            <Button variant="outline" size="sm" onClick={cancel}>
              Hủy gói (về Free)
            </Button>
          ) : null}
        </div>
      </Card>

      <div className="mt-6 flex items-center gap-2">
        <button
          type="button"
          className={cn("rounded-lg px-3 py-1.5 text-sm border", !yearly ? "bg-primary text-primary-fg border-primary" : "border-border")}
          onClick={() => setYearly(false)}
        >
          Tháng
        </button>
        <button
          type="button"
          className={cn("rounded-lg px-3 py-1.5 text-sm border", yearly ? "bg-primary text-primary-fg border-primary" : "border-border")}
          onClick={() => setYearly(true)}
        >
          Năm (−17%)
        </button>
      </div>

      {loading ? (
        <div className="mt-4 grid md:grid-cols-3 gap-4">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      ) : (
        <div className="mt-4 grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {plans
            .filter((p) => p.code !== "enterprise")
            .map((p) => {
              const price = yearly ? p.price_yearly_vnd : p.price_monthly_vnd;
              const current = user?.plan_code === p.code;
              return (
                <Card key={p.code} className={cn("p-5 flex flex-col", p.popular && "border-primary")}>
                  <h2 className="font-semibold text-lg">{p.name}</h2>
                  <p className="text-2xl font-bold mt-2">{price === 0 ? "Miễn phí" : formatVnd(price)}</p>
                  <ul className="mt-3 space-y-1.5 text-sm text-muted flex-1">
                    {(p.features || []).slice(0, 5).map((f) => (
                      <li key={f} className="flex gap-2">
                        <Check className="h-4 w-4 text-success shrink-0" /> {f}
                      </li>
                    ))}
                  </ul>
                  <Button
                    className="mt-4 w-full"
                    variant={current ? "secondary" : "primary"}
                    disabled={current || p.code === "free" || busy === p.code}
                    loading={busy === p.code}
                    onClick={() => checkout(p.code)}
                  >
                    {current ? "Đang dùng" : p.code === "free" ? "Gói mặc định" : "Thanh toán (mock)"}
                  </Button>
                </Card>
              );
            })}
        </div>
      )}

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Lịch sử thanh toán</CardTitle>
        </CardHeader>
        <CardContent>
          {payments.length === 0 ? (
            <p className="text-sm text-muted">Chưa có giao dịch.</p>
          ) : (
            <ul className="divide-y divide-border text-sm">
              {payments.map((p) => (
                <li key={p.id || p.transaction_id} className="py-2 flex justify-between gap-2">
                  <span>
                    {formatVnd(p.amount)} · {p.status} · {p.billing_cycle}
                  </span>
                  <span className="text-muted text-xs">{formatDate(p.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
