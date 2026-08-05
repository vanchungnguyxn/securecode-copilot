import { Helmet } from "react-helmet-async";
import { Link } from "react-router-dom";
import { Github, Gitlab, Webhook } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";

const ITEMS = [
  { icon: Github, name: "GitHub", desc: "Quét PR / push webhook — sắp ra mắt." },
  { icon: Gitlab, name: "GitLab", desc: "CI pipeline integration — sắp ra mắt." },
  { icon: Webhook, name: "Webhook / API", desc: "Gọi API phân tích từ hệ thống của bạn." },
];

export default function Integrations() {
  const { user } = useAuth();
  const needTeam = !["team", "enterprise"].includes(user?.plan_code || "");

  return (
    <div>
      <Helmet>
        <title>Tích hợp · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-2xl font-semibold tracking-tight">Tích hợp</h1>
      <p className="text-sm text-muted mt-1">Kết nối repo và CI — yêu cầu gói Team trở lên khi GA</p>

      {needTeam ? (
        <Card className="mt-6 p-6 text-center">
          <p className="text-muted text-sm">
            Tích hợp GitHub / CI sắp ra mắt đầy đủ trên gói <strong className="text-fg">Team</strong> và{" "}
            <strong className="text-fg">Enterprise</strong>.
          </p>
          <Link to="/dashboard/billing" className="inline-block mt-4">
            <Button>Xem gói Team</Button>
          </Link>
        </Card>
      ) : null}

      <div className="mt-6 grid sm:grid-cols-3 gap-4">
        {ITEMS.map((i) => (
          <Card key={i.name} className="p-5 opacity-80">
            <i.icon className="h-5 w-5 text-primary mb-3" />
            <h2 className="font-semibold">{i.name}</h2>
            <p className="text-sm text-muted mt-1">{i.desc}</p>
            <Button size="sm" variant="secondary" className="mt-4" disabled>
              Sắp ra mắt
            </Button>
          </Card>
        ))}
      </div>
    </div>
  );
}
