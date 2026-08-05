import { Helmet } from "react-helmet-async";
import { Link } from "react-router-dom";
import { Users } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { Card } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";

export default function Team() {
  const { user } = useAuth();
  const isTeam = ["team", "enterprise"].includes(user?.plan_code || "");

  return (
    <div>
      <Helmet>
        <title>Nhóm · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-2xl font-semibold tracking-tight">Nhóm</h1>
      <p className="text-sm text-muted mt-1">Workspace dùng chung cho đội ngũ nhỏ</p>

      <Card className="mt-8 p-10 text-center max-w-lg mx-auto">
        <Users className="h-10 w-10 text-primary mx-auto mb-4" />
        {isTeam ? (
          <>
            <h2 className="font-semibold text-lg">Workspace nhóm đang được hoàn thiện</h2>
            <p className="text-sm text-muted mt-2">
              Gói {user?.plan_name} của bạn đã sẵn sàng cho thành viên. Mời thành viên và dashboard nhóm sẽ có trong
              bản cập nhật tới.
            </p>
          </>
        ) : (
          <>
            <h2 className="font-semibold text-lg">Cần gói Team</h2>
            <p className="text-sm text-muted mt-2">
              Mời tới 5 thành viên, quota chung và dashboard nhóm — nâng cấp để mở khóa.
            </p>
            <Link to="/dashboard/billing" className="inline-block mt-5">
              <Button>Nâng cấp Team</Button>
            </Link>
          </>
        )}
      </Card>
    </div>
  );
}
