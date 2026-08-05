import { useState } from "react";
import { Helmet } from "react-helmet-async";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { Button } from "../../components/ui/Button";
import { Input, Select } from "../../components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/Card";
import { useToast } from "../../components/ui/Toast";

const profileSchema = z.object({
  full_name: z.string().min(2),
});

const pwSchema = z
  .object({
    current_password: z.string().min(1),
    new_password: z.string().min(8),
    confirm: z.string(),
  })
  .refine((d) => d.new_password === d.confirm, { path: ["confirm"], message: "Không khớp" });

export default function Settings() {
  const { user, refresh, setUser } = useAuth();
  const { theme, setTheme } = useTheme();
  const { toast } = useToast();
  const [clearing, setClearing] = useState(false);

  const profileForm = useForm({
    resolver: zodResolver(profileSchema),
    defaultValues: { full_name: user?.full_name || "" },
  });

  const pwForm = useForm({ resolver: zodResolver(pwSchema) });

  async function saveProfile(values) {
    try {
      const updated = await api.updateMe({ full_name: values.full_name, theme });
      setUser(updated);
      toast("Đã lưu hồ sơ", { variant: "success" });
    } catch (e) {
      toast(e.message, { variant: "danger" });
    }
  }

  async function savePassword(values) {
    try {
      await api.changePassword({
        current_password: values.current_password,
        new_password: values.new_password,
      });
      pwForm.reset();
      toast("Đã đổi mật khẩu", { variant: "success" });
    } catch (e) {
      toast(e instanceof ApiError ? e.message : "Lỗi", { variant: "danger" });
    }
  }

  async function onThemeChange(next) {
    setTheme(next);
    try {
      const updated = await api.updateMe({ theme: next });
      setUser(updated);
    } catch {
      /* local theme still applied */
    }
  }

  async function clearHistory() {
    if (!confirm("Xóa toàn bộ lịch sử phân tích? Không hoàn tác.")) return;
    setClearing(true);
    try {
      await api.clearAnalyses();
      toast("Đã xóa lịch sử", { variant: "success" });
      await refresh();
    } catch (e) {
      toast(e.message, { variant: "danger" });
    } finally {
      setClearing(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <Helmet>
        <title>Cài đặt · SecureCode Copilot</title>
      </Helmet>
      <h1 className="text-2xl font-semibold tracking-tight">Cài đặt</h1>

      <Card>
        <CardHeader>
          <CardTitle>Hồ sơ</CardTitle>
          <CardDescription>{user?.email}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={profileForm.handleSubmit(saveProfile)} className="space-y-4">
            <Input label="Họ tên" error={profileForm.formState.errors.full_name?.message} {...profileForm.register("full_name")} />
            <Button type="submit" loading={profileForm.formState.isSubmitting}>
              Lưu
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Mật khẩu</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={pwForm.handleSubmit(savePassword)} className="space-y-4">
            <Input
              label="Mật khẩu hiện tại"
              type="password"
              error={pwForm.formState.errors.current_password?.message}
              {...pwForm.register("current_password")}
            />
            <Input
              label="Mật khẩu mới"
              type="password"
              error={pwForm.formState.errors.new_password?.message}
              {...pwForm.register("new_password")}
            />
            <Input
              label="Xác nhận"
              type="password"
              error={pwForm.formState.errors.confirm?.message}
              {...pwForm.register("confirm")}
            />
            <Button type="submit" loading={pwForm.formState.isSubmitting}>
              Đổi mật khẩu
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Giao diện</CardTitle>
        </CardHeader>
        <CardContent>
          <Select label="Theme" value={theme} onChange={(e) => onThemeChange(e.target.value)}>
            <option value="system">Theo hệ thống</option>
            <option value="light">Sáng</option>
            <option value="dark">Tối</option>
          </Select>
        </CardContent>
      </Card>

      <Card className="border-danger/30">
        <CardHeader>
          <CardTitle>Vùng nguy hiểm</CardTitle>
          <CardDescription>Xóa toàn bộ lịch sử phân tích trên tài khoản này</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="danger" loading={clearing} onClick={clearHistory}>
            Xóa lịch sử
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
