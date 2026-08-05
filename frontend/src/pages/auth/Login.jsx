import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Shield } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/Card";
import { FadeIn } from "../../components/ui/Motion";
import { ApiError } from "../../lib/api";

const schema = z.object({
  email: z.string().email("Email không hợp lệ"),
  password: z.string().min(1, "Nhập mật khẩu"),
});

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState("");
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({ resolver: zodResolver(schema) });

  async function onSubmit(values) {
    setError("");
    try {
      await login(values.email, values.password);
      const to = location.state?.from || "/dashboard";
      navigate(to, { replace: true });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Đăng nhập thất bại");
    }
  }

  return (
    <div className="auth-stage">
      <Helmet>
        <title>Đăng nhập · SecureCode Copilot</title>
      </Helmet>
      <FadeIn className="w-full max-w-md">
        <Link to="/" className="mb-6 flex items-center justify-center gap-2 font-semibold text-fg">
          <span className="brand-mark">
            <Shield className="h-4 w-4" />
          </span>
          SecureCode Copilot
        </Link>
        <Card className="glass border-border/80 shadow-[0_24px_60px_-28px_rgba(55,48,163,0.35)]">
          <CardHeader>
            <CardTitle className="text-xl">Đăng nhập</CardTitle>
            <CardDescription>Chào mừng trở lại lab bảo mật của bạn</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <Input label="Email" type="email" autoComplete="email" error={errors.email?.message} {...register("email")} />
              <Input
                label="Mật khẩu"
                type="password"
                autoComplete="current-password"
                error={errors.password?.message}
                {...register("password")}
              />
              {error ? <p className="text-sm text-danger">{error}</p> : null}
              <Button type="submit" className="w-full" loading={isSubmitting}>
                Đăng nhập
              </Button>
            </form>
            <p className="mt-4 text-sm text-muted text-center">
              <Link to="/forgot-password" className="text-primary hover:underline">
                Quên mật khẩu?
              </Link>
            </p>
            <p className="mt-3 text-xs text-muted text-center leading-relaxed rounded-lg bg-fg/[0.03] border border-border/60 px-3 py-2">
              Demo: <code className="font-mono text-fg/80">pro@securecode.dev</code> /{" "}
              <code className="font-mono text-fg/80">Pro12345!</code>
            </p>
            <p className="mt-3 text-sm text-muted text-center">
              Chưa có tài khoản?{" "}
              <Link to="/register" className="text-primary hover:underline">
                Đăng ký
              </Link>
            </p>
          </CardContent>
        </Card>
      </FadeIn>
    </div>
  );
}
