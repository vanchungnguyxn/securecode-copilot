import { useState } from "react";
import { Link, useSearchParams, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { api, ApiError } from "../../lib/api";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/Card";

const schema = z
  .object({
    new_password: z.string().min(8, "Tối thiểu 8 ký tự"),
    confirm: z.string(),
  })
  .refine((d) => d.new_password === d.confirm, { message: "Không khớp", path: ["confirm"] });

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({ resolver: zodResolver(schema) });

  async function onSubmit(values) {
    setError("");
    try {
      await api.resetPassword({ token, new_password: values.new_password });
      navigate("/login");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Không thể đặt lại mật khẩu");
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-atmosphere px-4 py-12">
      <Helmet>
        <title>Đặt lại mật khẩu · SecureCode Copilot</title>
      </Helmet>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Đặt lại mật khẩu</CardTitle>
          <CardDescription>{token ? "Nhập mật khẩu mới" : "Thiếu token — kiểm tra link email"}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <Input
              label="Mật khẩu mới"
              type="password"
              error={errors.new_password?.message}
              {...register("new_password")}
            />
            <Input label="Xác nhận" type="password" error={errors.confirm?.message} {...register("confirm")} />
            {error ? <p className="text-sm text-danger">{error}</p> : null}
            <Button type="submit" className="w-full" loading={isSubmitting} disabled={!token}>
              Lưu mật khẩu
            </Button>
          </form>
          <p className="mt-4 text-center text-sm">
            <Link to="/login" className="text-primary hover:underline">
              Về đăng nhập
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
