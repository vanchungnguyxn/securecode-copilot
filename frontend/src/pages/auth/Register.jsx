import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/Card";
import { ApiError } from "../../lib/api";

const schema = z
  .object({
    full_name: z.string().min(2, "Tên tối thiểu 2 ký tự"),
    email: z.string().email("Email không hợp lệ"),
    password: z
      .string()
      .min(8, "Tối thiểu 8 ký tự")
      .regex(/[A-Z]/, "Cần chữ hoa")
      .regex(/[a-z]/, "Cần chữ thường")
      .regex(/[0-9]/, "Cần số"),
    confirm_password: z.string(),
    accept_terms: z.boolean().refine((v) => v === true, { message: "Bạn cần đồng ý điều khoản" }),
  })
  .refine((d) => d.password === d.confirm_password, {
    message: "Xác nhận mật khẩu không khớp",
    path: ["confirm_password"],
  });

export default function Register() {
  const { register: doRegister } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(schema),
    defaultValues: { accept_terms: false },
  });

  async function onSubmit(values) {
    setError("");
    try {
      await doRegister({
        full_name: values.full_name,
        email: values.email,
        password: values.password,
        confirm_password: values.confirm_password,
        accept_terms: true,
      });
      navigate("/dashboard", { replace: true });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Đăng ký thất bại");
    }
  }

  return (
    <div className="auth-stage">
      <Helmet>
        <title>Đăng ký · SecureCode Copilot</title>
      </Helmet>
      <Card className="w-full max-w-md glass border-border/80 shadow-[0_24px_60px_-28px_rgba(55,48,163,0.35)] page-enter">
        <CardHeader>
          <CardTitle className="text-xl">Tạo tài khoản Free</CardTitle>
          <CardDescription>5 lượt phân tích mỗi tháng — không cần thẻ</CardDescription>
        </CardHeader>        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <Input label="Họ tên" error={errors.full_name?.message} {...register("full_name")} />
            <Input label="Email" type="email" autoComplete="email" error={errors.email?.message} {...register("email")} />
            <Input
              label="Mật khẩu"
              type="password"
              autoComplete="new-password"
              hint="Ít nhất 8 ký tự, gồm hoa, thường và số"
              error={errors.password?.message}
              {...register("password")}
            />
            <Input
              label="Xác nhận mật khẩu"
              type="password"
              error={errors.confirm_password?.message}
              {...register("confirm_password")}
            />
            <label className="flex items-start gap-2 text-sm text-muted">
              <input type="checkbox" className="mt-1" {...register("accept_terms")} />
              <span>
                Tôi đồng ý{" "}
                <Link to="/terms" className="text-primary hover:underline">
                  Điều khoản
                </Link>{" "}
                và{" "}
                <Link to="/privacy" className="text-primary hover:underline">
                  Chính sách bảo mật
                </Link>
              </span>
            </label>
            {errors.accept_terms ? <p className="text-xs text-danger">{errors.accept_terms.message}</p> : null}
            {error ? <p className="text-sm text-danger">{error}</p> : null}
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Đăng ký
            </Button>
          </form>
          <p className="mt-4 text-sm text-muted text-center">
            Đã có tài khoản?{" "}
            <Link to="/login" className="text-primary hover:underline">
              Đăng nhập
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
