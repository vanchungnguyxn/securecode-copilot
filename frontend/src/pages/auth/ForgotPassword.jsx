import { useState } from "react";
import { Link } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { api } from "../../lib/api";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/Card";

const schema = z.object({ email: z.string().email("Email không hợp lệ") });

export default function ForgotPassword() {
  const [done, setDone] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({ resolver: zodResolver(schema) });

  async function onSubmit(values) {
    await api.forgotPassword(values);
    setDone(true);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-atmosphere px-4 py-12">
      <Helmet>
        <title>Quên mật khẩu · SecureCode Copilot</title>
      </Helmet>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Quên mật khẩu</CardTitle>
          <CardDescription>Nhập email — nếu tồn tại, bạn sẽ nhận hướng dẫn đặt lại</CardDescription>
        </CardHeader>
        <CardContent>
          {done ? (
            <p className="text-sm text-muted">
              Nếu email tồn tại, hướng dẫn đã được gửi (dev: xem log backend).{" "}
              <Link to="/login" className="text-primary hover:underline">
                Về đăng nhập
              </Link>
            </p>
          ) : (
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <Input label="Email" type="email" error={errors.email?.message} {...register("email")} />
              <Button type="submit" className="w-full" loading={isSubmitting}>
                Gửi hướng dẫn
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
