import { Link, NavLink, Outlet } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import { Menu, X, Shield } from "lucide-react";
import { useEffect, useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../ui/Button";
import { cn } from "../../lib/utils";

const NAV = [
  { to: "/features", label: "Tính năng" },
  { to: "/pricing", label: "Bảng giá" },
  { to: "/docs", label: "Tài liệu" },
  { to: "/about", label: "Về chúng tôi" },
  { to: "/contact", label: "Liên hệ" },
];

export function PublicShell({ title, description }) {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-atmosphere">
      <Helmet>
        <title>{title ? `${title} · SecureCode Copilot` : "SecureCode Copilot"}</title>
        {description ? <meta name="description" content={description} /> : null}
      </Helmet>

      <header
        className={cn(
          "sticky top-0 z-50 transition-all duration-300",
          scrolled
            ? "border-b border-border/80 backdrop-blur-xl shadow-[0_8px_30px_-18px_rgba(10,22,40,0.35)]"
            : "border-b border-transparent"
        )}
        style={{ background: scrolled ? "var(--nav-blur)" : "transparent" }}
      >
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <Link to="/" className="flex items-center gap-2.5 font-semibold tracking-tight text-fg group">
            <span className="brand-mark transition-transform duration-300 group-hover:scale-105">
              <Shield className="h-4 w-4" />
            </span>
            <span className="text-[0.95rem] sm:text-base">SecureCode Copilot</span>
          </Link>

          <nav className="hidden md:flex items-center gap-0.5">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    "rounded-lg px-3.5 py-2 text-sm text-muted transition-colors duration-200 hover:text-fg hover:bg-fg/[0.04]",
                    isActive && "text-fg bg-surface/80 border border-border/60"
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="hidden md:flex items-center gap-2">
            {user ? (
              <Link to="/dashboard">
                <Button size="sm">Vào app</Button>
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="text-sm text-muted hover:text-fg px-3 py-2 transition-colors"
                >
                  Đăng nhập
                </Link>
                <Link to="/register">
                  <Button size="sm">Dùng thử miễn phí</Button>
                </Link>
              </>
            )}
          </div>

          <button
            type="button"
            className="md:hidden p-2 rounded-lg text-muted hover:bg-fg/5 focus-ring"
            onClick={() => setOpen((o) => !o)}
            aria-label="Menu"
          >
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        {open ? (
          <div className="md:hidden border-t border-border glass px-4 py-4 space-y-1 animate-toast">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className="block rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-bg hover:text-fg"
                onClick={() => setOpen(false)}
              >
                {item.label}
              </Link>
            ))}
            <div className="flex gap-2 pt-3">
              <Link to="/login" className="flex-1" onClick={() => setOpen(false)}>
                <Button variant="secondary" className="w-full" size="sm">
                  Đăng nhập
                </Button>
              </Link>
              <Link to="/register" className="flex-1" onClick={() => setOpen(false)}>
                <Button className="w-full" size="sm">
                  Đăng ký
                </Button>
              </Link>
            </div>
          </div>
        ) : null}
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      <footer className="border-t border-border relative overflow-hidden">
        <div className="absolute inset-0 bg-surface/70 pointer-events-none" aria-hidden />
        <div className="relative mx-auto max-w-6xl px-4 sm:px-6 py-12 grid gap-10 sm:grid-cols-3 text-sm">
          <div>
            <div className="flex items-center gap-2 font-semibold text-fg">
              <span className="brand-mark">
                <Shield className="h-3.5 w-3.5" />
              </span>
              SecureCode Copilot
            </div>
            <p className="mt-3 text-muted leading-relaxed max-w-xs">
              Lab bảo mật cho developer — hybrid SAST + AI local để detect, explain và fix trước khi ship.
            </p>
          </div>
          <div>
            <p className="font-medium text-fg mb-3 text-xs uppercase tracking-wider">Sản phẩm</p>
            <ul className="space-y-2 text-muted">
              <li>
                <Link to="/features" className="hover:text-fg transition-colors">
                  Tính năng
                </Link>
              </li>
              <li>
                <Link to="/pricing" className="hover:text-fg transition-colors">
                  Bảng giá
                </Link>
              </li>
              <li>
                <Link to="/docs" className="hover:text-fg transition-colors">
                  Tài liệu
                </Link>
              </li>
            </ul>
          </div>
          <div>
            <p className="font-medium text-fg mb-3 text-xs uppercase tracking-wider">Pháp lý</p>
            <ul className="space-y-2 text-muted">
              <li>
                <Link to="/privacy" className="hover:text-fg transition-colors">
                  Chính sách bảo mật
                </Link>
              </li>
              <li>
                <Link to="/terms" className="hover:text-fg transition-colors">
                  Điều khoản sử dụng
                </Link>
              </li>
              <li>
                <Link to="/contact" className="hover:text-fg transition-colors">
                  Liên hệ
                </Link>
              </li>
            </ul>
          </div>
        </div>
        <div className="relative border-t border-border px-4 py-4 text-center text-xs text-muted">
          © {new Date().getFullYear()} SecureCode Copilot · Kết quả AI mang tính hỗ trợ — luôn review trước khi merge.
        </div>
      </footer>
    </div>
  );
}
