import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import {
  LayoutDashboard,
  ScanSearch,
  History,
  BarChart3,
  CreditCard,
  Settings,
  Puzzle,
  Users,
  Shield,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Moon,
  Sun,
  Monitor,
  Menu,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { QuotaBar } from "../ui/QuotaBar";
import { cn } from "../../lib/utils";

const NAV = [
  { to: "/dashboard", end: true, label: "Tổng quan", icon: LayoutDashboard },
  { to: "/dashboard/analyze", label: "Phân tích", icon: ScanSearch },
  { to: "/dashboard/history", label: "Lịch sử", icon: History },
  { to: "/dashboard/reports", label: "Báo cáo", icon: BarChart3 },
  { to: "/dashboard/billing", label: "Thanh toán", icon: CreditCard },
  { to: "/dashboard/integrations", label: "Tích hợp", icon: Puzzle },
  { to: "/dashboard/team", label: "Nhóm", icon: Users },
  { to: "/dashboard/settings", label: "Cài đặt", icon: Settings },
];

export function AppShell() {
  const { user, logout, isAdmin } = useAuth();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenu, setUserMenu] = useState(false);

  useEffect(() => {
    if (!userMenu) return;
    const close = () => setUserMenu(false);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [userMenu]);

  async function onLogout() {
    await logout();
    navigate("/");
  }

  const sidebar = (
    <aside
      className={cn(
        "flex flex-col border-r border-border bg-surface/95 backdrop-blur-md h-full transition-[width] duration-300 ease-out",
        collapsed ? "w-[72px]" : "w-60"
      )}
    >
      <div className={cn("flex h-16 items-center gap-2.5 border-b border-border px-3.5", collapsed && "justify-center px-2")}>
        <Link to="/dashboard" className="flex items-center gap-2.5 font-semibold text-sm truncate group">
          <span className="brand-mark shrink-0 transition-transform group-hover:scale-105">
            <Shield className="h-4 w-4" />
          </span>
          {!collapsed ? <span className="tracking-tight">SecureCode</span> : null}
        </Link>
      </div>
      <nav className="flex-1 overflow-y-auto p-2.5 space-y-0.5">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            title={item.label}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-muted transition-all duration-200",
                "hover:bg-fg/[0.04] hover:text-fg",
                isActive && "bg-primary/10 text-primary font-medium shadow-[inset_2px_0_0_0_var(--primary)]",
                collapsed && "justify-center px-2"
              )
            }
          >
            <item.icon className="h-4 w-4 shrink-0 opacity-90" />
            {!collapsed ? item.label : null}
          </NavLink>
        ))}
        {isAdmin ? (
          <NavLink
            to="/admin"
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-fg/[0.04] hover:text-fg mt-2 border-t border-border pt-3 transition-colors",
                isActive && "bg-primary/10 text-primary font-medium",
                collapsed && "justify-center"
              )
            }
          >
            <Shield className="h-4 w-4" />
            {!collapsed ? "Admin" : null}
          </NavLink>
        ) : null}
      </nav>
      <button
        type="button"
        className="hidden lg:flex items-center justify-center h-11 border-t border-border text-muted hover:text-fg hover:bg-fg/[0.03] transition-colors"
        onClick={() => setCollapsed((c) => !c)}
        aria-label="Thu gọn"
      >
        {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </button>
    </aside>
  );

  return (
    <div className="min-h-screen flex bg-atmosphere">
      <Helmet>
        <title>App · SecureCode Copilot</title>
      </Helmet>

      <div className="hidden lg:block sticky top-0 h-screen z-30">{sidebar}</div>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/45 backdrop-blur-[2px]" onClick={() => setMobileOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-60 shadow-2xl animate-toast">{sidebar}</div>
        </div>
      ) : null}

      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-40 flex h-16 items-center gap-3 border-b border-border/80 glass px-4 sm:px-5">
          <button
            type="button"
            className="lg:hidden p-2 rounded-lg text-muted hover:bg-fg/5 focus-ring"
            onClick={() => setMobileOpen(true)}
          >
            <Menu className="h-5 w-5" />
          </button>

          <div className="flex-1 max-w-xs">
            {user ? (
              <QuotaBar used={user.used_this_month} limit={user.monthly_limit} compact className="hidden sm:block" />
            ) : null}
          </div>

          <div className="flex items-center gap-1">
            <button
              type="button"
              className="p-2.5 rounded-lg text-muted hover:bg-fg/5 transition-colors focus-ring"
              title="Theme"
              onClick={() => {
                const cycle = { system: "light", light: "dark", dark: "system" };
                setTheme(cycle[theme] || "system");
              }}
            >
              {theme === "dark" ? (
                <Moon className="h-4 w-4" />
              ) : theme === "light" ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Monitor className="h-4 w-4" />
              )}
            </button>

            <div className="relative" onClick={(e) => e.stopPropagation()}>
              <button
                type="button"
                className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-fg/[0.04] text-sm transition-colors"
                onClick={() => setUserMenu((o) => !o)}
              >
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/15 text-primary text-xs font-semibold">
                  {(user?.full_name || "U").slice(0, 1).toUpperCase()}
                </span>
                <span className="hidden sm:block text-left">
                  <span className="block font-medium leading-tight">{user?.full_name}</span>
                  <span className="block text-xs text-muted capitalize">{user?.plan_name || user?.plan_code}</span>
                </span>
              </button>
              {userMenu ? (
                <div className="absolute right-0 mt-2 w-52 rounded-xl border border-border glass shadow-xl py-1.5 text-sm z-50 animate-toast">
                  <Link
                    to="/dashboard/settings"
                    className="block px-3.5 py-2.5 hover:bg-fg/[0.04]"
                    onClick={() => setUserMenu(false)}
                  >
                    Cài đặt
                  </Link>
                  <Link
                    to="/dashboard/billing"
                    className="block px-3.5 py-2.5 hover:bg-fg/[0.04]"
                    onClick={() => setUserMenu(false)}
                  >
                    Nâng cấp gói
                  </Link>
                  <button
                    type="button"
                    className="flex w-full items-center gap-2 px-3.5 py-2.5 hover:bg-fg/[0.04] text-danger"
                    onClick={onLogout}
                  >
                    <LogOut className="h-4 w-4" /> Đăng xuất
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto page-enter">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
