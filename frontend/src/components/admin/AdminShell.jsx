import { Link, NavLink, Outlet } from "react-router-dom";
import { Helmet } from "react-helmet-async";
import {
  LayoutDashboard,
  Users,
  CreditCard,
  ScanSearch,
  ScrollText,
  ArrowLeft,
  Shield,
} from "lucide-react";
import { cn } from "../../lib/utils";

const NAV = [
  { to: "/admin", end: true, label: "Tổng quan", icon: LayoutDashboard },
  { to: "/admin/users", label: "Người dùng", icon: Users },
  { to: "/admin/payments", label: "Thanh toán", icon: CreditCard },
  { to: "/admin/analyses", label: "Phân tích", icon: ScanSearch },
  { to: "/admin/audit", label: "Audit log", icon: ScrollText },
];

export function AdminShell() {
  return (
    <div className="min-h-screen flex bg-atmosphere">
      <Helmet>
        <title>Admin · SecureCode Copilot</title>
      </Helmet>
      <aside className="w-60 border-r border-border bg-surface/95 backdrop-blur-md flex flex-col sticky top-0 h-screen">
        <div className="h-16 flex items-center gap-2.5 px-4 border-b border-border font-semibold text-sm">
          <span className="brand-mark">
            <Shield className="h-3.5 w-3.5" />
          </span>
          Admin
        </div>
        <nav className="p-2.5 space-y-0.5 flex-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-fg/[0.04] hover:text-fg transition-colors",
                  isActive && "bg-primary/10 text-primary font-medium shadow-[inset_2px_0_0_0_var(--primary)]"
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <Link
          to="/dashboard"
          className="flex items-center gap-2 px-4 py-3.5 text-sm text-muted border-t border-border hover:text-fg transition-colors"
        >
          <ArrowLeft className="h-4 w-4" /> Về app
        </Link>
      </aside>
      <main className="flex-1 p-6 lg:p-8 max-w-6xl page-enter">
        <Outlet />
      </main>
    </div>
  );
}
