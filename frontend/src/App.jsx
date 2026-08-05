import { Routes, Route, Navigate } from "react-router-dom";
import { PublicShell } from "./components/public/PublicShell";
import { AppShell } from "./components/app/AppShell";
import { AdminShell } from "./components/admin/AdminShell";
import { ProtectedRoute, GuestOnly } from "./components/ProtectedRoute";

import Landing from "./pages/public/Landing";
import Features from "./pages/public/Features";
import Pricing from "./pages/public/Pricing";
import Docs from "./pages/public/Docs";
import About from "./pages/public/About";
import Contact from "./pages/public/Contact";
import Privacy from "./pages/public/Privacy";
import Terms from "./pages/public/Terms";

import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ForgotPassword from "./pages/auth/ForgotPassword";
import ResetPassword from "./pages/auth/ResetPassword";

import Dashboard from "./pages/app/Dashboard";
import Analyze from "./pages/app/Analyze";
import History from "./pages/app/History";
import HistoryDetail from "./pages/app/HistoryDetail";
import Reports from "./pages/app/Reports";
import Billing from "./pages/app/Billing";
import Settings from "./pages/app/Settings";
import Integrations from "./pages/app/Integrations";
import Team from "./pages/app/Team";

import AdminOverview from "./pages/admin/AdminOverview";
import AdminUsers from "./pages/admin/AdminUsers";
import AdminPayments from "./pages/admin/AdminPayments";
import AdminAnalyses from "./pages/admin/AdminAnalyses";
import AdminAudit from "./pages/admin/AdminAudit";

export default function App() {
  return (
    <Routes>
      <Route element={<PublicShell />}>
        <Route index element={<Landing />} />
        <Route path="features" element={<Features />} />
        <Route path="pricing" element={<Pricing />} />
        <Route path="docs" element={<Docs />} />
        <Route path="about" element={<About />} />
        <Route path="contact" element={<Contact />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="terms" element={<Terms />} />
      </Route>

      <Route element={<GuestOnly />}>
        <Route path="login" element={<Login />} />
        <Route path="register" element={<Register />} />
        <Route path="forgot-password" element={<ForgotPassword />} />
        <Route path="reset-password" element={<ResetPassword />} />
      </Route>

      <Route element={<ProtectedRoute />}>
        <Route path="dashboard" element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="analyze" element={<Analyze />} />
          <Route path="history" element={<History />} />
          <Route path="history/:id" element={<HistoryDetail />} />
          <Route path="reports" element={<Reports />} />
          <Route path="billing" element={<Billing />} />
          <Route path="settings" element={<Settings />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="team" element={<Team />} />
        </Route>
      </Route>

      <Route element={<ProtectedRoute adminOnly />}>
        <Route path="admin" element={<AdminShell />}>
          <Route index element={<AdminOverview />} />
          <Route path="users" element={<AdminUsers />} />
          <Route path="payments" element={<AdminPayments />} />
          <Route path="analyses" element={<AdminAnalyses />} />
          <Route path="audit" element={<AdminAudit />} />
        </Route>
      </Route>

      <Route path="app" element={<Navigate to="/dashboard/analyze" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
