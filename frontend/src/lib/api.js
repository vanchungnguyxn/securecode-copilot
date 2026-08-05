const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";
const TOKEN_KEY = "scc_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(message, { status, code, detail } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

function parseDetail(detail) {
  if (detail == null) return { message: "Request failed", code: null };
  if (typeof detail === "string") return { message: detail, code: null };
  if (Array.isArray(detail)) {
    const msg = detail
      .map((d) => (typeof d === "string" ? d : d.msg || JSON.stringify(d)))
      .join("; ");
    return { message: msg, code: null };
  }
  if (typeof detail === "object") {
    return {
      message: detail.message || detail.msg || JSON.stringify(detail),
      code: detail.code || null,
      detail,
    };
  }
  return { message: String(detail), code: null };
}

async function request(path, { method = "GET", body, auth = true, headers = {} } = {}) {
  const h = { ...headers };
  if (body != null && !(body instanceof FormData)) {
    h["Content-Type"] = "application/json";
  }
  if (auth) {
    const token = getToken();
    if (token) h.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: h,
    body: body == null ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });

  if (res.status === 204) return null;

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const parsed = parseDetail(data.detail ?? data.message ?? `HTTP ${res.status}`);
    throw new ApiError(parsed.message, {
      status: res.status,
      code: parsed.code,
      detail: parsed.detail || data.detail,
    });
  }
  return data;
}

export const api = {
  register: (body) => request("/auth/register", { method: "POST", body, auth: false }),
  login: (body) => request("/auth/login", { method: "POST", body, auth: false }),
  me: () => request("/auth/me"),
  updateMe: (body) => request("/auth/me", { method: "PATCH", body }),
  changePassword: (body) => request("/auth/change-password", { method: "POST", body }),
  forgotPassword: (body) => request("/auth/forgot-password", { method: "POST", body, auth: false }),
  resetPassword: (body) => request("/auth/reset-password", { method: "POST", body, auth: false }),
  logout: () => request("/auth/logout", { method: "POST" }),

  plans: () => request("/plans", { auth: false }),

  createAnalysis: (body) => request("/analyses", { method: "POST", body }),
  listAnalyses: (params = {}) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.language) q.set("language", params.language);
    if (params.limit) q.set("limit", String(params.limit));
    if (params.offset) q.set("offset", String(params.offset));
    const qs = q.toString();
    return request(`/analyses${qs ? `?${qs}` : ""}`);
  },
  getAnalysis: (id) => request(`/analyses/${id}`),
  deleteAnalysis: (id) => request(`/analyses/${id}`, { method: "DELETE" }),
  clearAnalyses: () => request("/analyses", { method: "DELETE" }),
  markFalsePositive: (analysisId, vulnId) =>
    request(`/analyses/${analysisId}/vulnerabilities/${vulnId}/false-positive`, { method: "POST" }),
  sendFeedback: (body) => request("/analyses/feedback", { method: "POST", body }),

  checkout: (body) => request("/billing/checkout", { method: "POST", body }),
  mockPay: (body) => request("/billing/mock-pay", { method: "POST", body }),
  payments: () => request("/billing/payments"),
  cancelSubscription: () => request("/billing/cancel", { method: "POST" }),

  adminStats: () => request("/admin/stats"),
  adminUsers: (params = {}) => {
    const q = new URLSearchParams();
    if (params.q) q.set("q", params.q);
    if (params.limit) q.set("limit", String(params.limit));
    if (params.offset) q.set("offset", String(params.offset));
    const qs = q.toString();
    return request(`/admin/users${qs ? `?${qs}` : ""}`);
  },
  adminLockUser: (id, locked) => request(`/admin/users/${id}/lock`, { method: "POST", body: { locked } }),
  adminAdjustQuota: (id, body) => request(`/admin/users/${id}/quota`, { method: "POST", body }),
  adminPayments: () => request("/admin/payments"),
  adminAnalyses: () => request("/admin/analyses"),
  adminAudit: () => request("/admin/audit-logs"),
  adminPlans: () => request("/admin/plans"),

  // Legacy scan helpers (with JWT when available)
  scan: (body) => request("/scan", { method: "POST", body }),
  explain: (body) => request("/explain", { method: "POST", body }),
  fix: (body) => request("/fix", { method: "POST", body }),
  applyFix: (body) => request("/apply-fix", { method: "POST", body }),
  health: () => request("/health", { auth: false }),

  scanRepo: (body) => request("/scan/repo", { method: "POST", body, auth: false }),
  scanRepoZip: async (file, opts = {}) => {
    const fd = new FormData();
    fd.append("file", file);
    const q = new URLSearchParams({
      include_explanations: String(opts.include_explanations !== false),
      include_fixes: String(opts.include_fixes !== false),
      max_files: String(opts.max_files || 300),
      ml_discovery: String(!!opts.ml_discovery),
      max_enrich: String(opts.max_enrich ?? 0),
    });
    return request(`/scan/repo/upload?${q}`, { method: "POST", body: fd, auth: false });
  },
};

export const SAMPLES = {
  python: `import os
import pickle

SECRET_PASSWORD = "SuperSecret123!"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

def run_cmd(name):
    os.system("ping " + name)

def load_profile(data):
    return pickle.loads(data)
`,
  javascript: `const { exec } = require("child_process");
const API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz";

function searchUser(userId) {
  const sql = \`SELECT * FROM users WHERE id = \${userId}\`;
  connection.query(sql);
}

function render(name) {
  document.getElementById("out").innerHTML = name;
}

function run(cmd) {
  exec("ls " + cmd);
}
`,
  java: `import java.sql.*;
import java.io.*;

public class Demo {
    public ResultSet find(Connection conn, String id) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
    public void run(String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
    }
    public Object load(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }
}
`,
  c: `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet(char *name) {
    char buf[32];
    strcpy(buf, name);
    printf(name);
}

void run_cmd(char *arg) {
    char cmd[128];
    sprintf(cmd, "ls %s", arg);
    system(cmd);
}
`,
};

export const LANG_EXT = {
  python: "py",
  javascript: "js",
  java: "java",
  c: "c",
  cpp: "cpp",
  auto: "txt",
};
