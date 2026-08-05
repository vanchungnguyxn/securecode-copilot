const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";

export async function scanCode(payload) {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Scan failed (${res.status})`);
  }
  return res.json();
}

export async function explainFinding(payload) {
  const res = await fetch(`${API_BASE}/explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Explain failed (${res.status})`);
  }
  return res.json();
}

export async function fixFinding(payload) {
  const res = await fetch(`${API_BASE}/fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Fix failed (${res.status})`);
  }
  return res.json();
}

export async function applyFix(payload) {
  const res = await fetch(`${API_BASE}/apply-fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Apply fix failed");
  return res.json();
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("API offline");
  return res.json();
}

export async function scanRepo(payload) {
  const res = await fetch(`${API_BASE}/scan/repo`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err.detail === "string" ? err.detail : `Repo scan failed (${res.status})`);
  }
  return res.json();
}

export async function scanRepoZip(file, opts = {}) {
  const fd = new FormData();
  fd.append("file", file);
  const q = new URLSearchParams({
    include_explanations: String(opts.include_explanations !== false),
    include_fixes: String(opts.include_fixes !== false),
    max_files: String(opts.max_files || 300),
    ml_discovery: String(!!opts.ml_discovery),
    max_enrich: String(opts.max_enrich || 80),
  });
  const res = await fetch(`${API_BASE}/scan/repo/upload?${q}`, { method: "POST", body: fd });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err.detail === "string" ? err.detail : `Zip scan failed (${res.status})`);
  }
  return res.json();
}

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
