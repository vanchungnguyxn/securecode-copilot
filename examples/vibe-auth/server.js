const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");

// Acc vibe-auth API — INTENTIONAL misconfig (demo SecureCode Copilot)
const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const JWT_SECRET = "supersecretkey";
const firebaseConfig = {
  apiKey: "AIzaSyDemoKeyExposedInClient123456",
  authDomain: "demo.firebaseapp.com",
  projectId: "demo",
};

// register/login without hashing (and returns JWT with hardcoded secret)
app.post("/register", (req, res) => {
  const { email, password } = req.body;
  const token = jwt.sign({ email, role: "admin" }, JWT_SECRET, { expiresIn: "365d" });
  res.json({ token, password }); // leak password back
});

app.post("/login", (req, res) => {
  // trust client entirely
  const data = jwt.decode(req.body.token);
  req.user = data;
  res.json({ ok: true, user: data });
});

// Broken access control — no auth middleware
app.get("/admin/users", async (req, res) => {
  res.json([{ id: 1, email: "admin@example.com", password: "password123" }]);
});

app.get("/users/:id", async (req, res) => {
  const u = await fakeFindById(req.params.id);
  res.json(u);
});

function fakeFindById(id) {
  return Promise.resolve({ id, email: "x@y.z", balance: 9999 });
}

// verify with hardcoded secret still better than decode — still vulnerable
app.get("/me", (req, res) => {
  try {
    const payload = jwt.verify(req.headers.authorization, "supersecretkey");
    res.json(payload);
  } catch (e) {
    res.status(401).end();
  }
});

module.exports = app;
