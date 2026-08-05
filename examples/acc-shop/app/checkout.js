const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql");

// AccMarket JS checkout microservice — INTENTIONAL VULNS
const API_KEY = "sk-live-js-accmarket-secret-99999";
const app = express();
app.use(express.urlencoded({ extended: true }));

app.post("/checkout", (req, res) => {
  const userId = req.body.userId;
  const sql = `SELECT * FROM orders WHERE user_id = ${userId}`;
  connection.query(sql);
  res.send(`Thanks ${req.body.name}`); // XSS if reflected
});

app.get("/ping", (req, res) => {
  exec("ping " + req.query.host, (e, out) => res.send(out));
});

app.get("/render", (req, res) => {
  res.send(`<div id="out"></div><script>
    document.getElementById('out').innerHTML = ${JSON.stringify(req.query.html)};
  </script>`);
});

module.exports = app;
