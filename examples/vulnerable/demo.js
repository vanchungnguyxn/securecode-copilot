// Vulnerable JavaScript sample — DO NOT use in production
const { exec } = require("child_process");
const mysql = require("mysql");
const fs = require("fs");

const API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz";

function searchUser(userId) {
  const sql = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(sql);
}

function render(name) {
  document.getElementById("out").innerHTML = name;
}

function run(cmd) {
  exec("ls " + cmd, (err, stdout) => console.log(stdout));
}

function readUserFile(p) {
  return fs.readFileSync(path.join("/var/www", p));
}

function dynamic(code) {
  return eval(code);
}
