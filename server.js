const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));

// セッション
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 30 } // 30分
  })
);

// DB
const db = new sqlite3.Database("./database.sqlite");
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`
  );
});

// ログインしているかチェック
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next();
}

// --------------------
// ルーティング
// --------------------

// ホーム
app.get("/", requireLogin, (req, res) => {
  res.render("home", { username: req.session.username });
});

// 登録フォーム
app.get("/register", (req, res) => {
  res.render("register");
});

// 会員登録
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    (err) => {
      if (err) return res.send("ユーザー名が既に存在します");
      res.redirect("/login");
    }
  );
});

// ログインフォーム
app.get("/login", (req, res) => {
  res.render("login");
});

// ログイン
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
    if (!row) return res.send("ユーザーが存在しません");

    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.send("パスワードが違います");

    req.session.userId = row.id;
    req.session.username = row.username;
    res.redirect("/");
  });
});

// ログアウト
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
