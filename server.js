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
      email TEXT UNIQUE,
      password TEXT,
      admin INTEGER DEFAULT 0,
      reset_token TEXT,
      reset_expire INTEGER
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

function requireAdmin(req, res, next) {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.send("権限がありません");
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
  const { username, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hashed],
    (err) => {
      if (err) return res.send("ユーザー名またはメールが既に存在します");
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
  req.session.isAdmin = row.admin === 1; // ← 追加
    res.redirect("/");
  });
});

// ログアウト
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/admin", requireAdmin, (req, res) => {
  db.all("SELECT id, username, email, admin FROM users", (err, rows) => {
    res.render("admin", { users: rows });
  });
});

app.get("/admin/delete/:id", requireAdmin, (req, res) => {
  db.run("DELETE FROM users WHERE id = ?", [req.params.id], () => {
    res.redirect("/admin");
  });
});


app.get("/forgot", (req, res) => {
  res.render("forgot");
});

const crypto = require("crypto");
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post("/forgot", (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(32).toString("hex");
  const expire = Date.now() + 1000 * 60 * 15; // 15分

  db.run(
    "UPDATE users SET reset_token=?, reset_expire=? WHERE email=?",
    [token, expire, email],
    function (err) {
      if (this.changes === 0) return res.send("メールが登録されていません");

      const resetLink = `${process.env.RESET_URL_BASE}/${token}`;
      const msg = {
        to: email,
        from: "noreply@example.com",
        subject: "パスワードリセット",
        text: `以下のURLからリセットしてください:\n${resetLink}`,
      };

      sgMail.send(msg);
      res.send("リセット用メールを送信しました");
    }
  );
});


app.get("/reset/:token", (req, res) => {
  const token = req.params.token;
  res.render("reset", { token });
});

app.post("/reset/:token", async (req, res) => {
  const token = req.params.token;
  const { password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.get(
    "SELECT * FROM users WHERE reset_token=? AND reset_expire > ?",
    [token, Date.now()],
    (err, row) => {
      if (!row) return res.send("トークンが無効または期限切れです");

      db.run(
        "UPDATE users SET password=?, reset_token=NULL, reset_expire=NULL WHERE id=?",
        [hashed, row.id],
        () => {
          res.send("パスワードを更新しました。ログインしてください。");
        }
      );
    }
  );
});


// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

