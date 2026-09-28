require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const db = require("./db");
const {
  hashPassword,
  verifyPassword,
  signAccessToken,
  signRefreshToken,
  signMfaPendingToken,
  verifyRefreshToken,
  verifyMfaPendingToken,
  randomTokenId,
  sha256,
  encryptSecret,
  decryptSecret
} = require("./security");
const { createMfaSetup, qrDataUrl, verifyTotp } = require("./mfa");
const { authRequired } = require("./middleware");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde alguns minutos." }
});

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8 && password.length <= 128;
}

function createRefreshSession(userId) {
  const jti = randomTokenId();
  const token = signRefreshToken(userId, jti);
  const decoded = verifyRefreshToken(token);
  db.prepare(`
    INSERT INTO refresh_sessions (user_id, jti, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(userId, jti, sha256(token), decoded.exp * 1000);
  return token;
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "central-auth-mfa" });
});

app.post("/auth/register", authLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "E-mail inválido." });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({ error: "A senha deve ter entre 8 e 128 caracteres." });
    }

    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(409).json({ error: "E-mail já cadastrado." });

    const passwordHash = await hashPassword(password);
    const result = db.prepare(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)"
    ).run(email, passwordHash);

    res.status(201).json({
      message: "Usuário criado com sucesso.",
      userId: result.lastInsertRowid
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno." });
  }
});

app.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (!user || !(await verifyPassword(user.password_hash, password || ""))) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    if (user.mfa_enabled) {
      return res.json({
        mfaRequired: true,
        mfaToken: signMfaPendingToken(user.id)
      });
    }

    const accessToken = signAccessToken(user.id);
    const refreshToken = createRefreshSession(user.id);

    res.json({ accessToken, refreshToken, expiresIn: "15m" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno." });
  }
});

app.post("/auth/mfa/setup", authRequired, async (req, res) => {
  try {
    const user = db.prepare("SELECT id, email, mfa_enabled FROM users WHERE id = ?").get(req.userId);
    if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
    if (user.mfa_enabled) return res.status(409).json({ error: "MFA já está habilitado." });

    const { secret, otpauthUrl } = createMfaSetup(user.email);
    const encrypted = encryptSecret(secret);

    db.prepare("UPDATE users SET mfa_secret_enc = ? WHERE id = ?").run(encrypted, user.id);

    const qrCode = await qrDataUrl(otpauthUrl);
    res.json({
      message: "Escaneie o QR Code no Google Authenticator e confirme com o código gerado.",
      qrCode,
      manualSecret: secret
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Não foi possível iniciar o MFA." });
  }
});

app.post("/auth/mfa/enable", authRequired, authLimiter, (req, res) => {
  try {
    const code = String(req.body.code || "").replace(/\s/g, "");
    const user = db.prepare("SELECT mfa_secret_enc FROM users WHERE id = ?").get(req.userId);

    if (!user?.mfa_secret_enc) {
      return res.status(400).json({ error: "Faça o setup do MFA antes." });
    }

    const secret = decryptSecret(user.mfa_secret_enc);
    if (!verifyTotp(secret, code)) {
      return res.status(401).json({ error: "Código TOTP inválido." });
    }

    db.prepare("UPDATE users SET mfa_enabled = 1 WHERE id = ?").run(req.userId);
    res.json({ message: "MFA habilitado com sucesso." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao habilitar MFA." });
  }
});

app.post("/auth/mfa/verify", authLimiter, (req, res) => {
  try {
    const { mfaToken, code } = req.body;
    const payload = verifyMfaPendingToken(mfaToken);

    if (payload.type !== "mfa_pending") {
      return res.status(401).json({ error: "Token MFA inválido." });
    }

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(Number(payload.sub));
    if (!user || !user.mfa_enabled || !user.mfa_secret_enc) {
      return res.status(401).json({ error: "MFA não configurado." });
    }

    const secret = decryptSecret(user.mfa_secret_enc);
    if (!verifyTotp(secret, code)) {
      return res.status(401).json({ error: "Código TOTP inválido." });
    }

    const accessToken = signAccessToken(user.id);
    const refreshToken = createRefreshSession(user.id);

    res.json({ accessToken, refreshToken, expiresIn: "15m" });
  } catch {
    res.status(401).json({ error: "Token MFA inválido ou expirado." });
  }
});

app.post("/auth/refresh", authLimiter, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "Refresh token ausente." });

    const payload = verifyRefreshToken(refreshToken);
    if (payload.type !== "refresh" || !payload.jti) {
      return res.status(401).json({ error: "Refresh token inválido." });
    }

    const session = db.prepare(`
      SELECT * FROM refresh_sessions
      WHERE jti = ? AND user_id = ? AND revoked = 0
    `).get(payload.jti, Number(payload.sub));

    if (!session || session.expires_at < Date.now() || session.token_hash !== sha256(refreshToken)) {
      return res.status(401).json({ error: "Refresh token inválido ou revogado." });
    }

    db.prepare("UPDATE refresh_sessions SET revoked = 1 WHERE jti = ?").run(payload.jti);

    const accessToken = signAccessToken(Number(payload.sub));
    const newRefreshToken = createRefreshSession(Number(payload.sub));

    res.json({ accessToken, refreshToken: newRefreshToken, expiresIn: "15m" });
  } catch {
    res.status(401).json({ error: "Refresh token inválido ou expirado." });
  }
});

app.post("/auth/logout", authRequired, (req, res) => {
  db.prepare("UPDATE refresh_sessions SET revoked = 1 WHERE user_id = ?").run(req.userId);
  res.json({ message: "Sessões de refresh revogadas." });
});

app.get("/me", authRequired, (req, res) => {
  const user = db.prepare(
    "SELECT id, email, mfa_enabled, created_at FROM users WHERE id = ?"
  ).get(req.userId);

  if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
  res.json(user);
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Erro interno do servidor." });
});

app.listen(PORT, () => {
  console.log(`Central Auth MFA rodando em http://localhost:${PORT}`);
});
