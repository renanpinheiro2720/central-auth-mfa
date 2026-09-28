const crypto = require("crypto");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const ISSUER = process.env.JWT_ISSUER || "central-auth-mfa";
const AUDIENCE = process.env.JWT_AUDIENCE || "central-auth-client";

function requireEnv(name) {
  if (!process.env[name]) throw new Error(`Variável ${name} não configurada.`);
  return process.env[name];
}

async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

async function verifyPassword(hash, password) {
  return argon2.verify(hash, password);
}

function signAccessToken(userId) {
  return jwt.sign(
    { sub: String(userId), type: "access" },
    requireEnv("JWT_ACCESS_SECRET"),
    { expiresIn: "15m", issuer: ISSUER, audience: AUDIENCE }
  );
}

function signRefreshToken(userId, jti) {
  return jwt.sign(
    { sub: String(userId), type: "refresh", jti },
    requireEnv("JWT_REFRESH_SECRET"),
    { expiresIn: "7d", issuer: ISSUER, audience: AUDIENCE }
  );
}

function signMfaPendingToken(userId) {
  return jwt.sign(
    { sub: String(userId), type: "mfa_pending" },
    requireEnv("JWT_ACCESS_SECRET"),
    { expiresIn: "5m", issuer: ISSUER, audience: AUDIENCE }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, requireEnv("JWT_ACCESS_SECRET"), {
    issuer: ISSUER,
    audience: AUDIENCE
  });
}

function verifyRefreshToken(token) {
  return jwt.verify(token, requireEnv("JWT_REFRESH_SECRET"), {
    issuer: ISSUER,
    audience: AUDIENCE
  });
}

function verifyMfaPendingToken(token) {
  return jwt.verify(token, requireEnv("JWT_ACCESS_SECRET"), {
    issuer: ISSUER,
    audience: AUDIENCE
  });
}

function randomTokenId() {
  return crypto.randomUUID();
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function getEncryptionKey() {
  const hex = requireEnv("MFA_ENCRYPTION_KEY");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("MFA_ENCRYPTION_KEY deve ter exatamente 64 caracteres hexadecimais.");
  }
  return Buffer.from(hex, "hex");
}

function encryptSecret(secret) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

function decryptSecret(payload) {
  const key = getEncryptionKey();
  const data = Buffer.from(payload, "base64");
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

module.exports = {
  hashPassword,
  verifyPassword,
  signAccessToken,
  signRefreshToken,
  signMfaPendingToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyMfaPendingToken,
  randomTokenId,
  sha256,
  encryptSecret,
  decryptSecret
};
