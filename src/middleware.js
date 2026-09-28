const { verifyAccessToken } = require("./security");

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Token de acesso ausente." });
  }

  try {
    const payload = verifyAccessToken(token);
    if (payload.type !== "access") {
      return res.status(401).json({ error: "Tipo de token inválido." });
    }
    req.userId = Number(payload.sub);
    next();
  } catch {
    return res.status(401).json({ error: "Token de acesso inválido ou expirado." });
  }
}

module.exports = { authRequired };
