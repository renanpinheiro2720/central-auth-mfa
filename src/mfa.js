const { generateSecret, generateURI, verifySync } = require("otplib");
const QRCode = require("qrcode");

function createMfaSetup(email) {
  const secret = generateSecret();
  const issuer = "Central Auth MFA";
  const otpauthUrl = generateURI({
    issuer,
    label: email,
    secret
  });
  return { secret, otpauthUrl };
}

async function qrDataUrl(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl, { width: 280, margin: 2 });
}

function verifyTotp(secret, code) {
  return verifySync({ secret, token: String(code).replace(/\s/g, "") }).valid;
}

module.exports = { createMfaSetup, qrDataUrl, verifyTotp };
