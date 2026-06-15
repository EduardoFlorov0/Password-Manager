import crypto from "node:crypto";

const tokenSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("base64url");
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function base64UrlEncode(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function base64UrlDecode(value) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
}

function sign(payload) {
  return crypto.createHmac("sha256", tokenSecret).update(payload).digest("base64url");
}

export function createToken(user) {
  const payload = base64UrlEncode({
    sub: user.id,
    username: user.username,
    exp: Date.now() + TOKEN_TTL_MS,
    nonce: crypto.randomBytes(12).toString("base64url")
  });

  return `${payload}.${sign(payload)}`;
}

export function verifyToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) {
    return null;
  }

  const [payload, signature] = token.split(".");
  const expected = sign(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const decoded = base64UrlDecode(payload);
    if (!decoded.exp || decoded.exp < Date.now()) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

export function hashAuthKey(authKeyBase64) {
  return crypto.createHash("sha256").update(Buffer.from(authKeyBase64, "base64")).digest("base64");
}

export function safeEqualBase64(left, right) {
  const leftBuffer = Buffer.from(left || "", "base64");
  const rightBuffer = Buffer.from(right || "", "base64");

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}
