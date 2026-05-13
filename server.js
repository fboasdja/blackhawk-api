const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const DEBUG = String(process.env.DEBUG_AUTH || "").toLowerCase() === "true";
const API_TOKEN_SECRET = process.env.API_TOKEN_SECRET || "";
const JWT_SECRET = process.env.JWT_SECRET || "";
const RESPONSE_SIGNING_KEY = process.env.RESPONSE_SIGNING_KEY || "";
const VALID_LICENSE_KEYS = new Set(
  (process.env.VALID_LICENSE_KEYS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
);
const BLACKLIST_KEYS = new Set(
  (process.env.BLACKLIST_KEYS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
);
const BLACKLIST_HWIDS = new Set(
  (process.env.BLACKLIST_HWIDS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
);
const REPLAY_WINDOW_SEC = 120;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQ = 30;
const JWT_TTL_SECONDS = Math.max(60, Number(process.env.JWT_TTL_SECONDS || 600));
const recentNonces = new Map();
const rateMap = new Map();

const C = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
};

function logInfo(msg) {
  console.log(`${C.cyan}[AUTH]${C.reset} ${msg}`);
}
function logOk(msg) {
  console.log(`${C.green}[AUTH]${C.reset} ${msg}`);
}
function logWarn(msg) {
  console.warn(`${C.yellow}[AUTH]${C.reset} ${msg}`);
}
function logErr(msg) {
  console.error(`${C.red}[AUTH]${C.reset} ${msg}`);
}
function logDebug(msg) {
  if (DEBUG) console.log(`${C.cyan}[DEBUG]${C.reset} ${msg}`);
}

app.set("trust proxy", true);
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json({ limit: "64kb", strict: true }));

app.use((req, res, next) => {
  if (req.method === "POST" && !req.is("application/json")) {
    return res.status(415).json({ success: false, error: "INVALID_CONTENT_TYPE" });
  }
  next();
});

app.use((req, res, next) => {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const now = Date.now();
  const arr = rateMap.get(ip) || [];
  const fresh = arr.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
  fresh.push(now);
  rateMap.set(ip, fresh);
  if (fresh.length > RATE_LIMIT_MAX_REQ) {
    logWarn(`rate limit ip=${ip}`);
    return res.status(429).json({ success: false, error: "TOO_MANY_REQUESTS" });
  }
  next();
});

function cleanupReplay() {
  const now = Date.now();
  for (const [nonce, ts] of recentNonces.entries()) {
    if (now - ts > REPLAY_WINDOW_SEC * 1000) {
      recentNonces.delete(nonce);
    }
  }
}

function isValidBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  const required = ["license_key", "hwid", "app_version", "checksum", "nonce", "timestamp"];
  return required.every((k) => Object.prototype.hasOwnProperty.call(body, k));
}

function invalidField(v, maxLen = 256) {
  return typeof v !== "string" || v.length === 0 || v.length > maxLen;
}

function readApiToken(req) {
  return String(req.get("X-Api-Token") || req.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
}

function requireApiToken(req, res, next) {
  // Optional hardening: when API_TOKEN_SECRET is configured, require matching token header.
  if (!API_TOKEN_SECRET) return next();
  const token = readApiToken(req);
  if (!token || token !== API_TOKEN_SECRET) {
    return responseWithSignature(res, 401, { success: false, error: "UNAUTHORIZED" });
  }
  return next();
}

function signToken(licenseKey, hwid, plan, expires) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET missing");
  }
  return jwt.sign(
    { license_key: licenseKey, hwid, plan, expires },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: JWT_TTL_SECONDS, issuer: "blackhawk-api" }
  );
}

function responseWithSignature(res, statusCode, payload) {
  const raw = JSON.stringify(payload);
  if (RESPONSE_SIGNING_KEY) {
    const normalized = JSON.stringify(payload, Object.keys(payload).sort());
    const sig = crypto
      .createHash("sha256")
      .update(`${normalized}.${RESPONSE_SIGNING_KEY}`)
      .digest("hex");
    res.set("X-Response-Signature", sig);
  }
  return res.status(statusCode).type("application/json").send(raw);
}

app.get("/", (_req, res) => {
  res.status(200).json({ success: true, service: "blackhawk-api", status: "ok" });
});

app.get("/health", (_req, res) => {
  res.status(200).json({ success: true, status: "healthy" });
});

function handleValidate(req, res) {
  cleanupReplay();
  const start = Date.now();
  try {
    if (!isValidBody(req.body)) {
      return responseWithSignature(res, 400, { success: false, error: "INVALID_BODY" });
    }
    const { license_key, hwid, app_version, checksum, nonce, timestamp } = req.body;

    if (
      invalidField(license_key, 128) ||
      invalidField(hwid, 256) ||
      invalidField(app_version, 64) ||
      invalidField(checksum, 128) ||
      invalidField(nonce, 128)
    ) {
      return responseWithSignature(res, 400, { success: false, error: "INVALID_FIELDS" });
    }
    if (!Number.isInteger(timestamp)) {
      return responseWithSignature(res, 400, { success: false, error: "INVALID_TIMESTAMP" });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSec - timestamp) > REPLAY_WINDOW_SEC) {
      return responseWithSignature(res, 401, { success: false, error: "TIMESTAMP_EXPIRED" });
    }
    if (recentNonces.has(nonce)) {
      return responseWithSignature(res, 409, { success: false, error: "REPLAY_DETECTED" });
    }
    recentNonces.set(nonce, Date.now());

    const expectedChecksum = crypto
      .createHash("sha256")
      .update(`${license_key}|${hwid}|${app_version}|${nonce}|${timestamp}`)
      .digest("hex");
    if (checksum !== expectedChecksum) {
      return responseWithSignature(res, 401, { success: false, error: "INVALID_CHECKSUM" });
    }

    if (BLACKLIST_KEYS.has(license_key) || BLACKLIST_HWIDS.has(hwid)) {
      return responseWithSignature(res, 403, { success: false, error: "BLACKLISTED" });
    }
    if (!VALID_LICENSE_KEYS.has(license_key)) {
      logWarn(`invalid key=${license_key}`);
      return responseWithSignature(res, 401, { success: false, error: "INVALID_KEY" });
    }

    const username = "hawk-user";
    const plan = "premium";
    const expires = new Date(Date.now() + JWT_TTL_SECONDS * 1000).toISOString();
    const token = signToken(license_key, hwid, plan, expires);

    logOk(`auth success key=${license_key} hwid=${hwid} ms=${Date.now() - start}`);
    return responseWithSignature(res, 200, {
      success: true,
      token,
      username,
      plan,
      expires,
    });
  } catch (err) {
    logErr(`unhandled error: ${err && err.message ? err.message : String(err)}`);
    return responseWithSignature(res, 500, { success: false, error: "INTERNAL_ERROR" });
  }
}

app.post("/V1/validate", requireApiToken, handleValidate);
app.post("/v1/validate", requireApiToken, handleValidate);

function handleSessionValidate(req, res) {
  try {
    const body = req.body || {};
    const token = String(body.token || "");
    const hwid = String(body.hwid || "");
    if (!token || !hwid) {
      return responseWithSignature(res, 400, { success: false, error: "INVALID_BODY" });
    }
    if (!JWT_SECRET) {
      return responseWithSignature(res, 500, { success: false, error: "JWT_SECRET_MISSING" });
    }
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"], issuer: "blackhawk-api" });
    if (!decoded || decoded.hwid !== hwid) {
      return responseWithSignature(res, 401, { success: false, error: "HWID_MISMATCH" });
    }
    if (BLACKLIST_KEYS.has(String(decoded.license_key || "")) || BLACKLIST_HWIDS.has(hwid)) {
      return responseWithSignature(res, 403, { success: false, error: "BLACKLISTED" });
    }
    return responseWithSignature(res, 200, { success: true });
  } catch (_e) {
    return responseWithSignature(res, 401, { success: false, error: "SESSION_INVALID" });
  }
}

app.post("/V1/session/validate", requireApiToken, handleSessionValidate);
app.post("/v1/session/validate", requireApiToken, handleSessionValidate);

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ success: false, error: "INVALID_JSON" });
  }
  return res.status(500).json({ success: false, error: "INTERNAL_ERROR" });
});

app.listen(PORT, () => {
  if (!API_TOKEN_SECRET || !JWT_SECRET || !RESPONSE_SIGNING_KEY) {
    logErr("Missing required secrets: API_TOKEN_SECRET/JWT_SECRET/RESPONSE_SIGNING_KEY");
  }
  if (VALID_LICENSE_KEYS.size === 0) {
    logWarn("VALID_LICENSE_KEYS is empty -> all login attempts will be rejected.");
  } else {
    logInfo(`Loaded ${VALID_LICENSE_KEYS.size} license key(s).`);
  }
  logInfo(`render api listening on :${PORT}`);
  logDebug("debug logging enabled");
});
