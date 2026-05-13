require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const NODE_ENV = String(process.env.NODE_ENV || "production");
const DEBUG = String(process.env.DEBUG_AUTH || "").toLowerCase() === "true";

// Security
const API_TOKEN_SECRET = String(process.env.API_TOKEN_SECRET || "").trim(); // app -> api (optional hardening)
const BOT_SHARED_SECRET = String(process.env.BOT_SHARED_SECRET || "").trim(); // api -> bot (required)
const JWT_SECRET = String(process.env.JWT_SECRET || "").trim(); // required
const RESPONSE_SIGNING_KEY = String(process.env.RESPONSE_SIGNING_KEY || "").trim(); // required (anti fake response)
const BOT_WAIT_MS = Math.max(1500, Number(process.env.BOT_WAIT_MS || 8000)); // API waits for bot result (long-poll)

const JWT_TTL_SECONDS = Math.max(60, Number(process.env.JWT_TTL_SECONDS || 900));
const REPLAY_WINDOW_SEC = Math.max(30, Number(process.env.REPLAY_WINDOW_SEC || 120));
const REQUIRE_HTTPS = String(process.env.REQUIRE_HTTPS || "true").toLowerCase() !== "false";

const recentNonces = new Map(); // nonce -> ts_ms

// Pull-mode queue (in-memory). Bot polls /v1/bot/pull, then pushes result /v1/bot/push.
// Note: On Render free tier, instance restarts will clear memory; keep BOT_WAIT_MS small.
const queue = [];
const waiters = new Map(); // request_id -> { resolve, timeout }
let reqSeq = 0;

const C = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  gray: "\x1b[90m",
};

function ts() {
  return new Date().toISOString();
}
function log(tag, color, msg) {
  // eslint-disable-next-line no-console
  console.log(`${C.gray}${ts()}${C.reset} ${color}${tag}${C.reset} ${msg}`);
}
function logInfo(msg) {
  log("[API]", C.cyan, msg);
}
function logOk(msg) {
  log("[SUCCESS]", C.green, msg);
}
function logWarn(msg) {
  log("[SECURITY]", C.yellow, msg);
}
function logErr(msg) {
  log("[ERROR]", C.red, msg);
}

function responseSignature(payload) {
  if (!RESPONSE_SIGNING_KEY) return "";
  const normalized = JSON.stringify(payload, Object.keys(payload).sort());
  return crypto.createHash("sha256").update(`${normalized}.${RESPONSE_SIGNING_KEY}`).digest("hex");
}

function sendJson(res, statusCode, payload) {
  if (RESPONSE_SIGNING_KEY) {
    res.set("X-Response-Signature", responseSignature(payload));
  }
  return res.status(statusCode).type("application/json").send(JSON.stringify(payload));
}

function isHttpsReq(req) {
  const proto = String(req.get("x-forwarded-proto") || "").toLowerCase();
  return proto === "https";
}

function cleanupReplay() {
  const now = Date.now();
  for (const [nonce, ms] of recentNonces.entries()) {
    if (now - ms > REPLAY_WINDOW_SEC * 1000) recentNonces.delete(nonce);
  }
}

function readApiToken(req) {
  return String(req.get("X-Api-Token") || req.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
}

function safeString(v, maxLen) {
  if (typeof v !== "string") return "";
  const s = v.trim();
  if (!s || s.length > maxLen) return "";
  return s;
}

function validateLoginBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "INVALID_BODY" };
  const license_key = safeString(body.license_key, 128);
  const hwid = safeString(body.hwid, 256);
  const pc_name = safeString(body.pc_name, 128);
  const app_version = safeString(body.app_version, 64);
  const ip = safeString(body.ip || "", 64); // optional; API will override from req.ip
  const nonce = safeString(body.nonce || "", 128);

  const timestamp = Number(body.timestamp);
  if (!license_key || !hwid || !pc_name || !app_version) return { ok: false, error: "INVALID_FIELDS" };
  if (!Number.isFinite(timestamp) || timestamp <= 0) return { ok: false, error: "INVALID_TIMESTAMP" };
  if (!nonce) return { ok: false, error: "MISSING_NONCE" };

  return { ok: true, license_key, hwid, pc_name, app_version, ip, nonce, timestamp };
}

async function callBotAuth(payload, sourceIp) {
  if (!BOT_SHARED_SECRET) throw new Error("BOT_SHARED_SECRET missing");
  // In pull-mode, API does not call bot directly.
  // This function is kept for compatibility but no longer used.
  return { status: 503, data: { ok: false, reason: "PULL_MODE" } };
}

function signJwt({ license_key, hwid, plan, expires }) {
  if (!JWT_SECRET) throw new Error("JWT_SECRET missing");
  return jwt.sign({ license_key, hwid, plan, expires }, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: JWT_TTL_SECONDS,
    issuer: "blackhawk-api",
  });
}

app.set("trust proxy", true);
app.use(helmet());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Api-Token"],
  }),
);

app.use(
  express.json({
    limit: "64kb",
    strict: true,
  }),
);

app.use(
  rateLimit({
    windowMs: 60_000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const ip = String(req.ip || "unknown");
      logWarn(`rate limit ip=${ip}`);
      return sendJson(res, 429, { success: false, error: "TOO_MANY_REQUESTS" });
    },
  }),
);

// content-type enforcement for POST
app.use((req, res, next) => {
  if (req.method === "POST" && !req.is("application/json")) {
    return sendJson(res, 415, { success: false, error: "INVALID_CONTENT_TYPE" });
  }
  next();
});

// Anti invalid JSON
app.use((err, _req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return sendJson(res, 400, { success: false, error: "INVALID_JSON" });
  }
  next(err);
});

app.get("/", (_req, res) => sendJson(res, 200, { success: true, service: "blackhawk-api", status: "ok" }));
app.get("/health", (_req, res) => sendJson(res, 200, { success: true, status: "healthy" }));

function requireBotSecret(req, res, next) {
  if (!BOT_SHARED_SECRET) {
    return sendJson(res, 503, { success: false, error: "BOT_SHARED_SECRET_MISSING" });
  }
  const s = String(req.get("X-Bot-Secret") || "").trim();
  if (!s || s !== BOT_SHARED_SECRET) {
    return sendJson(res, 401, { success: false, error: "UNAUTHORIZED" });
  }
  return next();
}

app.post("/v1/bot/pull", requireBotSecret, (req, res) => {
  const item = queue.shift() || null;
  return sendJson(res, 200, { success: true, item });
});

app.post("/v1/bot/push", requireBotSecret, (req, res) => {
  const body = req.body || {};
  const request_id = Number(body.request_id);
  if (!Number.isFinite(request_id) || request_id <= 0) {
    return sendJson(res, 400, { success: false, error: "INVALID_REQUEST_ID" });
  }
  const ok = Boolean(body.ok);
  const reason = safeString(String(body.reason || ""), 64) || (ok ? "OK" : "INVALID_KEY");
  const username = safeString(String(body.username || "hawk-user"), 64) || "hawk-user";
  const plan = safeString(String(body.plan || "premium"), 32) || "premium";
  const expires = safeString(String(body.expires || "∞"), 64) || "∞";

  const waiter = waiters.get(request_id);
  if (waiter) {
    clearTimeout(waiter.timeout);
    waiters.delete(request_id);
    waiter.resolve({ ok, reason, username, plan, expires });
  }
  return sendJson(res, 200, { success: true });
});

// Main route (per prompt)
app.post("/V1/login", async (req, res) => {
  const ip = String(req.ip || req.socket.remoteAddress || "unknown");
  const start = Date.now();

  try {
    if (REQUIRE_HTTPS && NODE_ENV === "production" && !isHttpsReq(req)) {
      logWarn(`blocked non-https ip=${ip}`);
      return sendJson(res, 403, { success: false, error: "HTTPS_REQUIRED" });
    }

    if (API_TOKEN_SECRET) {
      const token = readApiToken(req);
      if (!token || token !== API_TOKEN_SECRET) {
        logWarn(`unauthorized app token ip=${ip}`);
        return sendJson(res, 401, { success: false, error: "UNAUTHORIZED" });
      }
    }

    const v = validateLoginBody(req.body);
    if (!v.ok) return sendJson(res, 400, { success: false, error: v.error });

    cleanupReplay();
    const nowSec = Math.floor(Date.now() / 1000);
    const tsSec = Math.floor(v.timestamp);
    if (Math.abs(nowSec - tsSec) > REPLAY_WINDOW_SEC) {
      logWarn(`timestamp expired ip=${ip}`);
      return sendJson(res, 401, { success: false, error: "TIMESTAMP_EXPIRED" });
    }
    if (recentNonces.has(v.nonce)) {
      logWarn(`replay detected ip=${ip}`);
      return sendJson(res, 409, { success: false, error: "REPLAY_DETECTED" });
    }
    recentNonces.set(v.nonce, Date.now());

    const botPayload = {
      license_key: v.license_key,
      hwid: v.hwid,
      pc_name: v.pc_name,
      app_version: v.app_version,
      ip, // always trust API observed IP
      timestamp: v.timestamp,
      nonce: v.nonce,
    };

    // Enqueue request and wait bot result (long-poll).
    reqSeq += 1;
    const request_id = reqSeq;
    queue.push({ request_id, payload: botPayload, created_at: Date.now() });

    const result = await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        waiters.delete(request_id);
        resolve(null);
      }, BOT_WAIT_MS);
      waiters.set(request_id, { resolve, timeout });
    });

    if (!result) {
      logWarn(`bot timeout ip=${ip} ms=${Date.now() - start}`);
      return sendJson(res, 503, { success: false, error: "BOT_TIMEOUT" });
    }

    const ok = Boolean(result.ok);
    if (!ok) {
      logWarn(`login fail ip=${ip} reason=${result.reason}`);
      return sendJson(res, 401, { success: false, error: result.reason || "INVALID_KEY" });
    }

    const username = String(result.username || "hawk-user");
    const plan = String(result.plan || "premium");
    const expires = String(result.expires || "∞");
    const token = signJwt({ license_key: v.license_key, hwid: v.hwid, plan, expires });

    logOk(`login ok ip=${ip} ms=${Date.now() - start}`);
    return sendJson(res, 200, { success: true, token, username, plan, expires });
  } catch (e) {
    const msg = e && e.message ? e.message : String(e);
    if (DEBUG) logErr(`unhandled: ${msg}`);
    return sendJson(res, 500, { success: false, error: "INTERNAL_ERROR" });
  }
});

// Invalid route
app.use((_req, res) => sendJson(res, 404, { success: false, error: "NOT_FOUND" }));

// Crash-safe handler
app.use((err, _req, res, _next) => {
  logErr(`crash: ${err && err.message ? err.message : String(err)}`);
  return sendJson(res, 500, { success: false, error: "INTERNAL_ERROR" });
});

app.listen(PORT, () => {
  if (!JWT_SECRET || !RESPONSE_SIGNING_KEY || !BOT_SHARED_SECRET) {
    logErr("Missing required env: JWT_SECRET / RESPONSE_SIGNING_KEY / BOT_SHARED_SECRET");
  }
  logInfo(`listening :${PORT} env=${NODE_ENV}`);
});
