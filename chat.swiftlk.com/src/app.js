// Swift Akuru app backend: Google sign-in, anonymous install stats and the owner's admin dashboard.
// Never receives anything the user types. Admin pages are protected by a password (hash in config) and
// an HttpOnly signed cookie.
import { ADMIN_HTML } from "./admin.html.js";

const DAY = 86400;
const now = () => Math.floor(Date.now() / 1000);
const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const randomHex = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); };
const sha256 = async s => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function hmac(key, s) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(s)));
}
function safeEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

class AppError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
const fail = (s, c) => { throw new AppError(s, c); };
const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, POST, DELETE, OPTIONS" };
const json = (o, status = 200, extra = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS, ...extra } });
const clean = (v, max) => typeof v === "string" ? v.slice(0, max).replace(/[\u0000-\u001f]/g, "") : null;

async function cfg(env, k) { const r = await env.DB.prepare("SELECT v FROM config WHERE k=?").bind(k).first(); return r ? r.v : null; }
async function cfgOrCreate(env, k, make) {
  let v = await cfg(env, k);
  if (!v) { v = make(); await env.DB.prepare("INSERT OR IGNORE INTO config (k, v) VALUES (?, ?)").bind(k, v).run(); v = await cfg(env, k); }
  return v;
}
async function limit(env, key, max, win) {
  const t = now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (k, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(k) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start + ?3 <= ?2 THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start + ?3 <= ?2 THEN ?2 ELSE rate_limits.window_start END
     RETURNING count`).bind(key, t, win).first();
  if (row.count > max) fail(429, "rate_limited");
}
const ip = req => req.headers.get("cf-connecting-ip") || "unknown";

export function isAppRoute(p) { return p.startsWith("/v1/app/") || p.startsWith("/auth/google") || p === "/admin" || p.startsWith("/admin/"); }

export async function appRoute(req, env, url) {
  try {
    const p = url.pathname.replace(/\/+$/, "") || "/";
    const M = req.method;
    if (p === "/v1/app/ping" && M === "POST") return ping(req, env);
    if (p === "/v1/app/config" && M === "GET") return json({ googleSignIn: !!(await googleClient(env)) });
    if (p === "/auth/google/start" && M === "GET") return googleStart(req, env, url);
    if (p === "/auth/google/callback" && M === "GET") return googleCallback(req, env, url);
    if (p === "/v1/app/me" && M === "GET") { const a = await account(req, env); return json({ account: accountJSON(a) }); }
    if (p === "/v1/app/logout" && M === "POST") {
      const t = bearer(req); if (t) await env.DB.prepare("DELETE FROM app_sessions WHERE token_hash=?").bind(await sha256(t)).run();
      return json({ ok: true });
    }
    if (p === "/v1/app/account" && M === "DELETE") {
      const a = await account(req, env);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM app_sessions WHERE account_id=?").bind(a.id),
        env.DB.prepare("UPDATE app_installs SET account_id=NULL WHERE account_id=?").bind(a.id),
        env.DB.prepare("DELETE FROM app_accounts WHERE id=?").bind(a.id),
      ]);
      return json({ ok: true });
    }
    if (p === "/admin" && M === "GET") return new Response(ADMIN_HTML, { headers: {
      "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff", "strict-transport-security": "max-age=31536000; includeSubDomains",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
      "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https: data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" } });
    if (p === "/admin/login" && M === "POST") return adminLogin(req, env);
    if (p === "/admin/logout" && M === "POST") return json({ ok: true }, 200, { "set-cookie": "sa_admin=; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });
    if (p.startsWith("/admin/api/")) { await adminAuth(req, env); return adminApi(p, req, env, url); }
    fail(404, "not_found");
  } catch (e) {
    if (e instanceof AppError) return json({ error: e.code }, e.status);
    console.log("app_internal", e && e.name);
    return json({ error: "internal" }, 500);
  }
}

// ---------------------------------------------------------------- installs (anonymous stats)
async function ping(req, env) {
  await limit(env, "ping:" + ip(req), 120, 3600);
  const b = await req.json().catch(() => fail(400, "bad_json"));
  const id = clean(b.installId, 40);
  if (!id || !/^[0-9A-Fa-f-]{36}$/.test(id)) fail(400, "bad_install");
  let accountId = null;
  const t = bearer(req);
  if (t) { const s = await env.DB.prepare("SELECT account_id FROM app_sessions WHERE token_hash=?").bind(await sha256(t)).first(); if (s) accountId = s.account_id; }
  const n = now();
  const v = [clean(b.version, 20), clean(b.build, 10), clean(b.ios, 20), clean(b.model, 30), clean(b.locale, 20), clean(b.source, 20),
             b.keyboardOn ? 1 : 0, b.fullAccess === undefined || b.fullAccess === null ? null : (b.fullAccess ? 1 : 0)];
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO app_installs (install_id, account_id, app_version, build, ios, model, locale, source, keyboard_on, full_access, first_seen, last_seen, opens)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, 1)
                    ON CONFLICT(install_id) DO UPDATE SET account_id=COALESCE(?2, account_id), app_version=?3, build=?4, ios=?5, model=?6, locale=?7, source=?8,
                    keyboard_on=?9, full_access=COALESCE(?10, full_access), last_seen=?11, opens=opens+1`).bind(id, accountId, ...v, n),
    env.DB.prepare("INSERT OR IGNORE INTO app_daily (day, install_id) VALUES (?, ?)").bind(new Date(n * 1000).toISOString().slice(0, 10), id),
    ...(accountId ? [env.DB.prepare("UPDATE app_accounts SET last_seen=? WHERE id=?").bind(n, accountId)] : []),
  ]);
  return json({ ok: true });
}

// ---------------------------------------------------------------- Google sign-in (OAuth 2.0 + PKCE, server side)
async function googleClient(env) {
  const id = env.GOOGLE_CLIENT_ID || await cfg(env, "google_client_id");
  const secret = env.GOOGLE_CLIENT_SECRET || await cfg(env, "google_client_secret");
  return id && secret ? { id, secret } : null;
}
const callbackURL = url => url.origin + "/auth/google/callback";

async function googleStart(req, env, url) {
  await limit(env, "gstart:" + ip(req), 30, 3600);
  const g = await googleClient(env);
  if (!g) return appRedirect({ error: "google_not_configured" });
  const state = randomHex(16), verifier = randomHex(32);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
  const install = clean(url.searchParams.get("install"), 40);
  await env.DB.prepare("INSERT INTO oauth_states (state, verifier, install_id, created_at) VALUES (?, ?, ?, ?)").bind(state, verifier, install, now()).run();
  const q = new URLSearchParams({ client_id: g.id, redirect_uri: callbackURL(url), response_type: "code", scope: "openid email profile",
    state, code_challenge: challenge, code_challenge_method: "S256", prompt: "select_account" });
  return Response.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + q, 302);
}

function appRedirect(params) {
  return new Response(null, { status: 302, headers: { location: "swiftakuru://auth?" + new URLSearchParams(params), "cache-control": "no-store" } });
}

async function googleCallback(req, env, url) {
  const state = url.searchParams.get("state") || "", code = url.searchParams.get("code");
  if (url.searchParams.get("error")) return appRedirect({ error: "cancelled" });
  const st = await env.DB.prepare("SELECT * FROM oauth_states WHERE state=?").bind(state).first();
  await env.DB.prepare("DELETE FROM oauth_states WHERE state=? OR created_at < ?").bind(state, now() - 900).run();
  if (!st || !code || now() - st.created_at > 900) return appRedirect({ error: "expired" });
  const g = await googleClient(env);
  if (!g) return appRedirect({ error: "google_not_configured" });
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: g.id, client_secret: g.secret, redirect_uri: callbackURL(url), grant_type: "authorization_code", code_verifier: st.verifier }),
  });
  const tok = await r.json().catch(() => ({}));
  if (!r.ok || !tok.id_token) return appRedirect({ error: "google_failed" });
  // id_token came straight from Google's token endpoint over TLS: its claims can be trusted; still check audience/issuer/expiry.
  const claims = JSON.parse(atob(tok.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  if (claims.aud !== g.id || !["accounts.google.com", "https://accounts.google.com"].includes(claims.iss) || claims.exp < now()) return appRedirect({ error: "google_failed" });
  const n = now();
  let a = await env.DB.prepare("SELECT * FROM app_accounts WHERE provider='google' AND sub=?").bind(String(claims.sub)).first();
  if (!a) {
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO app_accounts (id, provider, sub, email, name, picture, created_at, last_seen) VALUES (?, 'google', ?, ?, ?, ?, ?, ?)")
      .bind(id, String(claims.sub), clean(claims.email, 200), clean(claims.name, 100), clean(claims.picture, 500), n, n).run();
    a = { id };
  } else {
    await env.DB.prepare("UPDATE app_accounts SET email=?, name=?, picture=?, last_seen=? WHERE id=?").bind(clean(claims.email, 200), clean(claims.name, 100), clean(claims.picture, 500), n, a.id).run();
  }
  const token = randomHex(32);
  await env.DB.prepare("INSERT INTO app_sessions (token_hash, account_id, created_at, last_seen) VALUES (?, ?, ?, ?)").bind(await sha256(token), a.id, n, n).run();
  if (st.install_id) await env.DB.prepare("UPDATE app_installs SET account_id=? WHERE install_id=?").bind(a.id, st.install_id).run();
  return appRedirect({ token });
}

const bearer = req => { const h = req.headers.get("authorization") || ""; return h.startsWith("Bearer ") ? h.slice(7) : null; };
async function account(req, env) {
  const t = bearer(req); if (!t) fail(401, "unauthorized");
  const s = await env.DB.prepare("SELECT account_id FROM app_sessions WHERE token_hash=?").bind(await sha256(t)).first();
  if (!s) fail(401, "unauthorized");
  const a = await env.DB.prepare("SELECT * FROM app_accounts WHERE id=?").bind(s.account_id).first();
  if (!a) fail(401, "unauthorized");
  return a;
}
const accountJSON = a => ({ id: a.id, provider: a.provider, email: a.email, name: a.name, picture: a.picture, plan: a.plan, createdAt: a.created_at });

// ---------------------------------------------------------------- admin
async function adminLogin(req, env) {
  await limit(env, "adminlogin:" + ip(req), 8, 900);
  await limit(env, "adminlogin:all", 40, 3600);          // also slows down attacks spread over many IPs
  const b = await req.json().catch(() => ({}));
  const stored = await cfg(env, "admin_pw");               // "salt:sha256(salt+password)"
  if (!stored || typeof b.password !== "string") fail(401, "bad_password");
  const [salt, h] = stored.split(":");
  if (!safeEq(await sha256(salt + b.password), h)) fail(401, "bad_password");
  const key = await cfgOrCreate(env, "admin_key", () => randomHex(32));
  const exp = now() + 7 * DAY;
  const cookie = exp + "." + await hmac(key, "admin." + exp);
  return json({ ok: true }, 200, { "set-cookie": `sa_admin=${cookie}; Path=/admin; Max-Age=${7 * DAY}; HttpOnly; Secure; SameSite=Strict` });
}
async function adminAuth(req, env) {
  const c = (req.headers.get("cookie") || "").split(/;\s*/).find(x => x.startsWith("sa_admin="));
  if (!c) fail(401, "login");
  const [exp, sig] = c.slice(9).split(".");
  const key = await cfg(env, "admin_key");
  if (!key || !exp || !sig || Number(exp) < now() || !safeEq(await hmac(key, "admin." + exp), sig)) fail(401, "login");
}

async function adminApi(p, req, env, url) {
  const n = now();
  if (p === "/admin/api/stats") {
    const one = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).first()) || {};
    const all = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).all()).results;
    const [installs, a24, a7, a30, accounts, newAcc7, kb, fa, chatUsers, msgs] = await Promise.all([
      one("SELECT COUNT(*) c FROM app_installs"),
      one("SELECT COUNT(*) c FROM app_installs WHERE last_seen > ?", n - DAY),
      one("SELECT COUNT(*) c FROM app_installs WHERE last_seen > ?", n - 7 * DAY),
      one("SELECT COUNT(*) c FROM app_installs WHERE last_seen > ?", n - 30 * DAY),
      one("SELECT COUNT(*) c FROM app_accounts"),
      one("SELECT COUNT(*) c FROM app_accounts WHERE created_at > ?", n - 7 * DAY),
      one("SELECT COUNT(*) c FROM app_installs WHERE keyboard_on=1 AND last_seen > ?", n - 30 * DAY),
      one("SELECT COUNT(*) c FROM app_installs WHERE full_access=1 AND last_seen > ?", n - 30 * DAY),
      one("SELECT COUNT(*) c FROM users"),
      one("SELECT COUNT(*) c FROM messages WHERE created_at > ?", n - DAY),
    ]);
    const since = new Date((n - 29 * DAY) * 1000).toISOString().slice(0, 10);
    const [daily, newDaily, versions, ios, models, sources] = await Promise.all([
      all("SELECT day, COUNT(*) c FROM app_daily WHERE day >= ? GROUP BY day ORDER BY day", since),
      all("SELECT date(first_seen, 'unixepoch') day, COUNT(*) c FROM app_installs WHERE first_seen > ? GROUP BY day ORDER BY day", n - 30 * DAY),
      all("SELECT app_version k, COUNT(*) c FROM app_installs WHERE last_seen > ? GROUP BY app_version ORDER BY c DESC LIMIT 8", n - 30 * DAY),
      all("SELECT substr(ios, 1, instr(ios || '.', '.') - 1) k, COUNT(*) c FROM app_installs WHERE last_seen > ? GROUP BY k ORDER BY c DESC LIMIT 8", n - 30 * DAY),
      all("SELECT model k, COUNT(*) c FROM app_installs WHERE last_seen > ? GROUP BY model ORDER BY c DESC LIMIT 8", n - 30 * DAY),
      all("SELECT source k, COUNT(*) c FROM app_installs WHERE last_seen > ? GROUP BY source ORDER BY c DESC LIMIT 5", n - 30 * DAY),
    ]);
    return json({ installs: installs.c, active1: a24.c, active7: a7.c, active30: a30.c, accounts: accounts.c, newAccounts7: newAcc7.c,
      keyboardOn: kb.c, fullAccess: fa.c, chatUsers: chatUsers.c, messages24h: msgs.c, daily, newDaily, versions, ios, models, sources,
      googleConfigured: !!(await googleClient(env)) });
  }
  if (p === "/admin/api/users") {
    const q = (url.searchParams.get("q") || "").slice(0, 60);
    const rows = (await env.DB.prepare(
      `SELECT a.id, a.email, a.name, a.picture, a.plan, a.created_at, a.last_seen,
              (SELECT app_version FROM app_installs i WHERE i.account_id = a.id ORDER BY last_seen DESC LIMIT 1) version,
              (SELECT model FROM app_installs i WHERE i.account_id = a.id ORDER BY last_seen DESC LIMIT 1) model,
              (SELECT COUNT(*) FROM app_installs i WHERE i.account_id = a.id) devices
       FROM app_accounts a WHERE (?1 = '' OR a.email LIKE ?2 OR a.name LIKE ?2) ORDER BY a.last_seen DESC LIMIT 200`).bind(q, "%" + q + "%").all()).results;
    return json({ users: rows });
  }
  if (p === "/admin/api/installs") {
    const rows = (await env.DB.prepare(
      `SELECT i.install_id, i.app_version, i.build, i.ios, i.model, i.locale, i.source, i.keyboard_on, i.full_access, i.first_seen, i.last_seen, i.opens, a.email
       FROM app_installs i LEFT JOIN app_accounts a ON a.id = i.account_id ORDER BY i.last_seen DESC LIMIT 200`).all()).results;
    return json({ installs: rows });
  }
  if (p === "/admin/api/password" && req.method === "POST") {
    // change the admin password; signs out every other admin session (new cookie key)
    const b = await req.json().catch(() => ({}));
    const pw = typeof b.password === "string" ? b.password : "";
    if (pw.length < 12) fail(400, "too_short");
    const salt = randomHex(16);
    const key = randomHex(32), exp = now() + 7 * DAY;
    await env.DB.batch([
      env.DB.prepare("UPDATE config SET v=? WHERE k='admin_pw'").bind(salt + ":" + await sha256(salt + pw)),
      env.DB.prepare("UPDATE config SET v=? WHERE k='admin_key'").bind(key),
    ]);
    const cookie = exp + "." + await hmac(key, "admin." + exp);
    return json({ ok: true }, 200, { "set-cookie": `sa_admin=${cookie}; Path=/admin; Max-Age=${7 * DAY}; HttpOnly; Secure; SameSite=Strict` });
  }
  if (p === "/admin/api/testers") {
    // phone numbers allowed to use the fixed test OTP
    let list = []; try { list = JSON.parse((await cfg(env, "test_allow")) || "[]"); } catch {}
    if (req.method === "POST" || req.method === "DELETE") {
      const b = await req.json().catch(() => ({}));
      const ph = typeof b.phone === "string" ? b.phone.replace(/[\s\-()]/g, "") : "";
      if (!/^\+[1-9]\d{7,14}$/.test(ph)) fail(400, "bad_phone");
      list = req.method === "POST" ? [...new Set([...list, ph])].slice(0, 50) : list.filter(x => x !== ph);
      await env.DB.prepare("INSERT INTO config (k, v) VALUES ('test_allow', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(list)).run();
    }
    return json({ testers: list, code: await cfg(env, "test_otp_all") });
  }
  if (p === "/admin/api/plan" && req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    if (!["free", "premium"].includes(b.plan)) fail(400, "bad_plan");
    await env.DB.prepare("UPDATE app_accounts SET plan=? WHERE id=?").bind(b.plan, String(b.id || "")).run();
    return json({ ok: true });
  }
  fail(404, "not_found");
}
