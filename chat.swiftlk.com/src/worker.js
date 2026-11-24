// Swift Akuru Chat API — Cloudflare Worker + D1.
//
// The server is a mailbox for end-to-end encrypted messages. It never sees message text, PINs or
// private keys. Identity comes only from the bearer session token; sender IDs in requests are ignored.
//
// All routes live under /v1. JSON in, JSON out.

const DAY = 86400, HOUR = 3600;
const MAX_CIPHERTEXT = 24 * 1024;          // base64 characters
const INVITE_TTL = 2 * DAY;
const MESSAGE_TTL = 30 * DAY;              // undelivered messages and delivered metadata are purged after this
const OTP_TTL = 5 * 60;
const E164 = /^\+[1-9]\d{7,14}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    try {
      if (url.pathname === "/" || url.pathname === "/v1/health") return json({ ok: true, service: "swiftakuru-chat", version: 1 });
      const res = await route(request, env, url);
      if (Math.random() < 0.02) ctx.waitUntil(cleanup(env));
      return res;
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.code }, e.status);
      // Never log request bodies, tokens or phone numbers.
      console.log("internal_error", e && e.name);
      return json({ error: "internal" }, 500);
    }
  },
};

class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const fail = (status, code) => { throw new HttpError(status, code); };

function cors() {
  return { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS" };
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...cors() } });
}
const now = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------- crypto helpers
const enc = new TextEncoder();
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }
function randomHex(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }
function uuid() { return crypto.randomUUID(); }
async function sha256(s) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function hmac(keyHex, s) {
  const key = await crypto.subtle.importKey("raw", hexToBytes(keyHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(s)));
}
function hexToBytes(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function pepper(env) {
  const row = await env.DB.prepare("SELECT v FROM config WHERE k='pepper'").first();
  if (row) return row.v;
  await env.DB.prepare("INSERT OR IGNORE INTO config (k, v) VALUES ('pepper', ?)").bind(randomHex(32)).run();
  return (await env.DB.prepare("SELECT v FROM config WHERE k='pepper'").first()).v;
}
const phoneHash = async (env, phone) => hmac(await pepper(env), "phone:" + phone);

// ---------------------------------------------------------------- rate limiting
async function limit(env, key, max, windowSec) {
  const t = now();
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (k, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(k) DO UPDATE SET
       count = CASE WHEN rate_limits.window_start + ?3 <= ?2 THEN 1 ELSE rate_limits.count + 1 END,
       window_start = CASE WHEN rate_limits.window_start + ?3 <= ?2 THEN ?2 ELSE rate_limits.window_start END
     RETURNING count`).bind(key, t, windowSec).first();
  if (row.count > max) fail(429, "rate_limited");
}
const clientIP = req => req.headers.get("cf-connecting-ip") || "unknown";

// ---------------------------------------------------------------- input helpers
async function body(req) {
  const len = Number(req.headers.get("content-length") || 0);
  if (len > 64 * 1024) fail(413, "too_large");
  try { return await req.json(); } catch { fail(400, "bad_json"); }
}
function str(v, max, name) {
  if (typeof v !== "string") fail(400, "bad_" + name);
  const s = v.trim();
  if (!s || s.length > max) fail(400, "bad_" + name);
  return s;
}
function phone(v) {
  const p = typeof v === "string" ? v.replace(/[\s\-()]/g, "") : "";
  if (!E164.test(p)) fail(400, "bad_phone");
  return p;
}
function key32(v) {
  if (typeof v !== "string" || !B64.test(v) || v.length !== 44) fail(400, "bad_key");
  return v;
}
function id(v, name = "id") { if (typeof v !== "string" || !UUID.test(v)) fail(400, "bad_" + name); return v; }

// ---------------------------------------------------------------- auth
async function auth(req, env) {
  const h = req.headers.get("authorization") || "";
  const m = h.match(/^Bearer ([0-9a-f]{64})$/);
  if (!m) fail(401, "unauthorized");
  const th = await sha256(m[1]);
  const row = await env.DB.prepare(
    `SELECT s.user_id, s.last_seen, u.display_name, u.discoverable, u.kem_pub, u.key_version
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND u.deleted_at IS NULL`).bind(th).first();
  if (!row) fail(401, "unauthorized");
  if (now() - row.last_seen > 300) await env.DB.prepare("UPDATE sessions SET last_seen=? WHERE token_hash=?").bind(now(), th).run();
  return { id: row.user_id, tokenHash: th, displayName: row.display_name, discoverable: !!row.discoverable, kemPub: row.kem_pub, keyVersion: row.key_version };
}

async function testCode(env, ph) {
  const row = await env.DB.prepare("SELECT v FROM config WHERE k='test_numbers'").first();
  if (!row) return null;
  try { const map = JSON.parse(row.v); return typeof map[ph] === "string" ? map[ph] : null; } catch { return null; }
}

async function sendSMS(env, to, text) {
  if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_FROM) fail(503, "sms_not_configured");
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`, {
    method: "POST",
    headers: { authorization: "Basic " + btoa(env.TWILIO_ACCOUNT_SID + ":" + env.TWILIO_AUTH_TOKEN), "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: text }),
  });
  if (!r.ok) fail(502, "sms_failed");
}

async function authStart(req, env) {
  const b = await body(req);
  const p = phone(b.phone);
  const ph = await phoneHash(env, p);
  await limit(env, "otp-ip:" + clientIP(req), 30, HOUR);
  await limit(env, "otp-phone:" + ph, 3, 10 * 60);
  const fixed = await testCode(env, p);
  const code = fixed || String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
  const t = now();
  await env.DB.prepare(
    `INSERT INTO otp_codes (phone_hash, code_hash, expires_at, attempts, sent_at) VALUES (?1, ?2, ?3, 0, ?4)
     ON CONFLICT(phone_hash) DO UPDATE SET code_hash=?2, expires_at=?3, attempts=0, sent_at=?4`)
    .bind(ph, await hmac(await pepper(env), "otp:" + ph + ":" + code), t + OTP_TTL, t).run();
  if (!fixed) await sendSMS(env, p, `Swift Akuru code: ${code}`);
  return json({ ok: true, expiresIn: OTP_TTL });
}

async function authVerify(req, env) {
  const b = await body(req);
  const p = phone(b.phone);
  const code = typeof b.code === "string" && /^\d{6}$/.test(b.code) ? b.code : fail(400, "bad_code");
  const kem = key32(b.kemPub);
  const device = typeof b.device === "string" ? b.device.slice(0, 60) : null;
  const ph = await phoneHash(env, p);
  await limit(env, "verify-ip:" + clientIP(req), 30, HOUR);
  const row = await env.DB.prepare("SELECT code_hash, expires_at, attempts FROM otp_codes WHERE phone_hash=?").bind(ph).first();
  if (!row || row.expires_at < now() || row.attempts >= 5) fail(400, "code_expired");
  const want = await hmac(await pepper(env), "otp:" + ph + ":" + code);
  if (!timingSafeEqual(want, row.code_hash)) {
    await env.DB.prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE phone_hash=?").bind(ph).run();
    fail(400, "wrong_code");
  }
  await env.DB.prepare("DELETE FROM otp_codes WHERE phone_hash=?").bind(ph).run();

  const t = now();
  let user = await env.DB.prepare("SELECT id, kem_pub, key_version, display_name FROM users WHERE phone_hash=? AND deleted_at IS NULL").bind(ph).first();
  let created = false;
  if (!user) {
    const name = str(b.displayName ?? "", 40, "name");
    const uid = uuid();
    await env.DB.prepare("INSERT INTO users (id, phone_hash, display_name, discoverable, kem_pub, key_version, key_updated_at, created_at) VALUES (?,?,?,?,?,1,?,?)")
      .bind(uid, ph, name, b.discoverable === false ? 0 : 1, kem, t, t).run();
    user = { id: uid, kem_pub: kem, key_version: 1, display_name: name };
    created = true;
  } else if (user.kem_pub !== kem) {
    // Logging in on a new device / reinstall → new encryption identity. One active device per account.
    await rotateKey(env, user.id, kem);
    user.key_version += 1;
  }
  // Single active session per account: a new login signs out other devices.
  await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id).run();
  const token = randomHex(32);
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, device, created_at, last_seen) VALUES (?,?,?,?,?)")
    .bind(await sha256(token), user.id, device, t, t).run();
  return json({ token, created, user: await meJSON(env, user.id) });
}

async function rotateKey(env, uid, kem) {
  const t = now();
  await env.DB.prepare("UPDATE users SET kem_pub=?, key_version=key_version+1, key_updated_at=? WHERE id=?").bind(kem, t, uid).run();
  const partners = await env.DB.prepare(
    `SELECT CASE WHEN c.user_a=?1 THEN c.user_b ELSE c.user_a END AS other FROM conversations c WHERE c.user_a=?1 OR c.user_b=?1`).bind(uid).all();
  const u = await env.DB.prepare("SELECT kem_pub, key_version FROM users WHERE id=?").bind(uid).first();
  for (const r of partners.results) await event(env, r.other, "key_changed", { userId: uid, kemPub: u.kem_pub, keyVersion: u.key_version });
}

async function meJSON(env, uid) {
  const u = await env.DB.prepare("SELECT id, display_name, discoverable, kem_pub, key_version, created_at FROM users WHERE id=?").bind(uid).first();
  return { id: u.id, displayName: u.display_name, discoverable: !!u.discoverable, kemPub: u.kem_pub, keyVersion: u.key_version, createdAt: u.created_at };
}
const publicUser = u => ({ id: u.id, displayName: u.display_name, kemPub: u.kem_pub, keyVersion: u.key_version });

async function event(env, uid, type, payload) {
  await env.DB.prepare("INSERT INTO events (user_id, type, payload, created_at) VALUES (?,?,?,?)").bind(uid, type, JSON.stringify(payload), now()).run();
}

async function isBlockedEither(env, a, b) {
  const r = await env.DB.prepare("SELECT 1 FROM blocks WHERE (blocker=?1 AND blocked=?2) OR (blocker=?2 AND blocked=?1) LIMIT 1").bind(a, b).first();
  return !!r;
}

async function membership(env, me, cid) {
  const c = await env.DB.prepare(
    `SELECT c.id, c.user_a, c.user_b, c.secret FROM conversations c JOIN conversation_members m ON m.conversation_id=c.id AND m.user_id=?2 WHERE c.id=?1`).bind(cid, me).first();
  if (!c) fail(404, "not_found");          // same answer for "doesn't exist" and "not yours"
  c.other = c.user_a === me ? c.user_b : c.user_a;
  return c;
}

// ---------------------------------------------------------------- router
async function route(req, env, url) {
  const p = url.pathname.replace(/\/+$/, "");
  const M = req.method;
  if (p === "/v1/auth/start" && M === "POST") return authStart(req, env);
  if (p === "/v1/auth/verify" && M === "POST") return authVerify(req, env);

  const me = await auth(req, env);
  if (Math.random() < 0.5) await limit(env, "api:" + me.id, 600, 60);   // coarse per-user ceiling

  if (p === "/v1/me" && M === "GET") return json({ user: await meJSON(env, me.id) });
  if (p === "/v1/me" && M === "PATCH") {
    const b = await body(req);
    if (b.displayName !== undefined) await env.DB.prepare("UPDATE users SET display_name=? WHERE id=?").bind(str(b.displayName, 40, "name"), me.id).run();
    if (b.discoverable !== undefined) await env.DB.prepare("UPDATE users SET discoverable=? WHERE id=?").bind(b.discoverable ? 1 : 0, me.id).run();
    return json({ user: await meJSON(env, me.id) });
  }
  if (p === "/v1/me" && M === "DELETE") return deleteAccount(env, me);
  if (p === "/v1/me/keys" && M === "PUT") {
    const b = await body(req);
    const kem = key32(b.kemPub);
    await limit(env, "keys:" + me.id, 10, DAY);
    if (kem !== me.kemPub) await rotateKey(env, me.id, kem);
    return json({ user: await meJSON(env, me.id) });
  }
  if (p === "/v1/auth/logout" && M === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(me.tokenHash).run();
    return json({ ok: true });
  }
  if (p === "/v1/auth/revoke-others" && M === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(me.id, me.tokenHash).run();
    return json({ ok: true });
  }

  if (p === "/v1/lookup" && M === "POST") {
    const b = await body(req);
    const ph = await phoneHash(env, phone(b.phone));
    await limit(env, "lookup:" + me.id, 20, HOUR);
    await limit(env, "lookup-ip:" + clientIP(req), 200, HOUR);
    const u = await env.DB.prepare("SELECT id, display_name, kem_pub, key_version FROM users WHERE phone_hash=? AND discoverable=1 AND deleted_at IS NULL").bind(ph).first();
    // Identical answer for: no account, hidden account, blocked, yourself.
    if (!u || u.id === me.id || await isBlockedEither(env, me.id, u.id)) return json({ found: false });
    return json({ found: true, user: publicUser(u) });
  }

  if (p === "/v1/conversations" && M === "GET") {
    const rows = await env.DB.prepare(
      `SELECT c.id, c.secret, c.created_at, u.id AS uid, u.display_name, u.kem_pub, u.key_version, u.deleted_at
       FROM conversation_members m JOIN conversations c ON c.id=m.conversation_id
       JOIN users u ON u.id = CASE WHEN c.user_a=?1 THEN c.user_b ELSE c.user_a END
       WHERE m.user_id=?1 AND m.hidden=0 ORDER BY c.created_at DESC LIMIT 500`).bind(me.id).all();
    return json({ conversations: rows.results.map(r => ({ id: r.id, secret: !!r.secret, createdAt: r.created_at,
      partner: r.deleted_at ? { id: r.uid, displayName: "Deleted account", kemPub: null, keyVersion: 0, deleted: true } : publicUser({ id: r.uid, display_name: r.display_name, kem_pub: r.kem_pub, key_version: r.key_version }) })) });
  }
  if (p === "/v1/conversations" && M === "POST") {
    const b = await body(req);
    const other = id(b.userId, "user");
    if (other === me.id) fail(400, "bad_user");
    const [a, z] = [me.id, other].sort();
    let c = await env.DB.prepare("SELECT id FROM conversations WHERE user_a=? AND user_b=?").bind(a, z).first();
    if (!c) {
      const u = await env.DB.prepare("SELECT id FROM users WHERE id=? AND discoverable=1 AND deleted_at IS NULL").bind(other).first();
      if (!u || await isBlockedEither(env, me.id, other)) fail(404, "not_found");
      await limit(env, "newconv:" + me.id, 30, DAY);
      c = { id: uuid() };
      await env.DB.batch([
        env.DB.prepare("INSERT INTO conversations (id, user_a, user_b, created_at) VALUES (?,?,?,?)").bind(c.id, a, z, now()),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id) VALUES (?,?)").bind(c.id, a),
        env.DB.prepare("INSERT INTO conversation_members (conversation_id, user_id) VALUES (?,?)").bind(c.id, z),
      ]);
    } else {
      await env.DB.prepare("UPDATE conversation_members SET hidden=0 WHERE conversation_id=? AND user_id=?").bind(c.id, me.id).run();
    }
    return json({ conversationId: c.id });
  }
  let m;
  if ((m = p.match(/^\/v1\/conversations\/([0-9a-f-]{36})$/)) && M === "DELETE") {
    const c = await membership(env, me.id, id(m[1]));
    await env.DB.prepare("UPDATE conversation_members SET hidden=1 WHERE conversation_id=? AND user_id=?").bind(c.id, me.id).run();
    return json({ ok: true });
  }

  if (p === "/v1/messages" && M === "POST") {
    const b = await body(req);
    const mid = id(b.id, "message");
    const c = await membership(env, me.id, id(b.conversationId, "conversation"));
    if (typeof b.enc !== "string" || !B64.test(b.enc) || b.enc.length > 200) fail(400, "bad_enc");
    if (typeof b.ciphertext !== "string" || !B64.test(b.ciphertext) || b.ciphertext.length > MAX_CIPHERTEXT) fail(400, "bad_ciphertext");
    const kv = Number.isInteger(b.keyVersion) ? b.keyVersion : fail(400, "bad_key_version");
    const sentAt = Number.isInteger(b.sentAt) ? b.sentAt : now();
    await limit(env, "send:" + me.id, 120, 60);
    const rcpt = await env.DB.prepare("SELECT key_version, deleted_at FROM users WHERE id=?").bind(c.other).first();
    if (!rcpt || rcpt.deleted_at) fail(410, "recipient_gone");
    if (kv !== rcpt.key_version) fail(409, "stale_key");              // client must refetch the partner's key
    const existing = await env.DB.prepare("SELECT seq, sender_id FROM messages WHERE id=?").bind(mid).first();
    if (existing) {
      if (existing.sender_id !== me.id) fail(409, "id_conflict");
      return json({ seq: existing.seq, duplicate: true });
    }
    if (await isBlockedEither(env, me.id, c.other)) return json({ seq: 0, duplicate: false }); // silently not delivered
    const r = await env.DB.prepare(
      `INSERT INTO messages (id, conversation_id, sender_id, recipient_id, enc, ciphertext, key_version, sent_at, created_at)
       VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING RETURNING seq`)
      .bind(mid, c.id, me.id, c.other, b.enc, b.ciphertext, kv, sentAt, now()).first();
    await env.DB.prepare("UPDATE conversation_members SET hidden=0 WHERE conversation_id=?").bind(c.id).run();
    return json({ seq: r ? r.seq : 0, duplicate: !r });
  }

  if (p === "/v1/sync" && M === "GET") {
    const afterM = Math.max(0, parseInt(url.searchParams.get("after") || "0", 10) || 0);
    const afterE = Math.max(0, parseInt(url.searchParams.get("events") || "0", 10) || 0);
    const msgs = await env.DB.prepare(
      `SELECT seq, id, conversation_id, sender_id, enc, ciphertext, key_version, sent_at, created_at FROM messages
       WHERE recipient_id=? AND seq>? AND ciphertext IS NOT NULL ORDER BY seq LIMIT 200`).bind(me.id, afterM).all();
    const evs = await env.DB.prepare("SELECT seq, type, payload, created_at FROM events WHERE user_id=? AND seq>? ORDER BY seq LIMIT 500").bind(me.id, afterE).all();
    return json({
      messages: msgs.results.map(r => ({ seq: r.seq, id: r.id, conversationId: r.conversation_id, senderId: r.sender_id, enc: r.enc, ciphertext: r.ciphertext, keyVersion: r.key_version, sentAt: r.sent_at, serverAt: r.created_at })),
      events: evs.results.map(r => ({ seq: r.seq, type: r.type, payload: JSON.parse(r.payload), at: r.created_at })),
    });
  }

  if (p === "/v1/messages/ack" && M === "POST") {
    const b = await body(req);
    const delivered = Array.isArray(b.delivered) ? b.delivered.slice(0, 500).map(x => id(x, "message")) : [];
    const read = Array.isArray(b.read) ? b.read.slice(0, 500).map(x => id(x, "message")) : [];
    const t = now();
    const bySender = {};
    for (const [list, field] of [[delivered, "delivered"], [read, "read"]]) {
      for (const mid of list) {
        const sql = field === "delivered"
          ? "UPDATE messages SET delivered_at=COALESCE(delivered_at, ?1), enc=NULL, ciphertext=NULL WHERE id=?2 AND recipient_id=?3 RETURNING sender_id, conversation_id"
          : "UPDATE messages SET read_at=COALESCE(read_at, ?1), delivered_at=COALESCE(delivered_at, ?1), enc=NULL, ciphertext=NULL WHERE id=?2 AND recipient_id=?3 RETURNING sender_id, conversation_id";
        const r = await env.DB.prepare(sql).bind(t, mid, me.id).first();
        if (r) ((bySender[r.sender_id] ??= {})[field] ??= []).push(mid);
      }
    }
    for (const [sender, st] of Object.entries(bySender)) await event(env, sender, "status", { delivered: st.delivered || [], read: st.read || [], at: t });
    return json({ ok: true });
  }

  if (p === "/v1/events/ack" && M === "POST") {
    const b = await body(req);
    const upTo = Number.isInteger(b.upTo) ? b.upTo : fail(400, "bad_seq");
    await env.DB.prepare("DELETE FROM events WHERE user_id=? AND seq<=?").bind(me.id, upTo).run();
    return json({ ok: true });
  }

  // ---- Secret Chat: invitation & mutual acceptance
  if (p === "/v1/secret/invite" && M === "POST") {
    const b = await body(req);
    const c = await membership(env, me.id, id(b.conversationId, "conversation"));
    if (c.secret) fail(409, "already_secret");
    if (await isBlockedEither(env, me.id, c.other)) fail(404, "not_found");
    await limit(env, "invite:" + me.id, 20, DAY);
    const t = now();
    await env.DB.prepare("UPDATE secret_invitations SET status='expired' WHERE conversation_id=? AND status='pending' AND expires_at<?").bind(c.id, t).run();
    const pending = await env.DB.prepare("SELECT id FROM secret_invitations WHERE conversation_id=? AND status='pending'").bind(c.id).first();
    if (pending) fail(409, "invite_pending");
    const inv = { id: uuid(), conversationId: c.id, fromUser: me.id, toUser: c.other, createdAt: t, expiresAt: t + INVITE_TTL, fromName: me.displayName };
    await env.DB.prepare("INSERT INTO secret_invitations (id, conversation_id, from_user, to_user, status, created_at, expires_at) VALUES (?,?,?,?, 'pending', ?, ?)")
      .bind(inv.id, c.id, me.id, c.other, t, inv.expiresAt).run();
    await event(env, c.other, "invite", inv);
    return json({ invitation: inv });
  }
  if (p === "/v1/secret/invitations" && M === "GET") {
    const rows = await env.DB.prepare(
      `SELECT i.id, i.conversation_id, i.from_user, i.to_user, i.status, i.created_at, i.expires_at, u.display_name AS from_name
       FROM secret_invitations i JOIN users u ON u.id=i.from_user
       WHERE (i.to_user=?1 OR i.from_user=?1) AND i.status='pending' AND i.expires_at>?2`).bind(me.id, now()).all();
    return json({ invitations: rows.results.map(r => ({ id: r.id, conversationId: r.conversation_id, fromUser: r.from_user, toUser: r.to_user, status: r.status, createdAt: r.created_at, expiresAt: r.expires_at, fromName: r.from_name })) });
  }
  if (p === "/v1/secret/respond" && M === "POST") {
    const b = await body(req);
    const inv = await env.DB.prepare("SELECT * FROM secret_invitations WHERE id=? AND to_user=?").bind(id(b.invitationId, "invitation"), me.id).first();
    if (!inv) fail(404, "not_found");
    const t = now();
    if (inv.status !== "pending") fail(409, "not_pending");
    if (inv.expires_at < t) { await env.DB.prepare("UPDATE secret_invitations SET status='expired' WHERE id=?").bind(inv.id).run(); fail(410, "expired"); }
    const accept = b.accept === true;
    await env.DB.prepare("UPDATE secret_invitations SET status=?, responded_at=? WHERE id=?").bind(accept ? "accepted" : "declined", t, inv.id).run();
    if (accept) {
      await env.DB.prepare("UPDATE conversations SET secret=1, secret_since=? WHERE id=?").bind(t, inv.conversation_id).run();
      for (const u of [inv.from_user, inv.to_user]) await event(env, u, "secret", { conversationId: inv.conversation_id, secret: true, at: t });
    }
    await event(env, inv.from_user, "invite_response", { invitationId: inv.id, conversationId: inv.conversation_id, accepted: accept });
    return json({ ok: true, accepted: accept });
  }
  if (p === "/v1/secret/leave" && M === "POST") {
    const b = await body(req);
    const c = await membership(env, me.id, id(b.conversationId, "conversation"));
    await env.DB.prepare("UPDATE conversations SET secret=0, secret_since=NULL WHERE id=?").bind(c.id).run();
    for (const u of [me.id, c.other]) await event(env, u, "secret", { conversationId: c.id, secret: false, at: now() });
    return json({ ok: true });
  }
  // Keyboard unlock: "which of MY secret conversations belongs to this phone number?"
  // Only matches partners in an existing, mutually accepted Secret Chat → no enumeration value.
  if (p === "/v1/secret/resolve" && M === "POST") {
    const b = await body(req);
    const ph = await phoneHash(env, phone(b.phone));
    await limit(env, "resolve:" + me.id, 30, HOUR);
    const r = await env.DB.prepare(
      `SELECT c.id AS cid, u.id, u.display_name, u.kem_pub, u.key_version FROM users u
       JOIN conversations c ON (c.user_a=u.id AND c.user_b=?2) OR (c.user_b=u.id AND c.user_a=?2)
       WHERE u.phone_hash=?1 AND u.deleted_at IS NULL AND c.secret=1`).bind(ph, me.id).first();
    if (!r) return json({ found: false });
    return json({ found: true, conversationId: r.cid, user: publicUser(r) });
  }

  if (p === "/v1/blocks" && M === "POST") {
    const b = await body(req);
    const other = id(b.userId, "user");
    if (other === me.id) fail(400, "bad_user");
    await env.DB.prepare("INSERT OR IGNORE INTO blocks (blocker, blocked, created_at) VALUES (?,?,?)").bind(me.id, other, now()).run();
    return json({ ok: true });
  }
  if ((m = p.match(/^\/v1\/blocks\/([0-9a-f-]{36})$/)) && M === "DELETE") {
    await env.DB.prepare("DELETE FROM blocks WHERE blocker=? AND blocked=?").bind(me.id, id(m[1], "user")).run();
    return json({ ok: true });
  }
  if (p === "/v1/blocks" && M === "GET") {
    const rows = await env.DB.prepare("SELECT b.blocked, u.display_name FROM blocks b LEFT JOIN users u ON u.id=b.blocked WHERE b.blocker=?").bind(me.id).all();
    return json({ blocked: rows.results.map(r => ({ id: r.blocked, displayName: r.display_name || "" })) });
  }
  if (p === "/v1/reports" && M === "POST") {
    const b = await body(req);
    const other = id(b.userId, "user");
    await limit(env, "report:" + me.id, 20, DAY);
    const reason = str(b.reason ?? "other", 500, "reason");
    const cid = b.conversationId ? id(b.conversationId, "conversation") : null;
    await env.DB.prepare("INSERT INTO reports (id, reporter, reported, conversation_id, reason, created_at) VALUES (?,?,?,?,?,?)").bind(uuid(), me.id, other, cid, reason, now()).run();
    return json({ ok: true });
  }

  fail(404, "not_found");
}

async function deleteAccount(env, me) {
  const uid = me.id;
  const convs = await env.DB.prepare("SELECT c.id, CASE WHEN c.user_a=?1 THEN c.user_b ELSE c.user_a END AS other FROM conversations c WHERE c.user_a=?1 OR c.user_b=?1").bind(uid).all();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(uid),
    env.DB.prepare("DELETE FROM messages WHERE sender_id=? OR recipient_id=?").bind(uid, uid),
    env.DB.prepare("DELETE FROM events WHERE user_id=?").bind(uid),
    env.DB.prepare("DELETE FROM secret_invitations WHERE from_user=? OR to_user=?").bind(uid, uid),
    env.DB.prepare("DELETE FROM blocks WHERE blocker=?").bind(uid),
    env.DB.prepare("UPDATE users SET deleted_at=?, phone_hash='deleted:'||id, display_name='Deleted account', discoverable=0, kem_pub='' WHERE id=?").bind(now(), uid),
  ]);
  for (const c of convs.results) await event(env, c.other, "conversation", { conversationId: c.id, partnerDeleted: true });
  return json({ ok: true });
}

async function cleanup(env) {
  const t = now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM messages WHERE created_at < ?").bind(t - MESSAGE_TTL),
    env.DB.prepare("DELETE FROM events WHERE created_at < ?").bind(t - MESSAGE_TTL),
    env.DB.prepare("DELETE FROM otp_codes WHERE expires_at < ?").bind(t - DAY),
    env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(t - 2 * DAY),
    env.DB.prepare("UPDATE secret_invitations SET status='expired' WHERE status='pending' AND expires_at < ?").bind(t),
    env.DB.prepare("DELETE FROM sessions WHERE last_seen < ?").bind(t - 180 * DAY),
  ]);
}
