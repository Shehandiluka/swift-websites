// Integration + security tests for the Swift Akuru Chat API.
// Usage: BASE=https://… TEST_A=+94700000001 TEST_B=+94700000002 TEST_C=+94700000003 TEST_CODE=xxxxxx node test/api.test.mjs
// The three numbers must be configured as test numbers (config.test_numbers) with TEST_CODE.
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";

const BASE = process.env.BASE || "http://127.0.0.1:8787";
const CODE = process.env.TEST_CODE;
const A = process.env.TEST_A, B = process.env.TEST_B, C = process.env.TEST_C;
let passed = 0, failed = 0;
const key = () => randomBytes(32).toString("base64");
const blob = n => randomBytes(n).toString("base64");

async function api(path, { method = "GET", token, body } = {}) {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = null; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}
async function test(name, fn) {
  try { await fn(); passed++; console.log("PASS", name); }
  catch (e) { failed++; console.log("FAIL", name, "-", e.message); }
}
async function login(phone, name, discoverable = true) {
  const s = await api("/v1/auth/start", { method: "POST", body: { phone } });
  assert.equal(s.status, 200, "start " + JSON.stringify(s.body));
  const v = await api("/v1/auth/verify", { method: "POST", body: { phone, code: CODE, displayName: name, kemPub: key(), discoverable, device: "test" } });
  assert.equal(v.status, 200, "verify " + JSON.stringify(v.body));
  return { token: v.body.token, user: v.body.user };
}

const a = await login(A, "Tester A");
const b = await login(B, "Tester B");
const c = await login(C, "Tester C");
// Reset discoverability/blocks from earlier runs.
for (const u of [a, b, c]) await api("/v1/me", { method: "PATCH", token: u.token, body: { discoverable: true } });
for (const [x, y] of [[a, b], [b, a], [a, c], [c, a], [b, c], [c, b]]) await api("/v1/blocks/" + y.user.id, { method: "DELETE", token: x.token });

let conv;
await test("health", async () => { const r = await api("/v1/health"); assert.equal(r.status, 200); });
await test("unauthenticated request rejected", async () => { assert.equal((await api("/v1/me")).status, 401); });
await test("forged token rejected", async () => { assert.equal((await api("/v1/me", { token: "a".repeat(64) })).status, 401); });
await test("invalid phone rejected", async () => { assert.equal((await api("/v1/auth/start", { method: "POST", body: { phone: "12345" } })).status, 400); });
await test("wrong OTP rejected, then locked after 5 attempts", async () => {
  await api("/v1/auth/start", { method: "POST", body: { phone: C } });
  const wrong = CODE === "000000" ? "111111" : "000000";
  for (let i = 0; i < 5; i++) {
    const r = await api("/v1/auth/verify", { method: "POST", body: { phone: C, code: wrong, kemPub: key() } });
    assert.equal(r.status, 400);
  }
  const r = await api("/v1/auth/verify", { method: "POST", body: { phone: C, code: CODE, kemPub: c.user.kemPub } });
  assert.equal(r.body.error, "code_expired", "correct code must fail after 5 wrong attempts");
});
await test("lookup finds discoverable user without exposing phone", async () => {
  const r = await api("/v1/lookup", { method: "POST", token: a.token, body: { phone: B } });
  assert.equal(r.body.found, true); assert.equal(r.body.user.id, b.user.id);
  assert.ok(!JSON.stringify(r.body).includes(B.slice(1)), "phone must not be in the response");
});
await test("non-discoverable user looks exactly like no user", async () => {
  await api("/v1/me", { method: "PATCH", token: c.token, body: { discoverable: false } });
  const hidden = await api("/v1/lookup", { method: "POST", token: a.token, body: { phone: C } });
  const none = await api("/v1/lookup", { method: "POST", token: a.token, body: { phone: "+94709999999" } });
  assert.deepEqual(hidden.body, none.body); assert.equal(hidden.status, none.status);
  await api("/v1/me", { method: "PATCH", token: c.token, body: { discoverable: true } });
});
await test("create conversation (idempotent)", async () => {
  const r1 = await api("/v1/conversations", { method: "POST", token: a.token, body: { userId: b.user.id } });
  const r2 = await api("/v1/conversations", { method: "POST", token: b.token, body: { userId: a.user.id } });
  assert.equal(r1.status, 200); assert.equal(r1.body.conversationId, r2.body.conversationId);
  conv = r1.body.conversationId;
});
await test("outsider cannot read or post to the conversation", async () => {
  const msg = { id: randomUUID(), conversationId: conv, enc: blob(32), ciphertext: blob(40), keyVersion: a.user.keyVersion, sentAt: 1 };
  assert.equal((await api("/v1/messages", { method: "POST", token: c.token, body: msg })).status, 404);
  assert.equal((await api("/v1/secret/invite", { method: "POST", token: c.token, body: { conversationId: conv } })).status, 404);
  assert.equal((await api("/v1/conversations/" + conv, { method: "DELETE", token: c.token })).status, 404);
});
let m1;
await test("send message; sender identity comes from token (impersonation ignored)", async () => {
  m1 = { id: randomUUID(), conversationId: conv, senderId: c.user.id, enc: blob(32), ciphertext: blob(64), keyVersion: b.user.keyVersion, sentAt: 1700000000 };
  const r = await api("/v1/messages", { method: "POST", token: a.token, body: m1 });
  assert.equal(r.status, 200); assert.ok(r.body.seq > 0);
  const s = await api("/v1/sync?after=0", { token: b.token });
  const got = s.body.messages.find(x => x.id === m1.id);
  assert.ok(got, "B receives it"); assert.equal(got.senderId, a.user.id, "sender must be A, not the forged id");
});
await test("retry with same id does not duplicate", async () => {
  const r = await api("/v1/messages", { method: "POST", token: a.token, body: m1 });
  assert.equal(r.body.duplicate, true);
  const s = await api("/v1/sync?after=0", { token: b.token });
  assert.equal(s.body.messages.filter(x => x.id === m1.id).length, 1);
});
await test("another user cannot reuse a message id (replay by third party)", async () => {
  const r = await api("/v1/messages", { method: "POST", token: b.token, body: { ...m1, conversationId: conv, keyVersion: a.user.keyVersion } });
  assert.equal(r.status, 409);
});
await test("stale recipient key is rejected", async () => {
  const r = await api("/v1/messages", { method: "POST", token: a.token, body: { ...m1, id: randomUUID(), keyVersion: 999 } });
  assert.equal(r.body.error, "stale_key");
});
await test("oversized ciphertext rejected", async () => {
  const r = await api("/v1/messages", { method: "POST", token: a.token, body: { ...m1, id: randomUUID(), ciphertext: blob(20000) } });
  assert.equal(r.status, 400);
});
await test("only the recipient can ack; ack clears ciphertext from server and notifies sender", async () => {
  await api("/v1/messages/ack", { method: "POST", token: c.token, body: { delivered: [m1.id] } });
  let s = await api("/v1/sync?after=0", { token: b.token });
  assert.ok(s.body.messages.some(x => x.id === m1.id), "outsider ack must not clear it");
  await api("/v1/messages/ack", { method: "POST", token: b.token, body: { read: [m1.id] } });
  s = await api("/v1/sync?after=0", { token: b.token });
  assert.ok(!s.body.messages.some(x => x.id === m1.id), "ciphertext gone after delivery");
  const ev = await api("/v1/sync?after=0&events=0", { token: a.token });
  assert.ok(ev.body.events.some(e => e.type === "status" && e.payload.read.includes(m1.id)));
});
let inv;
await test("secret invite → decline keeps conversation normal", async () => {
  const r = await api("/v1/secret/invite", { method: "POST", token: a.token, body: { conversationId: conv } });
  assert.equal(r.status, 200); inv = r.body.invitation;
  assert.equal((await api("/v1/secret/respond", { method: "POST", token: a.token, body: { invitationId: inv.id, accept: true } })).status, 404, "inviter cannot accept own invite");
  const d = await api("/v1/secret/respond", { method: "POST", token: b.token, body: { invitationId: inv.id, accept: false } });
  assert.equal(d.body.accepted, false);
  const l = await api("/v1/conversations", { token: a.token });
  assert.equal(l.body.conversations.find(x => x.id === conv).secret, false);
});
await test("secret invite → accept makes it secret for both", async () => {
  const r = await api("/v1/secret/invite", { method: "POST", token: a.token, body: { conversationId: conv } });
  assert.equal((await api("/v1/secret/invite", { method: "POST", token: a.token, body: { conversationId: conv } })).body.error, "invite_pending");
  await api("/v1/secret/respond", { method: "POST", token: b.token, body: { invitationId: r.body.invitation.id, accept: true } });
  for (const u of [a, b]) assert.equal((await api("/v1/conversations", { token: u.token })).body.conversations.find(x => x.id === conv).secret, true);
});
await test("resolve by phone only matches own secret partners", async () => {
  const ok = await api("/v1/secret/resolve", { method: "POST", token: a.token, body: { phone: B } });
  assert.equal(ok.body.found, true); assert.equal(ok.body.conversationId, conv);
  const no = await api("/v1/secret/resolve", { method: "POST", token: c.token, body: { phone: B } });
  assert.equal(no.body.found, false);
});
await test("block hides user from lookup and blocks new conversations", async () => {
  await api("/v1/blocks", { method: "POST", token: c.token, body: { userId: a.user.id } });
  assert.equal((await api("/v1/lookup", { method: "POST", token: a.token, body: { phone: C } })).body.found, false);
  assert.equal((await api("/v1/conversations", { method: "POST", token: a.token, body: { userId: c.user.id } })).status, 404);
  await api("/v1/blocks/" + a.user.id, { method: "DELETE", token: c.token });
});
await test("report accepted", async () => {
  assert.equal((await api("/v1/reports", { method: "POST", token: a.token, body: { userId: c.user.id, reason: "test report" } })).status, 200);
});
await test("key rotation notifies partners", async () => {
  const k = key();
  const r = await api("/v1/me/keys", { method: "PUT", token: b.token, body: { kemPub: k } });
  assert.equal(r.body.user.kemPub, k);
  const ev = await api("/v1/sync?after=0&events=0", { token: a.token });
  assert.ok(ev.body.events.some(e => e.type === "key_changed" && e.payload.userId === b.user.id && e.payload.kemPub === k));
});
await test("new login signs out the old session", async () => {
  const again = await login(C, "Tester C");
  assert.equal((await api("/v1/me", { token: c.token })).status, 401);
  assert.equal((await api("/v1/me", { token: again.token })).status, 200);
});
await test("lookup is rate limited", async () => {
  let limited = false;
  for (let i = 0; i < 25 && !limited; i++) limited = (await api("/v1/lookup", { method: "POST", token: b.token, body: { phone: "+9470" + String(1000000 + i) } })).status === 429;
  assert.ok(limited, "expected 429 within 25 lookups");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
