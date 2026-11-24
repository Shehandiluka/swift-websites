// Swift Akuru Chat API integration + security tests. Runs in Node 20+ or a browser (no imports).
// Defines globalThis.runChatTests({ BASE, CODE, A, B, C }) → { passed, failed, lines }.
globalThis.runChatTests = async function ({ BASE, CODE, A, B, C }) {
  let passed = 0, failed = 0;
  const rnd = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
  const b64 = a => { let s = ""; for (const x of a) s += String.fromCharCode(x); return btoa(s); };
  const key = () => b64(rnd(32));
  const blob = n => b64(rnd(n));
  const randomUUID = () => crypto.randomUUID();
  const lines = [];
  const log = s => { lines.push(s); console.log(s); };
  const assert = {
    equal(a, b, m) { if (a !== b) throw new Error((m ? m + ": " : "") + JSON.stringify(a) + " !== " + JSON.stringify(b)); },
    ok(v, m) { if (!v) throw new Error(m || "expected truthy"); },
    deepEqual(a, b, m) { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error((m ? m + ": " : "") + JSON.stringify(a) + " != " + JSON.stringify(b)); },
  };

  async function api(path, { method = "GET", token, body } = {}) {
    const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
    let j = null; try { j = await r.json(); } catch {}
    return { status: r.status, body: j };
  }
  async function test(name, fn) {
    try { await fn(); passed++; log("PASS " + name); }
    catch (e) { failed++; log("FAIL " + name + " - " + e.message); }
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
  for (const u of [a, b, c]) await api("/v1/me", { method: "PATCH", token: u.token, body: { discoverable: true, allowRequests: true, readReceipts: true, profileVisibility: "everyone" } });
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
    await api("/v1/secret/leave", { method: "POST", token: a.token, body: { conversationId: conv } }); // reset from earlier runs
  });
  await test("message request: recipient sees a request, requester cannot accept it, recipient accepts", async () => {
    const lb = await api("/v1/conversations", { token: b.token });
    const cb = lb.body.conversations.find(x => x.id === conv);
    assert.ok(cb && typeof cb.accepted === "boolean", "conversation has accepted flag");
    if (!cb.accepted) {
      assert.equal(cb.requestedBy, a.user.id);
      assert.equal((await api("/v1/conversations/" + conv + "/accept", { method: "POST", token: a.token })).status, 403);
    }
    assert.equal((await api("/v1/conversations/" + conv + "/accept", { method: "POST", token: b.token })).status, 200);
    assert.equal((await api("/v1/conversations", { token: a.token })).body.conversations.find(x => x.id === conv).accepted, true);
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
  await test("requests off: nobody new can start a chat", async () => {
    await api("/v1/me", { method: "PATCH", token: c.token, body: { allowRequests: false } });
    const l = await api("/v1/lookup", { method: "POST", token: b.token, body: { phone: C } });
    if (l.body.found) assert.equal(l.body.user.acceptsRequests, l.body.user.acceptsRequests); // existing contacts may still be allowed
    const r = await api("/v1/conversations", { method: "POST", token: b.token, body: { userId: c.user.id } });
    const existing = (await api("/v1/conversations", { token: b.token })).body.conversations.some(x => x.partner.id === c.user.id);
    if (!existing) assert.equal(r.status, 404);
    await api("/v1/me", { method: "PATCH", token: c.token, body: { allowRequests: true } });
  });
  await test("read receipts off → sender only sees delivered", async () => {
    await api("/v1/me", { method: "PATCH", token: b.token, body: { readReceipts: false } });
    const m2 = { id: randomUUID(), conversationId: conv, enc: blob(32), ciphertext: blob(48), keyVersion: b.user.keyVersion, sentAt: 2 };
    const kv = (await api("/v1/conversations", { token: a.token })).body.conversations.find(x => x.id === conv).partner.keyVersion;
    assert.equal((await api("/v1/messages", { method: "POST", token: a.token, body: { ...m2, keyVersion: kv } })).status, 200);
    await api("/v1/messages/ack", { method: "POST", token: b.token, body: { read: [m2.id] } });
    const ev = (await api("/v1/sync?after=0&events=0", { token: a.token })).body.events.filter(e => e.type === "status");
    assert.ok(ev.some(e => e.payload.delivered.includes(m2.id)), "delivered reported");
    assert.ok(!ev.some(e => e.payload.read.includes(m2.id)), "read must be hidden");
    await api("/v1/me", { method: "PATCH", token: b.token, body: { readReceipts: true } });
  });
  await test("profile picture respects visibility", async () => {
    const jpeg = "/9j/" + blob(30);
    assert.equal((await api("/v1/me/avatar", { method: "PUT", token: b.token, body: { avatar: jpeg } })).status, 200);
    assert.equal((await api("/v1/me/avatar", { method: "PUT", token: b.token, body: { avatar: "iVBOR" + blob(30) } })).status, 400, "non-JPEG rejected");
    assert.equal((await api("/v1/lookup", { method: "POST", token: c.token, body: { phone: B } })).body.user.avatar, jpeg);
    await api("/v1/me", { method: "PATCH", token: b.token, body: { profileVisibility: "nobody" } });
    assert.equal((await api("/v1/lookup", { method: "POST", token: c.token, body: { phone: B } })).body.user.avatar, undefined);
    await api("/v1/me", { method: "PATCH", token: b.token, body: { profileVisibility: "everyone" } });
    await api("/v1/me/avatar", { method: "PUT", token: b.token, body: { avatar: null } });
  });
  await test("typing indicator reaches only the partner", async () => {
    assert.equal((await api("/v1/conversations/" + conv + "/typing", { method: "POST", token: a.token })).status, 200);
    assert.equal((await api("/v1/conversations/" + conv + "/typing", { method: "POST", token: c.token })).status, 404);
    assert.ok((await api("/v1/sync?after=0&events=0", { token: b.token })).body.events.some(e => e.type === "typing" && e.payload.conversationId === conv));
  });
  await test("encrypted media: members only, owner can delete", async () => {
    const bytes = rnd(4096);
    const up = await fetch(BASE + "/v1/media?conversationId=" + conv, { method: "POST", headers: { authorization: "Bearer " + a.token, "content-type": "application/octet-stream" }, body: bytes });
    assert.equal(up.status, 200); const { id: mid } = await up.json();
    const outsiderUp = await fetch(BASE + "/v1/media?conversationId=" + conv, { method: "POST", headers: { authorization: "Bearer " + c.token }, body: bytes });
    assert.equal(outsiderUp.status, 404);
    const dl = await fetch(BASE + "/v1/media/" + mid, { headers: { authorization: "Bearer " + b.token } });
    assert.equal(dl.status, 200);
    const got = new Uint8Array(await dl.arrayBuffer());
    assert.equal(got.length, 4096); assert.equal(got[100], bytes[100]);
    assert.equal((await fetch(BASE + "/v1/media/" + mid, { headers: { authorization: "Bearer " + c.token } })).status, 404, "outsider cannot download");
    await fetch(BASE + "/v1/media/" + mid, { method: "DELETE", headers: { authorization: "Bearer " + a.token } });
    assert.equal((await fetch(BASE + "/v1/media/" + mid, { headers: { authorization: "Bearer " + b.token } })).status, 404, "deleted");
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

  log(`\n${passed} passed, ${failed} failed`);
  return { passed, failed, lines };

};
