# Swift Akuru Chat API (Cloudflare Worker + D1)

Mailbox for end-to-end encrypted Swift Akuru messages. The server stores HPKE ciphertext only until the
recipient's device acknowledges delivery, then clears it. It never receives message text, PINs or private keys.
Phone numbers are stored only as HMAC-SHA256(pepper, E.164); the pepper is generated inside D1 on first use.

## Deploy
1. D1 database `swiftakuru-chat` (id in `wrangler.jsonc`). Apply `schema.sql` once (`npx wrangler d1 execute swiftakuru-chat --remote --file schema.sql`).
2. Cloudflare dashboard → Workers → Create → Import a repository → `swift-websites`, root directory `chat.swiftlk.com`.
3. Test numbers (no SMS cost): `INSERT OR REPLACE INTO config (k,v) VALUES ('test_numbers','{"+94700000001":"<6-digit code>"}')`.
4. Real SMS (optional): add secrets `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` to the worker. Without them, real numbers get `503 sms_not_configured`.

## Test
`BASE=https://swiftakuru-chat.<account>.workers.dev TEST_A=… TEST_B=… TEST_C=… TEST_CODE=… npm run test:api`

## API (all under /v1, JSON, `Authorization: Bearer <token>` except auth)
| Method | Path | Purpose |
|---|---|---|
| POST | /auth/start `{phone}` | send OTP (E.164) — rate limited per phone & IP |
| POST | /auth/verify `{phone, code, displayName, kemPub, discoverable, device}` | create/login, returns token; one active device |
| GET/PATCH/DELETE | /me | profile, discoverability, account deletion |
| PUT | /me/keys `{kemPub}` | rotate encryption key → partners get `key_changed` |
| POST | /auth/logout, /auth/revoke-others | sessions |
| POST | /lookup `{phone}` | find discoverable user (same answer for hidden/none/blocked) |
| GET/POST | /conversations, DELETE /conversations/:id | list, create, hide |
| POST | /messages `{id, conversationId, enc, ciphertext, keyVersion, sentAt}` | send (idempotent by id) |
| GET | /sync?after=&events= | undelivered messages + events |
| POST | /messages/ack `{delivered[], read[]}`, /events/ack `{upTo}` | delivery/read receipts, clears ciphertext |
| POST | /secret/invite, /secret/respond, /secret/leave, /secret/resolve; GET /secret/invitations | Secret Chat consent flow |
| GET/POST/DELETE | /blocks, POST /reports | safety |
