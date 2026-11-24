// Usage: BASE=https://… TEST_A=+947… TEST_B=… TEST_C=… TEST_CODE=xxxxxx node test/api.test.mjs
await import("./suite.js");
const r = await globalThis.runChatTests({ BASE: process.env.BASE || "http://127.0.0.1:8787", CODE: process.env.TEST_CODE,
  A: process.env.TEST_A, B: process.env.TEST_B, C: process.env.TEST_C });
process.exit(r.failed ? 1 : 0);
