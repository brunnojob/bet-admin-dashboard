import test from "node:test";
import assert from "node:assert/strict";
import handler from "../api/index.mjs";

function response() {
  return {
    headers: {},
    statusCode: 0,
    setHeader(key, value) {
      this.headers[key] = value;
    },
    end(value) {
      this.body = JSON.parse(value);
    },
  };
}
test("unauthenticated production endpoints never access the database", async () => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    throw new Error("unexpected database access");
  };
  try {
    const res = response();
    await handler({ method: "GET", url: "/api/reports", headers: {} }, res);
    assert.equal(res.statusCode, 401);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = original;
  }
});
test("authenticated financial report reads paginated Supabase records", async () => {
  const original = globalThis.fetch;
  const priorUrl = process.env.SUPABASE_URL;
  const priorKey = process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_URL = "https://project.supabase.co";
  process.env.SUPABASE_SECRET_KEY = "test-server-key";
  globalThis.fetch = async (url) => {
    const name = new URL(url).pathname.split("/").pop();
    const data =
      name === "admin_sessions"
        ? [{ id: 1, user_id: 1, csrf: "csrf", expires_at: "2027-01-01" }]
        : name === "admin_users"
          ? [{ id: 1, username: "operator", active: true }]
          : name === "transactions"
            ? [
                {
                  id: 1,
                  kind: "deposito",
                  status: "concluido",
                  amount: 1234,
                  created_at: "2026-10-09T10:00:00Z",
                },
              ]
            : null;
    return new Response(data === null ? "" : JSON.stringify(data), {
      status: 200,
    });
  };
  try {
    const res = response();
    await handler(
      {
        method: "GET",
        url: "/api/reports?month=2026-10",
        headers: { cookie: "session=test-session" },
      },
      res,
    );
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.netMinor, 1234);
    assert.equal(res.body.truncated, false);
  } finally {
    globalThis.fetch = original;
    if (priorUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = priorUrl;
    if (priorKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = priorKey;
  }
});
