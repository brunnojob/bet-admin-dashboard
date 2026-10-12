import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import api from "../netlify/functions/api.mjs";

async function withBackend(run, responder) {
  const fetch = globalThis.fetch;
  const keys = ["SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_SECRET_KEY", "MERCADOPAGO_ENVIRONMENT", "MERCADOPAGO_ACCESS_TOKEN", "MERCADOPAGO_WEBHOOK_SECRET", "APP_URL"];
  const previous = Object.fromEntries(keys.map(k => [k, process.env[k]]));
  Object.assign(process.env, { SUPABASE_URL: "https://unit.supabase.co", SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test-only", SUPABASE_SECRET_KEY: "sb_secret_test-only", MERCADOPAGO_ENVIRONMENT: "test", MERCADOPAGO_ACCESS_TOKEN: "test-only", MERCADOPAGO_WEBHOOK_SECRET: "test-webhook", APP_URL: "https://example.com" });
  const calls = [];
  globalThis.fetch = async (input, options = {}) => {
    const url = new URL(input);
    const call = { url, method: options.method || "GET", data: options.body ? JSON.parse(options.body) : null, headers: options.headers };
    calls.push(call);
    let value = await responder?.(call);
    if (value === undefined) {
      const table = url.pathname.split("/").pop();
      value = table === "admin_sessions" ? [{ id: 1, user_id: 1, csrf: "csrf" }] : table === "admin_users" ? [{ id: 1, username: "operator", role: "supreme", active: true }] : [];
    }
    return Response.json(value);
  };
  try { await run(calls); } finally {
    globalThis.fetch = fetch;
    for (const k of keys) if (previous[k] === undefined) delete process.env[k]; else process.env[k] = previous[k];
  }
}
const request = (path, method = "GET", body, headers = {}) => api(new Request(`https://example.com/api/${path}`, {
  method, headers: { cookie: "session=token", "x-csrf-token": "csrf", ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
}));

test("Netlify adapter preserves unauthorized status and security headers", async () => {
  const response = await api(new Request("https://example.com/api/state"));
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
});
test("malformed cookies do not become internal errors", async () => {
  const response = await api(new Request("https://example.com/api/state", { headers: { cookie: "session=%ZZ" } }));
  assert.equal(response.status, 401);
});
test("missing Supabase credentials explain the failure instead of a generic internal error", async () => {
  const previous = [process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, process.env.SUPABASE_SERVICE_ROLE_KEY];
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  try {
    const response = await request("login", "POST", { username: "admin@novabet.com", password: "example-password" });
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /Supabase não configurado/);
  } finally {
    for (const [index, key] of ["SUPABASE_URL", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY"].entries())
      if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index];
  }
});
test("a publishable key cannot be used for privileged database access", async () => {
  await withBackend(async calls => {
    process.env.SUPABASE_SECRET_KEY = "sb_publishable_wrong-role";
    const response = await request("login", "POST", { username: "admin@novabet.com", password: "example-password" });
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /chave publicável/);
    assert.equal(calls.length, 0);
  });
});
test("invalid JSON shapes and oversized streamed payloads are rejected", async () => {
  for (const value of [null, [], "text"]) assert.equal((await request("login", "POST", value)).status, 400);
  assert.equal((await request("login", "POST", { text: "x".repeat(33000) })).status, 413);
});
test("DELETE does not require edit fields", async () => {
  await withBackend(async calls => {
    assert.equal((await request("sites/7", "DELETE", {})).status, 200);
    assert.ok(calls.some(c => c.url.pathname.endsWith("/sites") && c.method === "DELETE" && c.url.searchParams.get("id") === "eq.7"));
  }, c => c.url.pathname.endsWith("/sites") && c.method === "GET" ? [{ id: 7 }] : undefined);
});
test("unsupported methods and missing or unexpected IDs never write resources", async () => {
  await withBackend(async calls => {
    for (const [path, method, status] of [["sites", "DELETE", 400], ["sites", "PUT", 400], ["sites/1", "POST", 400], ["sites/1", "PATCH", 405]])
      assert.equal((await request(path, method, {})).status, status);
    assert.equal(calls.filter(c => c.url.pathname.endsWith("/sites") && c.method !== "GET").length, 0);
  });
});
test("missing CSRF rejects mutations", async () => {
  await withBackend(async () => assert.equal((await request("sites/7", "DELETE", {}, { "x-csrf-token": "wrong" })).status, 403));
});
test("provider payments cannot be edited or deleted", async () => {
  await withBackend(async calls => {
    assert.equal((await request("transactions/3", "DELETE", {})).status, 409);
    assert.equal((await request("transactions/3", "PUT", { kind: "deposito", amount: "20", status: "pendente" })).status, 409);
    assert.equal(calls.filter(c => c.url.pathname.endsWith("/transactions") && c.method !== "GET").length, 0);
  }, c => c.url.pathname.endsWith("/transactions") ? [{ id: 3, provider: "mercado_pago", status: "pendente", customer: "operator" }] : undefined);
});
test("withdrawals belong to the authenticated administrator and cannot be marked paid", async () => {
  await withBackend(async calls => {
    assert.equal((await request("transactions", "POST", { kind: "saque", amount: "10", customer: "other", status: "pendente" })).status, 200);
    assert.equal(calls.find(c => c.url.pathname.endsWith("/transactions") && c.method === "POST").data.customer, "operator");
    assert.equal((await request("transactions", "POST", { kind: "saque", amount: "10", status: "concluido" })).status, 409);
  });
});
test("password changes revoke existing sessions", async () => {
  await withBackend(async calls => {
    assert.equal((await request("users/2", "PUT", { username: "operator", active: true, password: "long-test-password" })).status, 200);
    assert.ok(calls.some(c => c.url.pathname.endsWith("/admin_sessions") && c.method === "DELETE"));
  }, c => c.url.pathname.endsWith("/admin_users") && c.url.searchParams.get("id") === "eq.2"
    ? [{ id: 2, username: "operator", active: true, role: "admin" }]
    : undefined);
});
test("only the supreme administrator can manage accounts, and its Auth account is protected", async () => {
  await withBackend(async calls => {
    assert.equal((await request("users", "POST", { username: "other", password: "long-test-password", active: true })).status, 403);
    assert.equal(calls.filter(c => c.url.pathname.endsWith("/admin_users") && c.method !== "GET").length, 0);
  }, c => c.url.pathname.endsWith("/admin_users") ? [{ id: 1, username: "operator", active: true, role: "admin" }] : undefined);
  await withBackend(async calls => {
    assert.equal((await request("users/1", "DELETE", {})).status, 409);
    assert.equal(calls.filter(c => c.url.pathname.endsWith("/admin_users") && c.method !== "GET").length, 0);
  });
});
test("Supabase Auth verifies the pinned supreme identity before issuing a session", async () => {
  await withBackend(async calls => {
    const response = await request("login", "POST", { username: "ADMIN@NOVABET.COM", password: "provided-to-auth-only" });
    assert.equal(response.status, 200);
    assert.ok(response.headers.get("set-cookie")?.includes("HttpOnly"));
    assert.ok(calls.some(c => c.url.pathname === "/auth/v1/token" && c.data.email === "admin@novabet.com"));
    assert.equal(calls.find(c => c.url.pathname === "/auth/v1/token").headers.apikey, "sb_publishable_test-only");
    assert.equal(calls.filter(c => c.url.pathname.endsWith("/admin_users") && c.method !== "GET").length, 0);
  }, c => c.url.pathname === "/auth/v1/token"
    ? { user: { id: "pinned-uid", email: "admin@novabet.com" } }
    : c.url.pathname.endsWith("/admin_users")
      ? [{ id: 1, username: "admin@novabet.com", active: true, role: "supreme", auth_user_id: "pinned-uid" }]
      : undefined);
  await withBackend(async () => {
    const response = await request("login", "POST", { username: "admin@novabet.com", password: "provided-to-auth-only" });
    assert.equal(response.status, 401);
  }, c => c.url.pathname === "/auth/v1/token"
    ? { user: { id: "different-uid", email: "admin@novabet.com" } }
    : c.url.pathname.endsWith("/admin_users")
      ? [{ id: 1, username: "admin@novabet.com", active: true, role: "supreme", auth_user_id: "pinned-uid" }]
      : undefined);
});
test("same Pix request persists once and reuses the provider payment", async () => {
  let row;
  const payment = { id: 200, status: "pending", live_mode: false, transaction_amount: 10, currency_id: "BRL", point_of_interaction: { transaction_data: { qr_code: "qr" } } };
  await withBackend(async calls => {
    const body = { amount: "10", payer_email: "admin@example.com", payer_document: "12345678909", idempotency_key: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" };
    assert.equal((await request("mercadopago/pix", "POST", body)).status, 200);
    assert.equal((await request("mercadopago/pix", "POST", body)).status, 200);
    assert.equal(calls.filter(c => c.url.hostname === "api.mercadopago.com" && c.method === "POST").length, 1);
    assert.equal((await request("mercadopago/pix", "POST", { ...body, amount: "11" })).status, 409);
    assert.equal(row.customer, "operator");
  }, c => {
    if (c.url.hostname === "api.mercadopago.com") {
      if (c.url.pathname === "/users/me") return { tags: ["test_user"] };
      if (c.method === "POST") payment.external_reference = c.data.external_reference;
      return payment;
    }
    if (c.url.pathname.endsWith("/transactions")) {
      if (c.method === "POST") row ||= { id: 10, ...c.data };
      if (c.method === "PATCH") Object.assign(row, c.data);
      return row ? [row] : [];
    }
  });
});
test("test mode blocks a production account before payment creation", async () => {
  await withBackend(async calls => {
    const res = await request("mercadopago/pix", "POST", { amount: "10", payer_email: "admin@example.com", payer_document: "12345678909", idempotency_key: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
    assert.equal(res.status, 409);
    assert.equal(calls.filter(c => c.url.hostname === "api.mercadopago.com" && c.method === "POST").length, 0);
  }, c => c.url.hostname === "api.mercadopago.com" ? { tags: [] } : undefined);
});
test("signed webhook reconciles an interrupted payment, but rejects mismatched amounts", async () => {
  let amount = 10;
  await withBackend(async calls => {
    const signature = createHmac("sha256", "test-webhook").update("id:200;request-id:request;ts:1704908010;").digest("hex");
    const headers = { "x-request-id": "request", "x-signature": `ts=1704908010,v1=${signature}` };
    assert.equal((await request("mercadopago/webhook?data.id=200", "POST", { type: "payment" }, headers)).status, 200);
    assert.ok(calls.some(c => c.url.pathname.endsWith("/transactions") && c.method === "PATCH" && c.data.provider_payment_id === "200"));
    amount = 11;
    assert.equal((await request("mercadopago/webhook?data.id=200", "POST", {}, headers)).status, 409);
    assert.equal((await request("mercadopago/webhook?data.id=200", "POST", {})).status, 401);
  }, c => c.url.hostname === "api.mercadopago.com" ? { id: 200, transaction_amount: amount, currency_id: "BRL", external_reference: "ref", live_mode: false, status: "approved" } : c.url.pathname.endsWith("/transactions") ? [{ id: 10, amount: 1000, external_reference: "ref", live_mode: false, provider_payment_id: null }] : undefined);
});
