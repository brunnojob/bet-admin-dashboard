import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt,
  timingSafeEqual,
  createHmac,
} from "node:crypto";
import { promisify } from "node:util";
import { summarizeTransactions } from "../lib/reports.mjs";

const scryptAsync = promisify(scrypt);
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const JSON_LIMIT = 32 * 1024;

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}
const fail = (message, status = 400) => {
  throw new HttpError(message, status);
};
const supabaseUrl = () => (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const supabaseKey = () =>
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  "";

function supabaseHeaders(extra = {}) {
  const key = supabaseKey();
  if (!supabaseUrl() || !key)
    fail("Backend Supabase não configurado na Vercel.", 503);
  const headers = { apikey: key, "Content-Type": "application/json", ...extra };
  if (!key.startsWith("sb_")) headers.Authorization = `Bearer ${key}`;
  return headers;
}

async function db(table, { method = "GET", query = {}, body, prefer } = {}) {
  const url = new URL(`${supabaseUrl()}/rest/v1/${table}`);
  for (const [k, v] of Object.entries(query))
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  const headers = supabaseHeaders(prefer ? { Prefer: prefer } : {});
  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
    redirect: "error",
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!response.ok) {
    console.error(
      "Supabase error",
      response.status,
      data?.code || "",
      data?.message || "",
    );
    const msg =
      response.status === 409 || data?.code === "23505"
        ? "Registro duplicado."
        : "Falha no banco de dados.";
    fail(msg, response.status === 404 ? 404 : 500);
  }
  return data;
}

function send(res, status, payload, cookie) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  if (cookie) res.setHeader("Set-Cookie", cookie);
  res.end(JSON.stringify(payload));
}

async function body(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > JSON_LIMIT) fail("Requisição muito grande.", 413);
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    fail("JSON inválido.");
  }
}

function cookie(req, name) {
  const raw = req.headers.cookie || "";
  const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const newToken = () => randomBytes(32).toString("base64url");

async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$16384$8$1$${salt.toString("base64url")}$${Buffer.from(derived).toString("base64url")}`;
}
async function verifyPassword(password, encoded) {
  const [kind, n, r, p, salt64, hash64] = String(encoded || "").split("$");
  if (kind !== "scrypt" || !salt64 || !hash64) return false;
  const expected = Buffer.from(hash64, "base64url");
  const derived = Buffer.from(
    await scryptAsync(
      password,
      Buffer.from(salt64, "base64url"),
      expected.length,
      {
        N: Number(n),
        r: Number(r),
        p: Number(p),
        maxmem: 64 * 1024 * 1024,
      },
    ),
  );
  return (
    expected.length === derived.length && timingSafeEqual(expected, derived)
  );
}

async function bootstrapAdmin() {
  const existing = await db("admin_users", {
    query: { select: "id", limit: 1 },
  });
  if (existing?.length) return;
  const username = process.env.INITIAL_ADMIN_USERNAME;
  const password = process.env.INITIAL_ADMIN_PASSWORD;
  if (!username || !password || password.length < 12)
    fail("Administrador inicial não configurado na Vercel.", 503);
  await db("admin_users", {
    method: "POST",
    body: {
      username,
      password_hash: await hashPassword(password),
      active: true,
    },
    prefer: "return=minimal",
  });
  await audit(username, "BOOTSTRAP ADMIN");
}

async function audit(actor, action) {
  try {
    await db("audit", {
      method: "POST",
      body: { actor, action },
      prefer: "return=minimal",
    });
  } catch (e) {
    console.error("Audit failure", e.message);
  }
}

async function getSession(req) {
  const token = cookie(req, "session");
  if (!token) return null;
  const sessions = await db("admin_sessions", {
    query: {
      select: "id,user_id,csrf,expires_at",
      token_hash: `eq.${sha256(token)}`,
      expires_at: `gt.${new Date().toISOString()}`,
      limit: 1,
    },
  });
  const s = sessions?.[0];
  if (!s) return null;
  const users = await db("admin_users", {
    query: { select: "id,username,active", id: `eq.${s.user_id}`, limit: 1 },
  });
  const user = users?.[0];
  if (!user?.active) return null;
  await db("admin_sessions", {
    method: "PATCH",
    query: { id: `eq.${s.id}` },
    body: { expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString() },
    prefer: "return=minimal",
  });
  return { ...s, user, token };
}

function requireCsrf(req, session) {
  const provided = String(req.headers["x-csrf-token"] || "");
  const expected = String(session.csrf || "");
  if (
    !provided ||
    Buffer.byteLength(provided) !== Buffer.byteLength(expected) ||
    !timingSafeEqual(Buffer.from(provided), Buffer.from(expected))
  )
    fail("Sessão inválida. Entre novamente.", 403);
}

function normalizeDomain(value) {
  const name = String(value || "")
    .trim()
    .toLowerCase();
  if (
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(
      name,
    )
  )
    fail("Domínio inválido.");
  return name;
}
function cents(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 100000000) fail("Valor inválido.");
  const c = Math.round(n * 100);
  if (Math.abs(c / 100 - n) > 0.00001)
    fail("Use no máximo duas casas decimais.");
  return c;
}
function statusFromMercadoPago(status) {
  if (status === "approved") return "concluido";
  if (["cancelled", "rejected", "refunded", "charged_back"].includes(status))
    return "cancelado";
  return "pendente";
}

async function login(req, res, data) {
  await bootstrapAdmin();
  const username = String(data.username || "").trim();
  const password = String(data.password || "");
  if (!username || !password || password.length > 256)
    fail("Login ou senha inválidos.", 401);

  const minuteAgo = new Date(Date.now() - 60000).toISOString();
  const attempts = await db("login_attempts", {
    query: {
      select: "id",
      username: `eq.${username}`,
      success: "eq.false",
      attempted_at: `gt.${minuteAgo}`,
    },
  });
  if ((attempts || []).length >= 10)
    fail("Aguarde um minuto antes de tentar novamente.", 429);

  const users = await db("admin_users", {
    query: {
      select: "id,username,password_hash,active",
      username: `eq.${username}`,
      limit: 1,
    },
  });
  const user = users?.[0];
  const ok =
    user?.active && (await verifyPassword(password, user.password_hash));
  await db("login_attempts", {
    method: "POST",
    body: { username, success: Boolean(ok) },
    prefer: "return=minimal",
  });
  if (!ok) fail("Login ou senha inválidos.", 401);

  const token = newToken(),
    csrf = newToken();
  await db("admin_sessions", {
    method: "POST",
    body: {
      token_hash: sha256(token),
      user_id: user.id,
      csrf,
      expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    },
    prefer: "return=minimal",
  });
  await audit(user.username, "LOGIN");
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  send(
    res,
    200,
    { username: user.username, csrf },
    `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`,
  );
}

async function state(res, session) {
  const [sites, domains, transactions, users, history] = await Promise.all([
    db("sites", {
      query: { select: "id,name,url,status,created_at", order: "id.desc" },
    }),
    db("domains", {
      query: { select: "id,name,site_id,status,created_at", order: "id.desc" },
    }),
    db("transactions", {
      query: {
        select:
          "id,kind,customer,amount,status,site_id,provider,provider_payment_id,external_reference,payment_method,payer_email,payer_document,created_at,updated_at",
        order: "id.desc",
      },
    }),
    db("admin_users", {
      query: {
        select: "id,username,active,created_at,updated_at",
        order: "id.desc",
      },
    }),
    db("audit", {
      query: {
        select: "id,actor,action,created_at",
        order: "id.desc",
        limit: 100,
      },
    }),
  ]);
  send(res, 200, {
    username: session.user.username,
    csrf: session.csrf,
    gateway: {
      connected: Boolean(process.env.MERCADOPAGO_ACCESS_TOKEN),
      provider: "mercado_pago",
      mode: "production",
    },
    sites,
    domains,
    transactions,
    users,
    audit: history,
  });
}

async function mutate(resource, method, id, data, session) {
  const actor = session.user.username;
  if (!["sites", "domains", "transactions", "users"].includes(resource))
    fail("Não encontrado.", 404);
  if (id && (!Number.isSafeInteger(id) || id < 1)) fail("ID inválido.");

  let payload = {};
  if (resource === "sites") {
    const name = String(data.name || "").trim();
    if (!name || name.length > 240) fail("Nome inválido.");
    let url;
    try {
      url = new URL(String(data.url || ""));
    } catch {
      fail("URL inválida.");
    }
    if (!["http:", "https:"].includes(url.protocol)) fail("URL inválida.");
    const status = String(data.status || "ativo");
    if (!["ativo", "inativo"].includes(status)) fail("Status inválido.");
    payload = { name, url: url.toString(), status };
  }
  if (resource === "domains") {
    const status = String(data.status || "ativo");
    if (!["ativo", "inativo"].includes(status)) fail("Status inválido.");
    payload = {
      name: normalizeDomain(data.name),
      site_id: data.site_id ? Number(data.site_id) : null,
      status,
    };
  }
  if (resource === "transactions") {
    const kind = String(data.kind || "");
    const status = String(data.status || "pendente");
    if (
      !["deposito", "saque"].includes(kind) ||
      !["pendente", "concluido", "cancelado"].includes(status)
    )
      fail("Dados inválidos.");
    if (method === "POST" && kind === "deposito")
      fail(
        "Depósitos reais devem ser criados pela integração Pix do Mercado Pago.",
        409,
      );
    if (kind === "saque" && status === "concluido")
      fail(
        "Saque não pode ser marcado como concluído sem uma operação real de payout.",
        409,
      );
    const customer = String(data.customer || "").trim();
    if (!customer || customer.length > 240)
      fail("Cliente/referência inválido.");
    payload = {
      kind,
      customer,
      amount: cents(data.amount),
      status,
      site_id: data.site_id ? Number(data.site_id) : null,
    };
  }
  if (resource === "users") {
    const username = String(data.username || "").trim();
    if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username)) fail("Login inválido.");
    const active =
      data.active === true || data.active === "true" || data.active === "1";
    payload = { username, active, updated_at: new Date().toISOString() };
    if (data.password) {
      if (String(data.password).length < 12)
        fail("A senha deve ter ao menos 12 caracteres.");
      payload.password_hash = await hashPassword(String(data.password));
    } else if (method === "POST")
      fail("Informe uma senha com ao menos 12 caracteres.");
  }

  const query = id ? { id: `eq.${id}` } : {};
  if (method === "POST") {
    const rows = await db(resource === "users" ? "admin_users" : resource, {
      method: "POST",
      body: payload,
      prefer: "return=representation",
    });
    const newId = rows?.[0]?.id;
    await audit(actor, `POST ${resource} #${newId}`);
    return { ok: true, id: newId };
  }

  const table = resource === "users" ? "admin_users" : resource;
  const before = await db(table, {
    query: { select: "*", id: `eq.${id}`, limit: 1 },
  });
  const existing = before?.[0];
  if (!existing) fail("Registro não encontrado.", 404);

  if (
    resource === "transactions" &&
    existing.provider === "mercado_pago" &&
    payload.status !== existing.status
  )
    fail(
      "O status de um pagamento Mercado Pago é atualizado apenas pelo webhook.",
      409,
    );

  if (resource === "users") {
    const activeUsers = await db("admin_users", {
      query: { select: "id", active: "eq.true" },
    });
    if (method === "DELETE" && id === session.user.id)
      fail("Não é possível excluir seu próprio login.", 409);
    if (
      existing.active &&
      (method === "DELETE" || payload.active === false) &&
      (activeUsers || []).length <= 1
    )
      fail("Mantenha ao menos um administrador ativo.", 409);
  }

  if (method === "PUT") {
    await db(table, {
      method: "PATCH",
      query,
      body: payload,
      prefer: "return=minimal",
    });
    if (resource === "users" && payload.active === false)
      await db("admin_sessions", {
        method: "DELETE",
        query: { user_id: `eq.${id}` },
        prefer: "return=minimal",
      });
  } else if (method === "DELETE") {
    await db(table, { method: "DELETE", query, prefer: "return=minimal" });
  } else fail("Método não permitido.", 405);

  await audit(actor, `${method} ${resource} #${id}`);
  return { ok: true, id };
}

async function createPix(data, session) {
  const accessToken = process.env.MERCADOPAGO_ACCESS_TOKEN;
  if (!accessToken)
    fail("Credencial de produção do Mercado Pago ainda não configurada.", 503);
  const amountCents = cents(data.amount);
  const email = String(data.payer_email || "")
    .trim()
    .toLowerCase();
  const cpf = String(data.payer_document || "").replace(/\D/g, "");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    fail("E-mail do pagador inválido.");
  if (!/^\d{11}$/.test(cpf)) fail("CPF do pagador inválido.");
  const customer = String(data.customer || email)
    .trim()
    .slice(0, 240);
  const externalReference = `nova-${randomUUID().replace(/-/g, "").slice(0, 24)}`;
  const idempotencyKey = randomUUID();

  const response = await fetch("https://api.mercadopago.com/v1/payments", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "X-Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      transaction_amount: amountCents / 100,
      description: String(data.description || "Depósito NOVA BET").slice(
        0,
        150,
      ),
      payment_method_id: "pix",
      external_reference: externalReference,
      payer: { email, identification: { type: "CPF", number: cpf } },
    }),
  });
  const payment = await response.json().catch(() => ({}));
  if (!response.ok || !payment?.id) {
    console.error(
      "Mercado Pago create error",
      response.status,
      payment?.message || "",
    );
    fail("Mercado Pago recusou a criação do pagamento.", 502);
  }

  const rows = await db("transactions", {
    method: "POST",
    body: {
      kind: "deposito",
      customer,
      amount: amountCents,
      status: statusFromMercadoPago(payment.status),
      site_id: data.site_id ? Number(data.site_id) : null,
      provider: "mercado_pago",
      provider_payment_id: String(payment.id),
      external_reference: externalReference,
      payment_method: "pix",
      payer_email: email,
      payer_document: cpf,
      updated_at: new Date().toISOString(),
    },
    prefer: "return=representation",
  });
  await audit(session.user.username, `CREATE PIX Mercado Pago #${payment.id}`);
  const tx = payment.point_of_interaction?.transaction_data || {};
  return {
    ok: true,
    transaction_id: rows?.[0]?.id,
    payment_id: String(payment.id),
    status: payment.status,
    external_reference: externalReference,
    qr_code: tx.qr_code || null,
    qr_code_base64: tx.qr_code_base64 || null,
    ticket_url: tx.ticket_url || null,
  };
}

function verifyWebhook(req, dataId) {
  const secret = process.env.MERCADOPAGO_WEBHOOK_SECRET;
  if (!secret) fail("Webhook do Mercado Pago não configurado.", 503);
  const signature = String(req.headers["x-signature"] || "");
  const requestId = String(req.headers["x-request-id"] || "");
  const parts = Object.fromEntries(
    signature.split(",").map((x) => x.trim().split("=")),
  );
  if (!parts.ts || !parts.v1 || !requestId || !dataId)
    fail("Assinatura de webhook ausente.", 401);
  const manifest = `id:${dataId};request-id:${requestId};ts:${parts.ts};`;
  const calculated = createHmac("sha256", secret)
    .update(manifest)
    .digest("hex");
  const a = Buffer.from(calculated, "hex"),
    b = Buffer.from(parts.v1, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b))
    fail("Assinatura de webhook inválida.", 401);
}

async function webhook(req, data, url) {
  const dataId = String(
    url.searchParams.get("data.id") ||
      url.searchParams.get("data_id") ||
      data?.data?.id ||
      "",
  );
  verifyWebhook(req, dataId);
  const accessToken = process.env.MERCADOPAGO_ACCESS_TOKEN;
  if (!accessToken) fail("Credencial do Mercado Pago não configurada.", 503);
  const response = await fetch(
    `https://api.mercadopago.com/v1/payments/${encodeURIComponent(dataId)}`,
    {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  );
  const payment = await response.json().catch(() => ({}));
  if (!response.ok || !payment?.id)
    fail("Falha ao consultar pagamento no Mercado Pago.", 502);
  await db("transactions", {
    method: "PATCH",
    query: {
      provider: "eq.mercado_pago",
      provider_payment_id: `eq.${payment.id}`,
    },
    body: {
      status: statusFromMercadoPago(payment.status),
      updated_at: new Date().toISOString(),
    },
    prefer: "return=minimal",
  });
  await audit(
    "mercado_pago",
    `WEBHOOK payment #${payment.id} status=${payment.status}`,
  );
  return { ok: true };
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const route = (
      url.searchParams.get("path") || url.pathname.replace(/^\/api\/?/, "")
    ).replace(/^\/+|\/+$/g, "");
    const data = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method)
      ? await body(req)
      : {};

    if (route === "login" && req.method === "POST")
      return await login(req, res, data);

    if (route === "mercadopago/webhook" && req.method === "POST") {
      const result = await webhook(req, data, url);
      return send(res, 200, result);
    }

    const session = await getSession(req);
    if (!session) fail("Entre para acessar o painel.", 401);

    if (route === "logout" && req.method === "POST") {
      requireCsrf(req, session);
      await db("admin_sessions", {
        method: "DELETE",
        query: { token_hash: `eq.${sha256(session.token)}` },
        prefer: "return=minimal",
      });
      await audit(session.user.username, "LOGOUT");
      const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
      return send(
        res,
        200,
        { ok: true },
        `session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`,
      );
    }

    if (route === "state" && req.method === "GET")
      return await state(res, session);
    if (route === "reports" && req.method === "GET") {
      const month = url.searchParams.get("month");
      if (month !== null && !/^\d{4}-(0[1-9]|1[0-2])$/.test(month))
        fail("Mês inválido.");
      const rows = [];
      let truncated = false;
      for (let page = 0; page < 10; page++) {
        const query = {
          select: "id,kind,amount,status,created_at",
          order: "id.asc",
          limit: 1000,
          offset: page * 1000,
        };
        if (month) {
          const [year, number] = month.split("-").map(Number);
          const from = new Date(Date.UTC(year, number - 1, 1)).toISOString();
          const to = new Date(Date.UTC(year, number, 1)).toISOString();
          query.and = `(created_at.gte.${from},created_at.lt.${to})`;
        }
        const batch = await db("transactions", { query });
        rows.push(...batch);
        if (batch.length < 1000) break;
        if (page === 9) truncated = true;
      }
      return send(res, 200, {
        ...summarizeTransactions(rows),
        truncated,
        month,
      });
    }

    if (route === "mercadopago/pix" && req.method === "POST") {
      requireCsrf(req, session);
      return send(res, 200, await createPix(data, session));
    }

    const match = route.match(
      /^(sites|domains|transactions|users)(?:\/(\d+))?$/,
    );
    if (!match) fail("Não encontrado.", 404);
    if (req.method !== "GET") requireCsrf(req, session);
    const id = match[2] ? Number(match[2]) : null;
    if (req.method === "GET") fail("Use /api/state para leitura.", 405);
    return send(
      res,
      200,
      await mutate(match[1], req.method, id, data, session),
    );
  } catch (error) {
    const status = error.status || 500;
    if (status === 500) console.error(error);
    send(res, status, {
      error: status === 500 ? "Erro interno." : error.message,
    });
  }
}
