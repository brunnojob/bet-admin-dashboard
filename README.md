# NOVA Administration

Internal administration for authorized administrators: sites, domains, financial records, administrator accounts, and an audit trail. New financial requests are attributed to the signed-in administrator. There are no player accounts, wagers, or betting services.

## Run and verify

Requires Node.js 24. The application has no runtime npm dependencies.

```sh
npm test
python -m unittest discover -s cloud
npm run build
node --env-file=.env server.mjs
```

Copy `.env.example` to `.env` and configure private values locally. Never commit credentials. The build publishes only `dist/index.html`; backend code and migrations are not public assets.

## Netlify

The repository is linked to the Netlify project `novabetadmin`, with `main` as the production branch. `netlify.toml` sets the build command, publish directory, and function bundle. The modern Netlify function serves `/api/*` and preserves the shared Node handler's cookies, body limits, HTTP status, and headers. `.netlify/` is excluded from Git.

Set runtime variables in Netlify with the Functions scope and redeploy after changing them:

| Variable | Purpose |
| --- | --- |
| `SUPABASE_URL` | Selected project URL |
| `SUPABASE_SECRET_KEY` | Server-only Supabase secret key; legacy `SUPABASE_SERVICE_ROLE_KEY` is also supported |
| `APP_URL` | Canonical HTTPS site URL used for payment notifications |
| `MERCADOPAGO_ENVIRONMENT` | `test` initially; switch deliberately to `production` with matching credentials |
| `MERCADOPAGO_ACCESS_TOKEN` | Server-only Mercado Pago credential |
| `MERCADOPAGO_WEBHOOK_SECRET` | Signature secret from the application's webhook settings |
| `NODE_ENV` | `production` for secure cookies |

The supreme administrator signs in with the confirmed `admin@novabet.com` Supabase Auth account. Its identity is pinned to the Auth user ID in the second database migration; its password is checked by Supabase Auth and never stored in this repository or `admin_users`. Other administrators created in the panel retain their local login and password hashes. Only the supreme administrator can create or change those accounts, and the supreme account is managed in Supabase Auth. Sessions expire after eight hours. This is a trusted internal team application, not a multi-tenant service.

## Supabase

The selected project is `nhqrzddvaexpozqxeeab`. The versioned schema is in `supabase/migrations/`. The second migration attaches the confirmed Auth user to the supreme account. All seven tables have RLS enabled, with access revoked from `anon` and `authenticated`. Only the server's service role accesses them. Audit rows are append-only for that role. The browser never receives a Supabase secret key or password hash. The Supabase advisor reports [RLS enabled without policies](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy) at INFO level: this is intentional because these tables are server-only, with browser-role grants revoked.

Do not apply the initial migration to an existing populated schema. Back up and reconcile such a schema first. This setup does not migrate data from any previous Supabase project.

## Financial records

Pix uses the Mercado Pago API, a verified account environment, signed webhook notifications, and a stable request key. Retrying the same request uses the same external reference and provider idempotency key. A pending local record is persisted before the provider call so a webhook can reconcile a payment after a lost response. Reusing a request key with different financial data is rejected.

Register `APP_URL/api/mercadopago/webhook` for payment notifications. The handler fetches each payment from the provider and validates its amount, currency, environment, and reference before updating the record. Processed provider records cannot be manually edited or deleted. Public keys are not required for this server-side Pix flow.

Withdrawal requests are persisted as pending or cancelled records. This repository does not execute bank payouts and cannot mark a withdrawal completed. Payment tests in CI use controlled responses and never move money. A deployed provider test with the configured account is still required before enabling production credentials.

`/api/reports?month=2026-10` returns integer-cent totals and a truncation flag. Dashboard lists are bounded and display a warning if incomplete.

## Optional report synchronization

`cloud/sync.py` is an independent outbox utility. It is not part of the dashboard deployment. Use it only with the explicitly configured destination and `BRUNNODEV_ACCESS_TOKEN`.

```sh
python -m unittest discover -s cloud
```
