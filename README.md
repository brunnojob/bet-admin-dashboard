# NOVA Administration

An administration dashboard with sessions, site and domain CRUD, financial records, Mercado Pago integration, and reports by day and state.

## Run

Requirements: Node.js 24, Vercel Functions, and Supabase.

```sh
npm test
npm start
```

## Behavior

The Supabase backend requires `SUPABASE_URL` and a server-only service key. Initial administrator setup requires `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD`. Mercado Pago uses `MERCADOPAGO_ACCESS_TOKEN` and `MERCADOPAGO_WEBHOOK_SECRET`. `/api/reports?month=2026-10` returns totals in cents and indicates when the query limit is reached. API tests use controlled responses and do not make payments.

## Result synchronization

The [operations archive](https://vercel-home-telemetry-api.vercel.app/laboratory.html?project=bet-admin-dashboard) stores execution results. Supabase migrations are in the [API repository](https://github.com/brunnojob/vercel-home-telemetry-api/tree/main/supabase/migrations).

```sh
python cloud/sync.py enqueue result.json --project bet-admin-dashboard
python cloud/sync.py sync
```

Set `BRUNNODEV_ACCESS_TOKEN` to your session token. The SQLite outbox retains reports until the server confirms persistence; identical content does not create duplicate records. Tokens are not stored in source code. To run the synchronization tests:

```sh
python -m unittest discover -s cloud
```
