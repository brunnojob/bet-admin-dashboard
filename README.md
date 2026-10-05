# NOVA BET

Local administration console for deposits, simulated withdrawals, sites, domains and administrator accounts. Built by [brunnodev](https://brunnodev.store).

## Run

Requires Python 3.10 or newer. No external dependencies.

```sh
python server.py
```

Open http://localhost:8000. Initial development login: `admingb` / `admin`.

The server binds to `127.0.0.1`. SQLite persists records in `admin.sqlite3`; do not commit this database. Set `BET_ADMIN_DB` to use another database location.

## Features

- Overview with completed deposit/withdrawal totals, pending records and infrastructure counts.
- Create, view, edit, search and delete deposits and simulated withdrawals.
- CRUD for sites, domains and administrator logins. Domain/site links enforce referential integrity.
- Password hashing with scrypt, server-side authentication, expiring HttpOnly sessions, CSRF tokens and login throttling.
- Audit trail for changes; protection against deleting your current login or removing the last active administrator.
- Responsive Portuguese interface, BRL formatting and integer-cent accounting.

Withdrawals only create local records; no payment provider, Pix or actual betting integration exists. Site/domain creation is inventory registration, not provisioning, hosting or DNS configuration. All administrators share management privileges. Sessions and login throttling reset when the server restarts. The default credentials are for localhost development; change them before adapting this application for deployment.

## Verify

```sh
python -m unittest discover -s tests -v
```
