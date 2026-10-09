import test from "node:test";
import assert from "node:assert/strict";
import { summarizeTransactions } from "../lib/reports.mjs";

test("reports count only completed money in net and preserve integer cents", () => {
  const date = "2026-10-09T10:00:00Z";
  const report = summarizeTransactions([
    {
      id: 1,
      kind: "deposito",
      status: "concluido",
      amount: 10,
      created_at: date,
    },
    {
      id: 2,
      kind: "deposito",
      status: "concluido",
      amount: 20,
      created_at: date,
    },
    { id: 3, kind: "saque", status: "concluido", amount: 5, created_at: date },
    {
      id: 4,
      kind: "deposito",
      status: "pendente",
      amount: 999,
      created_at: date,
    },
    {
      id: 5,
      kind: "saque",
      status: "cancelado",
      amount: 777,
      created_at: date,
    },
  ]);
  assert.equal(report.netMinor, 25);
  assert.equal(report.days[0].pendingMinor, 999);
  assert.throws(
    () =>
      summarizeTransactions([
        {
          id: 1,
          kind: "deposito",
          status: "concluido",
          amount: 0.1,
          created_at: date,
        },
      ]),
    /invalid_transaction/,
  );
});
