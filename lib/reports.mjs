export function summarizeTransactions(rows) {
  const days = new Map();
  const states = new Map();
  const seen = new Set();
  let completedDeposits = 0,
    completedWithdrawals = 0;
  for (const row of rows) {
    if (
      !Number.isSafeInteger(row.amount) ||
      row.amount < 1 ||
      !["deposito", "saque"].includes(row.kind) ||
      !["pendente", "concluido", "cancelado"].includes(row.status)
    )
      throw new Error("invalid_transaction_record");
    if (seen.has(row.id)) throw new Error("duplicate_transaction_record");
    seen.add(row.id);
    const day = new Date(row.created_at).toISOString().slice(0, 10);
    const key = `${row.kind}:${row.status}`;
    const total = states.get(key) ?? {
      kind: row.kind,
      status: row.status,
      count: 0,
      amountMinor: 0,
    };
    total.count++;
    total.amountMinor += row.amount;
    if (!Number.isSafeInteger(total.amountMinor))
      throw new Error("amount_overflow");
    states.set(key, total);
    const bucket = days.get(day) ?? {
      day,
      depositsMinor: 0,
      withdrawalsMinor: 0,
      pendingMinor: 0,
    };
    if (row.status === "pendente") bucket.pendingMinor += row.amount;
    if (row.status === "concluido" && row.kind === "deposito") {
      completedDeposits += row.amount;
      bucket.depositsMinor += row.amount;
    }
    if (row.status === "concluido" && row.kind === "saque") {
      completedWithdrawals += row.amount;
      bucket.withdrawalsMinor += row.amount;
    }
    days.set(day, bucket);
  }
  if (![completedDeposits, completedWithdrawals].every(Number.isSafeInteger))
    throw new Error("amount_overflow");
  return {
    count: rows.length,
    completedDepositsMinor: completedDeposits,
    completedWithdrawalsMinor: completedWithdrawals,
    netMinor: completedDeposits - completedWithdrawals,
    states: [...states.values()].sort((a, b) =>
      `${a.kind}:${a.status}`.localeCompare(`${b.kind}:${b.status}`),
    ),
    days: [...days.values()].sort((a, b) => a.day.localeCompare(b.day)),
  };
}
