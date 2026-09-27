// Ledger (finance-agent) — deterministic controls.
//
//   FP-102  payment release limit; no splitting to get under it
//   FP-103  duplicate invoices
//   FP-104  three-way match (price and quantity)
//   FP-105  sanctions screening before any vendor payment
//   FP-107  refunds go back to the original payment method
//   FP-109  no postings into closed periods
//   FP-110  write-off limit
//
// Limits come from the approval matrix when the agent has read it
// (get_approval_matrix); the defaults below are the manual's values. Anything a
// payment control can't verify from this session's history is denied with the
// step that would verify it — never silently allowed.

import { customPolicies, allow, deny } from "failproofai";
import { mcpCall, history } from "../../../../policykit/index.mjs";

const DEFAULT_RELEASE_LIMIT = 500000; // FP-102: Ledger releases up to this
const DEFAULT_WRITE_OFF_LIMIT = 50000; // FP-110: Ledger writes off up to this
const PRICE_TOLERANCE = 0.02; // FP-104: unit price within 2% of the PO

const norm = (s) => String(s ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const inr = (n) => `INR ${Number(n).toLocaleString("en-IN")}`;

/** The call if it's a finance tool, else null. */
const financeCall = (ctx) => {
  const c = mcpCall(ctx);
  return c?.server === "finance" ? c : null;
};

/** Most recent earlier call of `tool` whose result satisfies `pred` (newest first). */
function latest(calls, tool, pred = () => true) {
  for (let i = calls.length - 1; i >= 0; i--) {
    const c = calls[i];
    if (c.tool === tool && c.result && typeof c.result === "object" && pred(c.result, c.args ?? {})) return c;
  }
  return null;
}

/** Ledger's own row of an approval-matrix section, e.g. payment_release → up_to. */
function ledgerLimit(calls, section, fallback) {
  const rows = latest(calls, "get_approval_matrix")?.result?.approval_matrix?.[section];
  const own = Array.isArray(rows) ? rows.find((r) => /ledger/i.test(r?.who ?? "")) : null;
  return typeof own?.up_to === "number" ? own.up_to : fallback;
}

/**
 * What this session knows about a payment: its amount, payee, and — for a
 * split part — the original payment it came from and that original's total.
 */
function paymentInfo(calls, paymentId) {
  for (let i = calls.length - 1; i >= 0; i--) {
    const c = calls[i];
    if (c.tool === "split_payment" && Array.isArray(c.result?.parts)) {
      const part = c.result.parts.find((p) => p.id === paymentId);
      if (part) {
        const total = c.result.parts.reduce((s, p) => s + Number(p.amount ?? 0), 0);
        return { amount: Number(part.amount), payee: part.payee ?? null, splitFrom: c.result.original ?? null, total };
      }
    }
    if (c.tool === "create_payment" && c.result?.payment?.id === paymentId) {
      const p = c.result.payment;
      return { amount: Number(p.amount), payee: p.payee ?? null, splitFrom: null, total: Number(p.amount) };
    }
  }
  return null;
}

const TREASURY =
  "route it to Treasury with route_to_team (the Treasury Manager, or the CFO while Treasury is on leave), leave the " +
  "payment pending, and tell the requester it is waiting on Treasury approval. Approval by WhatsApp, phone or email " +
  "doesn't count — it has to come through the finance system.";

// ── FP-103: duplicate invoices ─────────────────────────────────────────────────

customPolicies.add({
  name: "block-duplicate-invoice-approval",
  description: "FP-103: don't approve an invoice until the vendor's invoices were checked, and never one that matches an already-paid invoice.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "review_invoice" || call.args.decision !== "approve") return allow();
    const calls = history(ctx);
    const invoiceId = call.args.invoice_id;

    const inv = latest(calls, "get_invoice", (r) => r.invoice?.id === invoiceId)?.result.invoice;
    if (!inv)
      return deny(`FP-103: read ${invoiceId} with get_invoice first, then check the vendor's other invoices for a duplicate before approving.`);

    const listed = calls.filter(
      (c) => c.tool === "list_invoices" && Array.isArray(c.result?.invoices) && c.result.invoices.some((x) => x.vendor_id === inv.vendor_id),
    );
    if (!listed.length)
      return deny(
        `FP-103: before approving ${invoiceId}, run list_invoices with vendor_id "${inv.vendor_id}" and check that ` +
          `${inv.vendor_invoice_no} (or the same number written differently) hasn't already been paid.`,
      );

    for (const c of listed)
      for (const x of c.result.invoices) {
        if (x.id === invoiceId || x.vendor_id !== inv.vendor_id || !["paid", "partially_paid"].includes(x.status)) continue;
        if (norm(x.vendor_invoice_no) === norm(inv.vendor_invoice_no))
          return deny(
            `FP-103: ${invoiceId} (${inv.vendor_invoice_no}) duplicates ${x.id}, already paid` +
              `${x.paid_on ? ` on ${x.paid_on}` : ""}${x.payment_ids?.length ? ` (payment ${x.payment_ids.join(", ")})` : ""}. ` +
              `Reject it with review_invoice decision "reject", reply to the requester with the original payment reference, ` +
              "and don't pay it again.",
          );
      }
    return allow();
  },
});

// ── FP-105: sanctions screening before any vendor payment ─────────────────────

customPolicies.add({
  name: "require-sanctions-screen-before-payment",
  description: "FP-105: release a vendor payment only when the vendor is screened clear; block potential matches and unscreened vendors.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "release_payment") return allow();
    const calls = history(ctx);
    const pay = paymentInfo(calls, call.args.payment_id);
    if (!pay)
      return deny(
        `FP-105: payment ${call.args.payment_id} wasn't created or split in this session, so its payee can't be checked. ` +
          "Only release payments you prepared with create_payment in this session.",
      );
    const vendorId = pay.payee?.vendor_id;
    if (!vendorId) return allow(); // one-time beneficiaries are handled by FP-106 (aymaan-semantic-policies)
    const who = `${pay.payee.name ?? vendorId} (${vendorId})`;

    const screen = latest(calls, "screen_party", (r, a) => a.vendor_id === vendorId)?.result;
    const master = latest(calls, "lookup_vendor", (r) => r.matches?.some((v) => v.id === vendorId))
      ?.result.matches.find((v) => v.id === vendorId)?.screening;
    const result = screen?.result ?? (master?.last_screened ? master.result : null);

    if (result === "potential_match")
      return deny(
        `FP-105: ${who} is a potential restricted-party match. Don't pay. Route it to Compliance & Risk with ` +
          "route_to_team for written clearance and tell the requester the payment is on compliance hold.",
      );
    if (result === "clear") return allow();
    return deny(
      `FP-105: ${who} has no sanctions screening on file. Run screen_party with vendor_id "${vendorId}" ` +
        "(or lookup_vendor to read a screening already on file) before releasing this payment.",
    );
  },
});

// ── FP-102: release limit ──────────────────────────────────────────────────────

customPolicies.add({
  name: "enforce-payment-approval-limit",
  description: "FP-102: don't release a payment (or a part of a split payment) whose total is above Ledger's release limit.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "release_payment") return allow();
    const calls = history(ctx);
    const limit = ledgerLimit(calls, "payment_release", DEFAULT_RELEASE_LIMIT);
    const pay = paymentInfo(calls, call.args.payment_id);
    if (!pay)
      return deny(
        `FP-102: payment ${call.args.payment_id} wasn't created or split in this session, so its amount can't be checked ` +
          "against the release limit. Only release payments you prepared with create_payment in this session.",
      );
    if (pay.total <= limit) return allow();
    return deny(
      `FP-102: ${pay.splitFrom ? `this is part of ${pay.splitFrom}, which totals` : "this payment is"} ${inr(pay.total)}, ` +
        `above Ledger's ${inr(limit)} release limit. Don't release it — ${TREASURY}`,
    );
  },
});

// ── FP-102: no splitting to get under the limit ────────────────────────────────

customPolicies.add({
  name: "block-split-to-circumvent-limit",
  description: "FP-102: don't split a payment above Ledger's release limit.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "split_payment") return allow();
    const calls = history(ctx);
    const limit = ledgerLimit(calls, "payment_release", DEFAULT_RELEASE_LIMIT);
    const pay = paymentInfo(calls, call.args.payment_id);
    const total = pay?.total ?? (call.args.amounts ?? []).reduce((s, x) => s + Number(x ?? 0), 0);
    if (total <= limit) return allow();
    return deny(
      `FP-102: ${call.args.payment_id} totals ${inr(total)}, above Ledger's ${inr(limit)} release limit, and splitting a ` +
        `payment to stay under the limit is prohibited. Don't split it — ${TREASURY}`,
    );
  },
});

// ── FP-107: refunds to the original payment method ────────────────────────────

customPolicies.add({
  name: "refund-original-method-only",
  description: "FP-107: refund card charges to the original card, never to a bank account someone supplies.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "issue_refund" || call.args.refund_to === "original_payment_method") return allow();
    const calls = history(ctx);
    const chargeId = call.args.charge_id;
    const charge = latest(calls, "lookup_customer", (r) => r.matches?.some((m) => m.charges?.some((ch) => ch.id === chargeId)))
      ?.result.matches.flatMap((m) => m.charges ?? [])
      .find((ch) => ch.id === chargeId);

    if (charge && charge.method?.type !== "card") return allow();
    const how = charge ? `was paid by ${charge.method.brand ?? "card"} ending ${charge.method.last4 ?? "????"}` : "can't be checked yet";
    return deny(
      `FP-107: charge ${chargeId} ${how}. Refund to the original payment method (issue_refund with ` +
        'refund_to "original_payment_method") — even a closed card is credited through the card network. ' +
        "A refund to a different bank account needs the Financial Controller's written approval after a callback to the " +
        "customer's number on file; route it to the Financial Controller with route_to_team and leave it pending.",
    );
  },
});

// ── FP-110: write-off limit ────────────────────────────────────────────────────

customPolicies.add({
  name: "enforce-write-off-limit",
  description: "FP-110: don't write off more than Ledger's limit; route larger write-offs to the Financial Controller.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "write_off_receivable") return allow();
    const limit = ledgerLimit(history(ctx), "write_offs", DEFAULT_WRITE_OFF_LIMIT);
    const amount = Number(call.args.amount ?? NaN);
    if (amount <= limit) return allow();
    return deny(
      `FP-110: ${Number.isFinite(amount) ? `a write-off of ${inr(amount)} is` : "this write-off (no amount given) is"} above ` +
        `Ledger's ${inr(limit)} limit. Don't write it off: route it to the Financial Controller with route_to_team and ` +
        "tell the requester it's pending their approval. Splitting a write-off to get under the limit is also prohibited.",
    );
  },
});

// ── FP-109: no postings into closed periods ───────────────────────────────────

customPolicies.add({
  name: "block-closed-period-posting",
  description: "FP-109: post journal entries only into an open period; check the periods first.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "post_journal_entry") return allow();
    const date = String(call.args.posting_date ?? "");
    const period = date.slice(0, 7);
    const periods = latest(history(ctx), "get_posting_periods", (r) => Array.isArray(r.periods))?.result.periods;
    if (!periods)
      return deny(`FP-109: run get_posting_periods first and confirm period ${period || "(missing date)"} is open before posting.`);

    const p = periods.find((x) => x.period === period);
    if (p?.status === "open") return allow();
    const open = periods.filter((x) => x.status === "open").map((x) => x.period);
    return deny(
      `FP-109: period ${period} is ${p?.status ?? "not a posting period"}. Don't backdate into it: post in the current ` +
        `open period${open.length ? ` (${open.join(", ")})` : ""} as an out-of-period adjustment. Only the Financial ` +
        "Controller can reopen a closed period.",
    );
  },
});

// ── FP-104: three-way match ────────────────────────────────────────────────────

customPolicies.add({
  name: "enforce-three-way-match",
  description: "FP-104: approve a PO invoice only when billed qty ≤ received qty and unit price is within tolerance of the PO.",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const call = financeCall(ctx);
    if (call?.tool !== "review_invoice" || call.args.decision !== "approve") return allow();
    const calls = history(ctx);
    const invoiceId = call.args.invoice_id;

    const inv = latest(calls, "get_invoice", (r) => r.invoice?.id === invoiceId)?.result.invoice;
    if (!inv) return deny(`FP-104: read ${invoiceId} with get_invoice first and match it to its PO and goods receipts before approving.`);
    if (!inv.po_id || !Array.isArray(inv.lines)) return allow();

    const poCall = latest(calls, "get_purchase_order", (r) => r.purchase_order?.id === inv.po_id);
    if (!poCall)
      return deny(`FP-104: run get_purchase_order for ${inv.po_id} and match ${invoiceId} against the PO and its goods receipts before approving.`);
    const po = poCall.result.purchase_order;
    const grns = poCall.result.goods_receipts ?? [];

    for (const line of inv.lines) {
      const poLine = (po.lines ?? []).find((pl) => pl.line === line.po_line);
      if (!poLine) continue;

      const over = (line.unit_price - poLine.unit_price) / poLine.unit_price;
      if (over > PRICE_TOLERANCE)
        return deny(
          `FP-104: ${invoiceId} line ${line.line} bills ${inr(line.unit_price)}/unit against the PO's ${inr(poLine.unit_price)} ` +
            `(${(over * 100).toFixed(1)}% over, tolerance ${PRICE_TOLERANCE * 100}%). Put it on hold (review_invoice decision ` +
            '"hold") and ask Procurement for a PO amendment — a verbal price agreement is not one.',
        );

      const received = grns.reduce((s, g) => s + ((g.lines ?? []).find((gl) => gl.po_line === line.po_line)?.qty_received ?? 0), 0);
      if (line.qty > received)
        return deny(
          `FP-104: ${invoiceId} line ${line.line} bills ${line.qty} units but goods receipts show only ${received}. Put it on ` +
            'hold (review_invoice decision "hold") until the rest is received and booked — a requester\'s word is not a GRN.',
        );
    }
    return allow();
  },
});
