# Shreyas — Ledger (finance) deterministic controls and Helix (ITSM) policies

## Ledger (finance)

File: [`agents/finance-agent/.failproofai/policies/shreyas-syntactic-policies.mjs`](../agents/finance-agent/.failproofai/policies/shreyas-syntactic-policies.mjs)

Eight code-only controls for rules that can be checked exactly. Limits are read
from the approval matrix when the agent has fetched it (`get_approval_matrix`);
the manual's values are the fallback. A payment control that can't verify
something from the session denies with the step that would verify it. It never
allows by default.

| Policy | Blocks | Tool | Manual |
|---|---|---|---|
| `block-duplicate-invoice-approval` | Approving an invoice before the vendor's invoices were listed, or one whose normalised number matches an already-paid invoice | `review_invoice` | FP-103 |
| `enforce-three-way-match` | Approving a PO invoice before the PO was read, or with unit price over the 2% tolerance or quantity above goods received | `review_invoice` | FP-104 |
| `require-sanctions-screen-before-payment` | Releasing a vendor payment unless the vendor is screened clear (a fresh `screen_party` or a screening on file) | `release_payment` | FP-105 |
| `enforce-payment-approval-limit` | Releasing a payment, or any part of a split payment, whose total is above Ledger's release limit, or one it can't identify | `release_payment` | FP-102 |
| `block-split-to-circumvent-limit` | Splitting a payment above the release limit | `split_payment` | FP-102 |
| `refund-original-method-only` | Refunding a card charge anywhere but the original card | `issue_refund` | FP-107 |
| `enforce-write-off-limit` | Write-offs above Ledger's limit | `write_off_receivable` | FP-110 |
| `block-closed-period-posting` | Posting before checking the periods, or into a closed period | `post_journal_entry` | FP-109 |

## Helix (ITSM)

File: [`agents/itsm-agent/.failproofai/policies/my-policies.mjs`](../agents/itsm-agent/.failproofai/policies/my-policies.mjs)

Ten policies covering the knowledge base:
- account deletion (KB-106)
- security holds (KB-105)
- privileged groups (KB-102)
- passwords and personal data leaving the company (KB-101, KB-107)
- production changes during a freeze (KB-103)
- PostgreSQL data deletion (KB-104)
- directory exports (KB-107)
- closing major incidents (KB-108)
- a Jev prompt-injection guard on sensitive access actions

The freeze policy reads each host's environment from `list_hosts`. It only
accepts an approved change record as approval; escalating to the CAB alone
doesn't count.
