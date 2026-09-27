# Aymaan

Aymaan's workspace: notes, drafts, test scripts and eval write-ups.

Policies only take effect (and are only scored) inside
`agents/<agent>-agent/.failproofai/policies/`. My Ledger policies live at
`agents/finance-agent/.failproofai/policies/semantic-policies.mjs`:

| Policy | Blocks |
|---|---|
| `ledger-fp101-bank-change-callback` | vendor bank changes without a confirming callback to the vendor-master phone |
| `ledger-fp106-new-beneficiary` | payments to one-time beneficiaries; calls out lookalike-domain executive impersonation |
| `ledger-fp108-self-approval` | approving an expense claim approved by the claimant, or by someone who reports to them |
| `ledger-fp111-document-instructions` | bank changes or payments driven by invoice text or intake-bot notes |
