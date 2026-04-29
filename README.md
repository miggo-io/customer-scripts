# customer-scripts

Standalone scripts that Miggo ships to customers — read-only audits,
environment probes, and similar diagnostics that customers run inside their
own infrastructure.

Every script in this repo is intended to be:

- **Self-contained** — one folder, one entry-point script, a small
  `requirements.txt`, and a customer-facing `README.md`.
- **Read-only** — no writes to customer infrastructure unless explicitly
  scoped and documented.
- **Auditable** — minimal dependencies, clear required IAM / RBAC, and an
  explicit list of what data is collected (and what isn't).
- **Portable** — should run on a stock Python install with `pip install -r
  requirements.txt`, no internal Miggo packages.

## Scripts

| Script | Purpose |
|--------|---------|
| [`aws-waf-audit/`](./aws-waf-audit) | Inventory every AWS WAFv2 Web ACL, its rules, and the resources each ACL protects. |

## Conventions for new scripts

When adding a new script, create a folder at the repo root with:

```
<script-name>/
├── README.md           # customer-facing: what it does, prerequisites,
│                       # required permissions, usage, output, troubleshooting
├── requirements.txt    # third-party dependencies, pinned to a minimum version
└── <entry-point>.py    # single-file script, runnable as `python <entry-point>.py`
```

Keep it simple — one script per folder, no shared utilities across scripts.
Customers receive a single folder, not the whole repo.
