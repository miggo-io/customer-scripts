# customer-scripts

Standalone scripts that Miggo ships to customers — read-only audits,
environment probes, and similar diagnostics that customers run inside their
own infrastructure.

Every script in this repo is intended to be:

- **Self-contained** — single-file scripts using
  [PEP 723](https://peps.python.org/pep-0723/) inline dependency metadata
  so the script is runnable end-to-end with `uv run` (or `./script.py` via
  the `uv` shebang). No `requirements.txt`, no virtualenv setup.
- **Read-only** — no writes to customer infrastructure unless explicitly
  scoped and documented.
- **Auditable** — minimal dependencies, clear required IAM / RBAC, and an
  explicit list of what data is collected (and what isn't).
- **Portable** — runs on any machine with [`uv`](https://docs.astral.sh/uv/)
  (or, as a fallback, a stock Python with the inline-declared deps installed
  manually). No internal Miggo packages.

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
└── <entry-point>.py    # single-file script with PEP 723 inline metadata
                        # and `#!/usr/bin/env -S uv run --script` shebang
```

Inline metadata block (top of every script):

```python
#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["<pkg>>=<min-version>", ...]
# ///
```

Keep it simple — one script per folder, no shared utilities across scripts.
Customers receive a single folder (or single file), not the whole repo.
