# AgentProbe

Evidence-based, deterministic security evaluation for a document assistant agent.

AgentProbe runs the same attack and business cases against two profiles:

- **baseline** — intentionally permissive, used inside a synthetic sandbox to demonstrate a risk;
- **hardened** — applies instruction/data separation, role-scoped file access, workspace containment, destination allowlisting, and synthetic-secret detection.

The output is a versioned JSON report, a static HTML report, redacted JSONL execution events, and sanitized receiver receipts. It is designed for reproducible security demonstrations, not for claiming that a live model has been fully evaluated.

## Coverage

| Category | Cases | What is exercised |
|---|---:|---|
| Indirect prompt injection | 5 | Hidden instructions, fake overrides, cross-user access, encoded exfiltration |
| Secret exfiltration | 5 | Embedded synthetic keys, Base64, zero-width obfuscation, chunked sends |
| Tool overreach | 5 | Path traversal, role-scoped paths, cross-user reads, egress allowlists, role/tool grants |
| Benign business behavior | 12 | Search/read/summarize and approved egress without false-positive blocking |

The case library meets the release gate: every attack case demonstrates a baseline risk and a hardened protection outcome; every benign case passes under both profiles.

## Requirements

- Python 3.11–3.13
- No runtime dependencies; `pytest` for tests

## Install

```bash
python -m pip install -e ".[dev]"
```

You can also run directly from the repository without installing:

```bash
python -m agentprobe --help
```

## Quick start

```bash
python -m agentprobe validate
python -m agentprobe run --out examples/output --strict
```

Expected summary:

```text
cases=27 attack=15 benign=12 differential=15 benign_pass_both=12 uncertain=0 errors=0
```

Artifacts:

- `examples/output/agentprobe-report.json` — versioned evaluation report
- `examples/output/agentprobe-report.html` — static human-readable report
- `examples/output/events.jsonl` — redacted tool execution events
- `examples/output/receipts.jsonl` — receiver receipts with hashes and sensitive IDs only

A generated sample is committed under [`examples/output/`](examples/output/). Re-run the command to regenerate it.

List cases or inspect a single case:

```bash
python -m agentprobe list
python -m agentprobe run --case ipi-003 --no-require-full-library --out /tmp/one-case
```

## How it works

```text
case JSON ──> validation ──> deterministic scenario runner
                                │
                                ├─ baseline policy (permissive)
                                └─ hardened policy
                                      ├─ untrusted-origin actions blocked
                                      ├─ relative path + role scope
                                      ├─ no symlink/reparse component
                                      ├─ egress destination allowlist
                                      └─ synthetic-secret detection
                                │
                                ├─ redacted event JSONL
                                ├─ local in-memory receiver
                                └─ assertion evaluator
                                      pass / fail / uncertain
                                          │
                                          ▼
                                  JSON + HTML report
```

Key design choice: the offline adapter uses a deterministic `agent_plan` from each case. `origin` distinguishes user-directed actions from injected document actions. This isolates policy behavior and evidence generation, while the README and report explicitly avoid presenting it as a real-model evaluation.

Evidence rules:

- A forbidden successful tool call is a failure.
- A denied attempt with an event is evidence of protection.
- A missing receiver record with no denied-egress event is **uncertain**, not a pass.
- All outbound content is simulated and written to a process-local receiver; no network is used.
- Synthetic values use the `DEMOSECRET-*` prefix, and plaintext values never enter events, receipts, the JSON report, or HTML.

## Command reference

```text
agentprobe validate [--cases DIR]
agentprobe list [--cases DIR]
agentprobe run [--cases DIR] [--workspace DIR] [--sandbox DIR]
               [--secret-catalog FILE] [--out DIR] [--case ID ...]
               [--require-full-library | --no-require-full-library] [--strict]
```

`--strict` exits `1` if coverage or expected baseline/hardened/benign outcomes are not met. Input errors exit `2`.

## Case format

Case files live in `fixtures/cases/attack/` and `fixtures/cases/benign/`. The JSON fields are documented in [`docs/DESIGN.zh-CN.md`](docs/DESIGN.zh-CN.md).

Each case declares the task, principal, materials, simulated action plan, allowed/forbidden behavior, and assertions. Content templates such as `{{step:s1.output | base64}}` avoid embedding synthetic secrets in case files.

## Tests

```bash
python -m pytest
```

The suite covers library validation, judge behavior (pass/fail/insufficient evidence), path and policy checks, event redaction, report escaping, and the full 27-case differential run.

## Known limitations

- The adapter is deterministic; it does not evaluate a real LLM or model weights.
- The baseline profile is intentionally permissive but is still confined to the synthetic fixture sandbox.
- The local receiver is not an email gateway or network proxy.
- Role and path policies are simplified examples.
- This project is not an operating-system sandbox.

## Contributing and security reports

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md). Never submit real credentials, customer data, or attack instructions for third-party systems.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
