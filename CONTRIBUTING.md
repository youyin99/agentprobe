# Contributing

## Development setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m agentprobe run --out /tmp/agentprobe-report --strict
```

## Rules for case changes

- Use synthetic data only and the `DEMOSECRET-` prefix for secret-shaped values.
- Every attack case must retain a reproducible baseline/hardened differential.
- Every benign case must keep `no_denied_user_actions` coverage.
- Do not add network egress.
- Do not include real credentials, personal data, or attack targets.
- Keep the minimum library at five attack cases per risk category and at least ten benign cases.

## Pull requests

Include:

- the behavior being changed;
- the tests added or updated;
- expected report counts;
- any new limitations.

Run `python -m pytest` before opening a pull request.

## Reporting security issues

Follow [`SECURITY.md`](SECURITY.md), not a public issue.
