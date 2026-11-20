# Security Policy

## Scope

AgentProbe is a synthetic, offline evaluation harness. It must not be pointed at
real systems, real credentials, or third-party data. The baseline profile is
intentionally permissive inside a synthetic sandbox.

## Reporting a vulnerability

Please use a private GitHub Security Advisory for this repository, or contact the
maintainer through the address listed on the GitHub profile. Do not open a public
issue for an unfixed vulnerability.

Include:

- affected version/commit;
- reproduction steps using synthetic data;
- expected and observed behavior;
- whether a report, event, or receipt could include plaintext secret material.

## What is in scope

- Sandbox escape from the fixture root in the tool layer.
- Plaintext synthetic secret material in generated events, receipts, JSON, or HTML.
- HTML/report injection through case titles or evidence.
- Incorrect `pass` verdicts when required evidence is absent.

## What is out of scope

- Attacks against real external services.
- Claims that the deterministic adapter evaluates model safety.
- Vulnerabilities requiring a malicious modification of the user's local Python
  installation or operating system.
