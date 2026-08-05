# Security policy

The CGE-P capstone is a coursework artefact. It is deliberately non-production and models a fictional workload ("Acme Health"). There is no live PHI in this repository, no live AWS credentials, and no user-facing service.

That said, real security-relevant issues can still show up in the code:

- Real credentials accidentally committed
- Vulnerabilities in dependencies pinned by this repo
- Weaknesses in the OPA policies (false negatives) or the GHA pipeline (e.g., unpinned actions, over-scoped OIDC trust)

## Reporting a vulnerability

If you find one, please **do not open a public issue**. Instead:

1. Email `poole-6118@users.noreply.github.com` with a description and a proof of concept if you have one.
2. Alternatively, open a [private security advisory](https://github.com/poole-6118/cgep-capstone/security/advisories) on the repo.

Expected response time: 72 hours to acknowledge, 30 days to remediate for anything real. Because this repo is a portfolio artefact, "remediate" may mean documenting the finding in `WRITEUP.md` §"Honest Gaps" rather than patching, if the finding is inherent to the design.

## Scope

**In scope:**

- Anything under `.github/workflows/`, `policies/`, `terraform/`, or `oscal/`.
- Committed secrets or PII.
- OIDC trust misconfiguration that could let an unauthorised repo assume the capstone's IAM role.

**Out of scope:**

- The starter's original non-compliance (that's [documented on purpose in `GAPS.md`](./GAPS.md); each gap has a corresponding Rego policy that would catch a re-introduction).
- The `terraform/bad_example.tf` file that only exists on the `layer3a/gate-fail-demo` branch. It re-introduces gaps deliberately as a gate-blocking demonstration.
- Fictional PII in `WORKLOAD.md` and policy test fixtures. Fake patient IDs are allowlisted in `.gitleaks.toml`.

## Related

- [`.gitleaks.toml`](./.gitleaks.toml) — secret-scanning ruleset (gitleaks default + narrow allowlist for fixtures).
- [`.pre-commit-config.yaml`](./.pre-commit-config.yaml) — local hooks that run gitleaks / terraform_fmt / opa fmt before every commit.
- [`.github/workflows/grc-gate.yml`](./.github/workflows/grc-gate.yml) — CI that reruns the same checks on every PR + push.
