# 01 — Capstone Build Plan

**Status:** Adopted
**Author:** Joe Poole
**Date:** 2026-08-05
**Related:** [`00-framework-choice.md`](./00-framework-choice.md)

## Objective

Take the deliberately-non-compliant Patient Intake API (`GRCEngClub/cgep-app-starter`), wrap it with four CGE-P layers, and produce a passing capstone submission (weighted avg ≥ 65 across 8 dimensions, no auto-fail triggers) targeted at **SOC 2 Type II** as the primary framework.

## Sequence

Each layer is a separate PR against `main`. Every PR runs the GHA pipeline once that layer exists. The build order below is chosen so the pipeline itself becomes progressively more discriminating.

| # | Branch | Delivers | Depends on | Estimated PR size |
|---|---|---|---|---|
| 1 | `docs/framework-choice-and-plan` | This PR: framework defense + build plan | — | S |
| 2 | `layer1/terraform-baseline` | KMS keys, S3 evidence vault with Object Lock, CloudTrail, harden starter (S3 SSE-KMS + TLS-only + versioning, DDB CMK, Lambda-in-VPC, IAM tightened, API GW access logs + throttling) | 1 | L |
| 3 | `layer2/rego-policies` | 5+ Conftest policies with `_test.rego` fixtures, each mapped to a SOC 2 TSC ID and closing a `GAPS.md` gap | 2 | M |
| 4 | `layer3a/gha-red-pr-demo` | *(intentionally-non-compliant PR to prove the gate blocks it — will be closed unmerged and referenced in the write-up)* | 3 | XS |
| 5 | `layer3/actions-pipeline` | `.github/workflows/grc-gate.yml` — plan → conftest → apply → cosign sign → upload to Object Lock vault | 3 | M |
| 6 | `layer4/oscal-component` | `oscal/components/patient-intake-api.json` with real UUIDs, TSC catalog source, resource-ARN implementation statements, resolvable evidence links | 5 | M |
| 7 | `writeup/final` | `WRITEUP.md` — design rationale, control coverage table, honest gaps, evidence-bundle verification instructions | 6 | M |

## Grading dimensions & where each is earned

Cross-referenced against the CGE-P rubric so every dimension has an explicit home in the plan.

| Rubric dimension (weight) | Where it's earned |
|---|---|
| **IaC Quality (15%)** | Layer 1. Modular Terraform, `terraform fmt` + `terraform validate` in CI, `checkov` scan passes in CI. Boundary between "starter" and "governance" resources is explicit — I extend, never rewrite. |
| **Policy-as-Code (15%)** | Layer 2. Every policy has metadata block + `_test.rego` with pass and fail fixtures. Deny-by-default. Policies exist in `policies/soc2/{cc6,cc7,a1}/`. |
| **CI/CD Compliance Integration (10%)** | Layer 3. Gate runs on every PR, blocks merge on policy failure, evidence bundle only produced on `main` merge. Layer 3a red PR is the proof-of-blocking. |
| **Continuous Monitoring & Detection (10%)** | Layer 1 (CloudTrail + API GW access logs + Lambda X-Ray) plus a small CloudWatch alarm module. Layer 2 has a Rego policy that fails plan if any of those detections are removed. |
| **Evidence Automation & OSCAL (10%)** | Layer 3 (Cosign keyless signing → tar.gz → S3 Object Lock vault, provenance preserved via GHA OIDC claim in signature) + Layer 4 (OSCAL component pointing at those signed artifacts by S3 URI). |
| **Control Test Coverage (10%)** | Layer 2. Every policy has positive + negative test fixtures. Integration-level: at least one test asserts that a re-introduced gap is caught by the policy suite running against the real starter's plan. |
| **Control-to-Code Documentation (15%)** | Bidirectional. `docs/controls/` has one file per TSC control, listing (policy file, TF resource, OSCAL requirement ID, evidence bundle path). OSCAL `implemented-requirement.description` links back to policy file + Terraform address. |
| **Engineering Hygiene (15%)** | Pinned dep versions, meaningful commit messages, no secrets (gitleaks in CI, `pre-commit` hook), `CODEOWNERS`, `SECURITY.md`, clear repo structure. |

## Auto-fail triggers — how we avoid them

- **Secrets/PII in repo:** gitleaks pre-commit hook + gitleaks CI stage. Real AWS creds live in GHA repo secrets (OIDC-federated IAM role — no long-lived keys). Test fixtures use fake patient IDs.
- **Fails to validate:** every Terraform PR runs `terraform fmt -check`, `terraform validate`, `checkov`, `conftest test policies/`.
- **Broken evidence pipeline:** `WRITEUP.md` includes a section that walks the grader through verifying the Cosign signature against Sigstore and recomputing the SHA-256 of the tar.gz.

## What "one green PR and one red PR" looks like

- **Green:** Layer 2's own PR. It adds the Rego suite. The gate runs against the *pre-Layer-2 Terraform state* and produces a green result because Layer 1 already closed the gaps the policies check for. This is the "compliant plan passes the gate" evidence.
- **Red:** Layer 3a. Its diff removes the SSE-KMS block from `aws_s3_bucket.uploads`, re-introducing GAP-01. The Conftest gate runs and denies with the policy's `msg`. PR closed unmerged, linked in `WRITEUP.md` §"Pipeline demonstration".

## AWS environment

- Personal AWS account (out of scope for Coreforce credentials).
- Region: `us-east-1`.
- Terraform state: local for the capstone. (Real prod would use S3+DynamoDB backend; capstone doesn't gain grader points for that and adds bootstrapping complexity.)
- Cost estimate: ~$5–10 for the 30-day build window. Torn down with `make destroy` after submission.

## Timeline (compressed vs. the doc's 30-day plan)

The CGE-P doc assumes a human learner. This capstone is executed by an AI operator with prior experience across all four layers (Terraform, Rego/Conftest, GHA compliance gates, OSCAL). Compressed timeline:

| Day | Milestone |
|---|---|
| 1 | PR #1 (this doc) merged. Starter deployed once to confirm `make test` returns `{status: "received"}`, then destroyed. |
| 2–4 | PR #2 (Layer 1). |
| 5–7 | PR #3 (Layer 2) + PR #4 (Layer 3a red demo). |
| 8–10 | PR #5 (Layer 3). |
| 11–13 | PR #6 (Layer 4). |
| 14 | PR #7 (`WRITEUP.md` + evidence bundle produced end-to-end). |
| 15 | Submit repo URL + commit SHA. |

## Change log

| Date | Change |
|---|---|
| 2026-08-05 | Initial adoption (PR #1). |
