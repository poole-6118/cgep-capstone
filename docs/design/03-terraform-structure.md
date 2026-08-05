# 03 — Terraform Module Structure

**Status:** Adopted
**Date:** 2026-08-05
**Related:** [`01-capstone-plan.md`](./01-capstone-plan.md)

## Decision

Keep everything in a **single Terraform root module** at `terraform/`. Do not restructure the starter into a nested module. Add governance resources as new sibling `.tf` files (`grc_*.tf`) alongside the starter's `main.tf`. Where a gap can only be closed by modifying an inline attribute on a starter resource (DDB `server_side_encryption`, Lambda `vpc_config`, etc.), edit the starter file in place. Everywhere else, prefer attach-style separate resources.

## Alternatives Considered

| Approach | Pro | Con | Rejected because |
|---|---|---|---|
| **Nested module** — move starter to `terraform/starter/`, top-level module calls it and layers overrides via variables | Cleanest boundary; no starter-file edits needed for propagatable inputs | Requires refactor of the starter's outputs into module outputs; increases PR blast radius on every change; some inline attributes (IAM policy body) still can't be overridden from outside without variables the starter doesn't accept | Overkill for a 30-day capstone; the starter isn't versioned as an upstream we're pulling from — we own the fork |
| **Terraform overrides file** — `terraform/main_override.tf` with `provider`/`resource` blocks that override starter values | Zero starter-file edits | Terraform's `_override.tf` mechanism only merges *attributes*, not blocks; won't work for `vpc_config` (nested block), `server_side_encryption` (nested block), or IAM policy replacement | Doesn't cover the failure modes we actually need to close |
| **Sibling files + starter edits** *(chosen)* | Matches how the capstone brief describes it ("Add the missing resource... learner expected to add this") — every starter comment saying `# GAP-XX: learner expected to add ...` is an in-file edit invitation. Small diff surface. Auditors reading the code see one root module, one plan, one story. | Starter files aren't pristine after the capstone. Diff-vs-upstream is not trivial. | — |

## Rules for edits to starter files

To keep the diff-vs-upstream readable and defend "we didn't rewrite the app":

1. **No renamed resources, no changed resource types.** The starter's `aws_dynamodb_table.intake` stays `aws_dynamodb_table.intake` after Layer 1. If a gap forces a resource replacement, document it in `docs/design/`.
2. **Every attribute I add carries a comment referencing the GAP ID it closes.** `# GRC: closes GAP-02 (SOC 2 CC6.1)` — one line per addition.
3. **No removed lines from the starter without a comment explaining why.** The intentional gaps in comments (`# GAP-05: no vpc_config block...`) stay in place *even after I add the vpc_config*, so a reader can see the before/after story.
4. **New resources go in new files, not `main.tf`.** `main.tf` continues to hold the starter's workload; `grc_*.tf` holds my additions.

## File layout after Layer 1 completes

```
terraform/
├── main.tf                       # (edited) starter, plus gap-closing attribute
│                                 # additions on DDB, Lambda, API GW stage,
│                                 # IAM inline policy
├── variables.tf                  # (unchanged) starter
├── outputs.tf                    # (unchanged) starter — I add mine in outputs_grc.tf
├── outputs_grc.tf                # (new) evidence vault ARN, CMK ARNs, trail name
├── lambda/handler.py             # (unchanged)
│
├── grc_kms.tf                    # (new) three CMKs: data-at-rest, evidence, cloudtrail
├── grc_evidence_vault.tf         # (new) S3 Object Lock evidence bucket + related
├── grc_cloudtrail.tf             # (new) multi-region trail + its log bucket
├── grc_s3_hardening.tf           # (new) SSE-KMS + versioning + TLS-only policy
│                                 # attached to the starter's uploads bucket
├── grc_apigw_logging.tf          # (new) CloudWatch log group for API GW access logs
├── grc_security_groups.tf        # (new) Lambda security group (egress-restricted)
└── grc_locals.tf                 # (new) shared locals (evidence prefix conventions,
                                  # retention periods, CMK aliases)
```

Everything under `grc_*` is my work. Everything else is the starter, possibly with gap-closing edits.

## Terraform state

Local state for the capstone. Not remote. Rationale:

- Grading is on the code + evidence bundle, not state management practice
- Remote state adds a chicken-and-egg (need an S3 bucket + DynamoDB table *before* Terraform can run — those would be bootstrap resources requiring their own IAM setup)
- The `WRITEUP.md` will call this out explicitly and note the real-prod pattern (S3+DDB backend with KMS-encrypted state) as a follow-on

## AWS provider version pin

`~> 5.0` — matches the starter. If I ever need a v5.x feature the starter didn't (e.g., newer default tag propagation), bump the lower bound explicitly and note it in a change-log commit.

## Teardown constraint

`aws_s3_bucket.evidence` has `force_destroy = false` and (once Layer 3 runs) will accumulate signed evidence bundles under Object Lock COMPLIANCE. That is the *point* — the auditor needs to trust that a bundle exists as-produced for 90 days. It also means `terraform destroy` cannot fully tear down the environment once evidence has been written; the vault will remain until every object's retain-until date has elapsed.

For capstone submission, this is fine. For teardown after the audit window: wait out the 90 days, then re-run destroy. For emergency teardown, the only path is to disable COMPLIANCE-mode retention on individual objects, which requires the root account and is deliberately hard (see AWS docs on "deleting objects under Object Lock legal hold or COMPLIANCE retention").

The starter's `Makefile destroy` target will fail while any versioned bucket has content. `WRITEUP.md` documents the ordered-teardown procedure.
