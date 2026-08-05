# 00 — Framework Choice: SOC 2 Type II

**Status:** Adopted
**Author:** Joe Poole
**Date:** 2026-08-05
**Applies to:** All four capstone layers (Terraform, Rego, GHA pipeline, OSCAL)

## Decision

The capstone's declared **primary framework is SOC 2 Type II** (AICPA Trust Services Criteria — 2017 with 2022 Points of Focus, Common Criteria + Availability and Confidentiality categories).

Every Rego policy in this repo carries at least one Common Criteria control ID (`CC*`, `A*`, or `C*`) in its `custom.controls` metadata. The OSCAL component's `control-implementation.source` points at a SOC 2 TSC catalog (see "OSCAL catalog choice" below). Secondary framework mappings (HIPAA 164.x and CMMC L2 800-171r3 practice IDs) appear as `props` on each `implemented-requirement`, never as the primary source.

## Alternatives Considered

| Framework | Fit for this workload | Rejected because |
|---|---|---|
| **HIPAA Security Rule** | Strong — the workload handles PHI, so the Security Rule Safeguards apply directly. | The Rule is thin on technical specifics (many safeguards are "addressable" org processes), which makes the "5+ technical Rego policies mapped to controls" bar awkward. Also no official NIST OSCAL catalog — teams cite 800-66 as a proxy, which is one hop of indirection I don't want in the graded artifact. |
| **CMMC Level 2 / 800-171r3** | Strong — 110 practices, official NIST OSCAL catalog, unambiguous mapping to technical controls. | 110 practices is over-scoped for a 30-day capstone. To defend "we implement CMMC L2" honestly, I'd need to explain non-coverage across ~100 practices in the write-up. SOC 2 lets me claim coverage of a smaller, cleaner criteria set for the same policy work. |
| **SOC 2 Type II** *(chosen)* | Strong — TSC map cleanly to the eight `GAPS.md` items, and Type II specifically requires *evidence of continuous control operation*, which is exactly what the CGE-P pipeline produces (signed evidence bundles landing in an Object Lock vault on every merge). | — |

## Why SOC 2 is the right primary here

1. **Type II fit for the CGE-P pipeline.** SOC 2 Type II is not a point-in-time attestation; it audits that controls *operated effectively over a period*. The capstone's Cosign-signed evidence bundle, uploaded to an S3 Object Lock vault on every `main` merge, is exactly the kind of continuous evidence trail Type II auditors expect. This is a stronger narrative than HIPAA or CMMC, both of which are structured around point-in-time control implementation.
2. **Trust Services Criteria map 1:1 to the named gaps.** Every entry in `GAPS.md` names a SOC 2 TSC control. GAP-01/02 → CC6.1, GAP-03 → CC6.7, GAP-04 → A1.2, GAP-05 → CC6.6, GAP-06/08 → CC7.2, GAP-07 → CC6.3. No stretching, no re-interpreting.
3. **Business context matches.** Per the scenario, "an enterprise customer is asking" for SOC 2. That is the single most common real-world driver for GRC work at a 50-person software company. Framing the capstone around the buyer-driven motivation makes the write-up more useful as a portfolio artifact than a defense-industry-focused CMMC narrative would be for a telehealth company.

## OSCAL catalog choice

AICPA does not publish an official OSCAL catalog for the Trust Services Criteria. Two defensible options exist:

1. **Community-maintained SOC 2 TSC catalog** — e.g., the [oscal-content](https://github.com/usnistgov/oscal-content) family or a public community fork. Directly cites `CC6.1`, `CC7.2`, etc.
2. **NIST SP 800-53 Rev. 5** as the source catalog, with each `implemented-requirement`'s `props` carrying the TSC ID it maps to (using AICPA's own 2018 TSC-to-800-53 mapping guide).

**This capstone uses option (1)** — a community SOC 2 TSC OSCAL catalog, pinned at a specific commit SHA in `oscal/README.md`. Rationale: (1) reads directly to the auditor; (2) doesn't require the reader to hop through a mapping document to verify a control claim. If the pinned catalog is unavailable, the fallback is (2) — 800-53r5 with TSC IDs as `props`.

## Controls in scope for this capstone

The following seven TSC controls are the primary implementation targets. Each has at least one Rego policy, one Terraform remediation, and one OSCAL `implemented-requirement`.

| TSC ID | Criterion | Layer(s) addressing it | Gap(s) closed |
|---|---|---|---|
| **CC6.1** | Logical access — restrict access to information assets | Terraform (KMS CMK on S3 + DDB), Rego, OSCAL | GAP-01, GAP-02 |
| **CC6.3** | Authorization — least privilege | Terraform (scoped IAM policy), Rego, OSCAL | GAP-07 |
| **CC6.6** | Boundary protection | Terraform (Lambda-in-VPC), Rego, OSCAL | GAP-05 |
| **CC6.7** | Transmission security | Terraform (S3 TLS-only bucket policy), Rego, OSCAL | GAP-03 |
| **CC7.2** | System monitoring — detection | Terraform (CloudTrail, API GW access logs, Lambda DLQ+X-Ray), Rego, OSCAL | GAP-06, GAP-08 |
| **CC8.1** | Change management | GHA pipeline (Conftest gate blocks non-compliant plans), OSCAL | *(cross-cutting — every merge is evidenced)* |
| **A1.2** | Recovery — backups, versioning | Terraform (S3 versioning + Object Lock on evidence vault), Rego, OSCAL | GAP-04 |

Secondary mappings to HIPAA 164.x and CMMC L2 800-171r3 practices are recorded per-policy and per-OSCAL-requirement, so a downstream reader pursuing HIPAA or CMMC can trace what we already implemented.

## Non-goals

- **Full SOC 2 Type II audit-readiness for a real company.** This capstone builds *audit-defensible engineering* for a fictional workload. It does not produce management assertions, complementary user entity controls, or a Type II report. A real Type II engagement would require sustained operation of the controls (typically 6–12 months of evidence) and an independent auditor.
- **CMMC or HIPAA primary treatment.** Secondary cross-references only. If Acme's federal pilot advances, a follow-on capstone would re-source the OSCAL to the 800-171r3 catalog and lift the same evidence trail into that structure.

## Change log

| Date | Change |
|---|---|
| 2026-08-05 | Initial adoption (PR #1). |
