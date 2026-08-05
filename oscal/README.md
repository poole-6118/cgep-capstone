# OSCAL — Component Definition & Profile

Layer 4 of the capstone. Two files that make the SOC 2 posture of the
governed Patient Intake API machine-readable per the [OSCAL 1.1.2][oscal]
schema:

```
oscal/
├── README.md                              this file
├── components/
│   └── patient-intake-api.json            OSCAL component-definition
└── profiles/
    └── capstone-profile.json              Profile selecting the 7 TSC controls we implement
```

## Catalog pin

Both files reference a single upstream OSCAL catalog:

- **Repo:** [`grcwarlock/oscal-catalog-library`](https://github.com/grcwarlock/oscal-catalog-library)
- **Commit SHA:** `ea49c4c05c8c62098b3766fd8f26b862fb5181f4`
- **File path (in that repo):** `soc2-oscal/catalog/catalog.json`
- **Catalog title (from metadata):** *SOC 2 Type II Trust Services Criteria*
- **Catalog version:** 2022 (2017 TSC with 2022 Points of Focus)
- **OSCAL version:** 1.1.2

We pin at commit SHA (not tag or branch tip) so the catalog cannot silently drift underneath us. The pin appears in three places:

1. `oscal/components/patient-intake-api.json` — `control-implementations[0].source`
2. `oscal/components/patient-intake-api.json` — `back-matter.resources[].rlinks[].href`
3. `oscal/profiles/capstone-profile.json` — `imports[0].href`

All three carry the same commit SHA. If you rotate the pin, update all three.

### Why this catalog

AICPA does not publish an official OSCAL catalog for the Trust Services Criteria. See `docs/design/00-framework-choice.md` §"OSCAL catalog choice" for the full alternatives analysis. Short version:

1. **Chosen:** the community-maintained SOC 2 TSC catalog above. Directly cites `cc6-1`, `cc7-2`, `a1-2`, etc. — a reviewer resolves control IDs in one hop.
2. **Fallback:** if the above catalog becomes unavailable, rewrite `source` and `imports` to the [NIST 800-53r5 OSCAL catalog][nist-oscal] and shift the SOC 2 TSC IDs onto each `implemented-requirement` as `props` (using AICPA's 2018 TSC-to-800-53 mapping).

[oscal]: https://pages.nist.gov/OSCAL/
[nist-oscal]: https://github.com/usnistgov/oscal-content

## Controls selected

The profile selects **seven** SOC 2 TSC controls — the ones this capstone actually implements. See `docs/design/00-framework-choice.md` §"Controls in scope" for the full mapping table, and each `implemented-requirement.description` in the component-definition for the specific Terraform address, Rego policy, and evidence-bundle path.

| Control | What it enforces | Terraform + Policy |
|---|---|---|
| `cc6-1` | Encryption at rest via customer-managed KMS | `aws_kms_key.data`, `aws_s3_bucket_server_side_encryption_configuration.uploads`, `aws_dynamodb_table.intake` + `policies/soc2/cc6/kms_on_data_stores.rego` |
| `cc6-3` | Least-privilege IAM | `aws_iam_role_policy.lambda_inline` + `policies/soc2/cc6/least_priv_iam.rego` |
| `cc6-6` | Boundary protection (Lambda-in-VPC) | `aws_lambda_function.intake.vpc_config` + `policies/soc2/cc6/lambda_in_vpc.rego` |
| `cc6-7` | Transmission security (TLS-only bucket policies) | `aws_s3_bucket_policy.*_tls_only` + `policies/soc2/cc6/tls_only_bucket_policy.rego` |
| `cc7-2` | System monitoring (CloudTrail, API GW access logs, Lambda DLQ+X-Ray) | `aws_cloudtrail.governance`, `aws_apigatewayv2_stage.default.access_log_settings`, `aws_lambda_function.intake.dead_letter_config` + `policies/soc2/cc7/detection_enabled.rego` |
| `cc8-1` | Change management (evidence pipeline) | `.github/workflows/grc-gate.yml` |
| `a1-2` | Availability / backups (evidence vault Object Lock + versioning) | `aws_s3_bucket.evidence`, `aws_s3_bucket_object_lock_configuration.evidence`, `aws_s3_bucket_versioning.evidence` + `policies/soc2/a1/object_lock_and_versioning.rego` |

Controls **not** included in the profile (e.g., `cc1.*` — org-level control environment, `p1.*` — Privacy series) are honest gaps documented in `WRITEUP.md` §"Honest Gaps". A real Type II engagement would require complementary user entity controls and organizational-process attestations for those; this capstone is scoped to engineering-implementable technical controls.

## Cross-framework crossrefs

Each `implemented-requirement.props` array on the component-definition carries HIPAA §164.x and CMMC L2 800-171r3 practice IDs. Consumers pursuing those frameworks can grep for `name = "hipaa"` or `name = "cmmc"` on any control to see what secondary crossrefs the SOC 2 implementation also satisfies. See `FRAMEWORKS.md` for the mapping primer.

## Validation

### Well-formed JSON

Always passes on this repo:

```bash
python3 -c "import json; json.load(open('oscal/components/patient-intake-api.json'))"
python3 -c "import json; json.load(open('oscal/profiles/capstone-profile.json'))"
```

The GHA `grc-gate` workflow currently does not validate the OSCAL files. Adding an `oscal-cli` step is a follow-up (see below).

### Full OSCAL schema validation (optional)

`oscal-cli` (Java) is not currently installed in the capstone environment. When available, run:

```bash
# Component definition
oscal-cli component-definition validate oscal/components/patient-intake-api.json

# Profile
oscal-cli profile validate oscal/profiles/capstone-profile.json

# Resolve the profile against the catalog (produces the effective control set)
oscal-cli profile resolve oscal/profiles/capstone-profile.json -o oscal/profiles/capstone-profile.resolved.json
```

Pin `oscal-cli` at the version whose bundled schema matches our declared `oscal-version` (1.1.2). At time of writing that is the `2.1.0` line (see [usnistgov/oscal-cli releases][cli-rel]).

[cli-rel]: https://github.com/usnistgov/oscal-cli/releases

## Rotation notes

- **Catalog pin:** rotate quarterly or on any upstream change that alters an included control ID.
- **UUIDs:** never change once published. They're stable identifiers used by any downstream OSCAL tooling that ingests this component. If a control implementation is materially rewritten, prefer bumping the component-definition `metadata.version` and re-authoring an `implemented-requirement` rather than mutating UUIDs.
- **Evidence links:** the `s3://acme-health-evidence-vault-<suffix>/evidence/<commit-sha>/...` URIs currently use `<suffix>` and `<commit-sha>` as template placeholders. Once Layer 1 provisions the bucket, `<suffix>` will be replaced with the concrete Terraform random-suffix. The `<commit-sha>` placeholder is per-run and resolves in the pipeline (see `.github/workflows/grc-gate.yml`).
