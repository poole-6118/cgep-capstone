# Rego policy suite — SOC 2 Trust Services Criteria

This directory holds the Conftest / OPA policies that gate the Terraform
plan in `terraform/`. Each policy carries a `# METADATA` block with the
SOC 2 TSC control ID it enforces and secondary crossrefs to HIPAA and
CMMC L2 (see `docs/design/00-framework-choice.md` for the framework
choice rationale).

## Layout

```
policies/
├── README.md
└── soc2/
    ├── cc6/
    │   ├── kms_on_data_stores.rego          # CC6.1 — GAP-01, GAP-02
    │   ├── kms_on_data_stores_test.rego
    │   ├── tls_only_bucket_policy.rego      # CC6.7 — GAP-03
    │   ├── tls_only_bucket_policy_test.rego
    │   ├── least_priv_iam.rego              # CC6.3 — GAP-07
    │   ├── least_priv_iam_test.rego
    │   ├── lambda_in_vpc.rego               # CC6.6 — GAP-05
    │   └── lambda_in_vpc_test.rego
    ├── cc7/
    │   ├── detection_enabled.rego           # CC7.2 — GAP-06, GAP-08
    │   └── detection_enabled_test.rego
    └── a1/
        ├── object_lock_and_versioning.rego  # A1.2 — GAP-04
        └── object_lock_and_versioning_test.rego
```

## Design decisions

- **Input shape:** every policy runs against the raw output of
  `terraform show -json <plan.tfplan>`. The relevant Terraform-plan-JSON
  key is `resource_changes[]` — an array of resource-address /
  `change.after` pairs. All policies read `input.resource_changes`.
- **Deny-by-default:** each rule appends to `deny[msg]`. Conftest exits
  non-zero on any deny. There are no `warn` rules — for the capstone we
  want the gate to fail closed.
- **Metadata:** every rule file has a top-level `# METADATA` block with
  `custom.controls`, `custom.severity`, `custom.remediation`,
  `custom.hipaa`, and `custom.cmmc`. `opa inspect --annotations` renders
  this; the OSCAL component-definition (`oscal/components/...`) also
  reads it back to link controls to policy files.
- **Tests:** every policy has a sibling `*_test.rego` with at least one
  positive fixture (input that should produce zero denies) and at least
  one negative fixture (input that should produce one or more denies).
  Rule names start with `test_`.

## Running the suite

```bash
# One-off: install conftest (see .tool-versions / WRITEUP.md for pin)
brew install conftest        # or download the release binary

# Against a live Terraform plan
cd terraform
terraform init -input=false
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json

# From the repo root — use --all-namespaces so conftest picks up every
# soc2.* package (default namespace is "main", which we don't use).
conftest test --all-namespaces --parser json --policy policies/ terraform/plan.json

# Run the policy unit tests (positive + negative fixtures)
opa test policies/
# ...or with conftest:
conftest verify --policy policies/
```

The GitHub Actions workflow at `.github/workflows/grc-gate.yml` (Layer
3) runs the same commands in CI and blocks merges whose Terraform plan
fails any policy.

## Adding a policy

1. Pick the TSC control it enforces. If it doesn't map cleanly to a TSC
   ID, it doesn't belong in the SOC 2 suite — put it in a
   framework-appropriate subdirectory instead.
2. Copy an existing policy's `# METADATA` block and fill in the new
   control/severity/remediation values.
3. Write the deny rule against `input.resource_changes`.
4. Write the sibling `_test.rego` — at least one `test_*_pass` (no
   denies) and one `test_*_fail` (>=1 deny).
5. Update `docs/design/00-framework-choice.md` if this adds a new
   in-scope control.

## Framework crossrefs

The `custom.hipaa` and `custom.cmmc` metadata fields on each rule are
consumed by the OSCAL component-definition to produce the crossref
props on each `implemented-requirement`. They are informational — the
policy's primary framework is always SOC 2 (see the framework-choice
doc).
