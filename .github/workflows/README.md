# GitHub Actions workflows

## `grc-gate.yml` — the GRC evidence pipeline

Layer 3 of the CGE-P capstone. One workflow, four jobs:

```
      ┌────────────┐   ┌───────────────┐   ┌────────────┐   ┌──────────────────────┐
PR →  │ plan       │─→ │ policy-gate   │─→ │ apply      │─→ │ evidence             │
push  │ fmt/valid  │   │ opa test +    │   │ terraform  │   │ tar → cosign sign    │
      │ plan.json  │   │ conftest      │   │ apply      │   │ → S3 Object Lock     │
      └────────────┘   └───────────────┘   └────────────┘   └──────────────────────┘
      always run       always run          push to main     push to main
                       (fails closed)      only             only
```

### What each job does

| Job | Trigger | Purpose |
|---|---|---|
| **plan** | PR + push | `terraform fmt -check` → `init` → `validate` → `plan -out=plan.tfplan` → `show -json > plan.json` → upload as artefact. Also computes and prints the plan's SHA-256 so a reviewer can compare against the value baked into the evidence bundle later. |
| **policy-gate** | PR + push | Downloads the plan artefact. Runs `opa test policies/` first (fails fast if the policy suite itself is broken). Then `conftest test --all-namespaces --parser json --policy policies/ plan.json`. Any `deny` message returned by any policy in `policies/soc2/**` causes the job (and the whole workflow) to fail. Machine-readable results (`policy-results.json`) are uploaded for the evidence bundle. |
| **apply** | push to `main` only | Downloads the plan artefact. `terraform init && terraform apply plan.tfplan`. Then `terraform show -json` → filtered `state-summary.json` (address / type / mode only — no attribute values, so no PHI leaks into the evidence trail). Uploads the summary as an artefact. |
| **evidence** | push to `main` only | Bundles `manifest.json` + `plan.json` + `state-summary.json` + `policy-results.{txt,json}` into `evidence-<sha>.tar.gz`. Signs it via `cosign sign-blob --yes --oidc-issuer=https://token.actions.githubusercontent.com` (keyless — the signing key is the GHA OIDC token, so the certificate binds the signature to this repo + workflow + commit). Uploads bundle + `.sig` + `.cert` + a `pointer.json` metadata file to `s3://$EVIDENCE_BUCKET/evidence/<sha>/`. |

### Required secrets

| Secret | Purpose | Notes |
|---|---|---|
| `AWS_ROLE_ARN` | IAM role assumed via GitHub OIDC. | The role's trust policy must allow `token.actions.githubusercontent.com` and restrict the subject to `repo:poole-6118/cgep-capstone:*` (or narrower — `:ref:refs/heads/main` for the apply/evidence path). |
| `EVIDENCE_BUCKET` | S3 bucket the signed bundle uploads to. | Provisioned by Layer 1 as the Object Lock evidence vault. The IAM role must have `s3:PutObject` on `<bucket>/evidence/*`. |

### Permissions

Workflow-level:

```yaml
permissions:
  id-token: write   # required for AWS OIDC and Cosign keyless
  contents: read    # read the checked-out code; nothing more
```

We deliberately do **not** grant `contents: write`, `pull-requests: write`, or `packages: write`. The workflow reads code and writes only to AWS (via the OIDC-federated role).

### Pinning policy

**Every action is pinned to a full commit SHA, not a `@v4` tag.** Tags are mutable in the GitHub Actions marketplace; SHAs are not. Rotation cadence is quarterly; each rotation bumps every SHA in a single PR and this table:

| Action | SHA | Version |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | v7.0.1 |
| `actions/download-artifact` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | v8.0.1 |
| `aws-actions/configure-aws-credentials` | `e6de054238d6b7531b4efff3b6587d9aade6a06c` | v6.2.3 |
| `hashicorp/setup-terraform` | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` | v4.0.1 |
| `sigstore/cosign-installer` | `6f9f17788090df1f26f669e9d70d6ae9567deba6` | v4.1.2 |

Tool versions (`terraform`, `conftest`, `opa`, `cosign`) are pinned in the workflow's `env:` block and mirrored in `WRITEUP.md` §Bill of Materials.

### Verifying an evidence bundle (what a grader does)

Detailed steps live in `WRITEUP.md` §"Evidence Verification". Short version:

```bash
# 1. Fetch the bundle + sig + cert from S3 (or from the GHA artefact).
aws s3 cp s3://$EVIDENCE_BUCKET/evidence/<sha>/ ./evidence-<sha>/ --recursive

# 2. Recompute the SHA-256 and compare against pointer.json.
sha256sum evidence-<sha>/evidence.tar.gz
jq -r .bundle_sha256 evidence-<sha>/pointer.json

# 3. Verify the Cosign signature (keyless).
cosign verify-blob \
  --certificate       evidence-<sha>/evidence.tar.gz.cert \
  --signature         evidence-<sha>/evidence.tar.gz.sig  \
  --certificate-identity-regexp 'https://github\.com/poole-6118/cgep-capstone/.*' \
  --certificate-oidc-issuer   https://token.actions.githubusercontent.com \
  evidence-<sha>/evidence.tar.gz

# 4. Inspect the bundle contents.
tar -tzf evidence-<sha>/evidence.tar.gz
```

### Local development

To run only the parts that don't need AWS:

```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate

# The plan step needs AWS creds; skip it locally, or use a fake provider.

# Policy suite unit tests (no AWS):
opa test policies/ -v

# Gate against a hand-crafted plan.json (see WRITEUP.md fixtures):
conftest test --all-namespaces --parser json --policy policies/ path/to/plan.json
```
