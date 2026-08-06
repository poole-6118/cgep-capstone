# CGE-P Capstone — Patient Intake API, governed for SOC 2 Type II

Joe Poole's Certified GRC Engineer (Practitioner) capstone. Wraps the [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) Patient Intake API with the four CGE-P layers so the workload is audit-defensible against **SOC 2 Type II** as the primary framework.

**Full write-up:** [`WRITEUP.md`](./WRITEUP.md) — framework choice, architecture, control coverage, pipeline demonstration, honest gaps, and BOM.

**Grading commit SHA:** any commit on `main`. Every merge produces a fresh signed evidence bundle in the vault under `evidence/<sha>/`. Head-of-`main` at time of review is what to grade.

---

## Grader verification (five minutes)

Everything below runs read-only, from a fresh clone, with no AWS credentials required. The signed evidence bundle is published as a GitHub Actions artefact on every green run to `main`, so it downloads from the public repo in one click.

### 1. Layers exist in the repo

```bash
git clone https://github.com/poole-6118/cgep-capstone && cd cgep-capstone
ls terraform/grc_*.tf                                # Layer 1 — 8 files
ls policies/soc2/*/*.rego | grep -v _test | wc -l    # Layer 2 — 6 policies
ls .github/workflows/grc-gate.yml                    # Layer 3 — pipeline
ls oscal/components/patient-intake-api.json          # Layer 4 — OSCAL
```

### 2. Policy suite passes its own unit tests

```bash
opa test policies/       # PASS: 24/24
```

### 3. Green PR and red PR both visible

- **Green** (all four jobs pass): [`grc-gate` run 31010439664](https://github.com/poole-6118/cgep-capstone/actions/runs/31010439664)
- **Red** (policy gate blocks non-compliant plan): PR [#11](https://github.com/poole-6118/cgep-capstone/pull/11), [`grc-gate` run 31010646301](https://github.com/poole-6118/cgep-capstone/actions/runs/31010646301). Closed unmerged, as designed.

### 4. Verify a signed evidence bundle end-to-end

**Grab the bundle from the latest green run** (no AWS access needed):

1. Go to the [Actions tab](https://github.com/poole-6118/cgep-capstone/actions/workflows/grc-gate.yml?query=branch%3Amain+is%3Asuccess) and open the newest green run on `main`.
2. Scroll to *Artifacts* and download `evidence-<sha>` — a zip containing:
   - `evidence-<sha>.tar.gz` + `.sig` + `.cert` — the signed bundle itself
   - `vault-attestation.json` + `.sig` + `.cert` — a signed statement of the vault-side state (Object Lock mode, retention date, SSE-KMS, versioning) captured *after* the bundle was uploaded to S3
3. Unzip into a working directory.

Then from that directory:

```bash
SHA=$(ls evidence-*.tar.gz | sed 's/evidence-\(.*\)\.tar\.gz/\1/')

# (a) SHA-256 matches what the pipeline recorded in the run log for the
#     'evidence bundle sha256:' line (also mirrored in pointer.json in the vault).
sha256sum evidence-${SHA}.tar.gz

# (b) Cosign keyless signature verifies against Sigstore — this is the
#     tamper-evident guarantee. Only a signature minted by *this* repo's
#     GHA workflow via OIDC will verify.
cosign verify-blob \
  --certificate evidence-${SHA}.tar.gz.cert \
  --signature   evidence-${SHA}.tar.gz.sig \
  --certificate-identity-regexp 'https://github\.com/poole-6118/cgep-capstone/.*' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  evidence-${SHA}.tar.gz
# → "Verified OK"

# (c) Inspect what got signed.
tar tzf evidence-${SHA}.tar.gz
# → manifest.json, plan.json, state-summary.json,
#    policy-results.txt, policy-results.json
```

**Object Lock retention proof** (no AWS access needed):

```bash
# Verify the signed vault attestation is authentic (same Sigstore chain as the bundle).
cosign verify-blob \
  --certificate vault-attestation.json.cert \
  --signature   vault-attestation.json.sig \
  --certificate-identity-regexp 'https://github\.com/poole-6118/cgep-capstone/.*' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  vault-attestation.json
# → "Verified OK"

# Read the attested vault state.
jq '{ mode: .object.object_lock_mode,
      retain_until: .object.object_lock_retain_until,
      sse: .object.sse,
      cmk: .object.sse_kms_key_id,
      versioning: .bucket_versioning.Status,
      object_lock_default: .bucket_object_lock.Rule.DefaultRetention }' \
   vault-attestation.json
# → GOVERNANCE mode, retain-until ~90 days out, aws:kms SSE with the
#   expected CMK, bucket versioning Enabled, default retention 90 days.
```

The attestation is produced by the pipeline *after* it uploads the bundle to `s3://acme-health-intake-grc-evidence-8d3b72e9/evidence/<sha>/` — it calls `s3:HeadObject`, `s3:GetObjectRetention`, `s3:GetBucketVersioning`, and `s3:GetObjectLockConfiguration`, snapshots the responses to JSON, and Cosign-signs the file with the same OIDC identity that signed the bundle. If the JSON were tampered with, `cosign verify-blob` would fail. If it were signed outside this repo's workflow, the certificate would not match `certificate-identity-regexp`. The vault declaration itself lives in [`terraform/grc_evidence_vault.tf`](./terraform/grc_evidence_vault.tf).

### 5. OSCAL validates with `trestle`

```bash
pip install compliance-trestle
mkdir trestle-check && cd trestle-check && trestle init
mkdir -p component-definitions/patient-intake-api profiles/capstone-profile
cp ../oscal/components/patient-intake-api.json component-definitions/patient-intake-api/component-definition.json
cp ../oscal/profiles/capstone-profile.json     profiles/capstone-profile/profile.json
trestle validate -a
# → VALID: both models
```

---

## Layout

```
cgep-capstone/
├── README.md                # this file
├── WRITEUP.md               # full submission narrative (~450 lines)
├── FRAMEWORKS.md            # starter's framework primer
├── GAPS.md                  # the 8 named gaps the policy suite closes
├── WORKLOAD.md              # what the API does
├── Makefile                 # make deploy | test | destroy
├── docs/design/             # ADRs: framework choice, plan, TF structure
├── terraform/               # Layer 1 — starter + GRC overlay (grc_*.tf)
├── policies/soc2/           # Layer 2 — 6 Rego policies, 24 unit tests
├── .github/workflows/       # Layer 3 — grc-gate.yml
└── oscal/                   # Layer 4 — component + profile
```

---

## Attribution

Starter code and framework primer are from [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter). Every additional file, policy, workflow, and OSCAL artefact in this repository was authored for this capstone submission and is signed with Cosign keyless per merge.

License follows the starter: MIT.
