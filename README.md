# CGE-P Capstone — Patient Intake API, governed for SOC 2 Type II

Joe Poole's Certified GRC Engineer (Practitioner) capstone. Wraps the [`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter) Patient Intake API with the four CGE-P layers so the workload is audit-defensible against **SOC 2 Type II** as the primary framework.

**Full write-up:** [`WRITEUP.md`](./WRITEUP.md) — framework choice, architecture, control coverage, pipeline demonstration, honest gaps, and BOM.

**Grading commit SHA:** any commit on `main`. Every merge produces a fresh signed evidence bundle in the vault under `evidence/<sha>/`. Head-of-`main` at time of review is what to grade.

---

## Grader verification (five minutes)

Everything below runs read-only and needs no AWS credentials for the core proof (only `cosign` + `sha256sum` + a downloaded bundle).

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

Bundles are named by commit SHA. This example uses the writeup-merge SHA `c04f9153252f1bea6b77dd699212d2f8248d893e`.

```bash
mkdir verify && cd verify
SHA=c04f9153252f1bea6b77dd699212d2f8248d893e
BUCKET=acme-health-intake-grc-evidence-8d3b72e9

aws s3 cp "s3://${BUCKET}/evidence/${SHA}/" . --recursive
# → evidence.tar.gz, evidence.tar.gz.sig, evidence.tar.gz.cert, pointer.json

# (a) SHA-256 matches the pointer.
computed=$(sha256sum evidence.tar.gz | cut -d' ' -f1)
recorded=$(jq -r .bundle_sha256 pointer.json)
[ "$computed" = "$recorded" ] && echo "sha256 OK"

# (b) Cosign keyless signature verifies against Sigstore.
cosign verify-blob \
  --certificate evidence.tar.gz.cert \
  --signature   evidence.tar.gz.sig \
  --certificate-identity-regexp 'https://github\.com/poole-6118/cgep-capstone/.*' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  evidence.tar.gz
# → "Verified OK"

# (c) Object Lock retention holds.
aws s3api get-object-retention --bucket "${BUCKET}" \
  --key "evidence/${SHA}/evidence.tar.gz"
# → GOVERNANCE mode, retain-until ~90 days out
```

The bundle contents (once extracted with `tar -xzf evidence.tar.gz`) include the Terraform plan JSON, a filtered state summary, `manifest.json` binding to the commit SHA, and the machine-readable `policy-results.json` from the Conftest run that gated the merge.

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
