# 02 — Starter Baseline Verified

**Status:** Complete
**Date:** 2026-08-05
**Related:** [`00-framework-choice.md`](./00-framework-choice.md), [`01-capstone-plan.md`](./01-capstone-plan.md)

## Purpose

The CGE-P starter (`GRCEngClub/cgep-app-starter`) ships intentionally non-compliant. Before I can wrap it with governance layers, I have to prove it deploys clean and the API works end-to-end. Real GRC engineers inherit working systems; step zero is confirming the system runs.

## What I did

1. Provisioned a scoped IAM user (`cgep-capstone`) in the personal AWS sandbox account (`837009194688`) with policies attached for API Gateway, Lambda, S3, DynamoDB, VPC, KMS, CloudTrail, IAM, and CloudWatch — no `AdministratorAccess`. Access key stored in 1P + on-disk profile.
2. `make deploy` against `us-east-1` — 21 resources created:
   - 1 VPC + 2 public + 2 private subnets + IGW + route tables
   - 1 Lambda function (Python handler)
   - 1 API Gateway HTTP API + integration + route + stage
   - 1 DynamoDB table (`acme-health-intake-submissions-*`)
   - 1 S3 bucket (`acme-health-intake-uploads-*`)
   - 1 IAM role + 1 inline role policy for the Lambda
   - Miscellaneous supporting resources (permissions, random suffix)
3. `make test` — POSTed a synthetic intake payload:
   ```json
   {"patient_id":"P-0001","fields":{"reason":"smoke-test"}}
   ```
   Response:
   ```json
   {"submission_id": "4c356ce2-036a-4688-b5a5-d7f328af2f1e", "status": "received"}
   ```
   API is live, Lambda executes, DynamoDB accepts the write.
4. `make destroy` — all 21 resources torn down. Account is back to zero-cost for the workload.

## What I did not touch

- No changes to the starter's `terraform/`, `Makefile`, or `test/`. This capstone extends the starter; it does not modify it. Later PRs will add new files (baseline modules, policies, workflows, OSCAL) and, where needed, override starter resources via new Terraform blocks — never in-place edits to the starter files.
- No hardening applied. The starter's eight named gaps (see [`GAPS.md`](../../GAPS.md)) are all still present. Closing them is the work of Layers 1–4.

## Cost so far

Deploy + smoke test + destroy in ~5 minutes. Total AWS spend for this run: effectively $0 (pay-per-use resources; empty DynamoDB read/write, one Lambda invocation, no CloudTrail deployed yet).

## Next

PR #2 begins. Branch: `layer1/terraform-baseline`.
