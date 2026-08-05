######################################################################
# GRC — shared locals for the governance overlay.
#
# Kept separate from the starter's locals so the starter's naming and
# suffixing patterns stay untouched. Everything I define lives under
# `local.grc_*` to avoid confusion with starter locals.
######################################################################

locals {
  # Names for governance resources reuse the starter's random suffix so
  # a single 'terraform apply' produces resources you can pair by suffix
  # in the AWS console. E.g. `acme-health-intake-evidence-<suffix>`.
  grc_name_prefix = "${local.name_prefix}-grc"

  # Object Lock retention on evidence artifacts. 90 days is short for a
  # real SOC 2 Type II engagement (retention typically matches the audit
  # period, often 12 months). For a 30-day capstone with a graded
  # evidence-verification step, 90 days is enough to survive the review
  # window while keeping teardown cheap. Documented in WRITEUP.md.
  grc_evidence_retention_days = 90

  # CloudTrail S3 retention. Longer than evidence — trail records are the
  # authoritative activity log and shouldn't fall off before the evidence
  # bundle they explain.
  grc_cloudtrail_retention_days = 365

  # KMS key rotation period is set on the key itself (annual).
  # AWS-managed rotation is enabled=true; period is not configurable.

  # Tag additions on GRC resources. Merged with the provider default_tags
  # (Project, ManagedBy, Workload, DataClass=phi) via per-resource `tags`.
  grc_common_tags = {
    Layer     = "grc-governance"
    Framework = "soc2-type-ii"
    Owner     = "grc-engineering"
  }
}
