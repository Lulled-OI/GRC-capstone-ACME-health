# Acme Health GRC Capstone — Write-Up

## Framework Selection: CMMC Level 2

For this assessment, I am selecting **CMMC Level 2** as the primary compliance framework, using **NIST SP 800-171** as the OSCAL catalog baseline.

Although Acme Health is a telehealth company and HIPAA is the most direct regulatory fit for protecting patient health information, the scenario also identifies a potential **federal pilot opportunity**. That changes the strategic compliance priority. If Acme intends to support federal work or handle Controlled Unclassified Information (CUI) in the future, CMMC Level 2 becomes the defensible, forward-looking choice — and one that must be designed in from the start, not retrofitted later.

CMMC Level 2 is technically appropriate here because it inherits the 110 security practices of NIST SP 800-171, which map directly to the gaps identified in Acme's current environment: insufficient encryption key custody, overly broad IAM permissions, missing boundary controls, no audit logging, and no network isolation for the workload Lambda. Each of these gaps has a named NIST 800-171 control that the remediation closes.

NIST SP 800-171 also provides a practical advantage for compliance-as-code work: NIST publishes 800-171 in OSCAL format, meaning the catalog source URI can be referenced directly in `component-definition.json` and validated with `trestle`. HIPAA does not offer the same OSCAL-native catalog support, making CMMC L2 the stronger fit for this project's technical goals.

Where a gap implicates HIPAA directly (for example, GAP-01 and GAP-02 on PHI encryption key custody), that mapping is noted as a secondary reference in the OSCAL `props` and in the policy metadata. The primary control chain, however, runs through NIST 800-171 throughout.

**Decision:** Primary framework is **CMMC Level 2**. OSCAL catalog source is NIST SP 800-171 Rev. 3.

---

## Pipeline Evidence: Green PR and Red PR

A core requirement of this capstone is demonstrating that the GRC gate pipeline does two things: it lets compliant code through, and it blocks non-compliant code. Both are proven in this repository's PR history.

| PR | Branch | Policy Check | Outcome | What It Proves |
|---|---|---|---|---|
| [PR #2 — GRC Baseline](https://github.com/Lulled-OI/GRC-capstone-ACME-health/pull/2) | `grc-baseline` | PASS | Merged to main, full pipeline ran | Compliant Terraform passes the gate, triggers Apply, Sign, and Upload |
| [PR #3 — Red PR](https://github.com/Lulled-OI/GRC-capstone-ACME-health/pull/3) | `red-pr/policy-violation` | FAIL | Blocked, never reached Apply | Non-compliant code is caught before it can be deployed |

PR #3 intentionally removed the `aws:SecureTransport` deny statement from the uploads bucket policy, re-introducing GAP-03. The `sc13_8_tls_enforcement` Rego policy detected the violation and failed the pipeline at the Policy Check step — Apply never ran, so no infrastructure change was made. This is the whole point: the gate decides whether deployment happens, not the engineer.

The pipeline executes five named steps in order:

1. **Plan** — Terraform generates a JSON plan of proposed changes
2. **Policy Check** — Conftest runs the OPA policy suite against the plan; failure here aborts the run
3. **Apply** — Terraform applies the plan to AWS (main branch only)
4. **Sign** — Cosign signs the evidence bundle keylessly via GitHub OIDC, producing a Sigstore-verifiable signature
5. **Upload** — The signed bundle lands in the S3 evidence vault under COMPLIANCE-mode Object Lock

---

## Design Decisions

### Layer 1: Terraform Baseline

The GRC baseline was designed to wrap the starter's existing resources without rebuilding them. All new resources reference the starter's VPC, subnets, and resource addresses directly — there is no second network, no duplicate data store.

Two KMS customer-managed keys were provisioned: one for PHI data stores (S3 uploads bucket and DynamoDB submissions table) and one for the evidence vault. Separate keys provide independent blast radius — a compromise of one key does not expose both workloads. Both keys have annual rotation enabled, satisfying the key management requirements of CMMC SC.L2-3.13.11.

The evidence vault uses **COMPLIANCE-mode Object Lock with a 1-day retention period**. COMPLIANCE mode was chosen over GOVERNANCE because it provides true immutability — no user, including root, can delete or shorten retention. The 1-day period is appropriate for a sandbox environment; a production deployment would use a longer period (90+ days) aligned to the organization's retention policy.

CloudTrail was configured as a multi-region trail with log file validation enabled. This ensures that management events across all regions are captured and that log integrity can be verified cryptographically — satisfying CMMC AU.L2-3.3.1 and AU.L2-3.3.2.

### Layer 2: OPA Policy Suite

Five Rego policies enforce CMMC L2 controls at plan time. Each policy targets a specific gap from `GAPS.md` and cites the relevant NIST 800-171 control ID in its deny message so a developer reading a failed PR knows exactly what to fix.

| Policy | Gap | Control | What It Catches |
|---|---|---|---|
| `sc13_11_kms_encryption` | GAP-01, GAP-02 | SC.L2-3.13.11 | S3 or DynamoDB not using SSE-KMS |
| `sc13_8_tls_enforcement` | GAP-03 | SC.L2-3.13.8 | S3 bucket policy missing `aws:SecureTransport` deny |
| `ac1_5_least_privilege` | GAP-07 | AC.L2-3.1.5 | IAM policies using wildcard actions (`dynamodb:*`, `s3:*`) |
| `sc13_1_vpc_boundary` | GAP-05 | SC.L2-3.13.1 | Lambda function missing `vpc_config` block |
| `au3_1_audit_logging` | GAP-08 | AU.L2-3.3.1 | API Gateway stage missing `access_log_settings` |

One design decision worth noting: policies check for the presence of the correct structure at plan time, not the resolved values. KMS key ARNs and CloudWatch log group ARNs are computed references (`known after apply`) in the Terraform plan JSON, so they appear as null. The policies were tuned to accept null ARNs when the correct algorithm or block structure is present — this is the right behavior for plan-time enforcement, where the goal is to catch missing configuration, not to verify runtime values that don't exist yet.

### Gap Remediation Summary

| Gap | Remediation Layer | CMMC Control |
|---|---|---|
| GAP-01: S3 SSE-KMS | Terraform (`gap_overrides.tf`) + OPA policy | SC.L2-3.13.11 |
| GAP-02: DynamoDB CMK | Terraform (`main.tf` patch) + OPA policy | SC.L2-3.13.11 |
| GAP-03: TLS enforcement | Terraform (`gap_overrides.tf`) + OPA policy | SC.L2-3.13.8 |
| GAP-04: S3 versioning | Terraform (`gap_overrides.tf`) | MP.L2-3.8.9 |
| GAP-05: Lambda VPC isolation | Terraform (`main.tf` patch) + OPA policy | SC.L2-3.13.1 |
| GAP-06: Reserved concurrency, DLQ, X-Ray | Not closed — documented below | SI.L2-3.14.6 |
| GAP-07: Least-privilege IAM | Terraform (`gap_overrides.tf`) + OPA policy | AC.L2-3.1.5 |
| GAP-08: API Gateway logging + throttling | Terraform (`main.tf` patch) + OPA policy | AU.L2-3.3.1 |

---

## Trade-offs

**Single AWS account vs. separate evidence vault account.** A production deployment would isolate the evidence vault in a separate AWS account to prevent workload administrators from tampering with audit artifacts. For this capstone, a single account was used. COMPLIANCE-mode Object Lock compensates for the lack of account separation by making evidence immutable even to account administrators.

**Terraform state in S3.** State is stored in a dedicated S3 bucket (`acme-health-intake-tfstate-04edba1b`) so that both local development and the GitHub Actions pipeline operate against the same state. This prevents the pipeline from attempting to re-create resources that already exist.

**GAP-06 not closed in Terraform.** Reserved concurrency, a Dead Letter Queue, and X-Ray tracing (GAP-06) were not closed in the Terraform baseline. These are operational resilience controls (SOC 2 CC7.2, CMMC SI.L2-3.14.6) rather than security controls with direct PHI impact. Given the 30-day scope, closing the five highest-severity gaps (encryption, network isolation, least privilege, audit logging) was prioritized. GAP-06 would be addressed in the next sprint.

**Plan-time vs. apply-time policy enforcement.** Conftest runs against the Terraform plan JSON, which means it catches configuration intent before deployment. It does not verify runtime state in AWS. A mature program would pair this with AWS Config rules for drift detection — that layer was not built in this capstone.

---

## What I Would Do With Another Sprint

- Close GAP-06: add reserved concurrency, DLQ, and X-Ray to the Lambda
- Add AWS Config rules for continuous compliance monitoring (drift detection)
- Move the evidence vault to a separate AWS account
- Extend the OSCAL component with a full profile selecting all 110 NIST 800-171 controls
- Add a `terraform destroy` workflow with evidence vault pre-drain

## What Didn't Get Done

- GAP-06 (reserved concurrency, DLQ, X-Ray) was not closed in Terraform
- No AWS Config rules — runtime drift is not monitored
- Evidence vault account separation was not implemented
- OSCAL profile does not enumerate all 110 800-171 controls, only the ones directly implemented

---

*Section to be completed: OSCAL Component*
