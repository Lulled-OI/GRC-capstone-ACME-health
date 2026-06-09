# Acme Health GRC Capstone

**Student:** Lulled-OI  
**Framework:** CMMC Level 2 / NIST SP 800-171 Rev. 3  
**Submission SHA:** `e57172b27f6d86ccf8a251d14f3d6cef1f6bfe35`

GRC controls wrapped around the [cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter) Patient Intake API. Four layers — Terraform baseline, OPA policy suite, GitHub Actions pipeline, OSCAL component — make the starter audit-defensible against CMMC Level 2.

---

## Repo Structure

```
├── terraform/
│   ├── main.tf              # starter workload + gap patches (GAP-02, 05, 07, 08)
│   ├── kms.tf               # customer-managed KMS keys (PHI + evidence)
│   ├── evidence.tf          # S3 evidence vault, COMPLIANCE Object Lock, versioning
│   ├── cloudtrail.tf        # multi-region CloudTrail with log file validation
│   ├── gap_overrides.tf     # S3 encryption, TLS policy, versioning, VPC sg, IAM
│   └── outputs.tf
├── policies/
│   ├── sc13_11_kms_encryption.rego       # GAP-01/02 — SSE-KMS required
│   ├── sc13_8_tls_enforcement.rego       # GAP-03  — TLS-only S3 access
│   ├── ac1_5_least_privilege.rego        # GAP-07  — no wildcard IAM actions
│   ├── sc13_1_vpc_boundary.rego          # GAP-05  — Lambda must be in VPC
│   ├── au3_1_audit_logging.rego          # GAP-08  — API Gateway access logging
│   └── *_test.rego                       # 16 tests, all passing
├── .github/workflows/
│   └── grc-gate.yml         # Plan → Policy Check → Apply → Sign → Upload
├── oscal/components/
│   └── acme-health-intake.json           # NIST 800-171 component definition
└── WRITEUP.md               # design decisions, gap remediation, trade-offs
```

---

## Grader Verification

### 1. Run OPA policy tests

```bash
opa test ./policies
# Expected: 16/16 pass
```

### 2. Verify green PR and red PR

| PR | Result |
|---|---|
| [PR #2 — grc baseline](https://github.com/Lulled-OI/GRC-capstone-ACME-health/pull/2) | Policy Check PASS → merged |
| [PR #3 — red pr](https://github.com/Lulled-OI/GRC-capstone-ACME-health/pull/3) | Policy Check FAIL → blocked |

### 3. Verify signed evidence bundle

```bash
# List bundles in the vault
aws s3 ls s3://acme-health-intake-evidence-<suffix>/pipeline/ --profile <your-profile>

# Verify Cosign signature
cosign verify-blob \
  --bundle <bundle>.tar.gz.bundle \
  <bundle>.tar.gz
```

### 4. Verify Object Lock on evidence vault

```bash
aws s3api get-object-retention \
  --bucket acme-health-intake-evidence-<suffix> \
  --key pipeline/<bundle>.tar.gz \
  --profile <your-profile>
```

### 5. Validate OSCAL component

```bash
trestle validate --file oscal/components/acme-health-intake.json
```

---

## Pipeline

`.github/workflows/grc-gate.yml` runs on every push to `main` and every PR targeting `main`:

1. **Plan** — `terraform plan -out=tfplan.binary && terraform show -json`
2. **Policy Check** — `conftest test tfplan.json --policy ./policies --all-namespaces`
3. **Apply** — `terraform apply` (main branch only)
4. **Sign** — `cosign sign-blob` keyless via GitHub OIDC
5. **Upload** — signed bundle → S3 evidence vault under COMPLIANCE Object Lock

---

## See Also

- [`WRITEUP.md`](WRITEUP.md) — full design rationale and trade-offs
- [`GAPS.md`](GAPS.md) — the eight named starter gaps
- [`FRAMEWORKS.md`](FRAMEWORKS.md) — framework mapping primer
