# Acme Health GRC Capstone — Write-Up

## Framework Selection: CMMC Level 2

For this assessment, I am selecting **CMMC Level 2** as the primary compliance framework, using **NIST SP 800-171** as the OSCAL catalog baseline.

Although Acme Health is a telehealth company and HIPAA is the most direct regulatory fit for protecting patient health information, the scenario also identifies a potential **federal pilot opportunity**. That changes the strategic compliance priority. If Acme intends to support federal work or handle Controlled Unclassified Information (CUI) in the future, CMMC Level 2 becomes the defensible, forward-looking choice — and one that must be designed in from the start, not retrofitted later.

CMMC Level 2 is technically appropriate here because it inherits the 110 security practices of NIST SP 800-171, which map directly to the gaps identified in Acme's current environment: insufficient encryption key custody, overly broad IAM permissions, missing boundary controls, no audit logging, and no network isolation for the workload Lambda. Each of these gaps has a named NIST 800-171 control that the remediation closes.

NIST SP 800-171 also provides a practical advantage for compliance-as-code work: NIST publishes 800-171 in OSCAL format, meaning the catalog source URI can be referenced directly in `component-definition.json` and validated with `trestle`. HIPAA does not offer the same OSCAL-native catalog support, making CMMC L2 the stronger fit for this project's technical goals.

Where a gap implicates HIPAA directly (for example, GAP-01 and GAP-02 on PHI encryption key custody), that mapping is noted as a secondary reference in the OSCAL `props` and in the policy metadata. The primary control chain, however, runs through NIST 800-171 throughout.

**Decision:** Primary framework is **CMMC Level 2**. OSCAL catalog source is NIST SP 800-171 Rev. 3.

---

*Sections to be completed: Design Decisions · Gap Remediation · Trade-offs · What's Next · What Didn't Get Done*
