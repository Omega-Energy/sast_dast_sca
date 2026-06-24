package compliance

# Compliance policy — checks adherence to organizational security standards.
#
# Input format:
# {
#   "project": {
#     "name": "myapp",
#     "classification": "internal",  // public | internal | confidential | restricted
#     "has_encryption": true,
#     "stores_pii": true
#   },
#   "scan_results": {
#     "sast_passed": true,
#     "sca_passed": true,
#     "secrets_clean": true,
#     "dast_passed": false
#   },
#   "artifacts": {
#     "sbom_exists": true,
#     "signed": true,
#     "scan_report_exists": true
#   }
# }

default compliant = false

# Project is compliant if all required checks pass for its classification
compliant {
    basic_checks
    classification_checks
}

# Basic checks required for all projects
basic_checks {
    input.scan_results.sast_passed == true
    input.scan_results.secrets_clean == true
    input.artifacts.scan_report_exists == true
}

# Additional checks based on data classification
classification_checks {
    input.project.classification == "public"
}

classification_checks {
    input.project.classification == "internal"
    input.scan_results.sca_passed == true
}

classification_checks {
    input.project.classification == "confidential"
    input.scan_results.sca_passed == true
    input.scan_results.dast_passed == true
    input.artifacts.sbom_exists == true
}

classification_checks {
    input.project.classification == "restricted"
    input.scan_results.sca_passed == true
    input.scan_results.dast_passed == true
    input.artifacts.sbom_exists == true
    input.artifacts.signed == true
}

# PII handling requires additional encryption check
pii_compliant {
    not input.project.stores_pii
}

pii_compliant {
    input.project.stores_pii
    input.project.has_encryption == true
}

# Violation messages
violations[msg] {
    not input.scan_results.sast_passed
    msg := "SAST scan not passed"
}

violations[msg] {
    not input.scan_results.secrets_clean
    msg := "Secrets detected in code"
}

violations[msg] {
    input.project.classification != "public"
    not input.scan_results.sca_passed
    msg := sprintf("SCA required for %s classification", [input.project.classification])
}

violations[msg] {
    input.project.stores_pii
    not input.project.has_encryption
    msg := "PII storage requires encryption"
}
