package release

# Release gate policy — blocks deployment if security criteria are not met.
#
# Input format:
# {
#   "critical_count": 0,
#   "high_count": 2,
#   "medium_count": 5,
#   "low_count": 10,
#   "scan_age_hours": 4,
#   "quality_gate": "OK",
#   "sbom_generated": true,
#   "secrets_found": 0
# }

default allow = false

# Allow release if all security gates pass
allow {
    critical_gate
    high_gate
    secrets_gate
    freshness_gate
    sbom_gate
}

# No critical vulnerabilities allowed
critical_gate {
    input.critical_count == 0
}

# Maximum 3 high-severity findings
high_gate {
    input.high_count <= 3
}

# No secrets in code
secrets_gate {
    input.secrets_found == 0
}

# Scan must be less than 24 hours old
freshness_gate {
    input.scan_age_hours < 24
}

# SBOM must be generated
sbom_gate {
    input.sbom_generated == true
}

# Denial reasons for debugging
deny[msg] {
    not critical_gate
    msg := sprintf("BLOCKED: %d critical vulnerabilities found (max: 0)", [input.critical_count])
}

deny[msg] {
    not high_gate
    msg := sprintf("BLOCKED: %d high vulnerabilities found (max: 3)", [input.high_count])
}

deny[msg] {
    not secrets_gate
    msg := sprintf("BLOCKED: %d secrets found in code (max: 0)", [input.secrets_found])
}

deny[msg] {
    not freshness_gate
    msg := sprintf("BLOCKED: scan is %d hours old (max: 24h)", [input.scan_age_hours])
}

deny[msg] {
    not sbom_gate
    msg := "BLOCKED: SBOM not generated"
}
