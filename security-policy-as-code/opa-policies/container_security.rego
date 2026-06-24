package container

# Container security policy — validates Dockerfile and container configurations.
#
# Input format:
# {
#   "image": "myapp:latest",
#   "user": "root",
#   "ports": [80, 443, 22],
#   "capabilities": ["NET_ADMIN", "SYS_ADMIN"],
#   "privileged": false,
#   "read_only_fs": true,
#   "base_image": "python:3.12-slim",
#   "base_image_pinned": true
# }

default allow = false

allow {
    not_root
    no_dangerous_caps
    not_privileged
    no_ssh_port
    pinned_base
}

# Container must not run as root
not_root {
    input.user != "root"
    input.user != "0"
}

# No dangerous capabilities
no_dangerous_caps {
    dangerous := {"SYS_ADMIN", "NET_RAW", "SYS_PTRACE", "DAC_OVERRIDE"}
    count({cap | cap := input.capabilities[_]; dangerous[cap]}) == 0
}

# Container must not be privileged
not_privileged {
    input.privileged == false
}

# SSH port should not be exposed
no_ssh_port {
    not 22 in input.ports
}

# Base image must be pinned (not :latest)
pinned_base {
    input.base_image_pinned == true
}

# Violation details
deny[msg] {
    not not_root
    msg := "Container runs as root — specify a non-root USER"
}

deny[msg] {
    not no_dangerous_caps
    msg := sprintf("Dangerous capabilities: %v", [input.capabilities])
}

deny[msg] {
    not not_privileged
    msg := "Container is running in privileged mode"
}

deny[msg] {
    not no_ssh_port
    msg := "SSH port (22) should not be exposed in containers"
}

deny[msg] {
    not pinned_base
    msg := "Base image must be pinned to specific version (no :latest)"
}
