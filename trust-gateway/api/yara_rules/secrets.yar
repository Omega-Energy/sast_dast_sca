rule HardcodedAWSKey {
    meta:
        description = "AWS Access Key hardcoded in source"
        severity = "HIGH"
        category = "secrets"
    strings:
        $key = /AKIA[0-9A-Z]{16}/ fullword
    condition:
        $key
}

rule HardcodedAWSSecret {
    meta:
        description = "AWS Secret Key pattern"
        severity = "HIGH"
        category = "secrets"
    strings:
        $s1 = /aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*['\"][A-Za-z0-9\/+=]{40}['\"]/  nocase
    condition:
        $s1
}

rule HardcodedPrivateKey {
    meta:
        description = "Private key (PEM) embedded in file"
        severity = "HIGH"
        category = "secrets"
    strings:
        $pem = "-----BEGIN RSA PRIVATE KEY-----"
        $ec  = "-----BEGIN EC PRIVATE KEY-----"
        $gen = "-----BEGIN PRIVATE KEY-----"
    condition:
        any of them
}

rule HardcodedPassword {
    meta:
        description = "Hardcoded password assignment"
        severity = "MEDIUM"
        category = "secrets"
    strings:
        $p1 = /password\s*=\s*['"][^'"]{6,}['"]/ nocase
        $p2 = /passwd\s*=\s*['"][^'"]{6,}['"]/ nocase
        $p3 = /secret\s*=\s*['"][^'"]{8,}['"]/ nocase
    condition:
        any of them
}

rule HardcodedToken {
    meta:
        description = "Generic API token or bearer token"
        severity = "MEDIUM"
        category = "secrets"
    strings:
        $t1 = /token\s*=\s*['"][A-Za-z0-9_\-\.]{20,}['"]/ nocase
        $t2 = /api[_\-]?key\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]/ nocase
        $t3 = /bearer\s+[A-Za-z0-9_\-\.]{20,}/ nocase
    condition:
        any of them
}
