rule CryptoMiner_Strings
{
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "HIGH"
        category = "crypto"
        author = "Omega-Energy Security"

    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $pool3 = "pool.minergate" ascii nocase
        $pool4 = "xmrpool" ascii nocase
        $pool5 = "nanopool" ascii nocase
        $pool6 = "2miners" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
        $tool1 = "xmrig" ascii nocase
        $tool2 = "cpuminer" ascii nocase
        $tool3 = "cgminer" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii  // BTC address
        $xmr = /4[0-9AB][0-9a-zA-Z]{93}/ ascii  // XMR address

    condition:
        2 of ($pool*) or 2 of ($algo*) or any of ($tool*) or ($wallet and 1 of ($pool*))
}

rule Unauthorized_Crypto_Usage
{
    meta:
        description = "Non-standard cryptographic library usage that may indicate custom crypto"
        severity = "MEDIUM"
        category = "crypto"
        author = "Omega-Energy Security"

    strings:
        $custom1 = "def encrypt(" ascii
        $custom2 = "def decrypt(" ascii
        $xor1 = "XOR" ascii
        $xor2 = "^ key" ascii
        $rot = "rot13" ascii nocase
        $b64 = "base64" ascii
        $no_lib = "AES" ascii

    condition:
        ($custom1 or $custom2) and ($xor1 or $xor2 or $rot) and not $no_lib
}
