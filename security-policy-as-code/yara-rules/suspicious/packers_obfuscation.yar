rule UPX_Packed
{
    meta:
        description = "File packed with UPX"
        severity = "MEDIUM"
        category = "suspicious"
        author = "Omega-Energy Security"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of ($upx*)
}

rule High_Entropy_Section
{
    meta:
        description = "PE with high-entropy section (likely packed/encrypted)"
        severity = "MEDIUM"
        category = "suspicious"
        author = "Omega-Energy Security"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_sections - 1):
        (
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
        )
}

rule Base64_Encoded_PE
{
    meta:
        description = "Base64-encoded PE file detected in content"
        severity = "MEDIUM"
        category = "suspicious"
        author = "Omega-Energy Security"

    strings:
        $b64_mz = "TVqQAAMAAAAEAAAA" ascii  // MZ header in base64
        $b64_pe = "UEUAAEwB" ascii  // PE\x00\x00L\x01 in base64

    condition:
        any of them
}

rule Obfuscated_PowerShell
{
    meta:
        description = "Obfuscated PowerShell commands"
        severity = "HIGH"
        category = "suspicious"
        author = "Omega-Energy Security"

    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $iex1 = "IEX(" ascii nocase
        $iex2 = "Invoke-Expression" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $download = "DownloadString(" ascii nocase
        $webclient = "Net.WebClient" ascii nocase

    condition:
        2 of them
}
