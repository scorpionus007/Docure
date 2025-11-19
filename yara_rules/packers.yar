/*
 * YARA Rules for Packer Detection
 * Detects common packers and protectors used in malware
 */

rule UPX_Packer
{
    meta:
        description = "Detects UPX (Ultimate Packer for Executables)"
        packer_type = "UPX"
        severity = "medium"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
        $upx5 = "UPX3" ascii
        $upx_section = "UPX" ascii wide
    condition:
        any of them
}

rule ASPack_Packer
{
    meta:
        description = "Detects ASPack packer"
        packer_type = "ASPack"
        severity = "medium"
    strings:
        $aspack1 = "ASPack" ascii
        $aspack2 = "aspack" ascii
        $aspack3 = "ASPack v" ascii
    condition:
        any of them
}

rule PECompact_Packer
{
    meta:
        description = "Detects PECompact packer"
        packer_type = "PECompact"
        severity = "medium"
    strings:
        $pecompact1 = "PECompact" ascii
        $pecompact2 = "PEC2" ascii
        $pecompact3 = "PEC2MO" ascii
    condition:
        any of them
}

rule NSPack_Packer
{
    meta:
        description = "Detects NSPack packer"
        packer_type = "NSPack"
        severity = "medium"
    strings:
        $nspack1 = "NSPack" ascii
        $nspack2 = "nspack" ascii
    condition:
        any of them
}

rule UPack_Packer
{
    meta:
        description = "Detects UPack packer"
        packer_type = "UPack"
        severity = "medium"
    strings:
        $upack1 = "UPack" ascii
        $upack2 = "UPack v" ascii
    condition:
        any of them
}

rule MEW_Packer
{
    meta:
        description = "Detects MEW packer"
        packer_type = "MEW"
        severity = "medium"
    strings:
        $mew1 = "MEW" ascii
        $mew2 = "MEW11" ascii
    condition:
        any of them
}

rule FSG_Packer
{
    meta:
        description = "Detects FSG (Fast Small Good) packer"
        packer_type = "FSG"
        severity = "medium"
    strings:
        $fsg1 = "FSG!" ascii
        $fsg2 = "FSG" ascii
    condition:
        any of them
}

rule Petite_Packer
{
    meta:
        description = "Detects Petite packer"
        packer_type = "Petite"
        severity = "medium"
    strings:
        $petite1 = "Petite" ascii
        $petite2 = "petite" ascii
    condition:
        any of them
}

rule RLPack_Packer
{
    meta:
        description = "Detects RLPack packer"
        packer_type = "RLPack"
        severity = "medium"
    strings:
        $rlpack1 = "RLPack" ascii
        $rlpack2 = "RLPack!" ascii
    condition:
        any of them
}

rule VMProtect_Protector
{
    meta:
        description = "Detects VMProtect protector"
        packer_type = "VMProtect"
        severity = "high"
    strings:
        $vmprotect1 = "VMProtect" ascii
        $vmprotect2 = "VMProtect begin" ascii
        $vmprotect3 = "VMProtect end" ascii
    condition:
        any of them
}

rule Themida_Protector
{
    meta:
        description = "Detects Themida protector"
        packer_type = "Themida"
        severity = "high"
    strings:
        $themida1 = "Themida" ascii
        $themida2 = "TMD" ascii
    condition:
        any of them
}

rule Enigma_Protector
{
    meta:
        description = "Detects Enigma Protector"
        packer_type = "Enigma"
        severity = "high"
    strings:
        $enigma1 = "Enigma Protector" ascii
        $enigma2 = "Enigma" ascii
    condition:
        any of them
}

rule Armadillo_Protector
{
    meta:
        description = "Detects Armadillo protector"
        packer_type = "Armadillo"
        severity = "high"
    strings:
        $armadillo1 = "Armadillo" ascii
        $armadillo2 = ".tls" ascii  // Armadillo often uses TLS sections
    condition:
        any of them
}

rule Obsidium_Protector
{
    meta:
        description = "Detects Obsidium protector"
        packer_type = "Obsidium"
        severity = "high"
    strings:
        $obsidium1 = "Obsidium" ascii
        $obsidium2 = "OBSIDIUM" ascii
    condition:
        any of them
}

rule Generic_Packer_Indicators
{
    meta:
        description = "Generic indicators of packing/compression"
        packer_type = "Generic"
        severity = "low"
    strings:
        $pack1 = "PACK" ascii
        $pack2 = "packed" ascii
        $pack3 = "compressed" ascii
        $pack4 = "PACKED" ascii
    condition:
        any of them
}

