rule Exec_Base64 {
    meta:
        description = "Detects base64 decode combined with exec or eval"
        severity = "high"
    strings:
        $a = "base64.b64decode"
        $b = "exec("
        $c = "eval("
    condition:
        $a and ($b or $c)
}

rule Marshal_Load {
    meta:
        description = "Detects marshal.loads used to deserialize hidden bytecode"
        severity = "high"
    strings:
        $a = "marshal.loads"
        $b = "base64.b64decode"
    condition:
        $a and $b
}

rule Multilevel_Obfuscation {
    meta:
        description = "Detects multiple layers of encoding"
        severity = "high"
    strings:
        $a = "base64.b64decode"
        $b = "zlib.decompress"
        $c = "exec("
    condition:
        2 of them
}

rule Exec_Chr_Obfuscation {
    meta:
        description = "Detects exec with chr() map obfuscation technique"
        severity = "critical"
    strings:
        $a = "exec("
        $b = "map(chr"
        $c = "join("
    condition:
        $a and $b and $c
}

rule BlankOBF_Obfuscation {
    meta:
        description = "Detects BlankOBF obfuscation pattern"
        severity = "critical"
    strings:
        $a = "BlankOBF"
        $b = /eval\("\\x[0-9a-f]{2}/
        $c = "_____=eval"
    condition:
        any of them
}
