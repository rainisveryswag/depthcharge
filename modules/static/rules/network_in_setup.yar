rule Network_Call_In_Setup {
    meta:
        description = "Detects outbound network calls during package installation"
        severity = "high"
    strings:
        $a = "socket.connect"
        $b = "socket.create_connection"
        $c = "urllib.request.urlopen"
    condition:
        any of them
}

rule Reverse_Shell {
    meta:
        description = "Detects reverse shell pattern via socket"
        severity = "critical"
    strings:
        $a = "socket.socket"
        $b = "connect("
        $c = "subprocess"
    condition:
        $a and $b and $c
}

rule DNS_Exfiltration {
    meta:
        description = "Detects DNS based data exfiltration"
        severity = "high"
    strings:
        $a = "socket.getaddrinfo"
        $b = "socket.gethostbyname"
        $c = "base64"
    condition:
        ($a or $b) and $c
}
rule Hardcoded_Token {
    meta:
        description = "Detects hardcoded Telegram bot token"
        severity = "critical"
    strings:
        $a = /[0-9]{9,10}:AA[A-Za-z0-9_-]{33}/
    condition:
        $a
}

rule MAC_Address_Theft {
    meta:
        description = "Detects MAC address collection for fingerprinting"
        severity = "critical"
    strings:
        $a = "getmac"
        $b = "ifconfig"
        $c = "base64.b64encode"
    condition:
        any of ($a,$b) and $c
}
