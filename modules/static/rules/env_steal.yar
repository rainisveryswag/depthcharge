rule AWS_Credentials_Steal {
    meta:
        description = "Detects attempt to steal AWS credentials from environment"
        severity = "critical"
    strings:
        $a = "os.environ"
        $b = "AWS_SECRET_ACCESS_KEY"
        $c = "AWS_ACCESS_KEY_ID"
        $d = "AWS_SESSION_TOKEN"
    condition:
        $a and any of ($b,$c,$d)
}

rule Generic_Token_Steal {
    meta:
        description = "Detects environment tokens being exfiltrated over network"
        severity = "high"
    strings:
        $env1 = "os.environ"
        $env2 = "os.getenv"
        $net1 = "requests.post"
        $net2 = "requests.get"
        $net3 = "socket.connect"
        $net4 = "urllib.request"
    condition:
        ($env1 or $env2) and any of ($net1,$net2,$net3,$net4)
}

rule Env_Exfiltration {
    meta:
        description = "Detects environment variables being sent over network"
        severity = "critical"
    strings:
        $a = "os.environ"
        $b = "requests.post"
        $c = "urllib.request.urlopen"
        $d = "socket.connect"
    condition:
        $a and any of ($b,$c,$d)
}
rule Telegram_Exfiltration {
    meta:
        description = "Detects data exfiltration via Telegram bot API"
        severity = "critical"
    strings:
        $a = "api.telegram.org"
        $b = "sendDocument"
        $c = "sendMessage"
    condition:
        $a and any of ($b,$c)
}

rule System_Info_Exfiltration {
    meta:
        description = "Detects system info collection and exfiltration"
        severity = "critical"
    strings:
        $a = "getpass.getuser"
        $b = "platform.node"
        $c = "urllib.request.urlopen"
        $d = "subprocess.check_output"
    condition:
        2 of them
}
