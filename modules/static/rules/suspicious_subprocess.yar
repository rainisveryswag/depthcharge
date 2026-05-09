rule Subprocess_Shell {
    meta:
        description = "Detects subprocess spawning a shell with network"
        severity = "high"
    strings:
        $a = "subprocess.Popen"
        $b = "subprocess.call"
        $c = "subprocess.run"
        $d = "shell=True"
        $e = "socket"
        $f = "urllib"
    condition:
        any of ($a,$b,$c) and $d and any of ($e,$f)
}

rule OS_System_Call {
    meta:
        description = "Detects os.system usage to run shell commands"
        severity = "high"
    strings:
        $a = "os.system("
        $b = "os.popen("
    condition:
        any of them
}

rule Persistence_Mechanism {
    meta:
        description = "Detects attempt to write persistence via cron or startup"
        severity = "critical"
    strings:
        $a = "crontab"
        $b = ".bashrc"
        $c = ".bash_profile"
        $e = "/etc/rc"
    condition:
        any of them
}
