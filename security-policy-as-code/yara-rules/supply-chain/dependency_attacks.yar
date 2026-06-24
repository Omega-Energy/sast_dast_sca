rule Typosquatting_Install_Scripts
{
    meta:
        description = "Suspicious install script patterns common in supply-chain attacks"
        severity = "HIGH"
        category = "supply-chain"
        author = "Omega-Energy Security"

    strings:
        $setup1 = "setup(" ascii
        $cmd1 = "os.system(" ascii
        $cmd2 = "subprocess.call(" ascii
        $cmd3 = "subprocess.run(" ascii
        $net1 = "urllib.request.urlopen(" ascii
        $net2 = "requests.get(" ascii
        $net3 = "socket.socket(" ascii
        $exfil1 = "/etc/passwd" ascii
        $exfil2 = "~/.ssh" ascii
        $exfil3 = ".env" ascii
        $exfil4 = "AWS_SECRET" ascii

    condition:
        $setup1 and (1 of ($cmd*)) and (1 of ($net*) or 1 of ($exfil*))
}

rule NPM_Postinstall_Suspicious
{
    meta:
        description = "Suspicious postinstall script in package.json"
        severity = "HIGH"
        category = "supply-chain"
        author = "Omega-Energy Security"

    strings:
        $post = "\"postinstall\"" ascii
        $pre = "\"preinstall\"" ascii
        $curl = "curl " ascii
        $wget = "wget " ascii
        $node_exec = "node -e" ascii
        $eval = "eval(" ascii

    condition:
        ($post or $pre) and (1 of ($curl, $wget, $node_exec, $eval))
}

rule PyPI_Stealer_Pattern
{
    meta:
        description = "Python package with data exfiltration pattern"
        severity = "HIGH"
        category = "supply-chain"
        author = "Omega-Energy Security"

    strings:
        $import1 = "import os" ascii
        $import2 = "import platform" ascii
        $import3 = "import getpass" ascii
        $collect1 = "os.environ" ascii
        $collect2 = "platform.node()" ascii
        $collect3 = "getpass.getuser()" ascii
        $send1 = "requests.post(" ascii
        $send2 = "urllib" ascii
        $webhook = "discord" ascii nocase
        $webhook2 = "webhook" ascii nocase

    condition:
        2 of ($import*) and 2 of ($collect*) and (1 of ($send*) or 1 of ($webhook*))
}
