import re

PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|\*|-$)"
)

LOLBIN_NET = {
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "certutil.exe",
    "powershell.exe",
    "cmd.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msbuild.exe",
    "cmstp.exe",
}

LSASS_WHITELIST = {
    "csrss.exe",
    "wininit.exe",
    "lsass.exe",
    "werfault.exe",
    "services.exe",
    "winlogon.exe",
    "taskmgr.exe",
    "msmpeng.exe",
    "msseces.exe",
    "antimalware service executable",
}

HIGH_ACCESS_MASKS = {"0x1fffff", "0x1f0fff", "0x143a"}

