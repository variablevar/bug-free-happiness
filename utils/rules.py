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

# Well-known CDN / cloud prefixes (browser/update traffic — not malware C2 by IP alone).
KNOWN_BENIGN_IP_PREFIXES = (
    "142.250.",
    "172.217.",
    "173.194.",
    "216.239.",
    "74.125.",
    "13.107.",
    "20.",
    "40.",
    "52.",
    "104.",
)


def is_known_benign_ip(addr: str) -> bool:
    """True for common Google/Microsoft/CDN ranges used by browsers and updates."""
    if not addr or addr in ("*", "-", "0.0.0.0"):
        return False
    a = str(addr).strip()
    if PRIVATE_IP_RE.match(a):
        return True
    return any(a.startswith(p) for p in KNOWN_BENIGN_IP_PREFIXES)

