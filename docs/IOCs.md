# Indicators of Compromise (IOCs)

tags: #IOC #MITRE #forensics #ransomware

MalVol detects four categories of memory-resident IOCs, mapped to MITRE ATT&CK:

---

## 1. Code Injection

**Script:** `code_injection_analysis.py`  
**Volatility plugin:** `windows.malfind`  
**MITRE:** T1055 — Process Injection

Detects suspicious executable memory regions with RWX permissions and MZ headers — a classic indicator of injected shellcode or PE files.

---

## 2. Hidden Processes

**Script:** `hidden_proc_analysis.py`  
**Volatility plugins:** `windows.psscan` vs `windows.pslist`  
**MITRE:** T1564 — Hide Artefacts

Processes visible in `psscan` (raw pool scanning) but absent from `pslist` (walk the EPROCESS linked list) indicate rootkit-style process hiding.

---

## 3. Suspicious File Staging

**Script:** `filescan_analysis.py`  
**Volatility plugin:** `windows.filescan`  
**MITRE:** T1486 — Data Encrypted for Impact

Scans for executables and payloads in unusual paths (Temp, AppData, ProgramData) — common ransomware staging behaviour.

---

## 4. Non-Standard Network Activity

**Script:** `network_analysis.py`  
**Volatility plugin:** `windows.netscan`  
**MITRE:** T1071 — Application Layer Protocol (C2)

Flags ESTABLISHED connections to external IPs on unusual ports, indicative of C2 beaconing.

---

## Heuristic Scoring

The `filter_malicious.py` heuristic engine scores across 5 MITRE dimensions:

| Tactic | MITRE | Signal |
|---|---|---|
| Initial Access / Execution | T1218, T1566 | LOLBin usage, script extensions in args |
| Defense Evasion / Injection | T1055 | malfind RWX + MZ header |
| Command & Control | T1071 | ESTABLISHED external connections |
| Credential Access | T1003.001 | Full LSASS handle (0x1fffff) |
| Execution / Impact | T1486 | High-score processes, ransomware note args |

Verdict levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`
