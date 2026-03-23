## What Changed

### No More Keyword Lists
The old `keywords = ["cerber","ransom",...]` is completely gone. Instead, every process is scored by **14 behavioural signals** that catch 0-days equally:

| Signal | Score | Why it catches 0-days |
|---|---|---|
| LOLBin execution | +2 | Attackers always abuse living-off-the-land binaries |
| Path in temp/appdata | +3 | Malware drops to writable dirs |
| Encoded/obfuscated args | +4 | Obfuscation is universal TTPs |
| Script file in args (.hta/.ps1/.vbs) | +2 | Script-based dropper pattern |
| Ransom note reference in args | +4 | Structural, not name-based |
| Abnormal parent-child | +5 | e.g. svchost spawned by explorer |
| External network connections | +N | C2 communication |
| Injected RWX memory | +3×N | Process hollowing/injection |
| lsass full-access handle | +6 | Credential dumping |
| Hidden process (psscan≠pslist) | +8 | Rootkit/DKOM |
| WoW64 mismatch + suspicious | +1 | 32-bit on 64-bit evasion |
| High in-degree anomaly | +2 | Unexpected connection burst |
| Spawned LOLBin child | +2 | Lateral tool transfer |
| Shellcode opcodes in disasm | +2 | JMP/CALL patterns |

### Output: Structured JSON 
```
analysis_report.json
  ├── meta              version, source
  ├── summary           node/edge/suspicious counts
  ├── attack_chain      5 kill-chain steps + MITRE ATT&CK IDs + verdict
  ├── entry_points      scored list of likely entry processes
  ├── processes         all 44 processes with score + severity + reasons
  ├── hidden_processes  DKOM-hidden PIDs
  ├── network           29 suspicious connections
  ├── injections        malfind+VAD regions scored
  ├── credentials       lsass handle holders
  └── drivers           phantom/rootkit drivers
```