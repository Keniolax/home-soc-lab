# Detection coverage matrix

One row per emulated technique. Verdict is what the SIEM did during the
technique's run window.

| Technique | ATT&CK | Tactic | Verdict | Rules fired |
|---|---|---|---|---|
| Brute Force: Password Guessing | T1110.001 | credential-access | 🟢 detected | 5710 (L5), 5712 (L10) |
| Create Account: Local Account | T1136.001 | persistence | 🟢 detected | 5902 (L8) |
| Account Discovery: Local Account | T1087.001 | discovery | 🔴 blind | — |
| System Information Discovery | T1082 | discovery | 🔴 blind | — |
| System Owner/User Discovery | T1033 | discovery | 🔴 blind | — |
| Process Discovery | T1057 | discovery | 🔴 blind | — |
| File and Directory Discovery | T1083 | discovery | 🔴 blind | — |
| Network Service Discovery | T1046 | discovery | 🔴 blind | — |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | execution | 🔴 blind | — |
| Account Manipulation: SSH Authorized Keys | T1098.004 | persistence | 🔴 blind | — |
| Event Triggered Execution: Unix Shell Configuration Modification | T1546.004 | persistence | 🟡 logged | — |
| File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification | T1222.002 | defense-evasion | 🔴 blind | — |
| Indicator Removal: Clear Command History | T1070.003 | defense-evasion | 🔴 blind | — |
| Unsecured Credentials: Credentials In Files | T1552.001 | credential-access | 🔴 blind | — |
