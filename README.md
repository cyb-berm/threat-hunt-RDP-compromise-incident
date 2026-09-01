
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>


# 🕵️ DFIR Investigation: RDP Compromise → C2 → Exfiltration

> A Microsoft Defender for Endpoint (MDE) Advanced Hunting investigation tracing a simulated RDP compromise from initial access through data exfiltration.

**Severity:** 🔴 High &nbsp;|&nbsp; **Status:** ✅ Complete &nbsp;|&nbsp; **Tooling:** Microsoft Defender for Endpoint · KQL / Advanced Hunting


---

## 📖 Table of Contents

- [Overview](#-overview)
- [Attack Chain](#-attack-chain)
- [Investigation Timeline](#-investigation-timeline)
- [Flag-by-Flag Findings](#-flag-by-flag-findings)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Key KQL Queries](#-key-kql-queries)
- [Challenges & How I Solved Them](#-challenges--how-i-solved-them)
- [Lessons Learned](#-lessons-learned)
- [IOC Summary](#-ioc-summary)
- [Conclusion](#-conclusion)

---

## 🧾 Overview

This investigation reconstructs a simulated Windows host compromise using **Microsoft Defender for Endpoint** telemetry and **KQL Advanced Hunting** queries. The attacker gained access via **RDP**, executed a masquerading binary, established persistence, disabled defenses, performed reconnaissance, staged data, and attempted exfiltration to external C2 infrastructure.

The investigation moved sequentially across five MDE tables — `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` — pivoting on indicators discovered at each stage.

---

## 🧩 Attack Chain

```
RDP Initial Access
        │
        ▼
Compromised Account  →  slflare
        │
        ▼
Malicious Execution  →  msupdate.exe
        │
        ▼
Persistence          →  Scheduled Task: MicrosoftUpdateSync
        │
        ▼
Defense Evasion      →  Defender Exclusion: C:\Windows\Temp
        │
        ▼
System Discovery     →  systeminfo
        │
        ▼
Data Staging         →  backup_sync.zip
        │
        ▼
C2 Communication     →  185.92.220.87
        │
        ▼
Exfiltration Attempt →  185.92.220.87:8081
```

---

## 🕒 Investigation Timeline

| Stage | Technique | Description |
|---|---|---|
| 1️⃣ Initial Access | External RDP session | Attacker connects to the host over RDP |
| 2️⃣ Account Compromise | Credential use | Attacker operates as `slflare` |
| 3️⃣ Execution | Malicious binary | Runs `msupdate.exe`, disguised as a legitimate update process |
| 4️⃣ Persistence | Scheduled task | Creates `MicrosoftUpdateSync` to survive reboot/logoff |
| 5️⃣ Defense Evasion | Defender exclusion | Excludes `C:\Windows\Temp` from AV scanning |
| 6️⃣ Discovery | System enumeration | Runs `systeminfo` to profile the host |
| 7️⃣ Collection | Data staging | Compresses data into `backup_sync.zip` |
| 8️⃣ C2 | Outbound beacon | Connects to `185.92.220.87` |
| 9️⃣ Exfiltration | Data transfer attempt | Sends data to `185.92.220.87:8081` |

---

## 🚩 Flag-by-Flag Findings

<details>
<summary><strong>Flag 1 — Initial Access</strong> (T1133 / T1021.001)</summary>

**Objective:** Identify how the attacker initially gained access.

**Approach:** Reviewed `DeviceLogonEvents` for `RemoteInteractive` logon types, filtering on successful authentication, external source IPs, and unusual logon times.

```kql
DeviceLogonEvents
| where DeviceName =~ "TARGET-HOST"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by Timestamp asc
```

**Finding:** Established that the attacker's entry point was an external RDP session.

![Flag 1 - RDP Logon Event](./images/flag1-rdp-logon.png)
</details>

<details>
<summary><strong>Flag 2 — Compromised Account</strong></summary>

**Objective:** Identify the account used by the attacker.

**Approach:** Correlated the successful RDP logon with the account used in subsequent process, registry, file, and network activity.

```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where RemoteIP != ""
| project TimeGenerated, AccountName, RemoteIP, ActionType
```

**Answer:** `slflare`

The query results show a `LogonSuccess` event for `slflare` from remote IP `159.26.106.84`, preceded by two `LogonFailed` attempts from the same source — consistent with a brute-force-then-success RDP pattern. This account became the primary pivot for every later stage of the investigation.

![Flag 2 - Compromised Account](./images/flag2-account.png)
</details>

<details>
<summary><strong>Flag 3 — Executed Binary</strong> (T1059.003 / T1204.002)</summary>

**Objective:** Identify the binary the attacker executed after gaining access.

```kql
DeviceProcessEvents
| where AccountName =~ "slflare"
| where Timestamp between (datetime(2025-09-10 18:40:00) .. datetime(2025-09-17 04:00:00))
| project
    Timestamp, DeviceName, AccountName, FileName, FolderPath,
    ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Answer:** `msupdate.exe` — named to imitate a legitimate Microsoft update process.

**Evidence:** `msupdate.exe` was launched from `C:\Users\Public\msupdate.exe` via PowerShell with:

```
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
```

It then spawned `conhost.exe` and `whoami.exe`, confirming the binary was actively executing and beginning reconnaissance immediately after launch.

![Flag 3 - Malicious Process Execution](./images/flag3-msupdate.png)
</details>

<details>
<summary><strong>Flag 4 — Initial Malicious Activity</strong></summary>

**Objective:** Identify the attacker's next action following execution of `msupdate.exe`.

**Answer:**
```
"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1
```

Immediately after execution, `msupdate.exe` invoked PowerShell with `-ExecutionPolicy Bypass` to run a script staged in the public user directory (`update_check.ps1`), sidestepping the host's PowerShell execution policy restrictions.

![Flag 4 - Initial Malicious Activity](./images/flag4-activity.png)
</details>

<details>
<summary><strong>Flag 5 — Persistence Mechanism</strong> (T1053.005)</summary>

**Objective:** Identify the persistence mechanism the attacker created.

```kql
DeviceProcessEvents
| where DeviceName =~ "TARGET-HOST"
| where ProcessCommandLine has_any ("schtasks", "ScheduledTask", "Register-ScheduledTask")
| project Timestamp, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** Scheduled task `MicrosoftUpdateSync`

> ⚠️ A decoy task, `LabUpdaterTask`, appeared during the search but did not correlate with the attacker's account, host, or timeline — it was ruled out.

![Flag 5 - Scheduled Task Persistence](./images/flag5-scheduled-task.png)
</details>

<details>
<summary><strong>Flag 6 — Defender Configuration Change</strong> (T1562.001)</summary>

**Objective:** Identify the folder excluded from Microsoft Defender scanning.

```kql
DeviceRegistryEvents
| where DeviceName =~ "TARGET-HOST"
| where RegistryKey has_any ("Windows Defender", "Exclusions")
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Answer:** `C:\Windows\Temp`

![Flag 6 - Defender Exclusion](./images/flag6-defender-exclusion.png)
</details>

<details>
<summary><strong>Flag 7 — Discovery Command</strong> (T1082)</summary>

**Objective:** Identify the exact discovery command executed.

```kql
DeviceProcessEvents
| where DeviceName =~ "TARGET-HOST"
| where ProcessCommandLine has_any ("systeminfo", "whoami", "ipconfig", "hostname", "wmic", "ver")
| project Timestamp, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
```

**Answer:** `C:\Windows\System32\cmd.exe /c systeminfo`

![Flag 7 - Discovery Command](./images/flag7-systeminfo.png)
</details>

<details>
<summary><strong>Flag 8 — Archive Created</strong> (T1560.001)</summary>

**Objective:** Identify the archive file created for data staging.

```kql
DeviceFileEvents
| where DeviceName =~ "TARGET-HOST"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Answer:** `backup_sync.zip`

> ⚠️ A second, unrelated archive (`docs.zip`) also appeared and was ruled out via account/process/timeline correlation.

![Flag 8 - Archive Creation](./images/flag8-archive.png)
</details>

<details>
<summary><strong>Flag 9 — C2 Destination</strong> (T1071.001 / T1105)</summary>

**Objective:** Identify the external server the attacker communicated with.

```kql
DeviceNetworkEvents
| where DeviceName =~ "TARGET-HOST"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp asc
```

**Answer:** `185.92.220.87`

![Flag 9 - C2 Network Connection](./images/flag9-c2.png)
</details>

<details>
<summary><strong>Flag 10 — Exfiltration Attempt</strong> (T1048.003)</summary>

**Objective:** Identify the destination IP and port used in the exfiltration attempt.

**Approach:** Reviewed `DeviceNetworkEvents` after archive creation, correlating with the previously identified C2 IP.

**Answer:** `185.92.220.87:8081`

![Flag 10 - Exfiltration Attempt](./images/flag10-exfiltration.png)
</details>

---

## 📊 Flag Answer Reference

| Flag | Finding | MITRE ATT&CK |
|:---:|---|---|
| 1 | RDP initial access | T1133 / T1021.001 |
| 2 | `slflare` | Account Compromise |
| 3 | `msupdate.exe` | T1059.003 / T1204.002 |
| 4 | `msupdate.exe -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` | T1059.001 |
| 5 | `MicrosoftUpdateSync` | T1053.005 |
| 6 | `C:\Windows\Temp` | T1562.001 |
| 7 | `cmd.exe /c systeminfo` | T1082 |
| 8 | `backup_sync.zip` | T1560.001 |
| 9 | `185.92.220.87` | T1071.001 / T1105 |
| 10 | `185.92.220.87:8081` | T1048.003 |

---

## 🧬 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence |
|---|---|---|
| T1133 | External Remote Services | RDP entry point |
| T1021.001 | Remote Services: RDP | Successful remote-interactive logon |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `-ExecutionPolicy Bypass -File update_check.ps1` |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe /c systeminfo` |
| T1204.002 | User Execution: Malicious File | `msupdate.exe` |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `MicrosoftUpdateSync` |
| T1562.001 | Impair Defenses: Disable or Modify Tools | `C:\Windows\Temp` exclusion |
| T1082 | System Information Discovery | `systeminfo` |
| T1560.001 | Archive Collected Data: Local Archiving | `backup_sync.zip` |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 communication |
| T1105 | Ingress Tool Transfer | Tooling retrieval via C2 |
| T1048.003 | Exfiltration Over Unencrypted Protocol | `185.92.220.87:8081` |

---

## 🔍 Key KQL Queries

**Process execution baseline**
```kql
DeviceProcessEvents
| where DeviceName =~ "TARGET-HOST"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

All stage-specific queries are included inline within each [flag write-up](#-flag-by-flag-findings) above.

---

## ⚠️ Challenges & How I Solved Them

**1. Distinguishing malicious from legitimate activity**
The environment contained many legitimate processes, scheduled tasks, and Defender events. A suspicious-looking name — like the decoy `LabUpdaterTask` — wasn't enough on its own. Every artifact had to correlate with the compromised account, host, timestamp, and overall attack timeline before being trusted as evidence.

**2. No single table told the whole story**
The attack had to be reconstructed by pivoting across five tables in sequence:

```
DeviceLogonEvents → DeviceProcessEvents → DeviceRegistryEvents → DeviceFileEvents → DeviceNetworkEvents
```

Each table contributed one piece: account → binary → Defender change → discovery/archive → network activity.

**3. Avoiding false positives**
Multiple archives (`docs.zip` vs. `backup_sync.zip`) and multiple external connections existed in the telemetry. Only correlation with the attacker's account, process, and timeline separated real evidence from noise.

**4. Isolating the correct network destination**
Not every external IP was attacker infrastructure. The C2 IP (`185.92.220.87`) and the exfiltration destination (`185.92.220.87:8081`) were only confirmed by tying network events back to the malicious process and account.

---

## 🧠 Lessons Learned

- **Follow the timeline.** Access → Execution → Persistence → Defense Evasion → Discovery → Collection → C2 → Exfiltration — treating the incident as a connected chain (not isolated events) made everything else click.
- **Pivot on known indicators.** Once `slflare`, `msupdate.exe`, or `backup_sync.zip` was confirmed, each became a search anchor for the next stage.
- **Command-line telemetry is gold.** Knowing `cmd.exe` ran is far less useful than knowing it ran `/c systeminfo`.
- **"Suspicious" ≠ "malicious."** The right question is always *"does this correlate with the attack?"* — not *"does this look bad?"*
- **Failed connections still matter.** Even unsuccessful outbound attempts reveal attacker infrastructure and intent.

---

## 🛡️ IOC Summary

**Host Indicators**

| Type | Value |
|---|---|
| Compromised Account | `slflare` |
| Malicious Executable | `msupdate.exe` |
| Staged Script | `C:\Users\Public\update_check.ps1` |
| Persistence (Scheduled Task) | `MicrosoftUpdateSync` |
| Defender Exclusion | `C:\Windows\Temp` |
| Discovery Command | `C:\Windows\System32\cmd.exe /c systeminfo` |
| Staged Archive | `backup_sync.zip` |

**Network Indicators**

| Type | Value |
|---|---|
| C2 Server | `185.92.220.87` |
| Exfiltration Destination | `185.92.220.87:8081` |

---

## 🎯 Conclusion

This investigation traced a full attack lifecycle — from RDP compromise to attempted exfiltration — using Microsoft Defender for Endpoint's Advanced Hunting tables. The core takeaway was **correlation over assumption**: a scheduled task, an archive, or an external IP can each look suspicious in isolation, but only tying them to the compromised account, host, process, and timeline confirms whether they're part of the attack.

**Final chain confirmed:**

`RDP Access → slflare → msupdate.exe → MicrosoftUpdateSync → C:\Windows\Temp exclusion → systeminfo → backup_sync.zip → 185.92.220.87 → 185.92.220.87:8081`

---

<p align="center"><sub>Investigation conducted using Microsoft Defender for Endpoint · Advanced Hunting (KQL)</sub></p>
---

<p align="center"><sub>Investigation conducted using Microsoft Defender for Endpoint · Advanced Hunting (KQL)</sub></p>
