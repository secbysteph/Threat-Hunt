# Introduction

Between October 1–15, 2025, I identified a pattern of unusual behavior across several workstations in the environment. Multiple endpoints were launching executables and scripts directly from the Downloads folder — something that rarely happens during normal operations. The files involved shared a noticeable pattern: names containing “support,” “help,” “desk,” and “tool,” raising suspicion that the activity was coordinated or intentionally crafted.

Of all the systems reviewed, gab-intern-vm stood out immediately. It showed the first suspicious execution, the highest volume of untrusted process activity, and multiple indicators matching the intel that intern-operated machines were affected early in the timeline. Because of this, it became the primary pivot point for the investigation.

This report breaks down the sequence of events, aligns the observed activity with MITRE ATT&CK techniques, and evaluates whether the “support session” was legitimate or an attempt to disguise targeted malicious behavior.
---

# Scenario Overview

What initially appeared to be normal IT assistance quickly unraveled into something far more concerning. The actions taken on the intern’s workstation did not align with genuine troubleshooting. Instead, they matched the type of reconnaissance and preparation typically seen during the early phases of hands-on-keyboard intrusion.

Across the timeline, the actor:

Launched support-themed files directly from Downloads

Collected details about sessions, users, privileges, and running processes

Read clipboard contents

Mapped available drives and storage capacity

Checked outbound connectivity

Created a ZIP archive of system information

Set up persistence with scheduled tasks and autoruns

Left behind staged artifacts designed to create a fake “support narrative”

Decoy files like DefenderTamperArtifact.lnk and SupportChat_log.lnk appeared to be intentionally placed to justify prior actions and steer analysts away from the real purpose of the activity.

Putting all the evidence together, this was not a support session — it was a reconnaissance-driven intrusion wrapped in a helpdesk disguise.
---

# Complete Timeline of Events

| Time (UTC) | Flag | Stage | Event / Artifact |
|------------|-------|--------|------------------|
| 12:22 | **Flag 0** | Starting Point | Most suspicious machine identified → `gab-intern-vm` |
| 12:22 | **Flag 1** | Initial Execution | `SupportTool.ps1` launched from Downloads (`-ExecutionPolicy`) |
| 12:34 | **Flag 2** | Defense Deception | Tamper decoy artifact created → `DefenderTamperArtifact.lnk` |
| 12:50 | **Flag 3** | Data Probe | Clipboard accessed via PowerShell (`Get-Clipboard`) |
| 12:51 | **Flag 4** | Host context reconnaissance | Host enumeration commands |
| 12:53 | **Flag 5** | Storage Mapping | `wmic logicaldisk get name,freespace,size` |
| 12:55 | **Flag 6** | Egress Check | First outbound connection → `www.msftconnecttest.com` |
| 12:51 | **Flag 7** | Session Recon | Session enumeration commands |
| 12:56 | **Flag 8** | Runtime Inventory | `tasklist.exe` executed |
| 12:52 | **Flag 9** | Privilege Recon | `whoami /groups` executed |
| 12:55 | **Flag 10** | Egress validation & proof-of-access | `www.msftconnecttest.com` connection |
| 12:58 | **Flag 11** | Staging | `C:\Users\Public\ReconArtifacts.zip` created |
| 12:59 | **Flag 12** | Exfil Attempt | Outbound connection attempted → `100.29.147.161` |
| 13:01 | **Flag 13** | Persistence | Scheduled task created → `SupportToolUpdater` |
| 13:01–13:02 | **Flag 14** | Fallback Persistence | Autorun entry created → `RemoteAssistUpdater` |
| 13:02 | **Flag 15** | Misdirection | Narrative artifact created → `SupportChat_log.lnk` |

---

# Flag-by-Flag Findings

## Flag 0 – Determining Where to Start

### Objective
The goal was to find the system that first showed suspicious support-themed activity during October 1–15. Using keyword-based hunting (“support,” “tool,” “help,” “desk”), gab-intern-vm surfaced immediately as the earliest and most consistently affected host.

### Why This Host Was Flagged
The earliest and most relevant suspicious activity was traced to **gab-intern-vm**, which showed:
- It executed a suspicious PowerShell script (SupportTool.ps1) from the Downloads folder.  
- It matched all keyword indicators from the scenario. 
- It showed multiple related process executions and artifacts. 

### Evidence
Within the date window of October 1–15, 2025, only **gab-intern-vm** recorded:
- A `SupportTool.ps1` file in the Downloads folder  
- Multiple process executions originating from this file  
- Matches to keyword indicators: *support*, *tool*, *help*, *desk*  

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceFileEvents
| where TimeGenerated between (T0 .. T1)
| where FileName contains "support"
  and FileName contains "tool"
  and FolderPath contains "Download"
| summarize Hosts = make_set(DeviceName), Count = dcount(DeviceName)
    by FileName, SHA256, FileSize
| sort by Count desc
```

### Flag Answer

<img width="1278" height="652" alt="Image" src="https://github.com/user-attachments/assets/85a4fc4f-f227-45a9-953c-f2841352f109" />
``` gab-intern-vm ```

---
## Flag 1 – First Anomalous Execution 

### Objective
Identify the earliest suspicious execution event that could represent the start of malicious activity on the host.

### Finding
The earliest abnormal command came from PowerShell executing SupportTool.ps1 with the -ExecutionPolicy flag, commonly used to bypass PowerShell restrictions and run unsigned or untrusted scripts.

### Evidence
- Execution originated from the Downloads folder.- The command line included the parameter:
- Included policy bypass (-ExecutionPolicy) in the command line.
- Matches the threat pattern associated with support-themed malicious tooling.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where ProcessCommandLine contains "SupportTool.ps1"
| where TimeGenerated between (T0 .. T1)
| extend FirstSwitch = extract(@"[\/\-]([A-Za-z0-9_\-]+)", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FirstSwitch
| order by TimeGenerated asc
```
### Flag Answer
<img width="680" height="299" alt="Image" src="https://github.com/user-attachments/assets/88a95314-0394-49f4-9823-368839e68c34" />

``` -ExecutionPolicy ```

---

## Flag 2 – Defense Disabling (Simulated Tamper Indicator)

### Objective
Determine whether the attacker attempted to disable or simulate changes to Windows Defender.

### Finding
A staged shortcut file named DefenderTamperArtifact.lnk was created and opened. No Defender settings were actually modified, indicating the file was used to create a false impression of tampering.

### Evidence
- .lnk artifact created during the intrusion window.
- Opened via Explorer.exe (manual access).
- No Defender registry or configuration changes detected.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-30);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| project TimeGenerated, FileName, InitiatingProcessCommandLine
| where InitiatingProcessCommandLine == "Explorer.EXE"
```

### Flag Answer
<img width="442" height="356" alt="Image" src="https://github.com/user-attachments/assets/58bbf5f7-4253-4880-a48d-04641d9d3bd7" />

``` DefenderTamperArtifact.lnk ```

---

## Flag 3 – Clipboard Probe

### Objective
Identify attempts to capture quick-access user data such as clipboard contents.

### Finding
PowerShell was used to silently request clipboard data — a common technique for capturing copied credentials, tokens, or sensitive text.

### Evidence
The following command was executed on **gab-intern-vm**:
- PowerShell executed with -NoProfile and -Sta for stealth.
- Command suppressed errors and produced no output (Out-Null).
- Behavior aligns with credential-harvesting reconnaissance.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| order by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| where ProcessCommandLine contains "clip"
```

### Flag Answer
<img width="597" height="356" alt="Image" src="https://github.com/user-attachments/assets/1d97262f-4c4f-4859-9c3c-98c78d2a3223" />

``` powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" ```

---

## Flag 4 – Session Enumeration

### Objective
Identify reconnaissance actions targeting user presence and session information.

### Finding
The attacker executed qwinsta, a native Windows utility used to list active user sessions, session states, and terminal information.

### Evidence
- Executed shortly after clipboard probing.
- Revealed user presence and session activity on gab-intern-vm.
- Common early-stage recon tactic.

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-30);
DeviceProcessEvents
| where DeviceName == @"gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine contains "qwi"
| order by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

Flag Answer
<img width="602" height="292" alt="Image" src="https://github.com/user-attachments/assets/36689496-6fc9-457e-aad7-746ee4b77633" />

``` 2025-10-09T12:51:44.3425653Z ```

---

## Flag 5 – Logical Disk Recon

### Objective
Determine whether the attacker inspected available storage for staging or exfiltration planning.

### Finding
wmic logicaldisk get name,freespace,size was executed to identify local and removable drives and free disk space.

### Evidence
- Output reveals writable paths and space available for ZIP staging.
- Execution occurred just before the creation of ReconArtifacts.zip.
- Matches common staging preparation behavior.

### Query Used
```
DeviceProcessEvents
| where ProcessCommandLine contains "wmic"
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-30))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated asc
```

### Flag Answer
<img width="768" height="289" alt="Image" src="https://github.com/user-attachments/assets/1b4f9532-8023-44a6-a963-cb787372e8e9" />

``` "cmd.exe" /c wmic logicaldisk get name,freespace,size" ```

---

## Flag 6 – Connectivity Check

### Objective
Identify outbound connectivity tests used to confirm internet access before exfiltration attempts.

### Finding
Outbound traffic originated from a chain where RuntimeBroker.exe was the parent process, helping blend the activity into normal OS operations.

### Evidence
- Outbound HTTP check executed via user context.
- Connection to known Windows connectivity test infrastructure.
- Parent process: RuntimeBroker.exe

### Query Used
```
let T0 = datetime(2025-10-01);
let T1 = datetime(2025-10-15);
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm" 
| where TimeGenerated between (T0 .. T1)
| where RemotePort == "80"
| where RemoteUrl != ""
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, RemotePort, RemoteUrl, DeviceName, 
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
```

### Flag Answer
<img width="563" height="350" alt="Image" src="https://github.com/user-attachments/assets/a6c2c9f6-412a-44b6-951c-1d75ab18fbe5" />


``` RuntimeBroker.exe ```

---

## Flag 7 – Initiating Process Unique ID

### Objective
Tie together recon actions under the same executing process chain to identify operator continuity.

### Finding
Multiple recon commands were linked to a single initiating process chain, identified by the unique ID 2533274790397065.

### Evidence
- qwinsta, query, whoami, and other recon commands traced back to the same ID.
- Indicates a single hands-on-keyboard operator session.

### Query Used
```
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
let needles = dynamic(["query user","quser","query session","qwinsta","session","whoami /all","tasklist"]);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any (needles)
| project
    TimeGenerated,
    DeviceName,
    ProcessCommandLine,
    InitiatingProcessUniqueId,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName
| order by TimeGenerated asc
```

### Flag Answer
<img width="1751" height="841" alt="Image" src="https://github.com/user-attachments/assets/9e2f6424-2786-448e-bb32-d6ce9373d64a" />

```2533274790397065```

---
## Flag 8 – Process Inventory

### Objective
Determine whether the attacker enumerated running processes to identify defenses or high-value processes.

### Finding
The attacker ran tasklist.exe, a native utility that enumerates all running processes and memory usage.

### Evidence
- Executed after privilege and session enumeration.
- Reveals defender tools, credential stores, and target processes.
- Common step in building host situational awareness.

### Query Used
```kql
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
let needles = dynamic(["query user","quser","query session","qwinsta","session","whoami /all","tasklist"]);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any (needles)
| project TimeGenerated, DeviceName, ProcessCommandLine,
          InitiatingProcessUniqueId, InitiatingProcessCommandLine,
          InitiatingProcessFileName, ProcessVersionInfoFileDescription
| order by TimeGenerated asc
```

### Flag Answer

<img width="743" height="437" alt="Image" src="https://github.com/user-attachments/assets/26899ab4-91e2-4742-93d8-2ddd154b767c" />

``` tasklist.exe ```

---

## Flag 9 – Privilege Enumeration

### Objective
Identify attempts to assess the account’s current security groups and privilege levels.

### Finding
The attacker executed whoami /groups, returning all security group memberships and privilege assignments.

### Evidence
- Timestamp indicates it immediately followed session enumeration.
- Provides clear insight into escalation opportunities.
- Confirms whether the user is administrative or privileged.

### Query Used
```kql
let T0 = datetime(2025-10-09);
let T1 = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (T0 .. T1)
| where ProcessCommandLine has_any ("whoami /all","whoami /groups","whoami /priv","whoami")
| project TimeGenerated, FileName, ProcessId, ProcessCommandLine,
          InitiatingProcessFileName, ReportId
| order by TimeGenerated asc
| take 1
```

### Flag Answer

<img width="824" height="338" alt="Image" src="https://github.com/user-attachments/assets/1a51ab9a-2c8e-49ff-a171-43f0f402b565" />


``` 2025-10-09T12:52:14.3135459Z ```

---

## Flag 10 – First Outbound Destination

### Objective
Determine the initial external resource contacted during the intrusion window.

### Finding
The first outbound destination was www.msftconnecttest.com, the domain used by Windows to test internet access.

### Evidence
- HTTP traffic aligned with egress verification.
- Initiated by the same PowerShell process chain.
- Used to validate connectivity before exfiltration attempts.

### Query Used
```
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm"
| where InitiatingProcessCommandLine !contains "exfiltrate"
| where InitiatingProcessCommandLine !contains "portscan"
| where InitiatingProcessCommandLine !contains "crypt"
| where InitiatingProcessCommandLine !contains "eicar"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe")
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Flag Answer

<img width="721" height="297" alt="Image" src="https://github.com/user-attachments/assets/dc802c8c-6ba2-4004-8a80-b3597ee3cb43" />


``` www.msftconnecttest.com ```

---

## Flag 11 – Data Staging

### Objective
Identify where the attacker staged reconnaissance data prior to exfiltration.

### Finding
A ZIP archive named ReconArtifacts.zip was created in the Public user directory.

### Evidence
- Created immediately after recon commands.
- Location (C:\Users\Public) chosen for write access and low visibility.
- Matches textbook pre-exfiltration staging behavior.

### Query Used
```
DeviceFileEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where FileName contains "zip"
| where InitiatingProcessAccountDomain == "gab-intern-vm"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountName, FileName, FolderPath
```

### Flag Answer

<img width="586" height="383" alt="Image" src="https://github.com/user-attachments/assets/2425dbb3-a1ee-4b8d-b2ef-5e4b263ac0dd" />

```C:\Users\Public\ReconArtifacts.zip```

---

## Flag 12 – Exfil Attempt

### Objective
Identify any attempt to transfer staged data to an external location.

### Finding
The attacker attempted an outbound connection to 100.29.147.161, shortly after ZIP creation.

### Evidence
- Outbound connection originated from PowerShell.
- The event timing correlates directly with staging completion.
- No confirmed download/upload, but clear exfil intent.

### Query Used
```
DeviceNetworkEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessCommandLine == "\"powershell.exe\" "
| where InitiatingProcessAccountName == "g4bri3lintern"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
```

### Flag Answer

<img width="1110" height="554" alt="Image" src="https://github.com/user-attachments/assets/85ca3c9e-2ebd-4d12-97ac-31daa777c960" />


``` 100.29.147.161 ``` 

---

## Flag 13 – Scheduled Task Persistence
### Objective
Identify persistence mechanisms created by the attacker to ensure their tool re-executes automatically.

### Finding
A scheduled task named SupportToolUpdater was added to trigger at logon.

### Evidence
- Created via schtasks.exe /Create.
- Matches the attack’s “support” naming theme.
- Ensures persistence across reboots and user logons.

### Query Used
```
DeviceProcessEvents
| where DeviceName =~ "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| where ProcessCommandLine contains "Create"
| where FileName contains "schtasks"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Flag Answer

<img width="1013" height="301" alt="Image" src="https://github.com/user-attachments/assets/80a63175-6dcb-4e82-af32-4ec4b8b83992" />

``` SupportToolUpdater ```

---

## Flag 14 – Registry Autorun Persistence

### Objective
Determine whether the attacker configured fallback persistence mechanisms.

### Finding
A registry-based autorun entry named RemoteAssistUpdater was added as a secondary persistence layer.

### Evidence
- Staged shortly after scheduled task creation.
- Mirrors naming pattern of support-themed tooling.
- Acts as self-healing persistence if the scheduled task is removed.

### Query Used
_The expected table returned no results due to data retention expiration, as acknowledged in scenario instructions._

If logs were present, the hunt would rely on:

```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "Run"
| where RegistryValueName contains "Assist" or RegistryValueName contains "Support"
```

### Flag Answer

``` RemoteAssistUpdater ```

---

## Flag 15 – Deception Artifact

### Objective
Identify artifacts intentionally planted to mislead investigators or justify earlier suspicious activity.

### Finding
A shortcut named SupportChat_log.lnk was created to fabricate the appearance of a legitimate support conversation.

### Evidence
- Created under the user’s Recent folder.
- Opened via Explorer.exe, confirming intentional viewing.
- The name aligns with the helpdesk-themed deception strategy.

### Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName =~ "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName contains "explorer"
| project TimeGenerated, ActionType, DeviceName, FileName,
        InitiatingProcessFileName, FolderPath
```

### Flag Answer

<img width="722" height="326" alt="Image" src="https://github.com/user-attachments/assets/f0470569-7c13-4571-a75f-bdc8b5c69cf3" />

``` SupportChat_log.lnk ```

---

# MITRE ATT&CK Mapping
**Phase 1: Initial Compromise (Flag 1)** 
- T1059.001 – PowerShell: Execution of a script using a bypassed execution policy to run untrusted code.

**Phase 2: Defense Evasion & Persistence Establishment (Flags 2, 13, 14, 15)** 
- T1562.001 – Impair Defenses: Use of staged tamper artifacts to simulate Defender alteration.
- T1053.005 – Scheduled Task: Creation of a malicious logon-based scheduled task for persistence.
- T1547.001 – Registry Autoruns: Addition of a user-level autorun entry as fallback persistence.
- T1036 – Masquerading: Deployment of deceptive files designed to disguise malicious activity as legitimate support operations.

**Phase 3: Systemwide Discovery (Flags 3–10)** 
- T1033 – Account Discovery: Enumeration of sessions and user context (Flags 3, 7).
- T1082 – System Information Discovery: Queries for system and privilege details (Flags 4, 9).
- T1083 – File & Directory Discovery: Logical disk enumeration to inspect storage surfaces (Flag 5).
- T1046 – Network Service Discovery: Connectivity checks to verify outbound access (Flag 6).
- T1057 – Process Discovery: Review of running processes using native tools (Flag 8).
- T1049 – System Network Connections Discovery: Identification of live outbound connections (Flag 10).

**Phase 4: Collection & Staging (Flags 3, 11, 12)** 
- T1560.001/002 – Archive Collected Data: Collection and compression of recon data.
- T1074.001 – Local Staging: Placement of a ZIP archive in a public directory prior to exfiltration.

**Phase 5: Exfiltration Attempts (Flags 10, 12)** 
- T1071.001 – Application Layer Protocol: Use of standard outbound HTTP to blend with normal traffic.
- T1041 – Exfiltration Over Command Channel: Attempted transfer of staged data to an external IP.

### Recommendation
- Isolate and Contain Affected Systems to stop further reconnaissance, staging, or execution of persistence mechanisms.
- Remove All Persistence Mechanisms, including scheduled tasks (e.g., SupportToolUpdater) and autorun entries (e.g., RemoteAssistUpdater).
- Audit and Block Suspicious Outbound Traffic, especially connections to unrecognized IPs or domains involved in the intrusion.
- Perform Deep Artifact Analysis on created archives and related files to assess data exposure and intent.
- Strengthen Monitoring and Alerting for clipboard access, privilege enumeration, and rapid recon sequences.
- Educate Users about the risks of running scripts or executables from untrusted sources—especially those delivered as “support tools.”
