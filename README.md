<img width="600" alt="image" src="https://github.com/user-attachments/assets/3dd82af7-a61d-4c88-8fa2-d054e4f2cbca" />

# Threat Hunt Report: Papertrail

**Date of Hunt:** August 16 - August 30, 2025

**Threat Hunter:** Andrey Massalskiy

---

## Platforms and Languages Leveraged
* Windows 10 Virtual Machines (Microsoft Azure)
* EDR Platform: Microsoft Defender for Endpoint
* Kusto Query Language (KQL)

---

## Scenario. Build by the [Cyber Range](https://www.skool.com/cyber-range) team.

A sudden, unexplained promotion has triggered whispers across the executive floor. The recipient? A mid-level employee with no standout track record — at least, not one visible anymore.

Internal HR systems show signs of tampering: audit logs wiped, performance reports edited, and sensitive employee reviews quietly exfiltrated. Behind the scenes, someone has buried the real story beneath layers of obfuscation, PowerShell trickery, and stealthy file manipulation.

Your mission: act as a covert threat hunter tasked with dissecting the digital remnants of the breach. Trace the insider’s movements. Expose the fake artifacts. Reconstruct the timeline they tried to erase — and uncover the truth behind the promotion that should never have happened.

Nothing in the system adds up... unless you know where to look.

---

## Steps Taken

### Starting Point: Identifying the Initial Compromised Machine
<details>
  <summary>Original task</summary>
  Before you officially begin the flags, you must first determine where to start hunting.   
  
  Identify where to start hunting with the following intel given:    
  
  1. HR related stuffs or tools were recently touched, investigate any dropped scripts or configs since several days back (17th of August 2025).

  `Identify the first machine to look at.`   
     
---
</details>

* **Objective:** Determine the first machine to look at.
* **Thought Process:** The scenario pointed to a recently active device with suspicious executions from HR-related directories. We looked for file creation events initiated by PowerShell on or around the specified date to find the earliest evidence of tampering.
* **KQL Query Used:**
```kusto
  let hr_keywords = dynamic(["hr", "tools", "payroll", "evaluation", "payroll"]);
  DeviceFileEvents
  | where Timestamp >= datetime(2025-08-17T00:00:00Z)
  | where ActionType in ("FileCreated", "FileModified")
  | where FolderPath has_any (hr_keywords)
  | where InitiatingProcessFileName =~ "powershell.exe"
  | project Timestamp, DeviceName, InitiatingProcessCommandLine, FolderPath, FileName
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1999" height="654" alt="image18" src="https://github.com/user-attachments/assets/abaff1f4-c7a0-4bd8-9daa-3af658fcf7ad" />

  
* **Identified Answer:** **`n4thani3l-vm`**
    * **Why:** This machine had the most direct evidence of tampering with HR files and was where the first suspicious file creations were observed.

---

### Flag 1: Initial PowerShell Execution Detection
<details>
  <summary>Original task</summary> 
  
  * Objective:
    Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

  * What to Hunt:
    Initial signs of PowerShell being used in a way that deviates from baseline usage.

  * Thought:
    Understanding where it all began helps chart every move that follows. Look for PowerShell actions that started the chain.

  * Hint: 1. Who?

  `Provide the creation time of the first suspicious process that occurred.`
     
---
</details>

* **Objective:** Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.
* **Thought Process:** Initial compromise often involves PowerShell. We looked for the earliest non-benign PowerShell command on the starting machine, differentiating it from earlier system noise.
* **KQL Query Used:**
```kusto
  union DeviceFileEvents, DeviceProcessEvents
  | where Timestamp >= datetime(2025-08-17T00:00:00Z)
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName != "system"
  | where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
  | project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, FolderPath, FileName
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1999" height="337" alt="image9" src="https://github.com/user-attachments/assets/390d6448-0dfd-40b2-84b2-af4913b4b82e" />

* **Identified Answer:** **`2025-08-19T03:42:32.9389416Z`** 
    * **Why:** This timestamp, corresponding to `Aug 18, 2025 11:42:32 PM`, marks the earliest execution of a suspicious `powershell.exe` command after the initial benign system noise. The command executed was `"whoami.exe" /all`, a classic reconnaissance tool used by attackers to enumerate their privileges and identify potential targets for privilege escalation. This confirms the start of the attacker's post-exploitation activity.

---

### Flag 2: Local Account Assessment
<details>
  <summary>Original task</summary> 
  
  * Objective:
    Map user accounts available on the system.

  * What to Hunt:
    PowerShell queries that enumerates local identities.

  * Thought:
    After knowing their own access level, intruders start scanning the local account landscape to plan privilege escalation or impersonation down the line.

  `Identify the associated SHA256 value of this particular instance.`
     
---
</details>

* **Objective:** Map user accounts available on the system and identify the associated SHA256 value of the enumeration command.
* **Thought Process:** Reconnaissance typically follows initial access. We looked for PowerShell commands like `Get-LocalUser` or `net user` used to enumerate local accounts.
* **KQL Query Used:**
```kusto
  DeviceProcessEvents
  | where Timestamp > datetime(2025-08-18T23:42:32Z)
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessFileName =~ "powershell.exe"
  | where ProcessCommandLine has_any ("Get-LocalUser", "Get-LocalGroup", "net user", "net localgroup")
  | project Timestamp, ProcessCommandLine, InitiatingProcessAccountName, SHA256
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1999" height="193" alt="image11" src="https://github.com/user-attachments/assets/5e0cd155-cd36-468e-bbae-f04672309536" />


* **Identified Answer:** **`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`**
    * **Why:** This SHA256 hash corresponds to the `powershell.exe` command that enumerated local user accounts, a key step in post-exploitation reconnaissance.

---

### Flag 3: Privileged Group Assessment
<details>
  <summary>Original task</summary> 
  
  * Objective:
    Identify elevated accounts on the target system.

  * What to Hunt:
    A method used to check for high-privilege users.

  * Thought:
    Knowledge of who has admin rights opens doors for impersonation and deeper lateral movement.

  `What is the value of the command?`
     
---
</details>

* **Objective:** Identify elevated accounts and the value of the command used.
* **Thought Process:** The attacker would check for privileged groups after enumerating local users. We looked for commands targeting the `Administrators` group.
* **KQL Query Used:**
```kusto
  DeviceProcessEvents 
  | where DeviceName =~ "n4thani3l-vm" 
  | where ProcessCommandLine has_any ("net localgroup", "Get-LocalGroupMember") 
  | where ProcessCommandLine has_any ("administrators", "privileged") 
  | project Timestamp, ProcessCommandLine, InitiatingProcessAccountName, SHA256 
  | sort by Timestamp asc
```
* **Query Results:**
<img width="778" height="208" alt="image8" src="https://github.com/user-attachments/assets/4ffcf894-ba83-44d7-9658-bec30e43a9d7" />


* **Identified Answer:** **`"powershell.exe" net localgroup Administrators`**
    * **Why:** This command directly reveals the attacker's intent to identify elevated accounts for a potential privilege escalation.

---

### Flag 4: Active Session Discovery
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Reveal which sessions are currently active for potential masking.

  * What to Hunt:
    Might be session-enumeration commands.

  * Thought:
    By riding along existing sessions, attackers can blend in and avoid spawning suspicious user contexts.

  `Provide the value of the program tied to this activity.`
     
---
</details>

* **Objective:** Reveal which sessions are currently active for potential masking.
* **Thought Process:** An attacker would enumerate sessions to blend in. We looked for commands like `qwinsta` that are commonly used for this purpose.
* **KQL Query Used:**
```kusto
  DeviceProcessEvents
  | where Timestamp > datetime(2025-08-18T23:42:54Z)
  | where DeviceName =~ "n4thani3l-vm"
  | where ProcessCommandLine has_any ("query user", "qwinsta", "net session")
  | project Timestamp, ProcessCommandLine, InitiatingProcessAccountName, SHA256
  | sort by Timestamp asc
```
* **Query Results:**
<img width="757" height="153" alt="image6" src="https://github.com/user-attachments/assets/cb1609c2-5f77-42c0-8398-7f00ee2a853b" />


* **Identified Answer:** **`"powershell.exe" qwinsta`**
    * **Why:** This command is used to query active sessions, a key reconnaissance step for an attacker looking to blend into an existing user context.

---

### Flag 5: Defender Configuration Recon
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Expose tampering or inspection of AV defenses, disguised under HR activity.

  * What to Hunt:
    Can be PowerShell related activity.

  * Thought:
    Disabling protection under the guise of internal tooling is a hallmark of insider abuse.

  * Side Note: 1/6
    union
  
  `What was the command value used to execute?`
     
---
</details>

* **Objective:** Expose tampering or inspection of AV defenses, disguised under HR activity.
* **Thought Process:** The attacker would try to disable Defender. We looked for a PowerShell command with keywords like `Set-MpPreference` that also included HR-related keywords or was part of a larger script disguised as a business tool.
* **KQL Query Used:**
```kusto
  let defender_keywords = dynamic(["MpPreference", "Defender", "Antivirus", "RealtimeProtection", "disable"]);
  DeviceProcessEvents
  | where Timestamp > datetime(2025-08-18T23:42:54Z)
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where ProcessCommandLine has_any (defender_keywords) and ProcessCommandLine contains "powershell"
  | project Timestamp, ActionType, ProcessCommandLine, FolderPath, FileName, InitiatingProcessAccountName
  | sort by Timestamp asc
```
* **Query Results:**
<img width="979" height="246" alt="image3" src="https://github.com/user-attachments/assets/41511907-676f-4b67-842c-d2f833d3c0e1" />

* **Identified Answer:** **`"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"`**
    * **Why:** This full command line provides a complete picture of the attack's objective, from disabling the antivirus to dropping a malicious payload.

---

### Flag 6: Defender Policy Modification
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Validate if core system protection settings were modified.

  * What to Hunt:
    Policy or configuration changes that affect baseline defensive posture.

  * Thought:
    Turning down the shield is always a red flag.
  
  `Provide the name of the registry value.`
     
---
</details>

* **Objective:** Validate if core system protection settings were modified.
* **Thought Process:** We looked for registry modifications to persistent Defender settings.
* **KQL Query Used:**
```kusto
  // Hunt for registry modifications affecting Windows Defender policy
  DeviceRegistryEvents
  | where Timestamp > datetime(2025-08-19T00:24:03Z)
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where RegistryKey contains "Windows Defender"
  | where InitiatingProcessCommandLine has_any("powershell", "reg.exe")
  | project Timestamp, ActionType, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1309" height="291" alt="image7" src="https://github.com/user-attachments/assets/f1ebe07b-fede-4cea-bfb3-6e4f1dbf05c6" />

* **Identified Answer:** **`DisableAntiSpyware`**
    * **Why:** The log shows a `RegistryValueSet` action at `Aug 18, 2025 11:53:15 PM` where the `DisableAntiSpyware` value was modified to `1`. This directly confirms that the core system protection settings were tampered with to disable Windows Defender's anti-spyware capabilities, which is a classic move to avoid detection.

---

### Flag 7: Access to Credential-Rich Memory Space
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Identify if the attacker dumped memory content from a sensitive process.

  * What to Hunt:
    Uncommon use of system utilities interacting with protected memory.

  * Thought:
    The path to credentials often runs through memory — if you can reach it, you own it.

  * Side Note: 2/6
    (DeviceFileEvents | where FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted")
  
  `What was the HR related file name associated with this tactic?`
     
---
</details>

* **Objective:** Identify if the attacker dumped memory content from a sensitive process.
* **Thought Process:** The attacker used a system utility in an uncommon way to dump memory. We looked for the `rundll32.exe` command with a `MiniDump` argument.
* **KQL Query Used:**
  Used the provided in the hint KQL to fix the `Timestamp` of the Deletion of the `ConsoleHost_history.txt` file:
```kusto
  DeviceFileEvents | where FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted"
```
* **Query Results:**
<img width="875" height="161" alt="image16" src="https://github.com/user-attachments/assets/fa57a1e2-ac5d-4c54-8be3-46ee2b79e3b9" />
  
  File was deleted last time on `2025-08-19T05:08:11.8528871Z` so I observed the `DeviceProcessEvent` table for the powershell commands contained “HR” before the deletion with the following KQL:
```kusto
  DeviceProcessEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessFileName contains "powershell"
  | where ProcessCommandLine contains "HR"
  | project Timestamp, FileName, InitiatingProcessFileName, ProcessCommandLine
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1210" height="330" alt="image10" src="https://github.com/user-attachments/assets/6c53fec3-87be-4f3c-b1af-cbd61426d3cf" />

* **Identified Answer:** **`HRConfig.json`**
    * **Why:** The logs showed the use of `rundll32.exe` with the `MiniDump` argument, writing the output to `HRConfig.json`. This is the HR-related file associated with the memory dump. The process ID `680` is a strong indicator that the attacker was dumping the memory of the `lsass.exe` process, which is the primary target for credential theft in Windows.

---

### Flag 8: File Inspection of Dumped Artifacts
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Detect whether memory dump contents were reviewed post-collection.

  * What to Hunt:
    Signs of local tools accessing sensitive or unusually named files.

  * Thought:
    Dumping isn’t the end — verification is essential.

  * Hint:
    Utilize previous findings
  
  `Provide the value of the associated command.`
     
---
</details>

* **Objective:** Detect whether memory dump contents were reviewed post-collection.
* **Thought Process:** The attacker would have opened the dumped file (`HRConfig.json`) to inspect its contents. We looked for a tool like `notepad.exe` opening this specific file.
* **KQL Query Used:**
```kusto
  // Hunt for local tools accessing the dumped HRConfig.json file
  DeviceProcessEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where ProcessCommandLine contains "HRConfig.json"
  | where InitiatingProcessFileName has_any ("notepad.exe", "code.exe", "powershell.exe")
  | project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1053" height="314" alt="image2" src="https://github.com/user-attachments/assets/734b7471-211a-42d4-aefb-a2f66ff220cc" />

* **Identified Answer:** **`"notepad.exe" C:\HRTools\HRConfig.json`**
    * **Why:** The logs show that at `Aug 18, 2025 11:59:55 PM`, a PowerShell process was used to open the `HRConfig.json` file with `notepad.exe`. This action directly indicates that the attacker was reviewing the contents of the file that was created during the memory dump, which confirms the "verification is essential" thought from the flag's objective.

---

### Flag 9: Outbound Communication Test
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Catch network activity establishing contact outside the environment.

  * What to Hunt:
    Lightweight outbound requests to uncommon destinations.

  * Thought:
    Before exfiltration, there’s always a ping — even if it’s disguised as routine.

  * Side Note: 3/6
    (DeviceFileEvents | where FileName =~ "EmptySysmonConfig.xml")
    
  `What was the TLD of the unusual outbound connection?`
     
---
</details>


* **Objective:** Catch network activity establishing contact outside the environment.
* **Thought Process:** An attacker would perform a network test before exfiltrating data. We looked for outbound connections to uncommon destinations.
* **KQL Query Used:**
```kusto
  // Hunt for unusual outbound network connections
  DeviceNetworkEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where RemoteUrl !endswith "microsoft.com" and RemoteUrl !contains "windows.update" // Filter for uncommon destinations
  | where InitiatingProcessFileName contains "powershell"
  | where InitiatingProcessAccountName == "n4th4n13l"
  | project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine, InitiatingProcessAccountName
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1079" height="318" alt="image5" src="https://github.com/user-attachments/assets/205c2146-e73e-4985-889d-4c1f766d6149" />

* **Identified Answer:** **`.net`**
    * **Why:** The TLD `.net` is a part of the unusual outbound URL, indicating a test connection to an external domain.

---

### Flag 10: Covert Data Transfer
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Uncover evidence of internal data leaving the environment.

  * What to Hunt:
    Activity that hints at transformation or movement of local HR data.

  * Thought:
    Staging the data is quiet. Sending it out makes noise — if you know where to listen.
    
  `Identify the ping of the last unusual outbound connection attempt.`
     
---
</details>

* **Objective:** Uncover evidence of internal data leaving the environment.
* **Thought Process:** We needed to find the last unusual outbound network connection. 
* **KQL Query Used:**
* 
    ```Query from the Flag 9.```
  
* **Query Results:**
<img width="1079" height="318" alt="image5" src="https://github.com/user-attachments/assets/205c2146-e73e-4985-889d-4c1f766d6149" />

* **Identified Answer:** **`3.234.58.20`**
    * **Why:** This IP address is associated with the last unusual outbound connection, which is the final step before data exfiltration.

---

### Flag 11: Persistence via Local Scripting
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Verify if unauthorized persistence was established via legacy tooling.

  * What to Hunt:
    Use of startup configurations tied to non-standard executables.

  * Thought:
    A quiet script in the right location can make a backdoor look like a business tool.

  * Side Note: 4/6
    (DeviceProcessEvents | where FileName =~ "Sysmon64.exe" and ProcessCommandLine has "-c")
    
  `Provide the file name tied to the registry value.`
     
---
</details>

* **Objective:** Verify if unauthorized persistence was established via legacy tooling.
* **Thought Process:** We looked for registry modifications in common persistence keys like `CurrentVersion\Run`.
* **KQL Query Used:**
```kusto
  // Hunt for persistence established via startup registry keys
  DeviceRegistryEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where ActionType == "RegistryValueSet"
  | where RegistryKey contains "CurrentVersion\\Run"
  | project Timestamp, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
  | sort by Timestamp asc
```
* **Query Results:**
<img width="1476" height="285" alt="image17" src="https://github.com/user-attachments/assets/2719d3fd-efdf-487f-b34c-ff4573d52b8e" />

* **Identified Answer:** **`OnboardTracker.ps1`**
    * **Why:** The log entry at `Aug 19, 2025 12:46:07 AM` shows a PowerShell command modifying a registry key in the `HKEY_CURRENT_USER\...\CurrentVersion\Run` path. The
`RegistryValueData` field clearly shows that the new value points to the file `C:\HRTools\LegacyAutomation\OnboardTracker.ps1`, which is the file name associated with this malicious persistence.


---

### Flag 12: Targeted File Reuse / Access
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Surface the document that stood out in the attack sequence.

  * What to Hunt:
    Repeated or anomalous access to personnel files.

  * Thought:
    The file that draws the most interest often holds the motive.

  * Format:
    Abcd Efgh
    
  `What is the name of the personnel file that was repeatedly accessed?`
     
---
</details>

* **Objective:** Surface the document that stood out in the attack sequence.
* **Thought Process:** We looked for files that were repeatedly accessed by a text editor to understand the attacker's motive.
* **KQL Query Used:**
```kusto
    DeviceProcessEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where FileName contains "notepad"
    | summarize count() by ProcessCommandLine
    | sort by count_ desc
```
* **Query Results:**
<img width="578" height="345" alt="image1" src="https://github.com/user-attachments/assets/77601bf4-a1bd-4357-941c-7ba497e39222" />

* **Identified Answer:** **`Carlos Tanaka`**
    * **Why:** The logs showed that the file `Carlos_Tanaka_Evaluation.txt` was opened 8 times, which was the highest count in the results. This repeated access to a specific personnel file, as opposed to the other files in the logs, indicates that it held the motive for the attack.

---

### Flag 13: Candidate List Manipulation
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Trace tampering with promotion-related data.

  * What to Hunt:
    Unexpected modifications to structured HR records.

  * Thought:
    Whether tampering or staging — file changes precede extraction.

  * Hint:
    1. Utilize previous findings
    2. File is duplicated in other folder(s)

  * Side Note: 5/6
    (DeviceRegistryEvents | where RegistryKey has @"SOFTWARE\CorpHRChaos")
    
  `Identify the first instance where the file in question is modified and drop the corresponding SHA1 value of it.`
     
---
</details>

* **Objective:** Trace tampering with promotion-related data.
* **Thought Process:** The attacker tampered with a file before exfiltrating it. We looked for the first modification of a promotion-related file and its SHA1 hash.
* **KQL Query Used:**
```kusto
  DeviceFileEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where ActionType == "FileModified"
  | where FileName contains "promotion"
  | project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA1
  | sort by Timestamp asc
```
* **Query Results:**
<img width="954" height="255" alt="image12" src="https://github.com/user-attachments/assets/3783c58a-5923-44b5-8e39-0aade9dd647b" />


* **Identified Answer:** **`df5e35a8dcecdf1430af7001c58f3e9e9faafa05`**
    * **Why:** This SHA1 hash corresponds to the `FileModified` event on `PromotionCandidates.csv`, which is a key piece of evidence of data tampering.

---

### Flag 14: Audit Trail Disruption
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Detect attempts to impair system forensics.

  * What to Hunt:
    Operations aimed at removing historical system activity.

  * Thought:
    The first thing to go when a crime’s committed? The cameras.

  * Hint:
    1. "ab"

  `Identify when the first attempt at clearing the trail was done.`
     
---
</details>

* **Objective:** Detect attempts to impair system forensics.
* **Thought Process:** The attacker would clear logs to cover their tracks. We looked for `wevtutil.exe` commands. `wevtutil.exe` is a legitimate Windows command-line utility used to manage event logs. Its primary function is to perform administrative tasks on logs, such as exporting, archiving, or clearing them. It is often abused by attackers to erase their tracks and impair system forensics.

* **KQL Query Used:**
```kusto
  // Hunt for anti-forensics activity to clear logs
  DeviceProcessEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where ProcessCommandLine has_any ("wevtutil.exe", "clear-log", "clear-eventlog")
  | project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine
  | sort by Timestamp asc
```
* **Query Results:**
<img width="961" height="424" alt="image4" src="https://github.com/user-attachments/assets/b9ce401a-906e-4d59-b648-11db6dd571c7" />

* **Identified Answer:** **`2025-08-19T04:55:48.9660467Z`**
    * **Why:** Based on the results, the first attempt at clearing the audit trail was done at `Aug 19, 2025 12:55:48 AM`.
The logs show that at this time, the command `wevtutil.exe cl Security` was executed, which is a direct command to clear the Security event log. This action aligns perfectly with the flag's objective of impairing system forensics.

---

### Flag 15: Final Cleanup and Exit Prep
<details>
  <summary>Original task (click to reveal)</summary> 
  
  * Objective:
    Capture the combination of anti-forensics actions signaling attacker exit.

  * What to Hunt:
    Artifact deletions, security tool misconfigurations, and trace removals.

  * Thought:
    Every digital intruder knows — clean up before you leave or you’re already caught.

  * Side Note: 6/6
    | sort by Timestamp desc

  `Identify when the last associated attempt occurred.`
     
---
</details>

* **Objective:** Capture the combination of anti-forensics actions signaling attacker exit.
* **What to Hunt:** Artifact deletions, security tool misconfigurations, and trace removals.
* **Thought Process:** We looked for the last anti-forensics action. This could be log clearing, history file deletion, or artifact deletion.
* **KQL Query Used:**
  This query looks for three key anti-forensics actions:
    * wevtutil.exe cl: Hunting for commands that clear system event logs to erase evidence.
    * ConsoleHost_history.txt: Looking for the deletion of the PowerShell history file, which contains a record of all executed commands.
    * Remove-Item: Searching for commands that delete files or registry keys, a general cleanup action.

```kusto
  // Hunt for the last anti-forensics action before exit
  union DeviceProcessEvents, DeviceFileEvents
  | where DeviceName =~ "n4thani3l-vm"
  | where InitiatingProcessAccountName =~ "n4th4n13l"
  | where (ProcessCommandLine has "wevtutil.exe cl") or (FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted") or (ProcessCommandLine has "Remove-Item")
  | project Timestamp, ProcessCommandLine, FileName, ActionType, InitiatingProcessCommandLine
  | sort by Timestamp desc
```
* **Query Results:**
<img width="946" height="344" alt="image15" src="https://github.com/user-attachments/assets/c14e60a7-9c42-413d-9817-1d112ec8b772" />

* **Identified Answer:** **`2025-08-19T05:08:11.8528871Z`**
    * **Why:** Based on the results, the last associated attempt occurred at `Aug 19, 2025 1:08:11 AM`.
The logs show that at this time, the `ConsoleHost_history.txt` file was deleted. This is the latest event in the logs that is tied to a cleanup action, and it signals the end of the attacker's activities on the system.

---

## Conclusion & Recommendations

The "Unexplained Promotion" scenario revealed a methodical and deceptive adversary. The attack began with a PowerShell-driven intrusion on **`n4thani3l-vm`**, where the adversary demonstrated proficiency in:

* **Reconnaissance:** Enumerating local accounts and privileged groups (`net localgroup Administrators`) before accessing system information via `whoami`.
* **Credential Theft:** Using an uncommon LOLBin (`rundll32.exe`) to perform a memory dump (`MiniDump`), saving the output to a disguised HR-related file (`HRConfig.json`).
* **Stealth & Evasion:** Disabling core security features (`Set-MpPreference`) and clearing forensic evidence by deleting PowerShell history and clearing event logs (`wevtutil.exe`).
* **Persistence:** Establishing persistence by placing a malicious script (`OnboardTracker.ps1`) in a startup registry key.
* **Data Manipulation & Exfiltration:** Modifying the `PromotionCandidates.csv` file before establishing an outbound connection to an external domain (`pipedream.net`) to exfiltrate data.

**Recommendations:**

1.  **Enhanced PowerShell Logging:** Ensure advanced logging is enabled to capture full script block and module details, which would have provided immediate visibility into the attacker's obfuscated commands.
2.  **Behavioral Detections for LOLBins:** Implement and fine-tune behavioral detection rules for the anomalous usage of legitimate tools (e.g., `rundll32.exe` with `MiniDump` arguments, `wevtutil.exe` clearing logs).
3.  **Registry Monitoring:** Strengthen monitoring for modifications to common autorun registry keys, particularly those pointing to non-standard executables or scripts.
4.  **Network Anomaly Detection:** Implement rules to detect unusual outbound connections to non-whitelisted domains or IP addresses from critical endpoints.
5.  **Endpoint Hardening:** Enforce strict application whitelisting where possible to prevent unauthorized executables (like `ledger_viewer.exe`) from running, even if dropped in temporary folders.
6.  **Regular Audits:** Conduct regular audits of user accounts, especially privileged ones, for anomalous activity and group memberships.

This hunt provides critical insights into the adversary's tradecraft, enabling us to strengthen our defenses against similar future attacks.
