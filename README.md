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
    | limit 10
    ```
* **Identified Answer:** **`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`**
    * **Why:** This SHA256 hash corresponds to the `powershell.exe` command that enumerated local user accounts, a key step in post-exploitation reconnaissance.

---

### Flag 3: Privileged Group Assessment

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
    | limit 5
    ```
* **Identified Answer:** **`"powershell.exe" net localgroup Administrators`**
    * **Why:** This command directly reveals the attacker's intent to identify elevated accounts for a potential privilege escalation.

---

### Flag 4: Active Session Discovery

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
    | limit 5
    ```
* **Identified Answer:** **`"powershell.exe" qwinsta`**
    * **Why:** This command is used to query active sessions, a key reconnaissance step for an attacker looking to blend into an existing user context.

---

### Flag 5: Defender Configuration Recon

* **Objective:** Expose tampering or inspection of AV defenses, disguised under HR activity.
* **Thought Process:** The attacker would try to disable Defender. We looked for a PowerShell command with keywords like `Set-MpPreference` that also included HR-related keywords or was part of a larger script disguised as a business tool.
* **KQL Query Used:**
    ```kusto
    let defender_keywords = dynamic(["MpPreference", "Defender", "Antivirus", "RealtimeProtection", "disable"]);
    let hr_keywords = dynamic(["HR", "HumanResources", "Payroll", "Employee", "Report", "documents"]);
    union DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents
    | where Timestamp > datetime(2025-08-18T23:42:54Z)
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where ProcessCommandLine has_any (defender_keywords) or FolderPath has_any (defender_keywords) or FileName has_any (defender_keywords) or RegistryKey has_any (defender_keywords)
    | where ProcessCommandLine has_any (hr_keywords) or FolderPath has_any (hr_keywords) or FileName has_any (hr_keywords) or RegistryKey has_any (hr_keywords)
    | project Timestamp, ActionType, ProcessCommandLine, FolderPath, FileName, InitiatingProcessAccountName, RegistryKey, RegistryValueData
    | sort by Timestamp asc
    | limit 10
    ```
* **Identified Answer:** **`"powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep -Seconds 1; Set-Content -Path "C:\Users\Public\PromotionPayload.ps1" -Value "Write-Host 'Payload Executed'"`**
    * **Why:** This full command line provides a complete picture of the attack's objective, from disabling the antivirus to dropping a malicious payload.

---

### Flag 6: Defender Policy Modification

* **Objective:** Validate if core system protection settings were modified.
* **Thought Process:** We looked for registry modifications to persistent Defender settings.
* **KQL Query Used:**
    ```kusto
    DeviceRegistryEvents
    | where Timestamp > datetime(2025-08-19T00:24:03Z)
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where RegistryKey contains "Windows Defender"
    | where InitiatingProcessCommandLine has_any("powershell", "reg.exe")
    | project Timestamp, ActionType, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
    | sort by Timestamp asc
    | limit 5
    ```
* **Identified Answer:** **`DisableAntiSpyware`**
    * **Why:** This is a definitive sign of the attacker modifying core protection settings to maintain their foothold.

---

### Flag 7: Access to Credential-Rich Memory Space

* **Objective:** Identify if the attacker dumped memory content from a sensitive process.
* **Thought Process:** The attacker used a system utility in an uncommon way to dump memory. We looked for the `rundll32.exe` command with a `MiniDump` argument.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where FileName contains "notepad"
    | summarize count() by ProcessCommandLine
    | sort by count_ desc
    ```
* **Identified Answer:** **`HRConfig.json`**
    * **Why:** The logs showed the use of `rundll32.exe` with the `MiniDump` argument, writing the output to `HRConfig.json`. This is the HR-related file associated with the memory dump.

---

### Flag 8: File Inspection of Dumped Artifacts

* **Objective:** Detect whether memory dump contents were reviewed post-collection.
* **Thought Process:** The attacker would have opened the dumped file (`HRConfig.json`) to inspect its contents. We looked for a tool like `notepad.exe` opening this specific file.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where Timestamp > datetime('2025-08-18T23:59:54Z')
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where ProcessCommandLine contains "HRConfig.json"
    | where InitiatingProcessFileName has_any ("notepad.exe", "code.exe", "powershell.exe")
    | project Timestamp, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256
    | sort by Timestamp asc
    | limit 5
    ```
* **Identified Answer:** **`"notepad.exe" C:\HRTools\HRConfig.json`**
    * **Why:** This command directly shows the attacker verifying the contents of the dumped credential file.

---

### Flag 9: Outbound Communication Test

* **Objective:** Catch network activity establishing contact outside the environment.
* **Thought Process:** An attacker would perform a network test before exfiltrating data. We looked for outbound connections to uncommon destinations.
* **KQL Query Used:**
    ```kusto
    DeviceNetworkEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where RemoteUrl !endswith "microsoft.com" and RemoteUrl !contains "windows.update"
    | where InitiatingProcessFileName contains "powershell"
    | project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine, InitiatingProcessAccountName
    | sort by Timestamp asc
    ```
* **Identified Answer:** **`.net`**
    * **Why:** The TLD `.net` is a part of the unusual outbound URL, indicating a test connection to an external domain.

---

### Flag 10: Covert Data Transfer

* **Objective:** Uncover evidence of internal data leaving the environment.
* **Thought Process:** We needed to find the last unusual outbound network connection. We sorted network events by timestamp in descending order.
* **KQL Query Used:**
    ```kusto
    DeviceNetworkEvents
    | where Timestamp > datetime('2025-08-19T00:37:45Z')
    | where DeviceName =~ "n4thani3l-vm"
    | where ActionType == "ConnectionSucceeded"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where RemoteUrl !endswith "microsoft.com" and RemoteUrl !contains "windows.update"
    | project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessCommandLine
    | sort by Timestamp desc
    | limit 5
    ```
* **Identified Answer:** **`3.234.58.20`**
    * **Why:** This IP address is associated with the last unusual outbound connection, which is the final step before data exfiltration.

---

### Flag 11: Persistence via Local Scripting

* **Objective:** Verify if unauthorized persistence was established via legacy tooling.
* **Thought Process:** We looked for registry modifications in common persistence keys like `CurrentVersion\Run`.
* **KQL Query Used:**
    ```kusto
    DeviceRegistryEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where ActionType == "RegistryValueSet"
    | where RegistryKey contains "CurrentVersion\\Run"
    | project Timestamp, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
    | sort by Timestamp asc
    | limit 5
    ```
* **Identified Answer:** **`OnboardTracker.ps1`**
    * **Why:** This script was registered in a startup key, which is a definitive method of achieving persistence.

---

### Flag 12: Targeted File Reuse / Access

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
* **Identified Answer:** **`Carlos Tanaka`**
    * **Why:** The logs showed that the file `Carlos_Tanaka_Evaluation.txt` was opened 8 times, which was the highest count in the results. This repeated access to a specific personnel file, as opposed to the other files in the logs, indicates that it held the motive for the attack.

---

### Flag 13: Candidate List Manipulation

* **Objective:** Trace tampering with promotion-related data.
* **Thought Process:** The attacker tampered with a file before exfiltrating it. We looked for the first modification of a promotion-related file and its SHA1 hash.
* **KQL Query Used:**
    ```kusto
    let promotion_keywords = dynamic(["PromotionCandidates.csv", "PromotionList.csv"]);
    DeviceFileEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where ActionType == "FileModified"
    | where FileName has_any (promotion_keywords)
    | project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA1
    | sort by Timestamp asc
    | limit 5
    ```
* **Identified Answer:** **`df5e35a8dcecdf1430af7001c58f3e9e9faafa05`**
    * **Why:** This SHA1 hash corresponds to the `FileModified` event on `PromotionCandidates.csv`, which is a key piece of evidence of data tampering.

---

### Flag 14: Audit Trail Disruption

* **Objective:** Detect attempts to impair system forensics.
* **Thought Process:** The attacker would clear logs to cover their tracks. We looked for `wevtutil.exe` commands.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where Timestamp > datetime('2025-08-19T00:00:00Z')
    | where ProcessCommandLine has_any ("wevtutil.exe", "clear-log", "clear-eventlog")
    | project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine
    | sort by Timestamp asc
    | limit 5
    ```
* **Identified Answer:** **`Aug 19, 2025 12:55:48 AM`**
    * **Why:** This is the earliest timestamp for an anti-forensics command, where the attacker is actively clearing system event logs.

---

### Flag 15: Final Cleanup and Exit Prep

* **Objective:** Capture the combination of anti-forensics actions signaling attacker exit.
* **What to Hunt:** Artifact deletions, security tool misconfigurations, and trace removals.
* **Thought Process:** We looked for the last anti-forensics action. This could be log clearing, history file deletion, or artifact deletion.
* **KQL Query Used:**
    ```kusto
    union DeviceProcessEvents, DeviceFileEvents
    | where DeviceName =~ "n4thani3l-vm"
    | where InitiatingProcessAccountName =~ "n4th4n13l"
    | where (ProcessCommandLine has "wevtutil.exe cl") or (FileName =~ "ConsoleHost_history.txt" and ActionType == "FileDeleted") or (ProcessCommandLine has "Remove-Item")
    | project Timestamp, ProcessCommandLine, FileName, ActionType, InitiatingProcessCommandLine
    | sort by Timestamp desc
    | limit 1
    ```
* **Identified Answer:** **`Aug 19, 2025 1:08:11 AM`**
    * **Why:** This is the latest timestamp of a confirmed anti-forensics action, signaling the final cleanup before the attacker's exit.

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
