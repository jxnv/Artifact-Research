# IOC Investigation: Is ASCTray.exe Malicious or Benign?

---

## Executive Summary

This investigation analyzes the binary **ASCTray.exe** (SHA-256: `da09c0f03f03015c06b6cc3bd1ce0ccbac5fd71aca5794c94c90d0d92e663883`) recovered from `C:\Program Files (x86)\IObit\Advanced SystemCare Ultimate\`. The file is the system tray module for **IObit Advanced SystemCare Ultimate**, a Chinese-developed PC optimization suite.

At face value, this is a commercially distributed, digitally signed executable. However, multiple security vendors consistently classify it and the broader ASC suite as a **Potentially Unwanted Program (PUP/PUA)**, citing aggressive startup persistence, undisclosed telemetry, keyboard and mouse monitoring capabilities, bundled software, and a historical record of intellectual property theft by its developer.

**Final Classification: Suspicious**
**Analyst Confidence: High**

The file is legitimate software — not novel malware — but its behavioral profile and vendor history raise substantive concerns for enterprise environments, and it serves as a documented masquerade target for at least two known malware families.

---

## Artifact Overview

- **Hash (SHA-256):** da09c0f03f03015c06b6cc3bd1ce0ccbac5fd71aca5794c94c90d0d92e663883
- **Hash (MD5):** 5D52DAD90573A35885666FDC46339BF7
- **File Name:** ASCTray.exe
- **File Description:** Advanced SystemCare Tray Module (Advanced SystemCare System Tray Icon)
- **Vendor:** IObit Information Technology (Chinese, founded 2004)
- **Product:** Advanced SystemCare Ultimate
- **Expected File Path:** `C:\Program Files (x86)\IObit\Advanced SystemCare Ultimate\ASCTray.exe`
- **Process:** ASCTray.exe /AutoStart
- **Child Processes:** ASC.exe
- **Digital Signature:** Signed by IObit Information Technology (VeriSign-issued Authenticode certificate)
- **Malware Family (Masquerade):** PE_NESHTA.A / Virus:Win32/Neshta.A
- **Threat Actor:** None attributed — commercial software with PUP/PUA classification

---

## Intelligence Findings

### Reputation and Detection History

The SHA-256 hash `da09c0f03f03015c06b6cc3bd1ce0ccbac5fd71aca5794c94c90d0d92e663883` was surfaced in a publicly documented Malwarebytes scan log, where it was quarantined under the detection name **PUP.Optional.AdvancedSystemCare** (Malwarebytes rule ID 8063, category 380353). The MD5 `5D52DAD90573A35885666FDC46339BF7` is associated with the same file.

This file appears across multiple vendor detections spanning several years:

- **Malwarebytes / ThreatDown:** PUP.Optional.AdvancedSystemCare — blocks installer via real-time protection and quarantines the executable
- **Microsoft Defender:** PUA:Win32/IObit — classified as a potentially unwanted application with low risk but persistent re-detection after removal attempts
- **Microsoft Defender:** PUABundler:Win32/IOBitBundler — separate detection targeting the bundled installer behavior
- **ESET NOD32:** Win32/Deceptor.AdvancedSystemCare.A — IObit disputed this as a false positive
- **Trend Micro:** PUA.Win32.IOBit.C and PUA.Win32.IOBit.D — both variants documented with specific behavioral and registry artifacts
- **Zscaler ThreatLibrary:** Win32.PUA.IOBit.C

None of the above detections indicate novel or weaponized malware code in this specific sample. The consensus from the security community is PUP/PUA — software that exhibits behaviors associated with unwanted programs but falls short of confirmed weaponized malware.

### First Seen / Context

ASCTray.exe has existed across multiple product generations of IObit's Advanced SystemCare (versions 4 through Ultimate current). The specific hash under review is tied to the **Advanced SystemCare Ultimate** product line and first appeared in Malwarebytes scan logs. The most recent version of the product (v19.4.0) was released May 2026, indicating the software is actively maintained.

### IObit Corporate History and Trust Concerns

IObit's reputation within the security community is notably poor. In **November 2009**, Malwarebytes publicly accused IObit of incorporating stolen malware detection signatures into their IObit Security 360 product. Proof was provided via planted "honeypot" definitions for a non-existent rogue application, which subsequently appeared in IObit's database. IObit subsequently removed the disputed definitions — which reduced their database by approximately 40% — without admitting wrongdoing. Malwarebytes stated that further investigation revealed IObit may have stolen databases from multiple security vendors.

IObit is a **Chinese company** and has been since its founding in 2004. Ownership concerns have been raised in community forums since at least 2015. IObit's own privacy policy explicitly states that user data is collected and may be shared with third parties and within its corporate family. Multiple user reports document persistent outbound network connections ("calls home") that continue even after the product is uninstalled.

---

## Behavioral Analysis

### Execution

ASCTray.exe launches at Windows startup as a tray icon process. Its command line is `ASCTray.exe /AutoStart`. Once running, it spawns `ASC.exe` as a child process in the background. The process runs with the privileges of the logged-in user account. It provides a GUI system tray icon (a circled "C") with a right-click menu for accessing ASC features.

### Persistence

This binary establishes multiple persistence mechanisms:

- **Registry Run Key:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` — adds an entry that launches ASCTray.exe at every user login; notably, disabling the startup option in ASC settings was historically insufficient to prevent re-registration of this key
- **Scheduled Task:** Class `{10C87E38-501D-4A91-8E15-26C69EF31399}` — runs on registration
- **Companion Scheduled Tasks:** `ASC7_AutoUpdate` (weekly Sundays at 17:20), `ASC7_AutoCare` (daily at 5:00 PM), `ASC7U_SkipUac_*` (UAC bypass task), `ASCService` (Windows service), `ASC7_PerformanceMonitor`
- **Windows Service:** `AdvancedSystemCareAntiVirus` service (in Ultimate variant), `ASCService.exe`
- **Shell Extension:** `ASCExtMenu_64.dll` added to Windows Explorer

### Network Activity

Multiple user reports document ASCTray.exe and related ASC processes making persistent outbound connections to IObit infrastructure. The product contacts IObit servers for update checks, telemetry, and license validation. Specific domains and IPs were not confirmed via live sandbox analysis for this exact hash, but the product is documented to maintain ongoing internet connectivity.

### Defense Evasion

The most significant defense evasion concern is **masquerading**. Two documented malware families are known to disguise themselves as `ASCTray.exe`:

- **PE_NESHTA.A** (Trend Micro) — a file-infecting virus that prepends its code to target executables, typically copying itself to `%SystemRoot%` as `svchost.com` and modifying `HKCR\exefile\shell\open\command` so it executes any time an `.exe` file is opened
- **Virus:Win32/Neshta.A** (Microsoft) — the same virus, cross-vendor detected

If `ASCTray.exe` is found in `C:\Windows\` or `C:\Windows\System32\`, it should be treated as a **high-confidence malware indicator**, not legitimate software. Legitimate ASCTray.exe resides exclusively in `C:\Program Files\IObit\` or `C:\Program Files (x86)\IObit\`.

The Neshta family's use of the ASCTray.exe name as a masquerade means defenders must verify file path, digital signature, and hash before drawing conclusions.

---

## Detection Engineering Notes

Artifacts most likely to trigger security tooling:

- **File Hash (SHA-256):** da09c0f03f03015c06b6cc3bd1ce0ccbac5fd71aca5794c94c90d0d92e663883
- **File Hash (MD5):** 5D52DAD90573A35885666FDC46339BF7
- **File Name:** ASCTray.exe (also: ASC.exe, ASCService.exe, ASCAvSvc.exe, Monitor.exe, AutoUpdate.exe, AutoCare.exe)
- **Process Path (Suspicious):** `C:\Windows\ASCTray.exe` or `C:\Windows\System32\ASCTray.exe` — treat as high-priority malware indicator
- **Process Path (Expected):** `C:\Program Files (x86)\IObit\Advanced SystemCare Ultimate\ASCTray.exe`
- **Command Line:** `ASCTray.exe /AutoStart`
- **Registry Keys:**
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` — value pointing to ASCTray.exe
  - `HKCR\exefile\shell\open\command` — if modified to point to svchost.com (Neshta indicator)
- **Scheduled Tasks:** Names containing `ASC7`, `ASCTray`, `Advanced SystemCare`, or class `{10C87E38-501D-4A91-8E15-26C69EF31399}`
- **Services:** `AdvancedSystemCareAntiVirus`, `ASCService`
- **Shell Extension:** `{2803063F-4B8D-4dc6-8874-D1802487FE2D}` in Windows Explorer

---

## Analyst Assessment

### What Supports Malicious or Suspicious Classification?

- Classified as PUP/PUA by Malwarebytes, Microsoft Defender, ESET, Trend Micro, and Zscaler — a cross-vendor consensus
- IObit's proven history of stealing proprietary malware signatures from Malwarebytes (2009), with indications other vendors were also affected
- Documented keyboard and mouse input monitoring capabilities in the process
- Persistent "call home" network activity reported by users even post-uninstall
- Data collection practices disclosed in privacy policy include sharing with third parties
- IObit is a Chinese company — relevant for environments with geopolitical data handling requirements
- Aggressive re-registration of startup persistence (Run keys) even when user disables the setting
- Known masquerade target for PE_NESHTA.A and Virus:Win32/Neshta.A — defenders must validate file path every time ASCTray.exe is observed
- UAC bypass scheduled task (`SkipUac`) documented in Advanced SystemCare Ultimate 7

### What Supports Benign Classification?

- The file is commercially distributed software, not a novel malware payload
- Carries a valid Authenticode digital signature issued by VeriSign to IObit Information Technology
- Expected file path (`C:\Program Files (x86)\IObit\`) matches legitimate installation
- No confirmed weaponized payload, exploit delivery, or C2 infrastructure in this hash
- File.net assigns a 29% danger rating — notably below the threshold for confirmed malware
- Consistently used by millions of consumers over 15+ years without widespread incident reports tied to direct data theft or ransomware delivery

### What Remains Unknown?

- Exact telemetry data collected and transmitted to IObit servers from this specific binary version
- Whether any supply chain compromise of IObit's update infrastructure has ever occurred
- Specific network destinations contacted by this hash in sandbox analysis (not confirmed via live detonation)
- Whether the bundler or installer accompanying this version includes additional PUPs beyond the core ASC suite

---

## Final Verdict

**Classification: Suspicious**

**Confidence: High**

This binary is legitimate software flagged as a PUP/PUA by a consistent cross-vendor coalition. It does not meet the threshold for **Malicious** because no confirmed weaponized payload, C2, or direct harm has been attributed to this specific hash. However, it does not merit a **Benign** classification given: IObit's documented history of intellectual property theft, persistent telemetry with a Chinese vendor, aggressive persistence mechanisms, keyboard/mouse monitoring capabilities, UAC bypass tasks, and its role as an active masquerade target for known file-infecting malware.

In **enterprise or regulated environments**, the presence of ASCTray.exe warrants removal and should be blocked by application control policy. In **consumer environments**, it is lower risk but users should be aware of the data collection and persistence behaviors.

**Critical Alert:** Any instance of `ASCTray.exe` found outside of `C:\Program Files\IObit\` should be treated as a probable Neshta family infection and escalated immediately.

---

## Quick Reference Indicators

**File Hashes:**
- SHA-256: `da09c0f03f03015c06b6cc3bd1ce0ccbac5fd71aca5794c94c90d0d92e663883` — ASCTray.exe from Advanced SystemCare Ultimate; PUP flagged by Malwarebytes, Microsoft Defender, ESET, Trend Micro
- MD5: `5D52DAD90573A35885666FDC46339BF7` — same file, alternate lookup reference

**File Names (hunt or block):**
- `ASCTray.exe` — block if found outside official IObit install path; high-priority if in System32 or Windows root (Neshta masquerade)
- `ASCService.exe`, `ASCAvSvc.exe`, `Monitor.exe`, `AutoCare.exe`, `AutoUpdate.exe` — companion ASC processes; investigate collectively
- `svchost.com` in `%SystemRoot%` — strong indicator of Neshta infection

**Processes:**
- `ASCTray.exe /AutoStart` — standard ASC startup command; verify path before dismissing
- Child process `ASC.exe` spawned by ASCTray.exe

**Registry Keys:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → ASCTray.exe entry — persistence; investigate if unexpected
- `HKCR\exefile\shell\open\command` — if modified away from default, investigate for Neshta infection immediately

**Scheduled Tasks:**
- Names containing `ASC7`, `Advanced SystemCare`, or CLSID `{10C87E38-501D-4A91-8E15-26C69EF31399}` — persistence artifacts; verify host is an authorized ASC install

**Services:**
- `AdvancedSystemCareAntiVirus` — Ultimate variant AV service
- `ASCService` — core background service

**Shell Extension:**
- `{2803063F-4B8D-4dc6-8874-D1802487FE2D}` added to Windows Explorer — monitor for unexpected appearances on non-IObit hosts

---

## MITRE ATT&CK Mapping

**T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**
ASCTray.exe writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to ensure execution at every user logon. Documented re-registration behavior even when the user attempts to disable the startup option.

**T1053.005 – Scheduled Task/Job: Scheduled Task**
Multiple scheduled tasks are created during installation including `ASCTray` (CLSID `{10C87E38-501D-4A91-8E15-26C69EF31399}`), `ASC7_AutoUpdate`, `ASC7_AutoCare`, and a UAC bypass task. These ensure execution across multiple time-based triggers independent of the Run key.

**T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control**
A scheduled task named `ASC7U_SkipUac_*` is documented in Advanced SystemCare Ultimate installations, indicating a deliberate UAC bypass mechanism for elevated execution without user prompts.

**T1056.001 – Input Capture: Keylogging**
ASCTray.exe is documented to be capable of recording keyboard and mouse inputs. This capability is acknowledged in process analysis databases and represents a significant concern regardless of stated intent.

**T1112 – Modify Registry**
The product modifies multiple registry locations beyond simple persistence — including `HKCR\exefile\shell\open\command` when infected by the Neshta masquerade variant, and general system optimization registry edits during normal operation.

**T1036 – Masquerading**
PE_NESHTA.A and Virus:Win32/Neshta.A are confirmed to masquerade as `ASCTray.exe`, placing the filename in attacker playbooks. Detection rules for ASCTray.exe must include path validation to avoid either false negatives (missing malware) or false positives (blocking legitimate software).

**T1071.001 – Application Layer Protocol: Web Protocols**
The product maintains ongoing outbound HTTP/HTTPS connectivity to IObit infrastructure for updates, telemetry, and license validation. Users have reported persistent outbound traffic continuing post-uninstall.

---

## Detection Opportunities

### Sigma Ideas

```yaml
title: Suspicious ASCTray.exe Outside IObit Install Path
status: experimental
description: Detects ASCTray.exe executing from a path other than the expected IObit installation directory, a known indicator of Neshta family masquerading.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\ASCTray.exe'
  filter_legitimate:
    Image|startswith:
      - 'C:\Program Files\IObit\'
      - 'C:\Program Files (x86)\IObit\'
  condition: selection and not filter_legitimate
falsepositives:
  - Non-standard IObit installation paths
level: high
tags:
  - attack.defense_evasion
  - attack.t1036
```

```yaml
title: IObit ASCTray UAC Bypass Scheduled Task
status: experimental
description: Detects creation of the ASC SkipUac scheduled task used by Advanced SystemCare to bypass UAC.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: 'SkipUac'
  condition: selection
falsepositives:
  - Authorized IObit installations
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548.002
```

### YARA Ideas

```yara
rule ASCTray_Masquerade_Neshta {
    meta:
        description = "Detects ASCTray.exe filename used by Neshta family in Windows system directories"
        author = "Threat Intelligence"
        reference = "file.net/process/asctray.exe.html"
    strings:
        $name = "ASCTray.exe" nocase
    condition:
        $name and (
            pe.sections[0].name contains ".text" and
            not pe.version_info["CompanyName"] contains "IObit"
        )
}
```

### Splunk Hunting Queries

```spl
| Search for ASCTray running from unexpected paths
index=windows EventCode=4688
| where process_name="ASCTray.exe"
    AND NOT (process_path LIKE "C:\\Program Files\\IObit\\%"
             OR process_path LIKE "C:\\Program Files (x86)\\IObit\\%")
| table _time, ComputerName, user, process_path, process_commandline
| sort -_time
```

```spl
| Hunt for ASC-related scheduled tasks suggesting persistence
index=windows EventCode=4698
| where task_name LIKE "%ASC7%" OR task_name LIKE "%AdvancedSystemCare%"
| table _time, ComputerName, user, task_name, task_content
```

### Microsoft Sentinel Hunting Queries

```kql
// Detect ASCTray.exe executing outside expected IObit install path
DeviceProcessEvents
| where FileName =~ "ASCTray.exe"
| where not (FolderPath startswith @"C:\Program Files\IObit\" 
          or FolderPath startswith @"C:\Program Files (x86)\IObit\")
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

```kql
// Detect IObit-related registry persistence entries on non-standard hosts
DeviceRegistryEvents
| where RegistryKey contains "CurrentVersion\\Run"
| where RegistryValueData contains "ASCTray"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp desc
```

---

## References

- Malwarebytes ThreatDown — PUP.Optional.AdvancedSystemCare: https://www.threatdown.com/threat-detections/pup-optional-advancedsystemcare/
- Malwarebytes Detection Page: https://www.malwarebytes.com/blog/detections/pup-optional-advancedsystemcare
- Microsoft Security Intelligence — PUA:Win32/IObit: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=PUA%3AWin32%2FIObit
- Microsoft Security Intelligence — PUABundler:Win32/IOBitBundler: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=PUABundler%3AWin32%2FIOBitBundler&threatId=362730
- Microsoft Security Intelligence — Virus:Win32/Neshta.A: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Virus%3AWin32%2FNeshta.A
- Trend Micro — PUA.Win32.IOBit.C: https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/pua.win32.iobit.c
- Trend Micro — PUA.Win32.IOBit.D: https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/pua.win32.iobit.d
- Trend Micro — PE_NESHTA.A: https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/pe_neshta.a
- Zscaler ThreatLibrary — Win32.PUA.IOBit.C: https://threatlibrary.zscaler.com/threats/6c1c3976-4a85-4da6-a344-7fbb6f325a84
- FreeFixer — ASCTray.exe Analysis: https://www.freefixer.com/library/file/ASCTray.exe-69544/
- File.net — ASCTray.exe Process Analysis: https://www.file.net/process/asctray.exe.html
- ShouldIBlockIt — ASCTray.exe: https://www.shouldiblockit.com/asctray.exe-1487.aspx
- ShouldIRemoveIt — Advanced SystemCare Ultimate 7: https://www.shouldiremoveit.com/Advanced-SystemCare-Ultimate-7-98273-program.aspx
- BleepingComputer Startup DB — ASCTray.exe: https://www.bleepingcomputer.com/startups/ASCTray.exe-27130.html
- Malwarebytes Forums — IObit IP Theft: https://forums.malwarebytes.com/topic/29681-iobit-steals-malwarebytes-intellectual-property/
- Computerworld — IObit accused of stealing from Malwarebytes: https://www.computerworld.com/article/1333950/iobit-accused-of-stealing-from-malwarebytes.html
- dotTech — Malwarebytes vs. IObit Fiasco Conclusion: https://dottech.org/13126/malwarebytes-vs-iobit-fiasco-comes-to-a-close/
- Microsoft Q&A — Hash Evidence Report: https://learn.microsoft.com/en-us/answers/questions/4472cdc8-a129-4514-a26d-3e5395ef5019/i-believe-there-is-a-malware-in-my-system
- IObit Privacy Policy: https://www.iobit.com/en/privacy.php
- ESET Forum — ASC False Positive Discussion: https://forum.eset.com/topic/11250-false-positive-advanced-systemcare-is-falsedly-detected-by-eset-nod-32/
- UMA Technology — Warning About IObit Software: https://umatechnology.org/warning-about-iobit-software/
