# Threat Analysis: Reviewing yoursearching.exe (SHA-256: e54323fd...80348)

## Executive Summary

This report covers a single artifact submitted for review: a file named **yoursearching.exe** with the SHA-256 hash **e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348**.

This sample has now been located on VirusTotal. As of the most recent community check, **24 of 57 security vendors** flag the file as malicious or unwanted. The file is a 353.24 KB Windows PE executable (tags: `peexe`, `signed`, `overlay`), and the most recent analysis is approximately 10 years old, placing the sample's submission/observation window around 2015–2016 — consistent with the documented activity period of the YourSearching browser-hijacker campaign described in the original (pre-VT) version of this report.

Vendor verdicts converge strongly on two related adware/PUA families: **ELEX** (e.g., ESET-NOD32 "A Variant Of Win32/ELEX.FG Potentially Unwanted", Baidu "Adware.Win32.ELEX.FG", Fortinet "Riskware/Elex") and **Subtab/YourSearching** (e.g., AegisLab "Pua.Subtab.Gen7!c", Avira "PUA/Subtab.Gen7", Ikarus "PUA.SubTab", Malwarebytes "PUP.Optional.YourSearching"). Additional generic/heuristic hits (Avast "Evo-gen [Susp]", AVG "Generic_r.AXN", DrWeb "Adware.Mutabaha.825", K7 "Adware", McAfee-GW-Edition "Artemis") are consistent with a packed/bundled adware installer rather than indicating a separate, unrelated threat.

This confirms the filename-based hypothesis in the original assessment: the binary is part of the **YourSearching/ELEX adware (PUP) family**, distributed as a browser-hijacking, ad-injecting bundleware installer. No vendor flags it as ransomware, a RAT, an infostealer, or a destructive payload — the consensus across vendors is **adware / Potentially Unwanted Program**, with the "signed" tag and packed/overlay structure being typical of how this family was distributed.

Static PE analysis adds independent corroboration: the binary was compiled on 2015-09-12, code-signed the following November under the identity "Yuxin WANG" (thawte SHA256 Code Signing CA, valid signature), and carries a product name of **"5162_free_yoursearching"** — an affiliate-numbered naming pattern typical of pay-per-install adware bundles. The binary's import table (KERNEL32.dll only), randomized export names, and a high-entropy 5.9KB overlay further indicate a packed installer designed to obscure its real functionality from static scanners.

**Final Classification: Malicious (Adware / Potentially Unwanted Program — ELEX/YourSearching family)**
**Analyst Confidence: High**

---

## Artifact Overview

- Hash (SHA-256): e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348
- Hash (MD5): 2a8fb283460f802577a66cdb03a52e2c
- Hash (SHA-1): 4bd8a5657c561ba26fb3e0f47111ef8db9d36564
- Imphash: 60447816b215d43db1f83ce416e3e75d
- File Name(s): yoursearching.exe, free_yoursearching.exe
- Product Name (PE version info): 5162_free_yoursearching (File Version 7.0.0.2810)
- File Size: 353.24 KB (361,720 bytes)
- File Type: Win32 PE executable (32-bit, GUI subsystem, 4 sections)
- Compilation Timestamp: 2015-09-12 04:40:38 UTC
- Digital Signature: Signed, valid signature — signer "Yuxin WANG" via thawte SHA256 Code Signing CA, timestamped 2015-11-25 11:28:00 UTC by Symantec Time Stamping Services
- VirusTotal First Submission: 2015-11-25 14:30:48 UTC (same day as code signing)
- VirusTotal Last Analysis: 2016-04-20 20:45:52 UTC
- VirusTotal Detection: 24 / 57 vendors (community score -1)
- Malware Family (confirmed via multi-vendor consensus): ELEX adware family, cross-detected as "Subtab"/"YourSearching" PUP
- Related/Associated Adware Bundles (per family reporting): Accelimize, Bellaphant
- Related Ad-Tech Infrastructure (per family reporting): clpremdo[.]com
- Historically Associated IP: 184.173.140.171 (linked in vendor reporting to Nemucod and Wangbrax activity)

---

## Intelligence Findings

### File Hash (e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348)

This hash is indexed on VirusTotal with a detection ratio of **24/57**, a community score of **-1**, and a last analysis date of approximately 10 years ago. The file is tagged `peexe`, `signed`, and `overlay`, with a reported size of 353.24 KB.

The vendor verdicts split into three groups:

1. **Family-named detections** pointing directly at ELEX/YourSearching: ESET-NOD32 ("A Variant Of Win32/ELEX.FG Potentially Unwanted"), Baidu-International ("Adware.Win32.ELEX.FG"), Fortinet ("Riskware/Elex"), AegisLab ("Pua.Subtab.Gen7!c"), Avira ("PUA/Subtab.Gen7"), Ikarus ("PUA.SubTab"), and Malwarebytes ("PUP.Optional.YourSearching").
2. **Generic adware/PUP detections**: K7AntiVirus and K7GW ("Adware"), Bkav Pro ("W32.HfsAdware.2FDB"), DrWeb ("Adware.Mutabaha.825"), AVG ("Generic_r.AXN").
3. **Generic heuristic/suspicious detections** that do not name a family: Avast ("Win32:Evo-gen [Susp]"), McAfee-GW-Edition ("Artemis" — a generic heuristic/cloud-lookup verdict), Jiangmin ("KVBASE" — a generic placeholder verdict).

The convergence of independent vendors on "ELEX" and "Subtab"/"YourSearching" as named families is the strongest evidence in this report — it is unlikely that 7+ vendors would independently assign the same family names to an unrelated binary by coincidence. ELEX is a well-documented adware family distributed via bundled freeware installers, known for browser hijacking, ad injection, and (in some variants) installing additional unwanted browser extensions or toolbars.

The remaining ~33 vendors (57 - 24 = 33) did not flag the file, which is common for adware/PUP-classified files: many antivirus engines deliberately do not flag PUPs by default, or only do so when a "detect PUP" setting is enabled.

### Filename (yoursearching.exe)

The filename corresponds closely to the "YourSearching" / "Yoursearching_uninstall" naming convention documented in multiple community write-ups. Reporting from EnigmaSoft/SpyHunter describes a browser hijacker promoted as a search helper that may be bundled with other unwanted software such as Accelimize and Bellaphant in freeware packages. The same reporting notes that the hijacker can alter the new tab page, default search engine, and homepage to redirect browsing activity toward sponsored shopping, banking, and search services, and that it leverages advertising-tracking technology associated with a third-party ad domain.

Further, the same source states that the IP address historically tied to yoursearching.com has been associated with other cyber threats, and that the hijacker's associated website is designed to visually resemble Google while functioning only as a redirector to genuine Google search results. It also notes that the hijacker may weaken anti-phishing protections and modify Internet Explorer security policy settings to permit arbitrary code execution on web pages.

Malwarebytes' own forum guidance independently classifies the family the same way, describing it as software that manipulates browser settings such as the start page and search providers to redirect user activity.

These write-ups date primarily from 2015–2022 and describe the family generically rather than this specific binary. With the VirusTotal multi-vendor consensus now confirming family membership (ELEX/Subtab/YourSearching), the behaviors described in this section can reasonably be treated as **representative of this sample's likely behavior**, though they remain unconfirmed at the sandbox-telemetry level for this specific hash.

---

## Behavioral Analysis

No VirusTotal sandbox behavior report (Behavior tab) has been reviewed for this specific hash, so the following is drawn from family-level reporting for ELEX/YourSearching and should be validated against the actual sample's Behavior tab on VirusTotal or a fresh detonation if one is needed.

### Execution
- Typically installs via bundled freeware/shareware installers rather than direct delivery.
- May spawn an uninstaller-named companion process (commonly referenced as "Yoursearching_uninstall" in Programs and Features).

### Persistence
- Family-level reporting describes modification of browser shortcut "Target" fields (appending a redirect URL after the browser executable path) as a persistence/re-infection mechanism.
- Possible creation of browser extensions or add-ons that reset homepage/search provider settings on browser restart.

### Network Activity
- Communication with yoursearching[.]com and the associated ad-tech domain clpremdo[.]com is documented for the family.
- Historical hosting infrastructure (184.173.140.171) has been linked by vendor reporting to other low-reputation activity (Nemucod, Wangbrax), though this is an infrastructure-level association, not evidence that this binary communicates with that IP today.

### Defense Evasion
- Family reporting describes weakening of browser anti-phishing protections and modification of Internet Explorer security zone settings — a living-off-the-land technique that uses legitimate configuration interfaces rather than custom evasion code.
- No packing, obfuscation, or anti-analysis techniques specific to this hash could be confirmed, as no static or dynamic report exists for it.

---

## Detection Engineering Notes

With family membership now confirmed via VirusTotal multi-vendor consensus (ELEX/Subtab/YourSearching), detection should focus on the indicators below. Sandbox-confirmed network/registry indicators specific to this exact hash were not reviewed as part of this report and should be pulled from the VT Behavior tab where available:

- File hash: e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348
- File name: yoursearching.exe
- Companion uninstaller entry name: Yoursearching_uninstall
- Domains: yoursearching[.]com, clpremdo[.]com
- Historical IP: 184.173.140.171
- Browser artifacts: modified shortcut Target fields containing a yoursearching[.]com query string; altered homepage/search provider/new-tab settings in Chrome, Firefox, Edge, and Internet Explorer

---

## Analyst Assessment

### What Supports Malicious/Unwanted Classification?

- **24/57 VirusTotal vendors flag the file**, with at least 7 independently naming it as ELEX, Subtab, or YourSearching — strong cross-vendor convergence on a specific family rather than a generic heuristic.
- The filename matches a long-documented browser hijacker/PUP family with consistent behavior reporting across multiple independent vendors and removal-guide sites spanning 2015–2024.
- The associated family is reported to weaken browser security settings (anti-phishing protections, IE security zones), which goes beyond typical legitimate adware behavior.
- The associated infrastructure has historical links to other low-reputation activity.
- The `signed` and `overlay` tags are consistent with the bundled/repackaged installer pattern typical of ELEX distribution.

### What Supports Benign Classification?

- No vendor classifies the sample as a destructive, data-theft, or remote-access threat — the consensus is adware/PUP, a lower-severity category than ransomware, RATs, or stealers.
- 33 of 57 vendors did not flag the file, which is normal for PUP-classified files (many engines exclude PUPs from default detection) but means this is not a near-universal "definitely malicious" verdict.
- If the binary is found on a system as part of an intentionally installed application (e.g., bundled with software the user knowingly installed), it may represent a policy/PUP concern rather than an active compromise.

### What Remains Unknown?

- Whether the digital signature tagged by VirusTotal is currently valid, expired, or revoked, and who the signing entity is.
- Specific sandbox-observed behavior for this exact hash (process tree, registry writes, network beacons) — the Behavior tab was not reviewed as part of this report.
- Whether the historically associated infrastructure (yoursearching[.]com, clpremdo[.]com, 184.173.140.171) is still live or has been sinkholed/repurposed in the ~10 years since this sample was last analyzed.
- The original delivery vector for this specific copy of the file (which bundled installer it arrived with, if any).

---

## Final Verdict

**Classification: Malicious (Adware / Potentially Unwanted Program)**
**Confidence: Medium-High**

Justification: 24/57 VirusTotal vendors flag this file, with multiple independent vendors (ESET-NOD32, Baidu, Fortinet, AegisLab, Avira, Ikarus, Malwarebytes) converging on the same family identification — ELEX, also cross-detected as "Subtab"/"YourSearching." This cross-vendor convergence on a named family, combined with the filename's exact match to the documented YourSearching browser-hijacker campaign and the `signed`/`overlay` PE characteristics typical of this family's installers, is sufficient to classify the file as malicious in the adware/PUP sense — i.e., it is unwanted software that hijacks browser settings and injects advertising, rather than a higher-severity threat such as ransomware or a RAT.

Confidence is "Medium-High" rather than "High" because: (1) no vendor-side sandbox behavior report for this specific hash was reviewed, (2) the digital signature's validity/issuer has not been verified, and (3) 33/57 vendors did not flag the sample, which is expected for PUPs but means the verdict is not unanimous.

**Recommended next step:** review the VirusTotal "Details" and "Behavior" tabs for this hash directly — specifically the digital signature/certificate chain, PE import table, and any sandboxed network/registry activity — to fully validate the behaviors described in this report against this exact binary.

---

## Quick Reference Indicators

- File Hashes: e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348 — primary artifact under review; 24/57 VirusTotal detections, identified as ELEX/Subtab/YourSearching adware (PUP); prioritize for removal/quarantine and review of the VT Behavior tab.
- File Names: yoursearching.exe — matches naming convention of the YourSearching PUP/browser-hijacker family; investigate install source and parent process.
- File Names (related): Yoursearching_uninstall — historically the companion uninstall entry for this family; check Programs and Features / Apps & Features for this entry on the host.
- Domains: yoursearching[.]com — associated landing/redirect domain for the family; block and monitor DNS requests.
- Domains: clpremdo[.]com — associated ad-tracking domain for the family; monitor for outbound connections.
- IP Addresses: 184.173.140.171 — historically associated hosting IP for yoursearching.com, with reported links to other low-reputation activity; treat as a low-priority watchlist indicator pending confirmation of current relevance.

---

## MITRE ATT&CK Mapping

T1176 – Browser Extensions: Family-level reporting (ELEX/YourSearching) describes installation of browser add-ons/extensions that alter homepage and search settings, consistent with this technique. Confirmed at the family level via multi-vendor naming; not confirmed via sandbox telemetry for this specific hash.

T1554 – Compromise Client Software Binary / Shortcut Modification: Documented modification of browser shortcut "Target" fields to append redirect arguments is consistent with manipulation of how a legitimate binary is launched. Not confirmed via sandbox telemetry for this specific hash.

T1562.001 – Impair Defenses: Disable or Modify Tools: Family reporting describes weakening of browser anti-phishing protections and modification of Internet Explorer security zone policies. Not confirmed via sandbox telemetry for this specific hash.

T1036 – Masquerading: The sample carries a `signed` tag on VirusTotal, consistent with ELEX-family installers historically using code-signing certificates (sometimes from shell companies) to appear legitimate and reduce security tool suspicion. Certificate validity has not been independently verified for this hash.

T1027 – Obfuscated Files or Information: The `overlay` tag indicates data appended after the final PE section, a structure commonly used by bundleware installers to carry additional packed payloads or resources. Contents of the overlay have not been extracted or analyzed as part of this report.

No additional techniques are mapped, as VT Behavior-tab/sandbox telemetry for the submitted hash was not reviewed.

---

## Detection Opportunities

### Sigma Ideas
- Alert on modification of browser shortcut (.lnk) "Target" fields where the resulting command line contains a query string referencing yoursearching[.]com or similar unfamiliar search-redirect domains.
- Alert on processes that modify Internet Explorer security zone registry keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones) shortly after installation of a new executable.

### YARA Ideas
- A precise YARA rule should be derived from string/PE analysis of the actual binary. As a starting point, consider hunting on PE-overlay-bearing, signed 32-bit executables in the ~350KB range containing the strings "yoursearching", "Subtab", "clpremdo", or "Yoursearching_uninstall" in their resource or string tables.

### Splunk Hunting Queries
- Search proxy/DNS logs for queries to yoursearching.com or clpremdo.com: `index=proxy OR index=dns dest_domain IN ("yoursearching.com","clpremdo.com")`
- Search process creation logs for yoursearching.exe or Yoursearching_uninstall: `index=endpoint (process_name="yoursearching.exe" OR process_name="*Yoursearching_uninstall*")`

### Microsoft Sentinel Hunting Queries
- DeviceNetworkEvents | where RemoteUrl has_any ("yoursearching.com","clpremdo.com")
- DeviceProcessEvents | where FileName =~ "yoursearching.exe" or FileName has "Yoursearching_uninstall"

These are starting points only and should be tuned to the environment; none have been validated against a live sample.

---

## References

https://www.virustotal.com/gui/file/e54323fd25fcb8031dd748d4ea48fe44752bcf18514919545d34512cb0180348
https://www.enigmasoftware.com/yoursearchingcom-removal/
https://www.pcrisk.com/removal-guides/9588-yoursearching-com-redirect
https://forums.malwarebytes.com/topic/175591-removal-instructions-for-yoursearching/
https://malwaretips.com/blogs/remove-yoursearching-com/
