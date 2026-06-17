# Threat Analysis: The OpenClaw Epidemic — Fake Installers, Poisoned Skills, and a New Frontier for AI Supply Chain Attacks

---

## Executive Summary

This report analyzes the multi-vector threat campaign targeting OpenClaw, a viral open-source AI agent framework, along with a review of official release artifacts submitted for hash verification. The investigated hashes span OpenClaw Core v2026.6.8 (macOS), OpenClaw Desktop v0.7.0 (Windows), and a FreeBSD source tarball (v2026.4.29). No direct malicious detections were found for these specific official release hashes; however, the broader OpenClaw ecosystem is under sustained attack from at least five concurrent threat campaigns — including supply chain poisoning, fake installer distribution via GitHub and Bing AI search results, infostealer delivery, and proxy malware deployment.

**Classification: Suspicious (Ecosystem-Level)**
**Analyst Confidence: High**

The artifacts submitted appear to be from official distribution channels. The threat is not the artifacts themselves — it is the environment they operate in.

---

## Artifact Overview

Hash: `9412ef91c4cbbf7b34cacbf846a671ff8a8a6d8b2e2ad85a1e29da56bc9bc0c5`
File Name: `OpenClaw-2026.6.8.dmg`
Platform: macOS

Hash: `531f0443ba747ee8c89d03df4f87b8e11d062302a586f6e894f04e2bd90e1d95`
File Name: `openclaw-2026.6.8-dependency-evidence.zip`

Hash: `34c3e31d8b879ac6f9894ee8366d2f361b35d04865daac24023c428dbb6c7a44`
File Name: `OpenClaw-2026.6.8.dSYM.zip`

Hash: `3334ec2ec9ad2bb1df4f398d5c437a4ef7b0125c4d88c8e257ed857b8ae1209e`
File Name: `OpenClaw-Setup-0.7.0.exe`
Platform: Windows

Hash: `43a6a82681cb48b14a5a4220e9c3440e1bcc8a5714908352b54b2f9fcb9ec091`
File Name: `latest.yml`
Platform: Windows (Electron update manifest)

Hash: `700fd92e7b94cc2d435dbb40a758e87cebcca0c79c155067d1b38ad14f4466e0`
File Name: `openclaw-2026.4.29.tar.gz`
Platform: FreeBSD

Domain: `github.com/agentkernel/openclaw-desktop`
Threat Actor: ClawHavoc operators (suspected Chinese origin per Repello AI)
Malware Family: Atomic Stealer (AMOS), Vidar, GhostSocks, Trojan/OpenClaw.PolySkill, LuaJIT Trojan (TroyDen's Lure Factory)

---

## Intelligence Findings

**OpenClaw Background**

OpenClaw is an open-source, self-hosted AI agent originally released in November 2025 under the name Clawdbot by Austrian developer Peter Steinberger. It was rebranded twice — first to Moltbot under pressure from Anthropic over branding similarities, and then to OpenClaw. By late January 2026, it had crossed 180,000 GitHub stars and drew over two million visitors in a single week, triggering a Mac mini shortage in several U.S. markets. The tool grants its runtime operator-level access to the local filesystem, terminal, messaging platforms (Telegram, Slack, WhatsApp, Discord), email, calendars, and cloud services.

**Official Release Hashes — Assessment**

The hashes submitted in this report correspond to artifacts published via `github.com/agentkernel/openclaw-desktop` (Windows desktop client) and the official OpenClaw Core release pipeline. These channels are the canonical distribution points. No known malicious associations have been identified for these specific digests at the time of analysis. However, threat actors have repeatedly cloned and mimicked official release pages, meaning hash verification against authoritative upstream release notes remains a critical practice before execution.

**Fake Installer Campaign (February 2 – 10, 2026)**

Huntress researchers confirmed a malicious GitHub organization, `openclaw-installer`, was active from February 2 through February 10, 2026. The repository appeared as the top-ranked Bing AI suggestion for the search term "OpenClaw Windows," directing users to instructions that deployed Vidar infostealer, GhostSocks proxy malware, and AMOS on macOS. The campaign used a novel loader called Stealth Packer, which injected payloads into memory, added firewall rules, created hidden scheduled tasks, and performed AntiVM checks by monitoring mouse movement before decrypting payloads.

**ClawHavoc Supply Chain Campaign (January 27 – February 2026 ongoing)**

The ClawHavoc campaign represents one of the largest coordinated supply chain attacks against AI infrastructure recorded to date. Koi Security initially identified 341 malicious skills in ClawHub (the official OpenClaw skills marketplace), representing 12% of all available packages at the time. By mid-February, independent scans by Bitdefender placed the figure at approximately 900 malicious packages, or roughly 20% of the total ecosystem. Antiy CERT independently confirmed 1,184 malicious packages across 12 publisher accounts, classifying the malware family as Trojan/OpenClaw.PolySkill. A single threat actor operating under the handle `hightower6eu` uploaded over 314 malicious packages in what appears to have been an automated deployment.

**TroyDen's Lure Factory (March 2026)**

Netskope Threat Labs identified a separate campaign distributing over 300 Trojanized GitHub packages under a fake OpenClaw Docker deployer. The campaign deployed a LuaJIT-based Trojan capable of capturing screenshots, performing victim geolocation, and exfiltrating sensitive data to a C2 server in Frankfurt. The campaign used AI assistance to generate lure names drawn from obscure biological taxonomy and archaic Latin. The Trojan included a 29,000-year sleep delay to defeat timed sandbox analysis.

**GhostClaw npm Campaign (March 2026)**

JFrog identified a malicious npm package `@openclaw-ai/openclawai` posing as an OpenClaw installer. The multi-stage payload used a postinstall hook to deploy a fake CLI with progress bars, a fake Keychain prompt, and an encrypted second-stage RAT. It included a SOCKS5 proxy and live browser session cloning capability. The package was downloaded 178 times before removal.

**Exposed Instances**

SecurityScorecard identified over 135,000 publicly exposed OpenClaw instances in February 2026, with approximately 12,812 directly exploitable via remote code execution. Censys tracked growth from roughly 1,000 to over 21,000 publicly exposed instances in under one week during the initial popularity surge.

---

## Behavioral Analysis

### Execution

- Fake installers execute via user-initiated double-click or copy-pasted terminal commands extracted from README or SKILL.md files
- Malicious skills deliver payloads through three primary vectors: staged downloads pulling additional malware from remote sources, reverse shells via Python `os.system()` calls, and direct in-memory payload execution via Stealth Packer
- LuaJIT-based Trojan (TroyDen) triggers on joint execution of two components, bypassing single-binary sandbox analysis

### Persistence

- Stealth Packer creates hidden scheduled tasks (referred to internally as "ghost tasks")
- GhostSocks registers as a system service to maintain backconnect proxy availability across reboots
- AMOS variant modifies `~/.openclaw/workspace/SOUL.md` and `MEMORY.md` to inject persistent instructions into agent long-term memory
- LaunchAgent entries created under `~/Library/LaunchAgents/` on macOS

### Network Activity

- GhostSocks proxies victim network traffic to threat actor infrastructure using the BlackBasta group's established SOCKS5 protocol stack
- Vidar infostealer retrieves C2 configuration via Steam profile pages
- LuaJIT Trojan exfiltrates data to a C2 server in Frankfurt, Germany
- AMOS variants compress and POST collected data to attacker-controlled endpoints
- Known malicious IP: `91.92.242[.]30` (associated with ClawHavoc macOS payload delivery)

### Defense Evasion

- Stealth Packer performs AntiVM checks by monitoring mouse movement before executing decrypted payloads
- 29,000-year sleep delay in LuaJIT Trojan defeats timed sandbox environments
- Fake repository contributors and GitHub stars manufactured to simulate legitimacy
- Malicious skills include professional documentation, category-appropriate naming (e.g., `solana-wallet-tracker`, `youtube-summarize-pro`), and credible README files
- Payloads use XOR-based string encryption with multi-key schemes (AMOS variant)
- ClickFix technique used to prompt user-initiated execution, bypassing endpoint behavioral detection

---

## Detection Engineering Notes

The following artifacts are high-confidence hunting anchors across EDR, SIEM, and NDR platforms.

**Hashes (Confirmed Malicious — Campaign-Associated)**

These hashes are distinct from the official release hashes submitted in this report and are documented in vendor reporting for reference:

- Vidar loader: Check Huntress blog (March 4, 2026) for current IOC package
- AMOS Mach-O samples: Available via Trend Micro research (February 23, 2026)
- GhostSocks binary (`serverdrive.exe`): Documented in Huntress blog

**Domains and Infrastructure**

- `91.92.242[.]30` — ClawHavoc macOS delivery IP
- GitHub organizations: `openclaw-installer` (taken down), `molt-bot` (taken down)
- npm package: `@openclaw-ai/openclawai` (taken down)

**Process Names**

- `svc_service.exe` — Rust-based Stealth Packer loader
- `serverdrive.exe` — GhostSocks backconnect proxy

**Mutex**

- `StealthPackerMutex_9A8B7C` — Stealth Packer loader

**Registry / Scheduled Tasks**

- Look for scheduled tasks with random or GUID-style names created immediately after OpenClaw installer execution
- Review startup entries for entries added post-installation

**File Paths (macOS)**

- `~/Library/LaunchAgents/` — Suspicious entries not prefixed with `com.apple` or `com.openclaw.security`
- `~/.openclaw/workspace/SOUL.md` — Monitor for injected content
- `~/.openclaw/workspace/MEMORY.md` — Monitor for injected content
- `~/.openclaw/.env` — Target of exfiltration campaigns

**User Agents**

- Monitor for Electron app user agents initiating outbound connections to non-Anthropic, non-OpenAI endpoints shortly after install

---

## Analyst Assessment

### What Supports Malicious Classification?

- Multiple concurrent threat campaigns actively targeting OpenClaw users documented by Huntress, Trend Micro, Kaspersky, Bitdefender, Netskope, Intel 471, and JFrog
- Over 1,184 confirmed malicious packages identified in official ClawHub marketplace
- Active C2 infrastructure identified (Frankfurt server, `91.92.242[.]30`)
- Fake installer campaign achieved top placement in Bing AI search results, indicating active malvertising investment
- GhostSocks has prior association with the BlackBasta ransomware group, indicating organized criminal involvement
- CVE-2026-25253 (CVSS 8.8) provides one-click RCE against any OpenClaw instance, including localhost-bound deployments
- Over 135,000 instances exposed publicly, with approximately 12,812 directly exploitable

### What Supports Benign Classification?

- The specific hashes submitted in this report correspond to official release artifacts published through canonical distribution channels
- The `agentkernel/openclaw-desktop` repository referenced in the submitted artifacts is the legitimate desktop client repository
- OpenClaw Core v2026.6.8 is a post-April 24 release, meeting the minimum safe version threshold identified by security researchers
- The FreeBSD port tarball (v2026.4.29) aligns with the minimum safe version boundary

### What Remains Unknown?

- Whether the submitted hashes have been independently verified against the upstream release signing process
- The full scope of C2 infrastructure used across all concurrent campaigns
- Whether any post-v2026.4.24 releases contain unpatched vulnerabilities not yet publicly disclosed
- The full attribution of ClawHavoc operators beyond suspected Chinese-origin indicators

---

## Final Verdict

**Classification: Suspicious**

**Confidence: High**

**Justification:** The specific artifacts submitted (official release hashes) do not carry direct malicious associations. However, the OpenClaw ecosystem represents an actively exploited threat surface. Defenders should treat any OpenClaw deployment as operating in a hostile environment regardless of installer provenance. The combination of broad system permissions, plaintext credential storage, minimal skills marketplace vetting, over 60 disclosed CVEs, and active multi-family malware campaigns targeting this platform warrants sustained monitoring and hardening. Any OpenClaw installation that cannot be fully isolated, monitored, and hardened should be considered a material risk to the host environment and connected services.

---

## Quick Reference Indicators

File Hashes (Official Release — Verify Before Execution):
- `9412ef91c4cbbf7b34cacbf846a671ff8a8a6d8b2e2ad85a1e29da56bc9bc0c5` — OpenClaw-2026.6.8.dmg (macOS). Cross-reference against official release notes before execution.
- `3334ec2ec9ad2bb1df4f398d5c437a4ef7b0125c4d88c8e257ed857b8ae1209e` — OpenClaw-Setup-0.7.0.exe (Windows). Verify against agentkernel/openclaw-desktop releases page.
- `700fd92e7b94cc2d435dbb40a758e87cebcca0c79c155067d1b38ad14f4466e0` — openclaw-2026.4.29.tar.gz (FreeBSD). Meets minimum safe version threshold.

IP Addresses:
- `91.92.242[.]30` — ClawHavoc macOS stage-2 payload delivery. HIGH PRIORITY. Block and alert on any connection to this host. Defang before deploying.

File Names (Malicious Indicators):
- `svc_service.exe` — Rust-based Stealth Packer loader. Investigate immediately if observed post-install.
- `serverdrive.exe` — GhostSocks backconnect proxy. Block at EDR and network perimeter.

Processes:
- Any process spawned from within `~/.openclaw/workspace/skills/` deserves investigation, particularly if it initiates outbound network connections.

Registry Keys / Scheduled Tasks:
- GUID-style or randomized scheduled task names created in the minutes following OpenClaw installer execution. Investigate and remove if source is unverifiable.

File Paths (macOS — Monitor for Tampering):
- `~/.openclaw/workspace/SOUL.md` — Agent memory file. Changes not initiated by the user indicate memory poisoning.
- `~/.openclaw/workspace/MEMORY.md` — Same as above.
- `~/Library/LaunchAgents/` — Entries added post-installation without `com.apple` or `com.openclaw.security` prefixes are suspicious.

Mutex:
- `StealthPackerMutex_9A8B7C` — Confirms Stealth Packer loader presence. HIGH PRIORITY. Treat host as compromised.

npm Package (Historical IOC):
- `@openclaw-ai/openclawai` — Removed from npm registry. Any system that installed this package prior to removal should be considered compromised.

---

## MITRE ATT&CK Mapping

T1195.002 – Supply Chain Compromise: Software Supply Chain
ClawHavoc planted over 1,184 malicious packages in ClawHub, the official OpenClaw skills marketplace. Attackers registered as legitimate developers and deployed poisoned skills mimicking high-demand tools.

T1566 – Phishing (via Social Engineering / ClickFix)
Malicious SKILL.md files and README documents presented fabricated "Prerequisites" sections, directing users to copy-paste base64-encoded terminal commands or download password-protected archives.

T1059 – Command and Scripting Interpreter
Reverse shells delivered via Python `os.system()` calls within malicious skills. Base64-obfuscated terminal commands executed through user-initiated ClickFix prompts.

T1055 – Process Injection
Stealth Packer injected malware payloads directly into memory to avoid on-disk detection by endpoint protection platforms.

T1027 – Obfuscated Files or Information
AMOS samples encrypted all strings with a multi-key XOR scheme. Stealth Packer performed runtime decryption. LuaJIT Trojan used a 29,000-year sleep delay to defeat sandbox timing heuristics.

T1547 – Boot or Logon Autostart Execution
GhostSocks and Stealth Packer created LaunchAgent entries (macOS) and hidden scheduled tasks (Windows) to maintain persistence across reboots.

T1090.003 – Proxy: Multi-hop Proxy
GhostSocks turned compromised hosts into residential SOCKS5 proxy nodes, enabling threat actors to route malicious traffic and bypass anti-fraud and MFA controls using the victim's IP address.

T1552.001 – Unsecured Credentials: Credentials in Files
OpenClaw stores API keys, OAuth tokens, Telegram bot tokens, and Anthropic/OpenAI credentials in plaintext Markdown and JSON files under `~/.openclaw/`. Multiple infostealer families (Vidar, RedLine, Lumma, AMOS) are documented as targeting this file structure.

T1041 – Exfiltration Over C2 Channel
AMOS and Vidar variants compressed and transmitted collected data (browser credentials, keychains, crypto wallets, SSH keys, cloud credentials) to attacker-controlled servers over HTTPS.

T1588.002 – Obtain Capabilities: Tool (Stealth Packer)
The ClawHavoc and fake-installer campaigns employed a novel custom packer, Stealth Packer, not previously observed in threat intelligence databases prior to February 2026.

T1102 – Web Service (C2 via Steam)
Vidar infostealer retrieved C2 server configuration from Steam profile pages, a technique designed to blend C2 traffic with legitimate platform traffic.

---

## Detection Opportunities

### Sigma Ideas

```yaml
title: Suspicious OpenClaw Skill Process Spawn
description: Detects process creation originating from within the OpenClaw skills directory
logsource:
  category: process_creation
detection:
  condition: selection
  selection:
    ParentImage|contains: '.openclaw/workspace/skills'
fields:
  - CommandLine
  - Image
  - ParentImage
level: high
```

```yaml
title: StealthPackerMutex Detected
description: Identifies Stealth Packer loader activity via known mutex
logsource:
  category: create_remote_thread
detection:
  condition: selection
  selection:
    MutexName: 'StealthPackerMutex_9A8B7C'
level: critical
```

### YARA Ideas

```yara
rule AMOS_MultiKeyXOR_OpenClaw {
  meta:
    description = "Detects AMOS variant targeting OpenClaw via multi-key XOR string encryption pattern"
    author = "Threat Intelligence Team"
    date = "2026-06"
  strings:
    $xor_init = { 48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? }
    $openclaw_path = ".openclaw" ascii wide
    $keychain = "Keychain" ascii wide
  condition:
    uint32(0) == 0xFEEDFACE and all of them
}
```

### Splunk Hunting Queries

```
// Detect GhostSocks binary (serverdrive.exe) execution
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*serverdrive.exe" OR OriginalFileName="*serverdrive.exe"
| table _time, ComputerName, User, Image, CommandLine, ParentImage

// Detect hidden scheduled task creation post-OpenClaw install
index=windows source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=106
| eval TaskPath=lower(TaskPath)
| search NOT TaskPath IN ("*microsoft*", "*windows*", "*openclaw.security*")
| where len(TaskPath) > 30 AND match(TaskPath, "^[\da-f\-]{20,}$")
| table _time, ComputerName, User, TaskPath
```

### Microsoft Sentinel Hunting Queries

```kql
// Hunt for OpenClaw SOUL.md or MEMORY.md modification not by the agent process
DeviceFileEvents
| where FolderPath contains ".openclaw/workspace"
| where FileName in ("SOUL.md", "MEMORY.md")
| where InitiatingProcessFileName !in ("openclaw", "node")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName

// Hunt for connections to known ClawHavoc C2 IP
DeviceNetworkEvents
| where RemoteIP == "91.92.242.30"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

---

## References

Huntress — Fake OpenClaw Installers, GhostSocks and Infostealer Campaign (March 4, 2026):
https://www.huntress.com/blog/openclaw-github-ghostsocks-infostealer

Malwarebytes — Beware of Fake OpenClaw Installers (March 6, 2026):
https://www.malwarebytes.com/blog/news/2026/03/beware-of-fake-openclaw-installers-even-if-bing-points-you-to-github

Trend Micro — Malicious OpenClaw Skills Used to Distribute Atomic MacOS Stealer (February 23, 2026):
https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html

Bitdefender — Technical Advisory: OpenClaw Exploitation in Enterprise Networks (February 10, 2026):
https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks

Microsoft Security Blog — Running OpenClaw Safely: Identity, Isolation, and Runtime Risk (February 19, 2026):
https://www.microsoft.com/en-us/security/blog/2026/02/19/running-openclaw-safely-identity-isolation-runtime-risk/

Kaspersky — New OpenClaw AI Agent Found Unsafe for Use (February 10, 2026):
https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/

Dark Reading — GitHub OpenClaw Deployer Repo Delivers Trojan (March 24, 2026):
https://www.darkreading.com/application-security/github-openclaw-deployer-repo-delivers-trojan

Intel 471 — OpenClaw: A Viral AI Assistant and a Magnet for Infostealer Malware (March 12, 2026):
https://www.intel471.com/blog/openclaw-a-viral-ai-assistant-and-a-magnet-for-infostealer-malware-and-clickfix-trickery

Conscia — The OpenClaw Security Crisis (February 23, 2026):
https://conscia.com/blog/the-openclaw-security-crisis/

Adversa AI — OpenClaw Security 101: Vulnerabilities and Hardening (February 15, 2026):
https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/

Immersive Labs — OpenClaw: Hunting Season is Open (March 12, 2026):
https://www.immersivelabs.com/resources/c7-blog/openclaw-hunting-season-is-open

CyberPress — ClawHavoc Poisons ClawHub with 1,184 Malicious Skills (February 19, 2026):
https://cyberpress.org/clawhavoc-poisons-openclaws-clawhub-with-1184-malicious-skills/

PolySwarm — The ClawHavoc Campaign:
https://blog.polyswarm.io/the-clawhavoc-campaign

GitHub — openclaw-security-monitor (Community Defense Tool):
https://github.com/adibirzu/openclaw-security-monitor

TechRadar — Hackers Exploit OpenClaw to Spread Malware via GitHub (March 5, 2026):
https://www.techradar.com/pro/security/hackers-exploit-openclaw-to-spread-malware-via-github-and-a-little-help-from-bing

IT Brew — New Vulnerability in Open-Source Repositories Uses Fake OpenClaw Install to Attack (March 4, 2026):
https://www.itbrew.com/stories/2026/03/03/new-vulnerability-in-open-source-repositories-uses-fake-openclaw-install-to-attack

Official OpenClaw Desktop Releases (agentkernel/openclaw-desktop):
https://github.com/agentkernel/openclaw-desktop/releases

FreshPorts — OpenClaw FreeBSD Port:
https://www.freshports.org/misc/openclaw/
