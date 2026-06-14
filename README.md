# Artifact Research

A curated collection of malware analyses, IOC investigations, threat intelligence research, detection engineering notes, and suspicious artifact assessments.

## Purpose

Security professionals regularly encounter unfamiliar binaries, domains, IP addresses, DLLs, processes, registry keys, and applications that generate alerts but have little publicly available intelligence. Determining whether an artifact is malicious, benign, or simply unusual often requires time-consuming research across multiple intelligence sources.

This repository aims to reduce that effort by providing structured, evidence-driven investigations into suspicious artifacts and emerging threats.

The goal is not only to document confirmed malware, but also to analyze legitimate software, potentially unwanted programs (PUPs), and uncommon applications that may appear suspicious during incident response or threat hunting activities.

## Research Philosophy

Every investigation attempts to answer a simple question:

> Is this artifact malicious, benign, or somewhere in between?

Findings are based on publicly available threat intelligence, sandbox analysis, reputation services, vendor research, and direct artifact analysis whenever possible.

Each assessment prioritizes:

* Evidence over assumptions
* Context over detection counts
* Analyst usability over academic depth
* Detection opportunities for defenders

## Repository Structure

```text
Cyber-Artifact-Research/
│
├── Malware-Analysis/
│   ├── Atomic-Arch/
│   ├── Lumma-Stealer/
│   └── ...
│
├── PUP-Analysis/
│   ├── Browser-Extensions/
│   ├── Adware/
│   └── ...
│
├── IOC-Investigations/
│   ├── Domains/
│   ├── IP-Addresses/
│   ├── Hashes/
│   └── ...
│
├── Threat-Intelligence/
│   ├── Campaigns/
│   ├── Threat-Actors/
│   └── ...
│
├── Detection-Engineering/
│   ├── Sigma/
│   ├── Splunk/
│   ├── Sentinel/
│   └── YARA/
│
└── Templates/
```

## Article Format

Most investigations follow a standardized structure:

* Executive Summary
* Artifact Overview
* Intelligence Findings
* Behavioral Analysis
* Detection Engineering Notes
* MITRE ATT&CK Mapping
* Analyst Assessment
* Final Verdict
* IOC Quick Reference Matrix
* References

This format is designed to allow readers to either:

* Perform a deep technical review
* Quickly reach an informed decision during triage

## Sources

Research may incorporate intelligence from:

* VirusTotal
* AbuseIPDB
* Cisco Talos
* Any.Run
* Joe Sandbox
* Hybrid Analysis
* AlienVault OTX
* MalwareBazaar
* ThreatFox
* GreyNoise
* Shodan
* Censys
* Vendor Threat Research
* Open Source Intelligence Sources

All sources are cited whenever possible.

## Intended Audience

This repository is intended for:

* Security Analysts
* Detection Engineers
* Threat Hunters
* Incident Responders
* SOC Teams
* DFIR Practitioners
* Threat Intelligence Analysts

## Disclaimer

All analysis is provided for educational and defensive cybersecurity purposes only.

Threat intelligence changes over time. An artifact classified as benign today may become malicious tomorrow, and vice versa. Readers should validate findings against their own environments and investigative procedures before making operational decisions.

## About

Maintained by Justin Chamreun, Detection Engineer.

This project serves as a public knowledge base for threat artifact investigations, malware analysis, and defender-focused research intended to help security professionals make faster and more informed decisions.
