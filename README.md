## Threat Detection and Incident Response (TDIR)
> Collection of notes, useful resources, list of tools and scripts related to threat detection, digital forensics and incident response.

### Table of Contents
- [I. Useful resources (ENISA, NIST, ANSSI, etc.)](#I-USEFUL-RESOURCES)
- [II. TDIR and DFIR Tools](#II-TDIR-and-DFIR-Tools)
- [III. MITRE ATTACK Framework](#III-MITRE-ATTACK-Framework)
- [IV. The Cyber Attack Kill Chain Model & Defense](#IV-The-Cyber-Attack-Kill-Chain-Model--Defense)
- [V. Threat Detection & Incident Response (TDIR) Methodology](#V-Threat-Detection--Incident-Response-TDIR)
- [VI. Security Operation Center (SOC)](#VI-SOC---Security-Operation-Center)
- [VII. ISO/IEC 27035 — Information Security Incident Management](#VII-ISOIEC-27035--Information-security-incident-management)
- [VIII. Glossary of TDIR and DFIR terms and definitions](#VIII-Glossary-of-TDIR-and-DFIR-terms-and-definitions)

--------
### I. USEFUL RESOURCES
+ ENISA Publication  - [Good Practice Guide for Incident Management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management/@@download/fullReport)
+ ENISA Publication - [Cyber Crisis Communication Guide](https://www.enisa.europa.eu/topics/cybersecurity-education/2023-ar-in-a-box-material/cyber_crisis_comm_guide_03-online.pdf)
+ NIST Publication - [Digital Forensics & Incident Response framework dedicated to Operational Technology](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8428.pdf)
+ NIST Publication - [Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
+ NIST Publication - [Guide for Cybersecurity Event Recovery](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-184.pdf)
+ ISO/IEC 27035 (2020-2023+) - [Information Security Incident Management](https://www.iso27001security.com/html/27035.html)
+ MITRE - [ATT&CK® Framework](https://attack.mitre.org) - Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
+ MITRE - [Enterprise Attack Excel matrix](https://attack.mitre.org/docs/enterprise-attack-v14.1/enterprise-attack-v14.1.xlsx) - This matrix covers the stages of a cyberattack lifecycle that occur after an exploit is initiated.
+ MITRE - [D3fend Matrix](https://d3fend.mitre.org) - A knowledge graph of cybersecurity countermeasures.
+ Tines - [SOC Automation Capability Matrix](https://tinesio.notion.site/4fd14ccf93e7408c8faf96c5aca8c3fd) - This matrix describes common activities which most SOC can automate.
+ ANSSI (French) - [Anticiper et gérer une crise Cyber](https://cyber.gouv.fr/anticiper-et-gerer-une-crise-cyber)
+ ANSSI (French) - [Organiser un exercice de gestion de crise cyber (Guide - v1.0)](https://cyber.gouv.fr/publications/organiser-un-exercice-de-gestion-de-crise-cyber)
+ ANSSI (French) - Piloter la remédiation d’un incident cyber - [Volet stratégique](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_strat%C3%A9gique_cyberattaquesetrem%C3%A9diation_v1g.pdf) - [Volet opérationnel](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_operationnel_cyberattaquesetremediation_a5_v1j.pdf) - [Volet technique](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_technique_cyberattaquesetremediation_a5_v1h.pdf)
+ GitHub - [Incident Response Methodologies](https://github.com/certsocietegenerale/IRM) - Incident Response Methodologies by CERT Societe Generale.
+ GitHub - [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response/tree/master) - A curated list of tools and resources for security incident response and DFIR teams.
+ GitHub - [Awesome SOC](https://github.com/cyb3rxp/awesome-soc) - A collection of sources of documentation, as well as field best practices, to build/run a SOC
+ GitHub - [The Threat Hunter Playbook](https://threathunterplaybook.com/intro.html) - Community-driven, open source project to share detection logic, adversary tradecraft and resources to make detection development more efficient.
+ GitHub - [Awesome Yara rules](https://github.com/InQuest/awesome-yara) - A curated list of awesome YARA rules, tools, and people.
+ GitHub - [Sigma rules](https://github.com/SigmaHQ/sigma) - SIGMA rule repository (more than 3000 detection rules).
+ GitHub - [Sigma rules](https://github.com/The-DFIR-Report/Sigma-Rules/) - A collection of SIGMA rules from the 'The-DFIR-Report'.
+ GitHub - [Yara rules](https://github.com/The-DFIR-Report/Yara-Rules) - A collection of YARA rules from the 'The-DFIR-Report'.
+ Atomic Threat Coverage - [RE&CT Framework](https://atc-project.github.io/atc-react/) - The RE&CT Framework is designed for accumulating, describing and categorizing actionable Incident Response techniques.
+ Microsoft - [Threat Intelligence community blog](https://aka.ms/threatintelblog)
+ AWS - [AWS Incident Response Playbook Samples](https://github.com/aws-samples/aws-incident-response-playbooks)
+ AWS - [AWS Customer Playbook Framework](https://github.com/aws-samples/aws-customer-playbook-framework) - This repository provides sample templates for security playbooks against various scenarios when using Amazon Web Services.
+ [Digital Forensics Discord Server](https://discord.com/servers/digital-forensics-427876741990711298) - This is a server for DFIR Professionals by DFIR Professionals. Community of 12,900+ working professionals from Law Enforcement, Private Sector, Students and Forensic Vendors.
+ List of Threat Actors: [MITRE - Adversary Groups](https://attack.mitre.org/groups/), [Mandiant - APT Groups](https://www.mandiant.com/resources/insights/apt-groups), [Crowstrike - Global Threat Landscape & Adversaries](https://www.crowdstrike.com/adversaries/)
+ DFIR reports - [Breach Report Collection](https://github.com/BushidoUK/Breach-Report-Collection) - A collection of companies that disclose adversary TTPs after they have been breached.
+ DFIR reports - [THE DFIR REPORT](https://thedfirreport.com) - Real intrusions by real attackers, the truth behind the intrusion.
+ DFIR news - [This week in4n6](https://thisweekin4n6.com) - Weekly roundup of Digital Forensics and Incident Response news.
+ Cyber Crime news - [Security Affairs](http://securityaffairs.co/wordpress/) - Blog that covers topics like Cyber Crime, Cyber Warfare, Hacktivism...

--------
### II. TDIR and DFIR TOOLS

#### 1. Community / Open-Source / Free Tools

+ Digital Forensics & Incident Response (Virtual Machine and tools)
  + [SANS - SIFT Workstation (Linux VM)](https://www.sans.org/tools/sift-workstation/) - The SIFT VM contains a collection of free and open-source incident response and forensic tools designed to conduct an in-depth forensic or incident response investigation.
  + [Mandiant FlareVM (Windows VM](https://github.com/mandiant/flare-vm) - A collection of software installations scripts for Windows systems that allows you to easily setup and maintain a reverse engineering environment on a Windows VM.
  + [Kali Purple (Linux VM)](https://gitlab.com/kalilinux/kali-purple/documentation/-/wikis/home) - It is an extension of the Kali Linux distribution designed specifically for defensive security operations, focusing on threat detection, incident response, and threat intelligence. It contains numerous tools including SIEM, IDS/IPS, Forensics and Incident Response software.
  + [The Sleuth Kit (TSK) & Autopsy](https://sleuthkit.org) - The Sleuth Kit® is a collection of command line tools and a C library that allows you to analyze disk images and recover files from them. It is used behind the scenes in Autopsy and many other open source and commercial forensics tools.
  + [Velociraptor](https://docs.velociraptor.app) - Velociraptor is an advanced digital forensic and incident response tool that enhances your visibility into your endpoints. It is a tool for collecting host based state information using the Velociraptor Query Language (VQL) queries.
  + [GRR Rapid Response](https://grr-doc.readthedocs.io/en/latest/) - GRR Rapid Response is an incident response framework focused on remote live forensics.
  + [Volatility Framework](https://volatilityfoundation.org) - World’s most widely used memory forensics tool.

+ Threat Hunting & Logs search
  + GitHub - [Velociraptor](https://github.com/Velocidex/velociraptor) - Actively search for suspicious activities using Velociraptor's library of forensic artifacts.
  + GitHub - [GRR Rapid Response](https://github.com/google/grr) - Actively search for suspicious activities using the GRR Rapid Response framework.
  + GitHub - [Chainsaw](https://github.com/WithSecureLabs/chainsaw) - Rapidly Search and Hunt through Windows Forensic Artefacts.
  + GitHub - [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - DeepBlueCLI is a PowerShell module for threat hunting via Windows event logs.
  + GitHub - [FastFinder](https://github.com/codeyourweb/fastfinder) - A lightweight tool made for threat hunting, live forensics and triage on both Windows and Linux Platforms.
  + GitHub - [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Threat Hunting tool for windows event logs (made with a purple team mindset) to detect APT movements hidden in the sea of windows event logs and to reduce the time to uncover suspicious activity.
  + GitHub - [Loki](https://github.com/Neo23x0/Loki) - Simple IOC and YARA Scanner.
  + Other - [Thor Lite](https://www.nextron-systems.com/thor-lite/) - Free IOC and YARA Scanner.

+ On-line Malware Analysis Platform & Sandbox
  + [Virustotal](https://www.virustotal.com/gui/home/upload) - Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.
  + [Joe Sandbox (Community)](https://www.joesandbox.com) - Analyzes potential malicious files & URLs on Windows/MacOS/Linux/Android/iOS providing comprehensive and detailed analysis reports.
  + [Hybrid-Analysis](https://www.hybrid-analysis.com) - Automated malware analysis service powered by Falcon sandbox.
  + [Metadefender](https://metadefender.opswat.com) - Malware analysis platform (Upload and scan your file for viruses with 38 anti-malware engines).
  + [Saferwall](https://saferwall.com) (https://github.com/saferwall/saferwall) -  Malware analysis platform allowing to analyze, triage and classify threats in just minutes.
  + [Threat Zone Scan Holistic](https://app.threat.zone/scan) - Malware analysis platform (Interactive Sandbox, Static Analyzer, Emulation).
  + [Valkyrie Comodo](https://valkyrie.comodo.com) - Valkyrie conducts several analysis using run-time behavior and hundreds of features from a file and based on analysis results can warn users against malware undetected by classic Anti-Virus products.
    
+ Malware Analysis Command-line Tools
  + GitHub - [Mandiant CAPA](https://github.com/mandiant/capa) - Capa detects capabilities in executable files. You run it against a PE, ELF, .NET module, shellcode file, or a sandbox report and it tells you what it thinks the program can do. 
  + GitHub - [PE-BEAR](https://github.com/hasherezade/pe-bear) - Portable Executable (PE) reversing tool with a friendly GUI which deliver fast and flexible “first view” for malware analyst.
  + GitHub - [PE-SIEVE](https://github.com/hasherezade/pe-sieve) - Scans a given process. Recognizes and dumps a variety of potentially malicious implants (replaced/injected PEs, shellcodes, hooks, in-memory patches)
  + GitHub - [System informer](https://github.com/winsiderss/systeminformer) - A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
  + GitHub - [Moneta](https://github.com/forrest-orr/moneta) - Moneta is a live usermode memory analysis tool for Windows with the capability to detect malware IOCs
  + GitHub - [CyberChef](https://github.com/gchq/CyberChef) (https://gchq.github.io/CyberChef/) - The Cyber Swiss Army Knife. A web app for encryption, encoding, compression and data analysis.
  + GitHub - [CyberChef Recipes](https://github.com/mattnotmax/cyberchef-recipes) - A list of cyber-chef recipes and curated links.
  + GitHub - [De4dot](https://github.com/de4dot/de4dot) - It is an open source .NET deobfuscator and unpacker that will try its best to restore a packed and obfuscated assembly to almost the original assembly.
  + GitHub - [Themida Unpacker for .NET](https://github.com/cg10036/Themida-Unpacker-for-.NET) - Tool developed to quickly and easily unpack packed .NET files.

+ Security Information and Event Management (SIEM)
  + [Elastic Security (SIEM)](https://www.elastic.co/elastic-stack/) - Centralized logging, real-time analysis, and visualization of security events and logs from various sources within the network. The free and open solution delivers SIEM, endpoint security, threat hunting, cloud monitoring, and more. A paid subscription is needed to unlock advanced capabilities like XDR, automated response, and in-depth analytics.
  + [Wazuh (XDR-SIEM)](https://wazuh.com) - Free & open source platform (XDR-SIEM) used for threat prevention, detection, and response for endpoints & cloud workloads. It offers real-time correlation, context, response, and monitoring of security events and incidents across public, private, and on-premise environments.
  + [AlienVault OSSIM](https://cybersecurity.att.com/products/ossim) - OSSIM (Open Source Security Information Management / SIEM) includes asset discovery, vulnerability assessment, intrusion detection, behavioral monitoring, SIEM event correlation).
  
+ Intrusion Detection System (IDS)
  + GitHub - [OSSEC HIDS](https://github.com/ossec/ossec-hids) (https://www.ossec.net/) - Open Source Host-based Intrusion Detection System (HIDS) that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.
  + GitHub - [Zeek](https://github.com/zeek/zeek) - Zeek is a powerful network analysis framework that is much different from the typical IDS you may know. 

+ Endpoint Detection and Response (EDR)
  + GitHub - [Open EDR](https://github.com/ComodoSecurity/openedr) - Free and Open-Source Endpoint Detection and Response (EDR) Platform (www.comodo.com).
  + [Elastic Security for Endpoint (Community)](https://www.elastic.co/fr/downloads) - A community version of Elastic Security is available.
  + [Elastic Detection Rules Explorer](https://elastic.github.io/detection-rules-explorer/) - Elastic Security detection rules help users to set up and get their detections and security monitoring going as soon as possible. 
  + GitHub - [Elastic Detection Rules](https://github.com/elastic/detection-rules) - Rules for Elastic Security's detection engine.
  + Other
    + GitHub - [Sysmon EDR](https://github.com/ion-storm/sysmon-edr) - Sysmon EDR POC Build within Powershell to prove ability.
    + GitHub - [Whids](https://github.com/0xrawsec/whids) - Open Source EDR for Windows.

+ Adversary Emulation
  + GitHub - [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Atomic Red Team™ is a library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.
  + GitHub - [Atomic Red Team (PowerShell)](https://github.com/redcanaryco/invoke-atomicredteam) - Invoke-AtomicRedTeam is a PowerShell module to execute tests as defined in the atomics folder of Red Canary's Atomic Red Team project.
  + GitHub - [MITRE Caldera™](https://github.com/mitre/caldera) - A cyber security platform designed to easily automate adversary emulation, assist manual red-teams, and automate incident response (built on the MITRE ATT&CK™ framework).
  + GitHub - [APTSimulator](https://github.com/NextronSystems/APTSimulator) - Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.

#### 2. Commercial products

+ Endpoint Detection and Response (EDR)
  + CrowdStrike EDR
  + Cortex EDR/XDR (Palo Alto Networks)
  + Microsoft Defender for Endpoint (EDR)
  + Elastic Security for Endpoint Pro (EDR)
  + Cybereason EDR
  + SentinelOne EDR
  + Carbon Black EDR (VMware)
  + Cynet 360 AutoXDR
  + Trend Micro Vision One
  + WatchGuard EDR
  + ...
    
  Useful GitHub project: [EDR Telemetry](https://github.com/tsale/EDR-Telemetry) - This project aims to compare and evaluate the telemetry of various EDR products.

+ Security Information and Event Management (SIEM) 
  + Microsoft Azure Sentinel SIEM
  + Splunk Enterprise Security 
  + Elastic Security for SIEM
  + IBM QRadar SIEM
  + ArcSight Enterprise Security Manager
  + LogRhythm SIEM
  + LogPoint SIEM
  + Securonix SIEM
  + McAfee Enterprise Security Manager
  + ...

+ Computer Forensics investigation software
  + EnCase Forensic
  + Forensic ToolKit (FTK)
  + X-Ways forensic suite

--------
### III. MITRE ATTACK Framework

+ MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. 
  It documents common tactics, techniques, and procedures (TTPs) that advanced persistent threats use against Windows enterprise networks.
  
+ The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector,
  in government, and in the cybersecurity product and service community.

+ Tactics, Techniques, and Procedures (TTPs) 
  + TACTICS represent the “why” of an ATT&CK technique or sub-technique. 
    It is the adversary’s tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access.
  
  + TECHNIQUES represent “how” an adversary achieves a tactical goal by performing an action. 
    For example, an adversary may dump credentials to achieve credential access.
  
  + PROCEDURES are the specific implementation the adversary uses for techniques or sub-techniques. 
    For example, a procedure could be an adversary using PowerShell to inject into lsass.exe to dump credentials by scraping LSASS memory on a victim.
    Procedures are categorized in ATT&CK as the observed in the wild use of techniques in the "Procedure Examples" section of technique pages.

There are currently 14 Enterprise tactics (https://attack.mitre.org/tactics/enterprise/)

|    ID   |   Name  | DESCRIPTION | 
| :-----: | :-----: |  :-------:  |
| TA0043  |  Reconnaissance  |  The adversary is trying to gather information they can use to plan future operations.  |  
| TA0042  |  Resource Development  |  The adversary is trying to establish resources they can use to support operations.  |  
| TA0001  |  Initial Access  |  The adversary is trying to get into your network.  |  
| TA0002  |  Execution  |  The adversary is trying to run malicious code.  |  
| TA0003  |  Persistence  |  The adversary is trying to maintain their foothold.  |  
| TA0004  |  Privilege Escalation  |  The adversary is trying to gain higher-level permissions.  |  
| TA0005  |  Defense Evasion  |  The adversary is trying to avoid being detected.  |  
| TA0006  |  Credential Access  |  The adversary is trying to steal account names and passwords.  |  
| TA0007  |  Discovery  |  The adversary is trying to figure out your environment.  |  
| TA0008  |  Lateral Movement  |  The adversary is trying to move through your environment.  |  
| TA0009  |  Collection  |  The adversary is trying to gather data of interest to their goal.  |  
| TA0011  |  Command and Control  |  The adversary is trying to communicate with compromised systems to control them.  |  
| TA0010  |  Exfiltration  |  The adversary is trying to steal data.  |  
| TA0040  |  Impact  |  The adversary is trying to manipulate, interrupt, or destroy your systems and data.  |  


--------
### IV. The Cyber Attack Kill Chain Model & Defense

+ Definition and Goals
  + The “Kill Chain” is a traditional warfare term most often used by the US Air Force in defining the command and control process for targeting 
and destroying enemy forces in order to make it most difficult for the enemy to continue in battle. 
  + Of late, Kill Chain has been applied by both the US Military and leading cyber threat defense teams at Mitre and Lockheed Martin to define 
a new defensive strategy for guarding against advanced persistent threats (APT) and other targeted cyber attacks.
  + In cyber attack, the “Kill Chain Defense” exploits the fact that a successful attack must complete all stages from planning and malware introduction 
to expansion and one or more command and control phases, until the target is identified, manipulated and ex-filtrated.  

+ Objective
  + The goal of a kill chain defense is to break one or more stages in the attack chain to stop the progress of the attack and force the opponent to start over. 
  + It is important to remember three things in this method:
    - the bad guy must make the entire chain work to succeed; 
    - you need only kill one link to stop them;
    - having detection and kill capability at each point in the enemy’s attack chain gives you the highest probability of success in this defense.	
  + The goal is to use the “kill chain” to help you develop capabilities that allow you to identify attacks earlier in the kill chain, rather than waiting for late-stage attacks to become apparent. In other words, develop capabilities that help you identify intrusions while they are still in phases 1, 2, or 3 – and the lower the number, the better.

+ The 7 "Kill Chain" phases
  + The intrusion kill chain breaks intrusions down into distinct phases, which are defined quite well in the Lockheed Martin paper:
```
➤ Phase 1 - Reconnaissance
  ------------------------
  + The reconnaissance phase of a cyberattack is focused on learning as much as possible about the target.  
    This can include the use of open-source intelligence (websites, social media, etc.) and active investigation of the target environment.  
  + Research, identification and selection of targets, often represented as crawling Internet websites such as conference proceedings and mailing lists
    for email addresses, social relationships, or information on specific technologies. 
    
➤ Phase 2 - Weaponization
  -----------------------
  + The goal of the reconnaissance phase is to discover a potential attack vector, and weaponization is intended to develop a method of exploiting a 
    discovered weakness. This may include development of custom malware, crafting a phishing email, etc.
  + Coupling a remote access trojan with an exploit into a deliverable payload, typically by means of an automated tool (weaponizer). 
    Increasingly, client application data files such as Adobe Portable Document Format (PDF) or Microsoft Office documents serve as the weaponized deliverable. 

➤ Phase 3 - Delivery
  ------------------
  + Transmission of the weapon to the targeted environment. 
    The three most prevalent delivery vectors for weaponized payloads by APT actors, as observed by the Lockheed Martin Computer Incident Response Team (LM-CIRT)
    for the years 2004-2010, are email attachments (phishing), websites, and USB removable media. 
  + The delivery stage involves setting up the target for exploitation. This could be as simple as clicking send on a phishing email or may involve 
    a complicated process of getting the right person at the right place at the right time.  
    
➤ Phase 4 - Exploitation
  ----------------------
  + The exploitation phase is when the attacker takes advantage of the discovered weakness to gain access to the target environment.  
    This may involve exploiting a vulnerability in a webserver, a user enabling macros on a malicious document, etc.
  + After the weapon is delivered to victim host, exploitation triggers intruders’ code. Most often, exploitation targets an application or operating system
    vulnerability, but it could also more simply exploit the users themselves or leverage an operating system feature that auto-executes code.

➤ Phase 5 - Installation
  ----------------------
  + Installation of a remote access trojan or backdoor on the victim system allows the adversary to maintain persistence inside the environment.
  + One of the goals of a cyberattack is to gain a foothold on the target network. Once the identified vulnerability has been exploited, 
    an attacker should be able to install and execute malware on the target system.
  
➤ Phase 6 - Command and Control (C2)
  ----------------------------------
  + Typically, compromised hosts must beacon outbound to an Internet controller server to establish a C2 channel. 
    APT malware especially requires manual interaction rather than conduct activity automatically. 
    Once the C2 channel establishes, intruders have “hands on the keyboard” access inside the target environment.
  + A great deal of malware is designed to be interactive, receiving instructions from its creator and/or sending data to them.  
    Establishing a channel for these communications is the next stage in the process.  
  
➤ Phase 7 - Actions on Objectives
  -------------------------------
  + Only now, after progressing through the first six phases, can intruders take actions to achieve their original objectives. 
    Typically, this objective is data exfiltration which involves collecting, encrypting and extracting information from the victim environment; 
    violations of data integrity or availability are potential objectives as well. 
    Alternatively, the intruders may only desire access to the initial victim box for use as a hop point to compromise additional systems
    and move laterally inside the network.
```

--------
###  V. Threat Detection & Incident Response (TDIR)

> Nowadays companies are more exposed than ever to a vast array of cyber threats. From ransomware to crypto-mining malware, phishing emails to DDoS attacks, organizations constantly grapple with the challenge of identifying and responding to threats in real time. Failure to do so can result in data breaches, financial losses, damaged reputation, and regulatory fines.

#### PROCESS / METHODOLOGY

#### STEP 1. Preparation 

+ Define and implement a comprehensive incident response plan
  - An incident response plan is a set of instructions that help organizations respond to a security incident swiftly and effectively. This plan should outline the roles and responsibilities of all team members, detail the procedures for ingestion and troubleshooting, then responding to different types of incidents. It should provide guidelines for communicating with stakeholders during and after an incident, including lessons learned and process improvement along with potential tooling enhancement.
  - Having a comprehensive incident response plan in place can significantly reduce the time it takes to respond to a security incident, minimizing the damage and disruption it can cause. It can also help to ensure that all team members know what to do in the event of an attack, boosting the organization’s overall security posture.
  - A clearly communicated incident response plan is critical to an organization’s cyber resilience. By defining discrete steps across all response activities, the plan enables security teams to reduce business disruption and mitigate operational impact arising from security incidents.

+ Determine a clear escalation path
  - Establishing a clear escalation path is crucial for efficient threat response. When a potential threat is detected, the relevant information should be quickly escalated to the right personnel or team for further analysis and remediation.
  - The escalation path may vary depending on the severity of the threat, its potential impact, and the skills required to handle it. Some types of threat, if they are high-level in terms of potential impact for media or external awareness, should have an executive sponsor or contact for informing at speed.
  - A clear and well-documented escalation and communication path can speed up the response process and ensure threats are handled by the appropriate expertise.

+ Centralize the Incident Response Process
  + By using SIEM and SOAR solutions, we can more effectively correlate and analyze information from across our environment. When we are responding to an attack, logging into multiple tools slows down our investigation, giving attackers more opportunities to hide in our systems and networks. With all our monitoring and investigation in a centralized location, we can build workflows and processes that streamline activities, enabling us to contain, eradicate, and recover from the incident faster.

+ Identify attack scenarios, define relevant detection use cases and create high-fidelity risk-based alerts
  + Security operations centers (SOCs) commonly receive many more alerts than they can process, which results in time being wasted investigating false positives while true threats are overlooked. Threat detection tools must generate high-quality alerts with low false-positive rates to ensure that security teams are able to focus on real threats to the enterprise

+ Define Reporting Requirements
  + We should have well-defined processes for reporting to management after you recover impacted systems. As part of reviewing our incident response plan’s effectiveness, we should have metrics for how quickly and effectively we:
    + Detected the incident
    + Investigated the incident
    + Contained and eradicated the attacker
    + Recovered systems

+ Conduct regular TDIR testing and training
  - Regularly test your detection and response capabilities through purple and red teaming exercises.
  - Conduct training sessions for staff on the latest threats and response procedures to ensure everyone is prepared.
        
#### STEP 2. Proactive Threat Hunting (and Attack Surface Monitoring)
+ The second step involves monitoring the attack surface of an organization and actively looking for potential threats that could jeopardize an organization’s digital assets. Unlike traditional security measures that react to threats, proactive threat hunting seeks to identify threats before they cause damages.
+ Threat hunting requires acquiring and maintaining a deep understanding of the organization’s infrastructure, systems, and typical network behaviors. By knowing what’s normal, security teams can quickly spot any anomalies that could indicate a potential threat. It also involves staying updated on the latest threat intelligence externally, especially specific to your industry and geography, to anticipate new types of attacks.

+ Four threat-hunting methodologies exist
```
1. Structured hunting
   ➤ Combining attacker tactics, techniques, and procedures (TTPs) with Indicators of Attack (IoA) often aligned to a known framework, like MITRE ATT&CK
2. Unstructured hunting
   ➤ Using a trigger event, like an Indicator of Compromise (IoC), to search logs for pre-detection and post-detection patterns
3. Intel-based hunting
   ➤ Initiating reactive hunting with inputs from IoCs, like hash values, domain names and networks, host artifacts, and IP addresses
4. Hybrid hunting
   ➤ Designing customized searches based on situational awareness that use structured, unstructured, and intel-based methodologies
```

+ Benefits of proactively detecting threats
```
1. Reduce Risks          - Identify vulnerabilities and threats early, reducing the chances of a successful breach.
2. Minimize Downtime     - Faster response times can lead to quicker recovery and reduced business disruption.
3. Protect Assets        - Safeguard critical data and intellectual property from theft or damage.
4. Stay Ahead of Threats - Continuously update threat intelligence to anticipate and prepare for emerging threats.
5. Save Costs            - Preventing or swiftly addressing incidents can reduce the financial impact of data breaches.
```

#### STEP 3. Incident Detection
+ The third step is the detection and identification of threats and anomalies at scale thanks to advanced security tools (e.g., SIEM, EDR, XDR, IPS, AV) that use both signature-based and behaviour-based detection methods and that perform log analysis and event correlation.
+ The main objectives are to:
  + detect threat actors' tactics, techniques, and procedures at the earliest stages of execution
  + trace the malicious activities to identify compromised assets and identify the malicious actor

#### STEP 4. Incident Investigation (Threat Analysis and Prioritization)
+ The fourth step is to prioritize and analyze the threats and anomalies that have been detected. Not all threats pose the same level of risk in terms of affect or impact to the organization, so it’s important to determine which ones need immediate attention. This step is crucial for devising an effective response strategy.
+ Analysis involves understanding the nature of the threat, its origin, its current reach and scope, and its potential trajectory.
+ Prioritization involves assessing the potential impact of the threat on the organization’s operations and data.
  
#### STEP 5. Containment
+ The objective of the fifth step is to contain and mitigate the damages that have already been caused.
+ The response could involve various actions such as:
  + lock compromised or malicious user/service/machine accounts
  + shut-down or isolate affected systems
  + block malicious external/internal IP addresses, domains and URLs
  + block malicious senders/domains on emails
  + quarantine files
  + disable system services
  + force an MFA check
  + rotate passwords
  + patch a vulnerability
  + ...
+ The cyber incident response plan should outline the containment procedure (playbook) that the CSIRT team must follow for each type of incidents / cyber attacks. 

#### STEP 6. Eradication
+ The objective of the sixth step is to eradicate the threat.
+ This step could involve various actions such as:
  + remove malicious user/service/machine accounts
  + remove malicious files, services, registry keys, ...
  + remove rogue network device
  + revoke authentication credentials (e.g. certificates, tokens, keys)
  + ...
+ The cyber incident response plan should outline the eradication procedure (playbook) that the CSIRT team must follow for each type of incidents / cyber attacks. 

#### STEP 7. Recovery and remediation
+ Recovery involves restoring business operations to normal, repairing any damage and addressing any residual effects of the threat.
+ This step could involve various actions such as:
  + restore data from backup tapes
  + recover lost data using forensic tools (if no backup)
  + reinstall software and systems from (safe) backup images
  + unlock legitimate user/service/machine accounts
  + application & systems hardening
  + patch vulnerabilitie
  + upgrade software and OS versions
  + ...
    
#### STEP 8. Lessons Learned
+ Learning involves conducting a post-incident analysis to understand what went wrong and how to prevent similar incidents in the future through process, technology and tools, and improved procedures.

#### Some best practices for effective TDIR

+ Define and assign clear Roles and Responsibilities
  + Cyber attacks disrupt IT services, but they’re more than just technical issues. Attacks impact everyone across the organization, so you should define the following roles and responsibilities:
    + IT Team: assessing severity, investigating incident, containing attack, recovering impacted systems, tracking and documenting activities
    + Human Resources: communicating with employees whose data has been impacted
    + Marketing or Communications: communicating across social media and responding to media requests
    + Senior Leadership: monitoring ongoing business impact and reviewing post-incident reports
    + Customer Support: handling incoming support tickets and updating customers during the incident

+ Proactive threat hunting
  - Actively look for potential threats that could jeopardize your organization’s digital assets. Unlike traditional security measures that react to threats, proactive threat hunting seeks to identify threats before they cause damage.

+ Implement continuous monitoring
  - Implement tools and solutions that provide real-time monitoring of networks, systems, and applications.
  - Continuous monitoring is crucial for effective threat detection and response. Organizations should monitor their systems and networks 24/7, using tools like SIEM and EDR to detect suspicious activities as soon as they occur.

+ Automate threat response
  - Automating threat response can help organizations quickly and effectively neutralize threats. This can involve using automated scripts to block malicious IP addresses, isolate affected systems, or execute other predefined response actions. Automation can also extend to the remediation process, such as automatically patching known vulnerabilities.
  - Advanced tools such as next-generation SIEM, and XDR systems can integrate with other security systems like security orchestration, automation, and response (SOAR) to automatically react to threats and anomalies they identify. 

+ Educate employees on cybersecurity to reduce human error and promote security awareness.
  
+ Threat Intelligence Integration
  - Leverage threat intelligence feeds to stay updated on the latest threat vectors and indicators of compromise.

+ Forensic Capabilities
  - Maintain capabilities to conduct digital forensics, helping to understand the scope and impact of an incident and to prevent future occurrences.

+ Conduct regular security assessemnts
  - Regular vulnerability assessments can help organizations identify security weaknesses (e.g., missing critical patches, default credentials) before a threat actor can exploit them. These assessments should be comprehensive, covering all aspects of the organization’s systems, applications, and networks.
  - Regular network and application penetration testing can help to uncover vulnerabilities that might not be visible during a vulnerability assessment. Penetration tests simulate real-world attacks, testing the organization’s defenses and providing insights into how well they can withstand an actual attack.

+ Network Segmentation
  - Use network segmentation to limit the spread of threats and contain incidents.

--------
### VI. SOC - Security Operation Center 

#### SOC Definition
  + A Security Operations Center (SOC) is a centralized unit within an organization responsible for monitoring, detecting, analyzing, and responding to cybersecurity incidents and threats.
  + It serves as a command center where security analysts and professionals work to ensure the security of the organization's information systems, networks, and data.
  + The SOC is equipped with technology, processes, and skilled personnel to actively defend against and mitigate potential cyber threats, as well as to maintain the overall security posture of the organization.
  + The target operational model of a SOC aims to establish a proactive, resilient, and agile security posture that can effectively defend against and respond to cyber threats while minimizing the impact of security incidents on the organization.
  
#### Common SOC Activities
  + Continuous Monitoring
    + The SOC maintains 24/7 monitoring of the organization's IT infrastructure, networks, and systems to detect and respond to security incidents in real time.
  + Incident Detection and Response
    + Rapid identification and analysis of security events and incidents, followed by appropriate response actions to mitigate and contain the impact of security breaches.
  + Incident Reporting and Analysis
    + Documenting and analyzing security incidents to understand their root causes, patterns, and trends, and using this information to improve security controls and incident response processes.
  + Threat Intelligence Integration
    + Incorporating threat intelligence feeds and data to stay informed about emerging cyber threats and to enhance the organization's ability to detect and respond to evolving attack techniques.
  + Proactive Threat Hunting
    + Actively seeking out and identifying potential security threats and vulnerabilities that may evade traditional security controls through proactive threat hunting initiatives.
  + Security Tool Management
    + Implementing and managing a suite of security tools, such as SIEM (Security Information and Event Management) systems, EDR (Endpoint Detection and Response) solutions, and other security technologies to support monitoring and incident response.
  + Collaboration and Communication
    + Facilitating effective communication and collaboration with internal teams, external partners, and stakeholders to coordinate incident response efforts and enhance overall security posture.
  + Training and Skill Development
    + Providing continuous training and skill development for SOC personnel to ensure they are equipped with the knowledge and expertise required to effectively manage security operations.
      
#### Common SOC Job Roles

  + SOC Manager
    + Oversees the overall operations of the SOC, including team management, resource allocation, and strategic decision-making to enhance security operations.
  + SOC Team Lead
    + Leads a team of analysts and engineers within the SOC, providing guidance, mentorship, and technical expertise to enhance the team's performance and effectiveness in handling security operations.
  + SOC Architect
    + Designs and implements the overall architecture and framework of the SOC, ensuring that it aligns with the organization's security objectives and industry best practices.
  + Security Operations Specialist
    + Provides specialized expertise in specific areas of security operations, such as network security, endpoint security, or threat intelligence analysis.
  + SOC Engineer
    + Designs, implements, and maintains the technical infrastructure and security tools within the SOC, ensuring the effectiveness of security monitoring and response capabilities.
  + SOC Analyst (Level 1)
    + Responsible for monitoring security events and alerts, analyzing potential security incidents (triage), and sometimes providing initial incident response.
 + Incident Responder / SOC Analyst (Level 2)
    + Engages in the immediate response to security incidents, containing and mitigating the impact of incidents as they occur, and leading post-incident analysis and remediation efforts.
    + Part of the Security Incident Response Team (SIRT) focused on responding to and managing security incidents, often involving coordination with external stakeholders and law enforcement.
  + Incident Responder / SOC Analyst (Level 3)
    + Conducts in-depth analysis of security threats, performs forensic investigations, and contributes to the development of security policies and procedures.
    + Part of the Security Incident Response Team (SIRT) focused on responding to and managing security incidents, often involving coordination with external stakeholders and law enforcement.
  + Threat Hunter
    + Proactively searches for and identifies advanced threats and vulnerabilities within the organization's environment that may evade traditional security measures.

#### Common SOC Challenges
  + Shortage of cybersecurity skills
    + Many SOC teams are understaffed and lack the advanced skills necessary to identify and respond to threats in a timely and effective manner. The (ISC)² Workforce Study estimated that the cybersecurity workforce needs to grow by 145% to close skills gap and better defend organizations worldwide.
  + Too many alerts
    + As organizations add new tools for threat detection, the volume of security alerts grows continually. With security teams today already inundated with work, the overwhelming number of threat alerts can cause threat fatigue. In addition, many of these alerts do not provide sufficient intelligence, context to investigate, or are false positives. False positives not only drain time and resources, but can also distract teams from real incidents.
  + Operational Overhead
    + Many organizations use an assortment of disconnected security tools. This means that security personnel must translate security alerts and policies between environments, leading to costly, complex, and inefficient security operations.

#### Cyber Fusion Center (CFC)
+ A Cyber Fusion Center (CFC) is an advanced cybersecurity operations center or next-generation SOC that integrates and aligns people, processes, and technologies to enhance the organization's ability to detect, respond to, and mitigate cyber threats and incidents. It is an evolution of the traditional Security Operations Center (SOC) and typically incorporates elements of threat intelligence, incident response, and proactive threat hunting in a collaborative and integrated environment.
+ The overarching goal of a Cyber Fusion Center is to foster a holistic, collaborative, and intelligence-driven approach to cybersecurity operations, enabling organizations to proactively identify, respond to, and mitigate cyber threats in an agile and integrated manner.

+ Key characteristics of a Cyber Fusion Center may include:
    + Integration of Threat Intelligence
      + CFCs leverage threat intelligence feeds and sources to stay informed about emerging cyber threats, threat actor behavior, and tactics, techniques, and procedures (TTPs).
    + Cross-Disciplinary Collaboration
      + CFCs promote collaboration among different cybersecurity functions, such as threat intelligence analysts, incident responders, forensic analysts, and security operations specialists, to share insights and improve the organization's security posture.
    + Proactive Threat Hunting
      + CFCs engage in proactive threat hunting activities to identify and neutralize potential threats that may evade traditional security controls, often using advanced analytics and machine learning techniques.
    + Advanced Incident Response Capabilities
      + CFCs are equipped with advanced incident response capabilities, including playbooks, automated response actions, and coordinated efforts to contain and remediate security incidents.
    + Real-Time Situational Awareness
      + CFCs provide real-time situational awareness by aggregating and correlating security events, logs, and alerts from various sources to identify patterns and potential security incidents.
    + Technology Integration
      + CFCs leverage advanced cybersecurity technologies, such as Security Information and Event Management (SIEM), Endpoint Detection and Response (EDR), and threat intelligence platforms, to support holistic monitoring and response capabilities.
    + Data-Driven Decision Making
      + CFCs emphasize data-driven decision-making processes, leveraging analytics and metrics to measure the effectiveness of security operations and incident response efforts.

--------
### VII. ISO/IEC 27035 — Information Security Incident Management

> The standard covers the processes for managing information security events, incidents and vulnerabilities.
Managing incidents effectively involves detective and corrective controls designed to recognize and respond to events and incidents, minimize adverse impacts,
gather forensic evidence (where applicable) and in due course ‘learn the lessons’ in terms of prompting improvements to the ISMS,
typically by improving the preventive controls or other risk treatments.

#### The standard lays out a process with 5 key stages:
+ Step 1 - Plan and prepare for handling incidents (e.g. prepare an incident management policy, form an Incident Response Team and establish a competent team to deal with incidents)
	   
+ Step 2 - Identify and detect potential security incidents through monitoring and report all incidents

+ Step 3 - Assess incidents and make decisions about how they are to be addressed (e.g. patch things up and get back to business quickly, or collect forensic evidences even if it delays resolving the issues)

+ Step 4 - Respond to the incident: contain, eradicate, recover from and forensically analyze the incident, where appropriate;

+ Step 5 - Learn and document key takeaways from every incident (more than simply identifying the things that might have been done better, this stage involves actually making changes that improve the processes)

--------
### VIII. Glossary of TDIR and DFIR terms and definitions

- DFIR - Digital Forensics & Incident Response <br>
  + Digital Forensics and Incident Response (DFIR) teams are groups of people in an organization responsible for managing the response to a security incident, including gathering evidence of the incident, remediating its effects, and implementing controls to prevent the incident from recurring in the future.
  
- TDIR - Threat Detection & Incident Response <br>
  + Threat Detection & Incident Response (TDIR) refers to the processes, tools, and strategies used to identify, monitor, and analyze cybersecurity threats in real-time, and to respond to security incidents when they occur. While Threat Detection focuses on identifying malicious activities, abnormal behaviour or vulnerabilities within a system or a network, Incident Response is concerned with managing and mitigating the impact of a security breach or attack once detected.
 
- Cyber Threats
  + The world of cybersecurity is constantly evolving, with new threats emerging every day. Understanding the different types of threats that exist is crucial for security teams to effectively protect their organizations.
  + Cyber threats can be separated into 2 main categories:
    + Common cyber threats including: data leakage, ransomware, crypto mining malware, distributed-denial-of-service (DDoS) attacks, etc.
    + Advanced persistent threats (APT) which are sophisticated cyber attacks that include long-term surveillance and intelligence gathering, punctuated by attempts to steal sensitive information and target vulnerable systems. They intentionally attack specific high-value targets.

+ TA - Threat Actors
  + A threat actor, also known as a malicious actor, is any person or organization that intentionally causes harm in the digital sphere. They exploit weaknesses in computers, networks and systems to carry out disruptive attacks on individuals or organizations.
  + Motivations for Threat Actors range from hacktivism to cyber espionage and financial gain:
    + Cybercriminals usually seeks monetary gain by retrieving/stealing data that they can sell to a 3rd party or by directly exploiting a victim through a ransomware attack or installation of crypto mining malware.
    + Insider threats may be selling information to competitors or comitting frauds. If they have a grudge against their company, they could attempt to compromise the network in retaliation. 
    + Nation-state threat actors are politically or nationalistically motivated. They primarily seek to improve their nation’s counter-intelligence but may have more disruptive goals as well, such as espionage, spreading disinformation and propaganda, and even interfering with key companies, leaders or infrastructure. 
    + Terrorists and hacktivists are also politically motivated but do not act at the state level. Hacktivists want to spread their individual ideas and beliefs while terrorists aim to spread mayhem and fear to accomplish their goals.

+ TI - Threat Intelligencee
  + Threat intelligence is data that is collected, processed, and analyzed to understand a threat actor’s motives, targets, and attack behaviors. Threat intelligence enables to make faster, more informed, data-backed security decisions and change behavior from reactive to proactive in the fight against threat actors.
  + Gathering actionable intelligence can be done from various sources including open-source intelligence (OSINT), network traffic analysis, and other security tools. Threat intelligence is evidence-based knowledge (e.g., context, mechanisms, indicators, implications and action-oriented advice) about existing or emerging menaces or hazards to assets.

+ CERT / CSIRT - Computer Emergency Response Team / Cyber Security Incident Response Team
  + A computer emergency response team (CERT) is an expert group that handles computer security incidents. Alternative names for such groups include cyber emergency response team, computer emergency readiness team, and Cyber Security Incident Response Team (CSIRT).
  + Although CSIRT and CERT are often used intertwined, there is a distinct difference between the two. The term CERT is typically reserved for the predominant computer security organisations authorised by government authorities, while a CSIRT can be the general incident response team in any organisation.

+ FIRST - Forum of Incident Response and Security Teams
  + FIRST is a global forum of incident response and security teams. They aim to improve cooperation between security teams on handling major cybersecurity incidents. FIRST is an association of incident response teams with global coverage.

+ SOC - Security Operation Center
  + A security operations center is a central function in an organization where security experts monitor, detect, analyze, respond to, and report security incidents. A SOC is typically staffed 24/7 by security analysts and IT engineers who use a variety of tools and techniques to detect, analyze, and respond to security threats. This helps ensure threats are contained and neutralized quickly, which in turn allows organizations to reduce their “breakout time” — the critical window between when an intruder compromises the first machine and when they can move laterally to other parts of the network.
  + The SOC team implements the organization’s overall cybersecurity strategy and acts as the central point of collaboration in coordinated efforts to monitor, assess, and defend against cyberattacks.

+ CFC - Cyber Fusion Center
  + A Cyber Fusion Center (CFC) can be thought of as an advanced or next-generation SOC.
  + The CFC employs a proactive approach to identifying threats and defending against them in a unified and timely manner. It fosters collaboration among various teams within an organization to support cybersecurity. This improves threat intelligence gathering, shortens the time it takes to respond to and stop an attack and reduces overall damage to the organization. These teams can include Security Operations, CSIRT, Threat Intelligence team, IT Operations, Fraud/Legal, and so on.

+ SOC Use Cases
  + SOC use cases are security incident detection rules applied to logs that trigger alerts. For each use case there should be a playbook or instructions on how to respond to them (i.e. steps to analyse and mitigate).
  + SOC use case development is a formalized mechanism for the selection and implementation of scenarios of cybersecurity incident detection rules, tools, and response measures. The end goal: build a repetitive process for detecting incidents and put down standardized response plans to various types of threats.

+ SOAR - Security Orchestration, Automation & Response solution
  + Software solution that enables security teams to integrate and coordinate separate tools into streamlined threat response workflows. SOAR's orchestration and automation capabilities allow it to serve as a central console for security incident response. Security analysts can use SOARs to investigate and resolve incidents without moving between multiple tools.
  + By integrating security tools and automating tasks, SOAR platforms can streamline common security workflows like case management, vulnerability management, and incident response. SOAR security solutions can automate low-level, time-consuming, repetitive tasks like opening and closing support tickets, event enrichment, and alert prioritization.
  
+ SIEM - Security Information & Event Management
  + A SIEM product collects information (raw logs and security alerts) from applications, systems and internal security tools (e.g. IPS/IDS, EDR, AV, WAF, Firewall, Proxy) aggregate it in a central log, and detect anomalies. They provide real-time analysis of logs and security alerts making them a vital component in the threat detection process.

+ EDR - Endpoint Detection and Response
  + EDR tools provide real-time monitoring and collection of endpoint data, allowing security teams to detect, investigate, and prevent potential threats. They are capable of identifying, analyzing and blocking suspicious activities on endpoints such as laptops, workstations, servers and mobile devices. They also provide threat hunting and response capabilities.

+ XDR - Extended Detection and Response
  + XDR integrate multiple security products into a cohesive security incident detection and response platform.

+ IDS/IPS - Intrusion Detection and Prevention Systems
  + Intrusion detection and prevention systems are critical components of a robust threat detection and response strategy. They monitor network traffic for suspicious activities and policy violations. Intrusion detection systems (IDS) analyze network traffic to detect potential threats and alert security teams, while intrusion prevention systems (IPS) can go a step further by automatically blocking or mitigating detected threats.

+ NGFW - Next Generation Firewall
  + NGFWs are sophisticated versions of traditional firewalls, equipped with advanced features like deep packet inspection, intrusion prevention systems, some anti virus hash matching, and the ability to incorporate external threat intelligence. 

+ WAF - Web Application Firewalls
  + Web Application Firewalls (WAFs) protect web applications by monitoring and filtering HTTP traffic between a web application and the Internet. They help detect and prevent web-based attacks such as cross-site scripting (XSS), SQL injection, and other threats such as those listed in the OWASP Top 10. 

+ Cloud Detection and Response Tools
  + Cloud detection and response (CDR) tools extend threat detection and response capabilities to cloud environments. They monitor and analyze access and other activities across various cloud services and infrastructure to detect potential security threats. They help in detecting misconfigurations, unauthorized access, and other threats specific to the cloud environment, and can often be part of the authentication and authorization for cloud services.  

+ TIPs - Threat Intelligence Platforms
  + They are a key technology in threat detection and response. They collect, aggregate, and analyze data from a variety of sources to provide actionable intelligence about current and potential threats. TIPs can help organizations to understand the threat landscape, identify trends, and prioritize their security efforts.
        
+ IoC - Indicator of Compromise
  + Indicator of compromise (IoC) in computer forensics is an artifact observed on a network or in an operating system that, with high confidence, indicates a computer intrusion. IOC-based detection methods are classified as static.
  + Typical IoCs are virus signatures and IP addresses, MD5 hashes of malware files, or URLs or domain names of botnet command and control servers.
  + After IoCs have been identified via a process of incident response and computer forensics, they can be used for early detection of future attack attempts using intrusion detection systems and antivirus software.
    
+ IoA - Indicator of Attacks
  + Indicators of Attack (IOAs) demonstrate the intentions behind a cyberattack and the techniques used by the threat actor to accomplish their objectives.
  + An IOA is any digital or physical evidence that a cyberattack is likely to occur or is occuring.
  + The following examples of IOAs are based on common cybercriminal behavior:
    + Public servers communicating with internal hosts. This could be indicative of data exfiltration and remote communications from criminal servers.
    + Connections via non-standard ports rather than port 80 or port 443.
    + Excessive SMTP traffic. Could be evidence of a compromised system being used to launch DDoS attacks or a data leakage.
    + Malware reinfection within a few minutes of removal. This could be indicative of an Advanced Persistent Threat.
    + Multiple user logins from different regions or one source towards numerous systems in a short period of time. This could be indicative of stolen user credentials and lateral movement.
    + Cleaning up logs after mutiple IT operations to leave no trace.
   
+ YARA rules
  + It is a pattern-matching framework used to identify and classify malware and other IT security threats / Indicators of Compromise (IOCs).
  + It provides an effective means to search for patterns of interest (such as IoCs) within multiple files, analyze them, and make informed decisions based on the results, making it an essential component of both network protection and endpoint security.
  + YARA is built into many malware scanners, including, but not limited to, ClamAV, Avast, ESET, Kaspersky, and VirusTotal; it is also featured in other popular types of IT security products such as Extended Detection and Response (EDR), Intrusion Detection and Prevention Systems (IDS/IPS), Security Information and Event Management (SIEM) solutions including AlienVault, and general threat intelligence platforms.  

+ SIGMA rules
  + It is a powerful tool that can be used for detection and malware threat hunting.
  + SIGMA rules are a type of open rule language that can be used to describe malicious activity and allow defenders to share detections (alerts, use cases) in a common language.
  + Much like YARA, or Snort Rules, SIGMA is another tool for the open sharing of detection, except focused on SIEM instead of files or network traffic.
