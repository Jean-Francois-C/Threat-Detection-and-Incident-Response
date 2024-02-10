## Threat / Incident Detection and Response
> Technical notes, methodologies, list of tools and scripts regarding the 'Threat Detection &amp; Incident Response' topic

--------
#### 1. GLOSSARY & ACRONYMS

- DFIR - Digital Forensics & Incident Response <br>
  + ...it stands for
  
- TDR - Threat Detection & Response <br>
  + TDR refers to a collection of cybersecurity processes and solutions aiming at identifying, investigating, and responding to security threats.
  + TDR process
    1. Proactive Threat Hunting
       + The first step involves actively looking for potential threats that could jeopardize an organization’s digital assets. Unlike traditional security measures that react to threats, proactive threat hunting seeks to identify threats before they cause damages.  
    2. Detection of Threats and Anomalies
       + The second step is the detection and identification of threats and anomalies at scale thanks to advanced security tools (e.g., SIEM, EDR, XDR, IPS, AV) that use both signature-based and behaviour-based detection methods. The objective is to detect threat actors' tactics, techniques, and procedures at the earliest stages of execution.
    3. Investigation: Prioritization and Analysis of Threats
       + The third step is to prioritize and analyze the threats and anomalies that have been detected. Not all threats pose the same level of risk in terms of affect or impact to the organization, so it’s important to determine which ones need immediate attention. This step is crucial for devising an effective response strategy.
       + Prioritization involves assessing the potential impact of the threat on the organization’s operations and data.
       + Analysis involves understanding the nature of the threat, its origin, its current reach and scope, and its potential trajectory. 
    4. Response and Remediation
       + The response could involve various actions such as disabling a user/service/machine account, shutting-down or isolating affected systems, blocking malicious IP addresses, forcing an MFA check, or removing malware from the network.
       + Remediation involves repairing any damage caused by the threat and restoring systems to their normal state. This could involve tasks like rotating passwords, patching vulnerabilities, recovering lost data, or reinstalling compromised software and systems.
    5. Recovery and Learning
       + Recovery involves restoring business operations to normal and addressing any residual effects of the threat.
       + Learning involves conducting a post-incident analysis to understand what went wrong and how to prevent similar incidents in the future through process, technology and tools, and improved procedures.
  + TDR process
    1. Proactive threat hunting
    2. Conduct regular security assessments (i.e, vulnerability assessments, penetration testing, red team exercices)
    3. Define and implement a comprehensive incident response plan
    4. Determine a clear escalation path
    5. Automate threat response
    6. Implement continuous monitoring
    7. Train employees and promote security awareness
  
- CERT - Computer Emergency Response Team / CSIRT - Cyber Security Incident Response Team <br>
  + A CERT / CSIRT is a team of cybersecurity experts that handles computer security incidents.
  
- SOC - Security Operation Center <br>
  + A SOC is related to the people, processes and technologies that provide situational awareness through the detection, containment, and remediation of IT threats in order to manage and enhance an organization's security posture.
  + A SOC will handle, on behalf of an institution or company, any threatening IT incident, and will ensure that it is properly identified, analyzed, communicated, investigated and reported.
  + The SOC also monitors applications to identify a possible cyber-attack or intrusion (event), and determines if it is a genuine malicious threat (incident), and if it could affect business.
  + In large organizations, SOCs rely on numerous tools to track and respond to cyberthreats.

- SOAR solutions - Security Orchestration, Automation & Response solutions <br>
  + It is a software solution that enables security teams to integrate and coordinate separate tools into streamlined threat response workflows.
  + SOAR's orchestration and automation capabilities allow it to serve as a central console for security incident response. Security analysts can use SOARs to investigate and resolve incidents without moving between multiple tools.
  + By integrating security tools and automating tasks, SOAR platforms can streamline common security workflows like case management, vulnerability management, and incident response.
  + SOAR security solutions can automate low-level, time-consuming, repetitive tasks like opening and closing support tickets, event enrichment, and alert prioritization. SOARs can also trigger the automated actions of integrated security tools.
  
- SIEM - Security Information & Event Management <br>
  + SIEM is the core component of any typical Security Operations Center (SOC).
  + SIEM product collects information (raw logs and security alerts) from applications, systems and internal security tools (e.g. IPS/IDS, EDR, AV, WAF, Firewall, Proxy) aggregate it in a central log, and detect anomalies. They provide real-time analysis of logs and security alerts.

- EDR solution - Endpoint Detection & Response solution <br>
  + EDR refers to a category of tools used to detect and investigate threats on endpoints.
  + EDR tools typically provide detection, investigation, threat hunting, and response capabilities.
    
- XDR solution - Extended Detection & Response solution <br>
  + XDR solutions collect and analyze security data from endpoints, networks, and the cloud. 

--------
#### 2. USEFUL RESOURCES

--------
#### 3. USEFUL TOOLS & SCRIPTS
