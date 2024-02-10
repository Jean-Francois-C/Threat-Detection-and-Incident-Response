## Threat Detection and Incident Response (TDIR)
> Technical notes, methodologies, list of tools and scripts regarding the 'Threat Detection &amp; Incident Response' topic

#### Context
Nowadays companies are more exposed than ever to a vast array of cyber threats. From ransomware to crypto-mining malware, phishing emails to DDoS attacks, organizations constantly grapple with the challenge of identifying and responding to threats in real time. Failure to do so can result in data breaches, financial losses, damaged reputation, and regulatory fines.

#### Table of Contents
+ I. USEFUL RESOURCES
+ II. GLOSSARY & ACRONYMS
+ III. ISO/IEC 27035 — Information security incident management (2016+)
+ IV. Threat Detection & Incident Response Methodology (TDIR)
+ V. Security Operation Center (SOC)
+ VI. MITRE ATTACK Framework	
+ VII. The CYBER ATTACK KILL CHAIN MODEL & DEFENSE

--------
#### I. USEFUL RESOURCES

+ NIST Publication - [Digital Forensics & Incident Response framework dedicated to Operational Technology](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8428.pdf)
+ NIST Publication - [Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
+ ISO/IEC 27035 (2020-2023+) - [Information Security Incident Management](https://www.iso27001security.com/html/27035.html)
+ ANSSI (French)  - [Anticiper et gérer une crise Cyber](https://cyber.gouv.fr/anticiper-et-gerer-une-crise-cyber)
+ ANSSI (French)  - [Organiser un exercice de gestion de crise cyber (Guide - v1.0)](https://cyber.gouv.fr/publications/organiser-un-exercice-de-gestion-de-crise-cyber)
+ ANSSI (French)  - Piloter la remédiation d’un incident cyber
    + [Volet stratégique](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_strat%C3%A9gique_cyberattaquesetrem%C3%A9diation_v1g.pdf) - Le volet stratégique s’adresse aux décideurs au sein des organisations.
    + [Volet opérationnel](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_operationnel_cyberattaquesetremediation_a5_v1j.pdf) - Le volet opérationnel est destiné à accompagner le pilotage opérationnel des opérations de remédiation suite à un incident de sécurité informatique.
    + [Volet technique](https://cyber.gouv.fr/sites/default/files/document/20231218_Volet_technique_cyberattaquesetremediation_a5_v1h.pdf) - Le volet technique s’adresse aux équipes d’exploitation et aux intervenants techniques d’opérations de remédiation.

--------
#### II. GLOSSARY & ACRONYMS

- DFIR - Digital Forensics & Incident Response <br>
  + Digital Forensics and Incident Response (DFIR) teams are groups of people in an organization responsible for managing the response to a security incident, including gathering evidence of the incident, remediating its effects, and implementing controls to prevent the incident from recurring in the future.
  
- TDR / TDIR - Threat Detection & (Incident) Response <br>
  + Threat Detection & Incident Response (TDIR) refers to the processes, tools, and strategies used to identify, monitor, and analyze cybersecurity threats in real-time, and to respond to security incidents when they occur. While Threat Detection focuses on identifying malicious activities or vulnerabilities within a system or a network, Incident Response is concerned with managing and mitigating the impact of a security breach or attack once detected.
  + Threat detection is the process of analyzing a security ecosystem at the holistic level to find threat actors (e.g., external hackers, malicious users), abnormal activities, malicious behaviors and anything that could compromise a network. Threat detection is built on threat intelligence, which involves tools that are strategic, tactical and operational.
  + Threat response consists of the mitigation efforts used to neutralize and prevent cyber threats before they create damages.
 
- Cyber Threats
  + The world of cybersecurity is constantly evolving, with new threats emerging every day. Understanding the different types of threats that exist is crucial for security teams to effectively protect their organizations.
  + Cyber threats can be separated into several categories:
    + Common cyber threats including: data leakage, ransomware, crypto mining malware, distributed-denial-of-service (DDoS) attacks, etc.
    + Advanced persistent threats (APT) which are sophisticated cyber attacks that include long-term surveillance and intelligence gathering, punctuated by attempts to steal sensitive information and target vulnerable systems. They intentionally attack specific high-value targets.

- Threat Actors
  + A threat actor, also known as a malicious actor, is any person or organization that intentionally causes harm in the digital sphere. They exploit weaknesses in computers, networks and systems to carry out disruptive attacks on individuals or organizations.
  + Motivations for Threat Actors range from hacktivism to cyber espionage and financial gain:
    + Cybercriminals usually seeks monetary gain. They do this by retrieving/stealing data that they can sell to a third party or by directly exploiting a victim through a ransomware attack or installation of crypto mining malware.
    + Insider threats may be following the lead of other cybercriminals by selling information to competitors. They may also be more personally motivated; if they have a grudge against their company or boss, they could attempt to compromise the network in retaliation. Finally, insider threats who plan to start a competing business may steal data to give themselves an edge.
    + Nation-state threat actors are politically or nationalistically motivated. They primarily seek to improve their nation’s counterintelligence. However, they may have more disruptive goals as well, such as espionage, spreading disinformation and propaganda, and even interfering with key companies, leaders or infrastructure. 
    + Terrorists and hacktivists are also politically motivated but do not act at the state level. Hacktivists want to spread their individual ideas and beliefs, usually rooted in a social or political issue. Terrorists, on the other hand, aim to spread mayhem and fear to accomplish their goals.

- Threat Intelligencee
  + Threat intelligence is data that is collected, processed, and analyzed to understand a threat actor’s motives, targets, and attack behaviors. Threat intelligence enables to make faster, more informed, data-backed security decisions and change behavior from reactive to proactive in the fight against threat actors.
  + Threat intelligence is evidence-based knowledge (e.g., context, mechanisms, indicators, implications and action-oriented advice) about existing or emerging menaces or hazards to assets.
  + Gathering actionable intelligence can be done from various sources including open-source intelligence (OSINT), network traffic analysis, and other security tools.

- CERT - Computer Emergency Response Team / CSIRT - Cyber Security Incident Response Team <br>
  + A CERT / CSIRT is a team of cybersecurity experts that handles computer security incidents.
  
+ SOC - Security Operation Center
  + A security operations center is a central function in an organization where security experts monitor, detect, analyze, respond to, and report security incidents. A SOC is typically staffed 24/7 by security analysts and IT engineers who use a variety of tools and techniques to detect, analyze, and respond to security threats. This helps ensure threats are contained and neutralized quickly, which in turn allows organizations to reduce their “breakout time” — the critical window between when an intruder compromises the first machine and when they can move laterally to other parts of the network.
  + The SOC team implements the organization’s overall cybersecurity strategy and acts as the central point of collaboration in coordinated efforts to monitor, assess, and defend against cyberattacks.
  + With multi-vector attacks, it is no surprise that SOC is becoming an increasingly important part of organizations’ efforts to keep ahead of the latest cybersecurity threats.
     
+ SOAR - Security Orchestration, Automation & Response solution
  + Software solution that enables security teams to integrate and coordinate separate tools into streamlined threat response workflows.
  + SOAR's orchestration and automation capabilities allow it to serve as a central console for security incident response. Security analysts can use SOARs to investigate and resolve incidents without moving between multiple tools.
  + By integrating security tools and automating tasks, SOAR platforms can streamline common security workflows like case management, vulnerability management, and incident response. SOAR security solutions can automate low-level, time-consuming, repetitive tasks like opening and closing support tickets, event enrichment, and alert prioritization. SOARs can also trigger the automated actions of integrated security tools.
  
+ SIEM - Security Information & Event Management
  + SIEM is the core component of any typical Security Operations Center (SOC).
  + SIEM product collects information (raw logs and security alerts) from applications, systems and internal security tools (e.g. IPS/IDS, EDR, AV, WAF, Firewall, Proxy) aggregate it in a central log, and detect anomalies. They provide real-time analysis of logs and security alerts making them a vital component in the threat detection process.

+ EDR - Endpoint Detection and Response
  + EDR tools provide real-time monitoring and collection of endpoint data, allowing security teams to detect, investigate, and prevent potential threats. They are capable of identifying, analyzing and blocking suspicious activities on endpoints such as laptops, workstations, servers and mobile devices. They also provide threat hunting and response capabilities.

+ XDR - Extended Detection and Response
  + XDR integrate multiple security products into a cohesive security incident detection and response platform.

+ IDS/IPS - Intrusion Detection and Prevention Systems
  + Intrusion detection and prevention systems are critical components of a robust threat detection and response strategy. They monitor network traffic for suspicious activities and policy violations. Intrusion detection systems (IDS) analyze network traffic to detect potential threats and alert security teams, while intrusion prevention systems (IPS) go a step further by sending a signal to firewalls/proxies to automatically block or mitigate detected threats.

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


--------
#### III. ISO/IEC 27035 — Information security incident management (2016+)

   ➤ https://www.iso27001security.com/html/27035.html

The standard covers the processes for managing information security events, incidents and vulnerabilities.

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
### IV. Threat Detection & Incident Response (TDIR)

#### PROCESS / METHODOLOGY

#### Step 1. Preparation 

+ Define and assign clear Roles and Responsibilities
  + Cyber attacks disrupt IT services, but they’re more than just technical issues. Attacks impact everyone across the organization, so you should define the following roles and responsibilities:
    + IT Team: assessing severity, investigating incident, containing attack, recovering impacted systems, tracking and documenting activities
    + Human Resources: communicating with employees whose data has been impacted
    + Marketing or Communications: communicating across social media and responding to media requests
    + Senior Leadership: monitoring ongoing business impact and reviewing post-incident reports
    + Customer Support: handling incoming support tickets and updating customers during the incident
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
+ Training security analysts and defining how to test processes

#### Step 2. Proactive Threat Hunting (and Attack Surface Monitoring)

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

#### Step 3. Incident Detection

+ The third step is the detection and identification of threats and anomalies at scale thanks to advanced security tools (e.g., SIEM, EDR, XDR, IPS, AV) that use both signature-based and behaviour-based detection methods and that perform log analysis and event correlation.
+ The main objectives are to:
  + detect threat actors' tactics, techniques, and procedures at the earliest stages of execution
  + trace the malicious activities to identify compromised assets and identify the malicious actor

#### Step 4. Incident Investigation (Threat Analysis and Prioritization)

+ The fourth step is to prioritize and analyze the threats and anomalies that have been detected. Not all threats pose the same level of risk in terms of affect or impact to the organization, so it’s important to determine which ones need immediate attention. This step is crucial for devising an effective response strategy.
+ Analysis involves understanding the nature of the threat, its origin, its current reach and scope, and its potential trajectory.
+ Prioritization involves assessing the potential impact of the threat on the organization’s operations and data.
  
#### Step 5. Incident Response (Containment)
+ The goal of the fifth step is to contain and mitigate the damages that have already been caused.
+ The response could involve various actions such as disabling a user/service/machine account, shutting-down or isolating affected systems, blocking malicious IP addresses, forcing an MFA check, or removing malware from the network.
+ A cyber incident response plan outlines the processes that the organization’s cybersecurity incident response team (CSIRT) follows once it detects an attack or data breach. 

#### Step 5. Remediation
+ Remediation involves identifying the incident’s root cause and repairing any damage caused by the threat.
+ This could involve tasks like rotating passwords, patching vulnerabilities, hardening systems, recovering lost data, or reinstalling compromised software and systems.
  
#### Step 6. Recovery
+ Recovery involves restoring business operations to normal and addressing any residual effects of the threat.

#### Step 7. Lessons Learned
+ Learning involves conducting a post-incident analysis to understand what went wrong and how to prevent similar incidents in the future through process, technology and tools, and improved procedures.


#### TOOLS and TECHNOLOGIES IN TDIR

+ Traditional threat detection uses technology like security information and event management (SIEM), endpoint detection and response (EDR) and network traffic analysis. SIEM collects data to generate security alerts, but lacks the ability to respond to threats. Network traffic analysis and endpoint detection and response are greatly effective in identifying localized threats, but cannot detect evasive threats and require complex integration. An intrusion detection system can monitor a network for policy violations and malicious activity. Advanced threat detection and response uses threat intelligence to monitor the entire system for attacks that bypass traditional threat detection.
            
#### Some best practices for effective TDIR:

+ Proactive threat hunting
  - Actively look for potential threats that could jeopardize your organization’s digital assets. Unlike traditional security measures that react to threats, proactive threat hunting seeks to identify threats before they cause damage.

+ Conduct regular security assessemnts
  - Regular vulnerability assessments can help organizations identify security weaknesses (e.g., missing critical patches, default credentials) before a threat actor can exploit them. These assessments should be comprehensive, covering all aspects of the organization’s systems, applications, and networks.
  - Regular network and application penetration testing can help to uncover vulnerabilities that might not be visible during a vulnerability assessment. Penetration tests simulate real-world attacks, testing the organization’s defenses and providing insights into how well they can withstand an actual attack. 

+ Conduct regular TDIR testing
  - Regularly test your detection and response capabilities through purple and red teaming exercises.

+ Define and implement a comprehensive incident response plan
  - An incident response plan is a set of instructions that help organizations respond to a security incident swiftly and effectively. This plan should outline the roles and responsibilities of all team members, detail the procedures for ingestion and troubleshooting, then responding to different types of incidents. It should provide guidelines for communicating with stakeholders during and after an incident, including lessons learned and process improvement along with potential tooling enhancement.
  - Having a comprehensive incident response plan in place can significantly reduce the time it takes to respond to a security incident, minimizing the damage and disruption it can cause. It can also help to ensure that all team members know what to do in the event of an attack, boosting the organization’s overall security posture.
  - A clearly communicated incident response plan is critical to an organization’s cyber resilience. By defining discrete steps across all response activities, the plan enables security teams to reduce business disruption and mitigate operational impact arising from security incidents.

+ Determine a clear escalation path
  - stablishing a clear escalation path is crucial for efficient threat response. When a potential threat is detected, the relevant information should be quickly escalated to the right personnel or team for further analysis and remediation.
  - The escalation path may vary depending on the severity of the threat, its potential impact, and the skills required to handle it. Some types of threat, if they are high-level in terms of potential impact for media or external awareness, should have an executive sponsor or contact for informing at speed.
  - A clear and well-documented escalation and communication path can speed up the response process and ensure threats are handled by the appropriate expertise.

+ Implement continuous monitoring
  - Implement tools and solutions that provide real-time monitoring of networks, systems, and applications.
  - Continuous monitoring is crucial for effective threat detection and response. Organizations should monitor their systems and networks 24/7, using tools like SIEM and EDR to detect suspicious activities as soon as they occur.

+ Automate threat response
  - Automating threat response can help organizations quickly and effectively neutralize threats. This can involve using automated scripts to block malicious IP addresses, isolate affected systems, or execute other predefined response actions. Automation can also extend to the remediation process, such as automatically patching known vulnerabilities.
  - Advanced tools such as next-generation SIEM, and XDR systems can integrate with other security systems like security orchestration, automation, and response (SOAR) to automatically react to threats and anomalies they identify. 

+ Educate employees on cybersecurity to reduce human error and promote security awareness
+ Regular TDIR Training
  - Conduct training sessions for staff on the latest threats and response procedures to ensure everyone is prepared.
+ Threat Intelligence Integration
  - Leverage threat intelligence feeds to stay updated on the latest threat vectors and indicators of compromise.
+ Forensic Capabilities
  - Maintain capabilities to conduct digital forensics, helping to understand the scope and impact of an incident and to prevent future occurrences.
+ Network Segmentation
  - Use network segmentation to limit the spread of threats and contain incidents.


--------
#### V. SOC - Security Operation Center 

  + The function of the security operations center (SOC) is to monitor, prevent, detect, investigate, and respond to cyber threats around the clock. SOC teams are charged with monitoring and protecting the organization’s assets including intellectual property, personnel data, business systems, and brand integrity. The SOC team implements the organization’s overall cybersecurity strategy and acts as the central point of collaboration in coordinated efforts to monitor, assess, and defend against cyberattacks.
  + A security operations center, or SOC, is a central function in an organization where security experts monitor, detect, analyze, respond to, and report security incidents. A SOC is typically staffed 24/7 by security analysts, engineers, and other IT personnel who use a variety of tools and techniques to detect, analyze, and respond to security threats.
  + A SOC is related to the people, processes and technologies that provide situational awareness through the detection, containment, and remediation of IT threats in order to manage and enhance an organization's security posture.
  + A SOC will handle, on behalf of an institution or company, any threatening IT incident, and will ensure that it is properly identified, analyzed, communicated, investigated and reported.
  + The SOC also monitors applications to identify a possible cyber-attack or intrusion (event), and determines if it is a genuine malicious threat (incident), and if it could affect business.
  + In large organizations, SOCs rely on numerous tools to track and respond to cyberthreats.
  + One key attribute of the SOC is that it operates continuously, providing 24/7 monitoring, detection and response capabilities. This helps ensure threats are contained and neutralized quickly, which in turn allows organizations to reduce their “breakout time” — the critical window between when an intruder compromises the first machine and when they can move laterally to other parts of the network.
  + With multi-vector attacks, it is no surprise that SOC is becoming an increasingly important part of organizations’ efforts to keep ahead of the latest cybersecurity threats.
  + SOC activities and responsibilities include:
    + Network monitoring to provide complete visibility into digital activity and better detect anomalies
    + Prevention techniques to deter and deflect a range of known and unknown risks
    + Threat detection and intelligence capabilities that assess the origin, impact and severity of each cybersecurity incident
    + Decisive incident response and remediation using a blend of automated technologies and human intervention
    + Reporting to ensure all incidents and threats are fed into the data repository, making it more precise and responsive in the future
    + Risk and compliance capabilities to ensure industry and government regulations are followed
  + SOC Job Roles
    + When a cyberattack occurs, the SOC acts as the digital front line, responding to the security incident with force while also minimizing the impact on business operations.
    + Common SOC roles include:
      + SOC Manager: Acts as the security center leader, overseeing all aspects of the SOC, its workforce and operations
      + Security Analyst Tier 1 – Triage: Categorizes and prioritizes alerts, escalates incidents to tier 2 analysts
      + Security Analyst Tier 2 – Incident Responder: Investigates and remediates escalated incidents, identifies affected systems and scope of the attack, uses threat intelligence to uncover the adversary
      + Security Analyst Tier 3 – Threat Hunter: Proactively searches for suspicious behavior and tests and assesses network security to detect advanced threats and identify areas of vulnerability or insufficiently protected assets
      + Security Architect: Designs the security system and its processes, and integrates various technological and human components
      + Compliance Auditor: Oversees the organization’s adherence to internal and external rules and regulations
    + SOC Challenges
      + Shortage of cybersecurity skills: Many SOC teams are understaffed and lack the advanced skills necessary to identify and respond to threats in a timely and effective manner. The (ISC)² Workforce Study estimated that the cybersecurity workforce needs to grow by 145% to close skills gap and better defend organizations worldwide.
      + Too many alerts: As organizations add new tools for threat detection, the volume of security alerts grows continually. With security teams today already inundated with work, the overwhelming number of threat alerts can cause threat fatigue. In addition, many of these alerts do not provide sufficient intelligence, context to investigate, or are false positives. False positives not only drain time and resources, but can also distract teams from real incidents.
      + Operational Overhead: Many organizations use an assortment of disconnected security tools. This means that security personnel must translate security alerts and policies between environments, leading to costly, complex, and inefficient security operations.


--------
#### VI. MITRE ATTACK Framework	

+ MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. 
  It documents common tactics, techniques, and procedures (TTPs) that advanced persistent threats use against Windows enterprise networks.
  
+ The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector,
  in government, and in the cybersecurity product and service community.

+ Tactics, Techniques, and Procedures (TTPs) 
```
➤ TACTICS represent the “why” of an ATT&CK technique or sub-technique. 
  It is the adversary’s tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access.
  
➤ TECHNIQUES represent “how” an adversary achieves a tactical goal by performing an action. 
  For example, an adversary may dump credentials to achieve credential access.
  
➤ PROCEDURES are the specific implementation the adversary uses for techniques or sub-techniques. 
  For example, a procedure could be an adversary using PowerShell to inject into lsass.exe to dump credentials by scraping LSASS memory on a victim.
  Procedures are categorized in ATT&CK as the observed in the wild use of techniques in the "Procedure Examples" section of technique pages.
```

There are currently 14 Enterprise tactics (https://attack.mitre.org/tactics/enterprise/)

ID	Name			Description
----------------------------------------------------------------------------------------------------------------------
TA0043	Reconnaissance		The adversary is trying to gather information they can use to plan future operations.
TA0042	Resource Development	The adversary is trying to establish resources they can use to support operations.
TA0001	Initial Access		The adversary is trying to get into your network.
TA0002	Execution		The adversary is trying to run malicious code.
TA0003	Persistence		The adversary is trying to maintain their foothold.
TA0004	Privilege Escalation	The adversary is trying to gain higher-level permissions.
TA0005	Defense Evasion		The adversary is trying to avoid being detected.
TA0006	Credential Access	The adversary is trying to steal account names and passwords.
TA0007	Discovery		The adversary is trying to figure out your environment.
TA0008	Lateral Movement	The adversary is trying to move through your environment.
TA0009	Collection		The adversary is trying to gather data of interest to their goal.
TA0011	Command and Control	The adversary is trying to communicate with compromised systems to control them.
TA0010	Exfiltration		The adversary is trying to steal data.
TA0040	Impact			The adversary is trying to manipulate, interrupt, or destroy your systems and data.


--------
#### VII. The CYBER ATTACK KILL CHAIN MODEL & DEFENSE	

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
  + The reconnaissance phase of a cyberattack is focused on learning as much as possible about the target.  
    This can include the use of open-source intelligence (websites, social media, etc.) and active investigation of the target environment.  
  + Research, identification and selection of targets, often represented as crawling Internet websites such as conference proceedings and mailing lists
    for email addresses, social relationships, or information on specific technologies. 
    
➤ Phase 2 - Weaponization
  + The goal of the reconnaissance phase is to discover a potential attack vector, and weaponization is intended to develop a method of exploiting a 
    discovered weakness. This may include development of custom malware, crafting a phishing email, etc.
  + Coupling a remote access trojan with an exploit into a deliverable payload, typically by means of an automated tool (weaponizer). 
    Increasingly, client application data files such as Adobe Portable Document Format (PDF) or Microsoft Office documents serve as the weaponized deliverable. 

➤ Phase 3 - Delivery
  + Transmission of the weapon to the targeted environment. 
    The three most prevalent delivery vectors for weaponized payloads by APT actors, as observed by the Lockheed Martin Computer Incident Response Team (LM-CIRT)
    for the years 2004-2010, are email attachments (phishing), websites, and USB removable media. 
  + The delivery stage involves setting up the target for exploitation. This could be as simple as clicking send on a phishing email or may involve 
    a complicated process of getting the right person at the right place at the right time.  
    
➤ Phase 4 - Exploitation
  + The exploitation phase is when the attacker takes advantage of the discovered weakness to gain access to the target environment.  
    This may involve exploiting a vulnerability in a webserver, a user enabling macros on a malicious document, etc.
  + After the weapon is delivered to victim host, exploitation triggers intruders’ code. Most often, exploitation targets an application or operating system
    vulnerability, but it could also more simply exploit the users themselves or leverage an operating system feature that auto-executes code.

➤ Phase 5 - Installation 
  + Installation of a remote access trojan or backdoor on the victim system allows the adversary to maintain persistence inside the environment.
  + One of the goals of a cyberattack is to gain a foothold on the target network. Once the identified vulnerability has been exploited, 
    an attacker should be able to install and execute malware on the target system.
  
➤ Phase 6 - Command and Control (C2)
  + Typically, compromised hosts must beacon outbound to an Internet controller server to establish a C2 channel. 
    APT malware especially requires manual interaction rather than conduct activity automatically. 
    Once the C2 channel establishes, intruders have “hands on the keyboard” access inside the target environment.
  + A great deal of malware is designed to be interactive, receiving instructions from its creator and/or sending data to them.  
    Establishing a channel for these communications is the next stage in the process.  
  
➤ Phase 7 - Actions on Objectives
  + Only now, after progressing through the first six phases, can intruders take actions to achieve their original objectives. 
    Typically, this objective is data exfiltration which involves collecting, encrypting and extracting information from the victim environment; 
    violations of data integrity or availability are potential objectives as well. 
    Alternatively, the intruders may only desire access to the initial victim box for use as a hop point to compromise additional systems and move laterally inside the network.
```

+ What are the differences between the Cyber Kill Chain Model and the MITRE ATT&CK Framework?
```
The MITRE ATT&CK Framework and the Cyber Kill Chain are both designed to describe how an adversary could carry out a cyberattack.  
However, the two tools differ in several ways:

➤ Depth: 
  + The Cyber Kill Chain is designed to outline the stages of the cyberattack lifecycle.  
  + MITRE ATT&CK’s Tactics loosely map to these stages, but MITRE ATT&CK goes deeper to describe the methods by which an attacker could meet the goals of a particular stage.

➤ Coverage: 
  + The Cyber Kill Chain maps the complete lifecycle of a cyberattack.  
  + MITRE ATT&CK breaks this into multiple matrices (i.e. PRE-ATT&CK and Enterprise).
  
➤ Stages: 
  + The Cyber Kill Chain outlines seven stages of a cyberattack.
  + MITRE ATT&CK’s Enterprise matrix alone includes fourteen Tactics that fit into the last five stages of the Cyber Kill Chain.
  
➤  Ordering: 
  + The Cyber Kill Chain has a defined order, where adversaries are expected to move linearly from one phase to another.  
  + The MITRE ATT&CK Framework is deliberately unordered to acknowledge that an adversary may move through Tactics out of order, skip some Tactics, and revisit some Tactics multiple times throughout the course of an attack.
```
