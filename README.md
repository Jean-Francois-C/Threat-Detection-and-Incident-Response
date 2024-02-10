## Threat Detection and Incident Response (TDIR)
> Technical notes, methodologies, list of tools and scripts regarding the 'Threat Detection &amp; Incident Response' topic

#### Context
Nowadays in our interconnected world, companies are more exposed than ever to a vast array of cyber threats. From crypto-miner malware to ransomware, phishing emails to DDoS attacks, organizations constantly grapple with the challenge of identifying and responding to threats in real time. Failure to do so can result in data breaches, financial losses, damaged reputation, and regulatory fines.

--------
#### 1. GLOSSARY & ACRONYMS

- DFIR - Digital Forensics & Incident Response <br>
  + Digital Forensics and Incident Response (DFIR) teams are groups of people in an organization responsible for managing the response to a security incident, including gathering evidence of the incident, remediating its effects, and implementing controls to prevent the incident from recurring in the future.
  
- TDR / TDIR - Threat Detection & (Incident) Response <br>
  + TDR refers to a collection of cybersecurity processes and solutions aiming at identifying, investigating, and responding to security threats.
  + Threat Detection & Incident Response (TDIR) refers to the processes, tools, and strategies used to identify, monitor, and analyze cybersecurity threats in real-time, and to respond to security incidents when they occur. While Threat Detection focuses on identifying malicious activities or vulnerabilities within a system, Incident Response is concerned with managing and mitigating the impact of a security breach or attack once detected.
  + Threat detection is the process of analyzing a security ecosystem at the holistic level to find threat actors (e.g., external hackers, malicious users), abnormal activities, malicious behaviors and anything that could compromise a network. Threat detection is built on threat intelligence, which involves tools that are strategic, tactical and operational.
  + Threat response consists of the mitigation efforts used to neutralize and prevent cyber threats before they create damages.
  + TDR process
    1. Attack Surface Monitoring and Proactive Threat Hunting
       + The first step involves reducing and monitoring the attack surface of an organization and actively looking for potential threats that could jeopardize an organization’s digital assets. Unlike traditional security measures that react to threats, proactive threat hunting seeks to identify threats before they cause damages.
       + By proactively detecting threats, we can:
         + Reduce Risks: Identify vulnerabilities and threats early, reducing the chances of a successful breach.
         + Minimize Downtime: Faster response times can lead to quicker recovery and reduced business disruption.
         + Protect Assets: Safeguard critical data and intellectual property from theft or damage.
         + Stay Ahead of Threats: Continuously update threat intelligence to anticipate and prepare for emerging threats.
         + Save Costs: Preventing or swiftly addressing incidents can reduce the financial impact of data breaches.
    2. Detection of Threats and Anomalies
       + The second step is the detection and identification of threats and anomalies at scale thanks to advanced security tools (e.g., SIEM, EDR, XDR, IPS, AV) that use both signature-based and behaviour-based detection methods and that perform log analysis and event correlation. The objective is to detect threat actors' tactics, techniques, and procedures at the earliest stages of execution.
    3. Threat Analysis and Prioritization (Incident investigation phase)
       + The third step is to prioritize and analyze the threats and anomalies that have been detected. Not all threats pose the same level of risk in terms of affect or impact to the organization, so it’s important to determine which ones need immediate attention. This step is crucial for devising an effective response strategy.
       + Analysis involves understanding the nature of the threat, its origin, its current reach and scope, and its potential trajectory.
       + Prioritization involves assessing the potential impact of the threat on the organization’s operations and data.
    4. Response and Remediation
       + The response could involve various actions such as disabling a user/service/machine account, shutting-down or isolating affected systems, blocking malicious IP addresses, forcing an MFA check, or removing malware from the network.
       + Remediation involves repairing any damage caused by the threat and restoring systems to their normal state. This could involve tasks like rotating passwords, patching vulnerabilities, recovering lost data, or reinstalling compromised software and systems.
    5. Recovery and Learning
       + Recovery involves restoring business operations to normal and addressing any residual effects of the threat.
       + Learning involves conducting a post-incident analysis to understand what went wrong and how to prevent similar incidents in the future through process, technology and tools, and improved procedures.
      
  + Tools and Technologies used in Threat Detection, Investigation, and Response <br>
    + Traditional threat detection uses technology like security information and event management (SIEM), endpoint detection and response (EDR) and network traffic analysis. SIEM collects data to generate security alerts, but lacks the ability to respond to threats. Network traffic analysis and endpoint detection and response are greatly effective in identifying localized threats, but cannot detect evasive threats and require complex integration. An intrusion detection system can monitor a network for policy violations and malicious activity. Advanced threat detection and response uses threat intelligence to monitor the entire system for attacks that bypass traditional threat detection.
    + Security Information and Event Management (SIEM)
      + SIEM solutions area key tool in the arsenal of any cybersecurity professional. They collect and aggregate log data generated across the IT environment, can identify deviations from the norm, and help security teams take appropriate action to mitigate the threat. SIEM solutions are usually capable of providing near-real-time analysis of security alerts, making them a vital component in the threat detection process.
      + SIEM systems can also correlate related events, helping security teams to understand the full scope of an attack. Additionally, SIEM tools can automate responses to certain types of threats, freeing up security personnel to focus on more complex issues. 
    + Endpoint Detection and Response (EDR)
      + EDR tools provide real-time monitoring and collection of endpoint data, allowing security teams to detect, investigate, and prevent potential threats. They are capable of identifying, analyzing and blocking suspicious activities on endpoints such as laptops, workstations, servers and mobile devices. 
    + Extended Detection and Response (XDR)
      + XDR integrate multiple security products into a cohesive security incident detection and response platform.
    + Intrusion Detection and Prevention Systems (IDS/IPS)
      + Intrusion detection and prevention systems are critical components of a robust threat detection and response strategy. They monitor network traffic for suspicious activities and policy violations. Intrusion detection systems (IDS) analyze network traffic to detect potential threats and alert security teams, while intrusion prevention systems (IPS) go a step further by sending a signal to firewalls/proxies to automatically block or mitigate detected threats.
    + Next Generation Firewall (NGFW)
      + NGFWs are sophisticated versions of traditional firewalls, equipped with advanced features like deep packet inspection, intrusion prevention systems, some anti virus hash matching, and the ability to incorporate external threat intelligence. 
    + Web Application Firewalls (WAF)
      + Web Application Firewalls (WAFs) protect web applications by monitoring and filtering HTTP traffic between a web application and the Internet. They help detect and prevent web-based attacks such as cross-site scripting (XSS), SQL injection, and other threats such as those listed in the OWASP Top 10. 
    + Cloud Detection and Response Tools
      + Cloud detection and response (CDR) tools extend threat detection and response capabilities to cloud environments. They monitor and analyze access and other activities across various cloud services and infrastructure to detect potential security threats. They help in detecting misconfigurations, unauthorized access, and other threats specific to the cloud environment, and can often be part of the authentication and authorization for cloud services.  
    + Threat Intelligence Platforms (TIPs)
      + They are a key technology in threat detection and response. They collect, aggregate, and analyze data from a variety of sources to provide actionable intelligence about current and potential threats. TIPs can help organizations to understand the threat landscape, identify trends, and prioritize their security efforts.
        
  + Some best practices for effective TDIR include:
    1. Proactive threat hunting
    2. Conduct regular security assessemnts
       - Regularly assess your security posture through vulnerability assessments, security audits and penetration tests.
       - Regular vulnerability assessments can help organizations identify weaknesses in their security posture before a threat actor can exploit them. These assessments should be comprehensive, covering all aspects of the organization’s systems, applications, and networks.
       - Regular network and application penetration testing can help to uncover vulnerabilities that might not be visible during a vulnerability assessment. Penetration tests simulate real-world attacks, testing the organization’s defenses and providing insights into how well they can withstand an actual attack. 
    3. Conduct regular TDIR testing
       - Regularly test your detection and response capabilities through purple and red teaming exercises.
    4. Define and implement a comprehensive incident response plan
       - Develop a detailed and regularly updated plan that outlines roles, responsibilities, and procedures in the event of a security incident.
       - An incident response plan is a set of instructions that help organizations respond to a security incident swiftly and effectively. This plan should outline the roles and responsibilities of all team members, detail the procedures for ingestion and troubleshooting, then responding to different types of incidents.
       - It should provide guidelines for communicating with stakeholders during and after an incident, including lessons learned and process improvement along with potential tooling enhancement.
       - Having a comprehensive incident response plan in place can significantly reduce the time it takes to respond to a security incident, minimizing the damage and disruption it can cause. It can also help to ensure that all team members know what to do in the event of an attack, boosting the organization’s overall security posture.
    5. Determine a clear escalation path
       - Establishing a clear escalation path is crucial for efficient threat response. When a potential threat is detected, the relevant information should be quickly escalated to the right personnel or team for further analysis and remediation.
       - The escalation path may vary depending on the severity of the threat, its potential impact, and the skills required to handle it. Some types of threat, if they are high-level in terms of potential impact for media or external awareness, should have an executive sponsor or contact for informing at speed.
       - A clear and well-documented escalation and communication path can speed up the response process and ensure threats are handled by the appropriate expertise.
    6. Implement continuous monitoring
        - Implement tools and solutions that provide real-time monitoring of networks, systems, and applications.
        - Continuous monitoring is crucial for effective threat detection and response. Organizations should monitor their systems and networks 24/7, using tools like SIEM and EDR to detect suspicious activities as soon as they occur.
    7. Automate threat detection
    8. Automate threat response
       - Automating threat response can help organizations quickly and effectively neutralize threats. This can involve using automated scripts to block malicious IP addresses, isolate affected systems, or execute other predefined response actions. Automation can also extend to the remediation process, such as automatically patching known vulnerabilities.
       - Advanced tools such as next-generation SIEM, and XDR systems can integrate with other security systems like security orchestration, automation, and response (SOAR) to automatically react to threats and anomalies they identify. 
    9. Educate employees on cybersecurity to reduce human error and promote security awareness
    10. Regular TDIR Training
        - Conduct training sessions for staff on the latest threats and response procedures to ensure everyone is prepared.
    11. Threat Intelligence Integration
       - Leverage threat intelligence feeds to stay updated on the latest threat vectors and indicators of compromise.
    12. Forensic Capabilities
       - Maintain capabilities to conduct digital forensics, helping to understand the scope and impact of an incident and to prevent future occurrences.
    13. Network Segmentation
       + Use network segmentation to limit the spread of threats and contain incidents.
      
- Examples of Cyber Threats
  + Cyber threats can be separated into 2 categories:
    + Common cyber threats including:
      + data leakage
      + ransomware
      + crypto mining malware
      + distributed-denial-of-service (DDoS) attacks
    + Advanced persistent threats (APT) which are attack campaigns where attackers establish a presence on a network to gain access and remain undetected over a long period of time. They intentionally attack specific high-value targets. They take time to study their target and conduct a specialized attack that is more likely to succeed.

- Threat Actors
  + A threat actor, also known as a malicious actor, is any person or organization that intentionally causes harm in the digital sphere. They exploit weaknesses in computers, networks and systems to carry out disruptive attacks on individuals or organizations.
  + The term “threat actor” includes:
    + cybercriminals
    + idealogues such as hacktivists (hacker activists) and terrorists
    + nation-state sponsored hackers
    + malevolent insiders
    + internet trolls
  + The term “cybercriminal” ofen refers to thieves behind a ransomware or a crypto mining malware attack. 
  + Nation-state threat actors work at a national level; they generally target intelligence in the nuclear, financial or technology sectors. This type of threat usually refers to government intelligence agencies or military, meaning they are highly trained, extremely stealthy and protected by their nation’s legal system. 

- Motivations for Threat Actors
  + Motivations range from hacktivism to cyber espionage and financial gain.
  + Cybercriminals usually seeks monetary gain. They do this by retrieving data that they can sell to a third party or by directly exploiting a victim through a ransomware attack or installation of crypto mining malware.
  + Insider threats may be following the lead of other cybercriminals by selling information to competitors. They may also be more personally motivated; if they have a grudge against their company or boss, they could attempt to compromise the network in retaliation. Finally, insider threats who plan to start a competing business may steal data to give themselves an edge.
  + Nation-state threat actors are politically or nationalistically motivated. They primarily seek to improve their nation’s counterintelligence. However, they may have more disruptive goals as well, such as espionage, spreading disinformation and propaganda, and even interfering with key companies, leaders or infrastructure. Regardless of their specific goal, nation-state threat actors receive state support and protection for their crimes.
  + Terrorists and hacktivists are also politically motivated but do not act at the state level. Hacktivists want to spread their individual ideas and beliefs, usually rooted in a social or political issue. Terrorists, on the other hand, aim to spread mayhem and fear to accomplish their goals.

- Threat Intelligencee
  + Threat intelligence is data that is collected, processed, and analyzed to understand a threat actor’s motives, targets, and attack behaviors. Threat intelligence enables to make faster, more informed, data-backed security decisions and change behavior from reactive to proactive in the fight against threat actors.
  + Threat intelligence is evidence-based knowledge (e.g., context, mechanisms, indicators, implications and action-oriented advice) about existing or emerging menaces or hazards to assets. 

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
