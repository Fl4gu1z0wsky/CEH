#  :globe_with_meridians: :computer: :closed_lock_with_key: CEH - Knowledges
CEH certification :milky_way:

This repository is here to help for the CEH.
The terminology and the information are from :
- Udemy: CEH v11 312-50: Certified Ethical Hacker Practice Exams. NEW (Good questions and answers well explained)

## :wrench: TOOLS

**Nmap** – to scan open port (old name was Ethereal)   

    -sS (TCP SYN (Stealth) Scan). It is the fastest and most popular way to scan a target. It uses the SYN scan which is unobtrusive and stealthy as it never 
    -sT (TCP Connect Scan). When SYN scan is not an option, and we don't have raw packets priv. or we want to scan IPv6 network. It establishes a connection with     
    the target machine and port with a handshake. It uses the Berkley Sockets API. However nmap uses this API to obtain status information on each connection attempt.
    -F (Fast (limited port) scan). It scans normally 1000 most common port but here it is reduced to 100.
    complete the full TCP handshake connexion. It also allows clear, reliable differentiation between open, closed, and filtered states.
    -sU (UDP Scan). It is generaly slower but we should'nt neglect the UDC ports. DNS, SNMP, and DHCP (registered ports 53, 161/162, and 67/68) are three of the most common.
    -sM (TCP Maimon Scan). Named after its discoverer, Uriel Maimon. Same as NULL, FIN, and Xmas scan, except that the probe is FIN/ACK. We send the FIN/ACK and a response   
    RST should be send. However if the port is OPEN/FILTERED, it often drop the packet.
    -oX Requests that XML output be directed to the given filename.
    -oG (grepable output). It is a simple format that lists each host on one line and can be trivially searched and parsed with standard Unix tools such as grep, awk, cut, sed, diff, and Perl.
    -sX (Xmas scan). Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
  
**Tcpdump** – wireshark but for CLI (no graphic)

**Nessus** – scan automatically vulnerabilities in a network. We can create session splicing as well with it.

**Maltego** -  It is a software used for open-source intelligence and forensics. Maltego focuses on providing a library of transforms for discovery of data from open sources and visualizing that information in a graph format, suitable for link analysis and data mining.

**Analyst's Notebook** - IBM Security i2 Analyst's Notebook is a software product from IBM for data analysis and investigation. Based on ELP (entity-link-property) methodology, it reveals relationships between data entities to discover patterns and provide insight into data. It is commonly used by digital analysts at law enforcement, military and other government intelligence agencies, and by fraud departments.

**Palantir** - The company is known for three projects in particular: Palantir Gotham, Palantir Metropolis, and Palantir Foundry. Palantir Gotham is used by counter-terrorism analysts at offices in the United States Intelligence Community (USIC) and United States Department of Defense. Palantir Metropolis is used by hedge funds, banks, and financial services firms. Palantir Foundry is used by corporate clients such as Morgan Stanley, Merck KGaA, Airbus, and Fiat Chrysler Automobiles NV.

**Metasploit** - Used for pentesting nearly everything.

    - Auxiliary modules: do not require the use of a payload to run like exploit modules. These types of modules include useful programs such as scanners, fuzzier, and SQL injection tools. Penetration testers use the plethora of scanners in the auxiliary directory to gather a deep understanding of the system to be attacked and then transition to exploit modules.
    - Exploit modules: are pieces of code within the database that when running on a victim computer, the attacker will attempt to leverage a vulnerability on the local or remote system compromising the payload module such as the Meterpreter shell.
    - Payload Module: A payload is generally attached to the exploit before its execution. The payload contains the set of instructions that the victim’s computer is to carry out after compromise (Bind Shells, Reverse Shells, Meterpreter Shell).
    - NOPS Module: level language (assembly language). It simply slides the program execution to the next memory address. NOPs are commonly used before the start of the ShellCode to ensure its successful execution in the memory while performing no operations and just sliding through the memory addresses. The \x90 instruction represents a NOP instruction in the hexadecimal format.
    
**Aircrack-ng** - It is a network software suite consisting of a detector, packet sniffer, WEP and WPA/WPA2-PSK cracker and analysis tool for 802.11 wireless LANs. It works with any wireless network interface controller whose driver supports raw monitoring mode and can sniff 802.11a, 802.11b and 802.11g traffic. 

**Snort** - It is a free open source network intrusion detection system (IDS) and intrusion prevention system (IPS). The program can also be used to detect probes or attacks, including, but not limited to, operating system fingerprinting attempts, semantic URL attacks, buffer overflows, server message block probes, and stealth port scans.

    - Sniffer Mode: The program will read network packets and display them on the console.
    - Packet Logger Mode: In packet logger mode, the program will log packets to the disk.
    - Network Intrusion Detection System Mode: In intrusion detection mode, the program will monitor network traffic and analyze it against a rule set defined by the user. The program will then perform a specific action based on what has been identified.
    
**Cain & Abel** - It is a password recovery tool for Microsoft Windows. It can recover many kinds of passwords using methods such as network packet sniffing, cracking various password hashes by using methods such as dictionary attacks, brute force and cryptanalysis attacks.


## :warning: ATTACKS

### Footprinting

**Reconnaissance stage** - a set of processes and techniques (Footprinting, Scanning & Enumeration) to discover and collect information about a target system covertly. There is passive and active recon. passive is just sniffing (not interacting directly with the network) while active is for example scanning ports.

**Google Dork** - Used for OSINT.

    site: - Limit results to those from a specific website.
    inurl: - Find pages with a certain word (or words) in the URL.
    link: - Find pages linking to a specific domain or URL. Google killed this operator in 2017, but it does still show some results.
    cache: - Returns the most recent cached version of a web page (providing the page is indexed, of course).

### Scan

**TCP Connect/Full Open Scan** - In TCP Connect scanning, the OS’s TCP connect() system call tries to open a connection to every port of interest on the target machine. It is one of the most reliable forms of TCP scanning by completing a three-way handshake.

**NULL Scan** - The Null Scan is a type of TCP scan that hackers — both ethical and malicious — use to identify listening TCP ports. It can help identify potential holes for server hardening.

**Xmas scan** - It is considered a stealthy scan which analyzes responses to Xmas packets to determine the nature of the replying device. Each operating system or network device responds in a different way to Xmas packets revealing local information such as OS (Operating System), port state and more.

**Half-open scann** - It is referred to as an SYN scan it’s a fast and sneaky scan that tries to find potential open ports on the target computer. This scan is fast and hard to detect because it never completes the full TCP 3 way-handshake. The scanner sends an SYN message and just notes the SYN-ACK responses. The scanner doesn’t complete the connection by sending the final ACK: it leaves the target hanging. Any SYN-ACK responses are possibly open ports. An RST (reset) is a closed port.

**IDLE/IPID Scanning** - We use a zombie to send a SYN/ACK packet and it increments it's IPID while sending a reset. We do the same for another PC but we change the source for the zombie. We do that again to the zombie and if the IPID has been incremented 2 times, it means the port is open.

**SSDP Scanning** - (Simple Service Discovery Protocol) is the basis of the discovery protocol of Universal Plug and Play (UPnP) and is intended for use in residential or small office environments.

**UDP Scanning** - send a UDP packet to various ports on the target host. We use it with nmap to scan UDP ports (the same as TCP ports).

**SYN/FIN scanning** - Use IP fragments in a process of scanning that was developed to avoid false positives generated by other scans because of a packet filtering device on the target system. The TCP header splits into several packets to evade the packet filter.

**ACK scanning** - It does not exactly determine whether the port is open or closed, but whether the port is filtered or unfiltered. This is especially good when attempting to probe for the existence of a firewall.

**ICMP scanning** - ICMP is used for checking live systems.

**Banner Grabbing** -  technique used to gain information about a computer system on a network and the services running on its open ports. We often use nmap for this and those services : HTTP (80), FTP (21) or SMTP (25).

**Firewalking** - Firewalking is the method of determining the movement of a data packet from an untrusted external host to a protected internal host through a firewall. 
It uses traceroute and TTL (Time to Live) to analyze IP packet response to in order to determine gateway ACL (Access Control List) filters and map network. The idea 
behind firewalking is to determine which ports are open and whether packets with control information can pass through a packet-filtering device. It is an active 
reconnaissance network security analysis technique that attempts to determine which layer 4 protocols a specific firewall will allow.

### Mail

**Email spoofing** - the fabrication of an email header in the hopes of duping the recipient into thinking the email originated from someone or somewhere other than the intended source.

**Email Masquerading** - the perpetrator assumes the identity of a fellow network user or co-employee to trick victims into providing user credentials. On the contrary of email spoofing, this is done from inside the network from a stolen account.

**Email Harvesting** - the process of obtaining lists of email addresses.

**Email Phishing** - a type of social engineering attack often used to steal user data, including login credentials and credit card numbers.

### SQL injection
  
 **Tautology** – use of a conditional OR clause in order to have a query always TRUE.
(select * from user_details where userid = 'abcd' and password = 'anything' or 'x'='x')
  
**Error-based** - insert malicious query in input fields and get some error which is regarding SQL syntax or database.
  
**Union** - the UNION keyword can be used to retrieve data from other tables within the database.
(SELECT a, b FROM table1 UNION SELECT c, d FROM table2)

**End-of-Line Comment** - the code is nullified with a end of line comments.
(SELECT * FROM user WHERE name = 'x' AND userid IS NULL; --';)

**Blind SQLi** - Blind SQL injection is used when a web application is vulnerable to an SQL injection but the results of the injection are not visible to the attacker. The page with the vulnerability may not be one that displays data but will display differently depending on the results of a logical statement injected into the legitimate SQL statement called for that page.

**Compound SQLi** - It is an attack that involve using SQLi alongside cross-site scripting, denial of service, DNS hijacking, or insufficient authentication attacks. Pairing SQLi with other methods of attack gives hackers additional ways to avoid detection and circumvent security systems.

**DMS-specific SQLi** - (or Out-of-band SQLi) This is a much less common approach to attacking an SQL server. It relies on certain features of an SQL database to be enabled; if those features aren't, the OOB attack won't succeed. OOB attacks involve submitting a DNS or HTTP query to the SQL server that contains an SQL statement. If successful, the OOB attack can escalate user privileges, transmit database contents, and generally do the same things other forms of SQLi attacks do.

### Router

**Traffic redirection** - the attacker modifies traffic in transit or sniff packets.

**Traffic sent to a routing black hole** - the traffic can be redirected to null0 and can kick an IP.

**Unauthorized route prefix origination** - It introduces a new prefix into the routing table. Used to get a covert attack network to be routable throughout the victim network.

### Cryptography

**Trickery and Deceit** – it involves the use of social engineering techniques to extract cryptography keys.

**One-Time Pad** – a one-time pad contains many non-repeating groups of letters or number keys, which are chosen randomly.

**Frequency Analysis** – It is the study of the frequency or letters or groups of letters in a cipher text. It works on the fact that, in any given stretch of written language, certain letters and combination of letters occur with varying frequencies.

**Collision attack** - A collision attack on a cryptographic hash tries to find two inputs producing the same hash value.

### WIFI

**aLTEr** - MITM attack using a fake eNodeB (the 4G cell tower). It acts as a malicious relay and the attacker has access to the encrypted communication of the target. Furthermore the information can be manipulated. The goal is to alter the IP of the DNS querry to redirect the trafic to a malicious DNS. Thus the server replies maliciously from a request.

**Sinkhole** - The attack is carried out by either hacking a node in the network or introducing a fabricated node in the network.The malicious node promotes itself as the shortest path to the base station and tries to guide the traffic from other nodes towards itself. Then the intruder can compromise the data.

**Wi-jacking** - An attack in which attackers accesss neighbor’s WiFi without any form of cracking, relying on saved browsers creadentials which are reused again for the same URL (router admin interface credentials remembered by the browser).

### Bluetooth

**Bluedriving** - This tool is to research about the targeted surveillance of people by means of its cellular phone or car. It can search for and show a lot 
of information about the device, the GPS address and the historic location of devices on a map.

**Bluejacking** - It sends unsolocited messages over bluetooth. IT is generally harmless. Usually, a bluejacker will only send a text message, but it's possible 
to send images or sounds with modern phones. Bluejacking has been used in guerrilla marketing campaigns to promote advergames.

**Bluesmacking** - It is denial of service (DoS). The crafted packet exceed the limited size available on bluetooth. The devince cannot process the packet 
and the it becomes unavailable.

**Bluesnarfing** - The unauthorized access of information from a wireless device through a Bluetooth connection. This allows access to calendars, contact lists, emails and text messages, and on some phones, users can copy pictures and private videos. 

**Bluebugging** - It was developed after the onset of bluejacking and bluesnarfing. Similar to bluesnarfing, bluebugging accesses and uses all phone featuresbut is limited by the transmitting power of class 2 Bluetooth radios, normally capping its range at 10–15 meters.

### Cloud

**Cloud Hopper** - This is an operation uncovered by security researchers in 2017. The attacks were leveled against managed IT service providers, which the group used as intermediaries to get their hands on their target’s corporate assets and trade secrets.

**Cloudborne** - An attack scenario affecting various cloud providers could allow an attacker to implant persistent backdoors for data theft into bare-metal cloud servers, which would be able to remain intact as the cloud infrastructure moves from customer to customer.

### Web

**Session Hijacking** - Also known as cookie hijacking, it exploits a valid computer session to gain unauthorized access. The HTTP cookies can be stolen by an intermediary computer or access to the saved cookies on the victim's computer.

**Insecure direct object references** - IDOR are a cybersecurity issue that occurs when a web application developer uses an identifier for direct access to an internal implementation object but provides no additional access control and/or authorization checks (e.g. https://www.example.com/transaction.php?id=74656, there is no check on the id provided).

**Wrapping attacks** - Injecting a faked element into the message structure so that a valid signature covers the unmodified element while the faked one is processed by the application logic. This type of attack usually occurs during the translation of SOAP messages in the Transport Layer Service (TLS) layer between the web server and valid user. The message body will be duplicated and sent to the server as a valid user.

**Cross-site request forgery** - (CSRF) also known as one-click attack or session riding. This is a type of malicious exploit of a website where unauthorized commands are submitted from a user that the web application trusts. In a CSRF attack, an innocent end user is tricked by an attacker into submitting a web request that they did not intend. This may cause actions to be performed on the website that can include inadvertent client or server data leakage, change of session state, or manipulation of an end user's account.

**Cross-site scripting** - Cross-site scripting (XSS) is a type of security vulnerability typically found in web applications. XSS attacks enable attackers to inject client-side scripts into web pages viewed by other users.

**Directory traversal** - A path traversal attack (also known as directory traversal) aims to access files and directories stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or using absolute file paths.

**Clickjacking** - It is an attack that tricks a user into clicking a webpage element which is invisible or disguised as another element. It is performed by displaying an invisible page or HTML element, inside an iframe, on top of the page the user sees. The user believes they are clicking the visible page but in fact they are clicking an invisible element.

**Session fixation** - It is a web application attack in which attackers can trick a victim into authenticating the application using the attacker's Session Identifier. An attacker can send a link containing a fixed session-id, and if the victim clicks on the link, the victim’s session id will be fixed since the attacker already know the session id so he/she can easily hijack the session.

**HTTP Parameter Pollution** - HPP - This is a vulnerability that occurs due to the passing of multiple parameters having the same name. By exploiting these effects, an attacker may bypass input validation, trigger application errors, or modify internal variables values.

**Website defacement vulnerability** - It is the unauthorized modification of web pages, including the addition, removal, or alteration of existing content. These attacks are commonly carried out by hacktivists.

### USB

**Juice jacking** - An infected USB charging station is used to compromise linked devices.

### Social Engineering

**Tailgating** - Also known as Piggybacking. It involves an attacker seeking entry to a restricted area that lacks the proper authentication.

**Pretexting** - The practice of presenting oneself as someone else to obtain private information. Usually, attackers create a fake identity and use it to manipulate the receipt of information.

**Reverse Social Engineering** - A reverse social engineering attack is a person-to-person attack in which an attacker convinces the target that he or she has a problem or might have a certain problem in the future and that he, the attacker, is ready to help solve the problem.

**Shoulder-Surfing** - This is a type of social engineering technique used to obtain information such as personal identification numbers (PINs), passwords and other confidential data by looking over the victim's shoulder.

**Quid pro quo** - Aka “something for something”. Instead of baiting a target with the promise of a good, a quid pro quo attack promises a service or a benefit based on a specific action's execution. In a quid pro quo attack scenario, the hacker offers a service or benefit in exchange for information or access (e.g. helping for downloading a major update).

**Ellicitation** - Elicitation means to bring or draw out or arrive at a conclusion (truth, for instance) by logic. In training materials, the National Security Agency of the United States government defines elicitation as "the subtle extraction of information during an apparently normal and innocent conversation." It can occur at a restaurant, a bar, a daycare, ...

### Network

**Sybil attack** -  Sybil Attack is a type of attack seen in peer-to-peer networks in which a node in the network operates multiple identities actively at the same time and undermines the authority/power in reputation systems. The main aim of this attack is to gain the majority of influence in the network to carry out illegal(with respect to rules and laws set in the network) actions in the system.

**WHOIS** - is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system, but is also used for a wider range of other information.

**Session splicing** - One basic technique is to split the attack payload into multiple small packets so that the IDS must reassemble the packet stream to detect the attack. By itself, small packets will not evade any IDS that reassembles packet streams. However, small packets can be further modified in order to complicate reassembly and detection. One evasion technique is to pause between sending parts of the attack, hoping that the IDS will time out before the target computer does.

**Insertion Attack** - The attacker can send packets whose time-to-live (TTL) fields are crafted to reach the IDS but not the target computers. This will result in the IDS and the target system having two different character strings. An attacker confronts the IDS with a stream of one-character packets (the attacker-originated data stream), in which one of the characters (the letter “X”) will be accepted only by the IDS. As a result, the IDS and the end system reconstruct two different strings.

**Unicode evasion** - Using Unicode representation, where each character has a unique value regardless of the platform, program, or language, is also an effective way to evade IDSs. For example, an attacker might evade an IDS by using the Unicode character c1 to represent a slash for a Web page request.

**Flood attack** - Flood attacks are also known as Denial of Service (DoS) attacks.

**Low-bandwidth attacks** - Attacks which are spread out across a long period of time or a large number of source IPs, such as nmap's slow scan, can be difficult to pick out of the background of benign traffic. An online password cracker which tests one password for each user every day will look nearly identical to a normal user who mistyped their password.

**Heartbleed** - This is a security bug in the OpenSSL cryptography library, which is a widely used implementation of the Transport Layer Security (TLS) protocol. It results from improper input validation (due to a missing bounds check) in the implementation of the TLS heartbeat extension. It is a buffer over-read vuln.

**SSL/TLS Renegotiation Vulnerability** - It allows one part of an encrypted connection (the one taking place before renegotiation) to be controlled by one party with the other part (the one taking place after renegotiation) to be controlled by another. A MITM attacker can open a connection to an SSL server, send some data, request renegotiation, and, from that point on, continue to forward to the SSL server the data coming from a genuine user.

**Vulnerability scanning** - A vulnerability penetration test on the organizational network in three steps.

    - Locating nodes: The first step in vulnerability scanning is to locate live hosts in the target network using various scanning techniques.
    - Performing service and OS discovery on them: After detecting the live hosts in the target network, the next step is to enumerate the open ports and services and the operating system on the target systems.
    - Testing those services and OS for known vulnerabilities: Finally, after identifying the open services and the operating system running on the target nodes, they are tested for known vulnerabilities.

### Others

**Side-channel** - This is an attack based on information gained from the implementation of a computer system. Timing information, power consumption, electromagnetic leaks or even sound can provide an extra source of information, which can be exploited.

**Exploit Kits** - An exploit kit is simply a collection of exploits, which is a simple one-in-all tool for managing a variety of exploits altogether. Exploit kits act as a kind of repository and make it easy for users without much technical knowledge to use exploits.

**Shellshock** - Also known as Bashdoor. It is a security bug in the Unix Bash shell. Shellshock could enable an attacker to cause Bash to execute arbitrary commands and gain unauthorized access to many Internet-facing services, such as web servers, that use Bash to process requests.

**POODLE** - Padding Oracle On Downgraded Legacy Encryption - It is a man-in-the-middle exploit which takes advantage of Internet and security software clients' fallback to SSL 3.0. If attackers successfully exploit this vulnerability, on average, they only need to make 256 SSL 3.0 requests to reveal one byte of encrypted messages.

**Fuzzing** - A Black Box software testing technique, which basically consists in finding implementation bugs using malformed/semi-malformed data injection in an automated fashion.

**Rootkit** - Malicious software that provides root-level, privileged access to a computer while hiding its existence and actions. Hackers use rootkits to conceal themselves until they decide to execute their malicious malware. The list below show what can be done with a rootkit:

    - Sensitive data stolen
    - Malware infection
    - File removal
    - Eavesdropping
    - Remote control
    

## :lock: SECURITY

### WIFI

**MAC filtering** – listing of allowed devices that you need on your Wi-Fi. Helps preventing unwanted access to the network.

### Router

    Counter methods:
    - Configuration modification : We must secure the router and the supporting system it makes use of, such as TFTP servers (used to upgrade several routers that   
    are separated from the TFTP server by slow WAN connections).
    - Introduction of a rogue router that : The other routing devices must trust the send information. We can block it by adding message authentication to the routing   
    protocol. And we can also add ACLs to block routing protocol messages unwanted.
    - Spoofing a valid routing protocol message or modifying a valid message in transit. We can prevent it with message authentication as well. And if we have a transport    
    layer protocol like TCP for BGP, it can render the task difficult due to the pseudo-random initial sequence numbers.
    - Sending of malformed or excess packets. Excess packets can be stopped with DoS mitigation techniques. Malformed packets are harder to identify. This is     
    an area of computer security that needs increased attention, not just in routing protocols but in all network applications.

### Cryptography

**Quantum cryptography** - The science of exploiting quantum mechanical properties to perform cryptographic tasks. The advantage of quantum cryptography lies in the fact that it allows the completion of various cryptographic tasks that are proven or conjectured to be impossible using only classical (i.e. non-quantum) communication. For example, it is impossible to copy data encoded in a quantum state. If one attempts to read the encoded data, the quantum state will be changed (no-cloning theorem). This could be used to detect eavesdropping in quantum key distribution.

**Hardware-based** - This is the use of computer hardware to assist software, or sometimes replace software, in the process of data encryption (e.g. AES).

**Homomorphic** - This is a form of encryption that permits users to perform computations on its encrypted data without first decrypting it.

**Elliptic-curve** - This is an approach to public-key cryptography based on the algebraic structure of elliptic curves over finite fields. ECC allows smaller keys compared to non-EC cryptography (based on plain Galois fields) to provide equivalent security

### Network

**Software Firewall** - It is placed between the normal application and the networking components of the operating system and regulates data traffic through two things: port numbers, and applications. Depending on your firewall settings, your firewall could stop programs from accessing the Internet, and/or block incoming or outgoing access via ports.

**DMZ** - demilitarized zone - functions as a subnetwork containing an organization's exposed, outward-facing services. It acts as the exposed point to untrusted networks, commonly the Internet. The goal of a DMZ is to add an extra layer of security to an organization's local area network. A protected and monitored network node that faces outside the internal network can access what is exposed in the DMZ. In contrast, the rest of the organization's network is safe behind a firewall.

**DNSSEC** - Domain Name System Security Extension - When deployed, computers will be able to confirm if DNS responses are legitimate. It also has the ability to verify that a domain name does not exist at all, which can help prevent man-in-the-middle attacks. DNSSEC will verify the root domain or sometimes called “signing the root.” When an end-user attempts to access a site, a stub resolver on their computer requests the site's IP address from a recursive name server. After the server requests the record, it will also request the zones DNSEC key. The key will then be used to verify that the IP address record is the same as the authoritative server's record. Next, the recursive name server would verify that the address record came from the authoritative name server. It would then verify it has been modified and resolves the correct domain source. If there has been a modification to the source, then the recursive name server will not allow the connection to occur to the site.

**HoneyPot** - It is a decoy system or servers deployed alongside production systems within the network. When deployed as enticing targets for attackers, honeypots can add security monitoring opportunities for blue teams and misdirect the adversary from their true target.

   1. Pure honeypots: The attacker's activities are monitored by using a bug tap installed on the honeypot's link to the network. No other software needs to be installed.
   2. Low-interaction Honeypots: It will only give an attacker minimal access to the operating system. ‘Low interaction’ means precisely that the adversary will not be able to interact with your decoy system in any depth, as it is a much more static environment.
   3. High interaction honeypots: It emulates certain protocols or services. The attacker is provided with real systems to attack, making it far less likely they will guess they are being diverted or observed. As the systems are only present as a decoy, any traffic that is found is by its very existence malicious, making it easy to spot threats and track and trace an attacker's behavior.
   4. Research honeypots: They are run to gather information about the black hat community's motives and tactics targeting different networks. These honeypots do not add direct value to a specific organization; instead, they are used to research the threats that organizations face and to learn how to better protect against those threats.
    
**DAI** - Dynamic arp inspection - protects switching devices against Address Resolution Protocol (ARP) packet spoofing (also known as ARP poisoning or ARP cache poisoning). It  inspects ARPs on the LAN and uses the information in the DHCP snooping database on the switch to validate ARP packets and to protect against ARP spoofing.

**Port security** - It helps secure the network by preventing unknown devices to connect to a port. You can limit the number of MAC addresses on a given port. Packets that have a matching MAC address (secure packets) are forwarded; all other packets (unsecure packets) are restricted. You can enable port security on a per port basis. There is 2 modes: Dynamic (learn automatically a certain number of MAC adresses) or Static (we have to specify the MAC).

### Security test

**SAST** - Static application security testing - It is used to secure software by reviewing the source code of the software to identify sources of vulnerabilities. An SAST tool scans the source code of applications and its components to identify potential security vulnerabilities in their software and architecture. Static analysis tools can detect an estimated 50% of existing security vulnerabilities.

**DAST** - Dynamic application security testing - It is a program which communicates with a web application through the web front-end in order to identify potential security vulnerabilities in the web application and architectural weaknesses. DAST tools allow sophisticated scans, detecting vulnerabilities with minimal user interactions once configured with host name, crawling parameters and authentication credentials. These tools will attempt to detect vulnerabilities in query strings, headers, fragments, verbs (GET/POST/PUT) and DOM injection.

**MAST** - Mobile Application Security Testing - It is a blend of SAST, DAST, and forensic techniques while it allows mobile application code to be tested specifically for mobiles-specific issues such as jailbreaking, and device rooting, spoofed Wi-Fi connections, validation of certificates, data leakage prevention, etc.

**IAST** - Interactive Application Security Testing - It is a combination of SAST and DAST. IAST tools can check whether known vulnerabilities (from SAST) can be exploited in a running application (i.e., DAST). These tools combine knowledge of data flow and application flow in an application to visualize advanced attack scenarios using test cases which are further used to create additional test cases by utilizing DAST results recursively.

### Incident handling

**Preparation** - During the preparation phase, organizations should establish policies and procedures for incident response management and enable efficient communication methods both before and after the incident.

**Identification** - The identification phase of an incident response plan involves determining whether or not an organization has been breached.

**Containment** - If it is discovered that a breach has occurred, organizations should work fast to contain the event. However, this should be done appropriately and does not require all sensitive data to be deleted from the system. Instead, strategies should be developed to contain the breach and prevent it from spreading further.

**Neutralization** - Once all systems and devices that have been impacted by the breach have been identified, an organization should perform a coordinated shutdown.

**Recovery** - Recovery plan involves restoring all affected systems and devices to allow for normal operations to continue. However, before getting systems back up and running, it is vital to ensure that the breach's cause has been identified to prevent another breach from occurring again.

**Review** - Throughout the incident, all details should have been properly documented so that the information can be used to prevent similar breaches in the future.


## :closed_book: TERMINOLOGY

**MBSA** - Microsoft Baseline Security Analyzer - is a software tool that helps determine the security of your Windows computer based on Microsoft’s security recommendations.

**WAP** - Wireless Access Point – use 802.11 

**PKI** - Public Key Infrastructure - Encryption is typically done at the 6th layer of the OSI model (Presentation Layer), although it can be done on the application, session, transport, or network layers, each having its own advantages and disadvantages. Decryption is also handled at the presentation layer.

**HIPAA** - Health Insurance Portability and Accountability Act - It was created primarily to modernize the flow of healthcare information, stipulate how personally identifiable information maintained by the healthcare and healthcare insurance industries should be protected from fraud and theft.

**NIST** - NIST Special Publication 800-53 provides a catalog of security and privacy controls for all U.S. federal information systems except those related to national security. It develops and issues standards, guidelines, and other publications to assist federal agencies in implementing the Federal Information Security Modernization Act of 2014 (FISMA) and to help with managing cost-effective programs to protect their information and information systems.

**FISMA** - The Federal Information Security Management Act - The act requires each federal agency to develop, document, and implement an agency-wide program to provide information security. 

**ISO/IEC 27002** - is an information security standard published by the International Organization for Standardization (ISO) and by the International Electrotechnical Commission (IEC). It comes from the ISO 27000 serie. 

**COBIT** - Control Objectives for Information and Related Technologies - Created by ISACA (Information Systems Audit and Control Association). It defines a set of 
generic processes for the management of IT, with each process defined together with process inputs and outputs, key process-activities, process objectives, performance measures and an elementary maturity model.

**IANA** - The Internet Assigned Numbers Authority - This is a standards organization that oversees global IP address allocation, autonomous system number allocation, root zone management in the Domain Name System (DNS), media types, and other Internet Protocol-related symbols and Internet numbers.

**IETF** - The Internet Engineering Task Force - This is an open standards organization, which develops and promotes voluntary Internet standards, in particular the standards that comprise the Internet protocol suite (TCP/IP).

**SOAP** - Simple Object Access Protocol - A lightweight XML-based protocol that is used for the exchange of information in decentralized, distributed application environments. You can transmit SOAP messages in any way that the applications require, as long as both the client and the server use the same method.

**802.11a** - It operates in the 5 GHz band with a maximum net data rate of 54 Mbit/s, plus error correction code, which yields realistic net achievable throughput in the mid-20 Mbit/s. Published in 1999.

**802.11g** - works in the 2.4 GHz band (like 802.11b), but uses the same OFDM based transmission scheme as 802.11a. It operates at a maximum physical layer bit rate of 54 Mbit/s exclusive of forward error correction codes, or about 22 Mbit/s average throughput. Compatible with 802.11b. Published in 2003.

**802.11i** - Implemented as Wi-Fi Protected Access II (WPA2). This standard specifies security mechanisms for wireless networks, replacing the short Authentication and privacy clause. It deprecated broken Wired Equivalent Privacy (WEP). Published in 2004.

**802.11n** - It operates on both the 2.4 GHz and the 5 GHz bands. Support for 5 GHz bands is optional. Its net data rate ranges from 54 Mbit/s to 600 Mbit/s. Published in 2006.

**Quantum coin flipping** - It is used between two participants who do not trust each other. The participants communicate via a quantum channel and exchange information through the transmission of qubits.

**Vulnerability scans** - They check for vulnerabilities in your system and report potential exposures. It is automated.

**Boot Sector Virus** - It infects the boot sector of the hard disk or the Master Boot Record(MBR). Before starting any security program like your antivirus program, the boot sector virus runs to execute malicious code. The boot sector virus uses DOS commands while it infects at a BIOS level.

**Penetration tests** - They are intended to exploit weaknesses in the architecture of your IT network and determine the degree to which a malicious attacker can gain unauthorized access to your assets. It is done manually.

**anomaly-based IDS** - An anomaly-based intrusion detection system is an intrusion detection system for detecting both network and computer intrusions and misuse by monitoring system activity and classifying it as either normal or anomalous. The classification is based on heuristics or rules, rather than patterns or signatures.

**signature-based IDS** - It monitors inbound network traffic to find sequences and patterns that match a particular attack signature.

**RSA** - (Rivest–Shamir–Adleman) It is a public-key cryptosystem that is widely used for secure data transmission. An RSA user creates and publishes a public key based on two large prime numbers, along with an auxiliary value. The prime numbers are kept secret. Messages can be encrypted by anyone, via the public key, but can only be decoded by someone who knows the prime numbers.

**MD5** - It is a widely used hash function producing a 128-bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption.

**SHA-1** - (Secure Hash Algorithm 1) It is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value known as a message digest – typically rendered as a hexadecimal number, 40 digits long.

**RC5** - (Rivest Cipher) It is a symmetric-key block cipher notable for its simplicity. The Advanced Encryption Standard (AES) candidate RC6 was based on RC5.

**IRC** - Internet Relay Chat - It is an application layer protocol that facilitates communication in text. The chat process works on a client/server networking model.

**IPsec** - Internet Protocol Security - It is a secure network protocol suite that authenticates and encrypts the packets of data to provide secure encrypted communication between two computers over an Internet Protocol network. It is used in virtual private networks (VPNs). It works on the network layer. 

**PPP** - Point-to-Point Protocol - It is a Data link layer (layer 2) communications protocol between two routers directly without any host or any other networking in between. It can provide connection authentication, transmission encryption, and compression.

**PEM** - Privacy-Enhanced Mail - It is a file format for storing and sending cryptographic keys, certificates, and other data.  While the original standards were never broadly adopted, and were supplanted by PGP and S/MIME, the textual encoding they defined became very popular. The PEM format was eventually formalized by the IETF in RFC 7468.

**SET** - Secure Electronic Transaction - It is a communications protocol standard for securing credit card transactions over networks, specifically, the Internet. It is a set of security protocols and formats that enabled users to employ the existing credit card payment infrastructure on an open network in a secure fashion. However, it failed to gain attraction in the market. Visa now promotes the 3-D Secure scheme.

**PCI-DSS** - Payment Card Industry Data Security Standard - It is an information security standard for organizations that handle branded credit cards from the major card schemes.

### IoT

    - The first layer consists of Sensor-connected IOT devices: These are the small, memory-constrained, often battery-operated electronics devices with onboard sensors and actuators. They must sense and record data, perform light computing and being able to connect to a network and communicate the data.
    - The second layer consists of IOT gateway devices: Layer 1 need to be connected to the internet via a more powerful computing device called the IOT gateway. It aggregates data from numerous sensing devices and relays it to the cloud. They must be equipped with multiple communication capabilities like Bluetooth, Zigbee, LoRa WAN, Sub-GHz proprietary protocols.
    - The third layer is the Cloud: All the sensor data relayed by IOT gateways is stored on cloud hosted servers. These servers accept, store and process data for analysis and decision making. This layer also enables creation of live dashboards which decision makers can monitor and take proactive data driven decisions
    - The forth layer is IOT Analytics: The collected raw data is converted into actionable business insights, which can help improve business operations, efficiency or even predict future events like machine failure.

## :bulb: MANAGEMENT

**AV** - Asset value - The cost of the hardware and the person who repair it (and the time to fix).

**EF** - Exposure factore - The impact of the risk over the asset, or percentage of asset lost.

**SLE** - Single Loss Expectancy - AV * EF

**ARO** - Annual rate of occurrence - The expected value (cost) of a yearly occurrence of incidents of given type (e.g. the chance of a HW to have a failure).

**ALE** - Annual Loss Expectancy = SLE * ARO

**Risk mitigation** - It can be defined as taking steps to reduce adverse effects. There are four types of risk mitigation strategies that hold unique to Business Continuity and Disaster Recovery.

    - Risk Acceptance: This strategy is a common option when the cost of other risk management options such as avoidance or limitation may outweigh the cost of the risk itself.
    - Risk Avoidance: It the opposite of risk acceptance. It is the action that avoids any exposure to the risk whatsoever. It the most expensive choice.
    - Risk Limitation: This strategy limits a company’s exposure by taking some action. It is a strategy employing a bit of risk acceptance and a bit of risk avoidance or an average of both.
    - Risk Transference: It is the involvement of handing risk off to a willing third party.
