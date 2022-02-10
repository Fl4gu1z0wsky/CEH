#  :globe_with_meridians: :computer: :closed_lock_with_key: CEH - Knowledges
CEH certification :milky_way:

This repository is here to help pass the CEH. Not everything is here, but it based on my knowledges and what I needed to improve to pass the certification.
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
  
**Tcpdump** – wireshark but for CLI (no graphic)

**Nessus** – scan automatically vulnerabilities in a network


## :warning: ATTACKS

**SQL injection**
  
 **Tautology** – use of a conditional OR clause in order to have a query always TRUE.
(select * from user_details where userid = 'abcd' and password = 'anything' or 'x'='x')
  
**Error-based** - insert malicious query in input fields and get some error which is regarding SQL syntax or database.
  
**Union** - the UNION keyword can be used to retrieve data from other tables within the database.
(SELECT a, b FROM table1 UNION SELECT c, d FROM table2)

**End-of-Line Comment** - the code is nullified with a end of line comments.
(SELECT * FROM user WHERE name = 'x' AND userid IS NULL; --';)

**IDLE/IPID Scanning** - We use a zombie to send a SYN/ACK packet and it increments it's IPID while sending a reset. We do the same for another PC but we change the source for the zombie. We do that again to the zombie and if the IPID has been incremented 2 times, it means the port is open.

**SSDP Scanning** - (Simple Service Discovery Protocol) is the basis of the discovery protocol of Universal Plug and Play (UPnP) and is intended for use in residential or small office environments.

**UDP Scanning** - send a UDP packet to various ports on the target host. We use it with nmap to scan UDP ports (the same as TCP ports).

**Email spoofing** - the fabrication of an email header in the hopes of duping the recipient into thinking the email originated from someone or somewhere other than the intended source.

**Email Masquerading** - the perpetrator assumes the identity of a fellow network user or co-employee to trick victims into providing user credentials. On the contrary of email spoofing, this is done from inside the network from a stolen account.

**Email Harvesting** - the process of obtaining lists of email addresses.

**Email Phishing** - a type of social engineering attack often used to steal user data, including login credentials and credit card numbers.

**Traffic redirection** - the attacker modifies traffic in transit or sniff packets.

**Traffic sent to a routing black hole** - the traffic can be redirected to null0 and can kick an IP.

**Unauthorized route prefix origination** - It introduces a new prefix into the routing table. Used to get a covert attack network to be routable throughout the victim network.

**reconnaissance stage** - a set of processes and techniques (Footprinting, Scanning & Enumeration) to discover and collect information about a target system covertly. There is passive and active recon. passive is just sniffing (not interacting directly with the network) while active is for example scanning ports.


## :lock: SECURITY

**MAC filtering** – listing of allowed devices that you need on your Wi-Fi. Helps preventing unwanted access to the network.

**Router**

    Counter methods:
    - Configuration modification : We must secure the router and the supporting system it makes use of, such as TFTP servers (used to upgrade several routers that   
    are separated from the TFTP server by slow WAN connections).
    - Introduction of a rogue router that : The other routing devices must trust the send information. We can block it by adding message authentication to the routing   
    protocol. And we can also add ACLs to block routing protocol messages unwanted.
    - Spoofing a valid routing protocol message or modifying a valid message in transit. We can prevent it with message authentication as well. And if we have a transport    
    layer protocol like TCP for BGP, it can render the task difficult due to the pseudo-random initial sequence numbers.
    - Sending of malformed or excess packets. Excess packets can be stopped with DoS mitigation techniques. Malformed packets are harder to identify. This is     
    an area of computer security that needs increased attention, not just in routing protocols but in all network applications.
        

## :floppy_disk: PROTOCOLS

**Telnet** – use TCP - does not encrypt, no authentication, several vulnerabilities.

## :closed_book: TERMINOLOGY

**MBSA** - Microsoft Baseline Security Analyzer - is a software tool that helps determine the security of your Windows computer based on Microsoft’s security recommendations.

**WAP** - Wireless Access Point – use 802.11 

**Banner Grabbing** -  technique used to gain information about a computer system on a network and the services running on its open ports. We often use nmap for this and those services : HTTP (80), FTP (21) or SMTP (25).

