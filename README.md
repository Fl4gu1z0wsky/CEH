#  :globe_with_meridians: :computer: :closed_lock_with_key: CEH - Knowledges
CEH certification :milky_way:

This repository is here to help pass the CEH. Not everything is here, but it based on my knowledges and what I needed to improve to pass the certification.
The terminology and the information are from :
- Udemy: CEH v11 312-50: Certified Ethical Hacker Practice Exams. NEW (Good questions and answers well explained)
- EC Council iClass: Certified Ethical Hacker (CEH v11) online course

## :wrench: TOOLS

**Nmap** – to scan open port (old name was Ethereal)
-F (Fast (limited port) scan). It scans normally 1000 most common port but here it is reduced to 100.
  
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

## :lock: SECURITY

**MAC filtering** – listing of allowed devices that you need on your Wi-Fi. Helps preventing unwanted access to the network.

## :floppy_disk: PROTOCOLS

**Telnet** – use TCP - does not encrypt, no authentication, several vulnerabilities.

## :closed_book: TERMINOLOGY

**MBSA** - Microsoft Baseline Security Analyzer - is a software tool that helps determine the security of your Windows computer based on Microsoft’s security recommendations.

**WAP** - Wireless Access Point – use 802.11 

