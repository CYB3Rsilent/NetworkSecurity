<h2></h2>
According to SANS Institute:  
 
   _"Network Security is the process of taking physical and software preventative measures to protect the underlying networking infrastructure from unauthorized access, misuse, malfunction, modification, destruction, or improper disclosure, thereby creating a secure platform for computers, users and programs to perform their permitted critical functions within a secure environment."_ - [SANS Network Security Resources](https://www.sans.org/network-security)

## Network Security
#### Security Control Types
The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set  of defense tactics.
1. Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?
    - Answer: Physical Security Controls
2. Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?
    - Answer: Management Security Controls
3. Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?
    - Answer: Data Protections Access Controls
#### Intrusion Detection and Attack indicators
1. What's the difference between an IDS and an IPS?
    - Answer: Intrusion Detection Systems (IDS): Network traffic is monitored and analyzed for signs that would indicate malicious actors are using known threats to compromise or steal the data from a given network. IDS systems compare the current network activity to a known threat database to detect several kinds of behaviors like security policy violations, malware, and port scanners. 
Intrusion Prevention Systems (IPS): live in the same area of the network as a firewall, between the outside world and the internal network. IPS proactively deny network traffic based on a security profile if that packet represents a known security threat. 
2. What's the difference between an Indicator of Attack and an Indicator of Compromise?
   - Answer: An IOC is often described in the forensics world as evidence on a computer that indicates that the security of the network has been breached. Unlike Indicators of Compromise (IOCs) used by legacy 
endpoint detection solutions, indicators of attack (IOA) focus on detecting the intent of what 
an attacker is trying to accomplish, regardless of the malware or exploit used in an attack. Just like 
AV signatures, an IOC-based detection approach cannot detect the increasing threats from malware-free 
intrusions and zero-day exploits. As a result, next-generation security solutions are moving to an IOA-
based approach pioneered by CrowdStrike. 

#### The Cyber Kill Chain
Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.
1. Stage 1: Reconnaissance - Port scanning is an example of active reconnaissance
2. Stage 2: Weaponization - Attackers consider the information gained from the reconnaissance phase and begin collecting and developing tools to exploit it. This can include the generation of malware or configuring existing malware through public or private channels and configuring it to address specific vulnerabilities in a prospective victim’s environment.
3. Stage 3: Delivery - Delivery can take many forms including but not limited to phishing email, social engineering, or even hacking into an organization’s network and exploiting a hardware or software vulnerability to infiltrate it.  
4. Stage 4: Exploitation - At the exploitation stage, attackers will seek other victim vulnerabilities that they did not know before entering. For instance, an attacker might not have privileged access to an organization’s database from outside; however, they might spot vulnerabilities in the database that allows them to gain entry after an intrusion.   
5. Stage 5: Installation - At the privilege escalation stage, the attacker attempts to gain the additional privilege to more accounts and systems. The attacker might decide to use brute force, or on the alternative, he might seek out unprotected repositories containing security credentials or monitor networks without encryption to track the credentials. He might as well consider changing permissions on previously existing compromised accounts. When he has the credentials he needs, the attacker then proceeds to other systems to find the most valuable assets of his target. Attackers typically move from one system to the other, seeking access to privileged accounts, sensitive data. This is usually a coordinated attack and usually affects several user accounts and IT systems. 
6. Stage 6: Command and Control (C2) - Now that the attacker has gained control of a significant part of the victim’s systems and user accounts and privileges, he will now develop a command control channel to operate and monitor his attack remotely. This stage will involve obfuscation and denial of service. Obfuscation is when the attacker tries to cover his tracks, making it look like nothing has happened. Examples of activities in the obfuscation stage include
	Binary padding
	Code signing
	File deletion
	Hidden users
	Process hollowing
After obfuscation, denial of service will then take place, which is the opposite of obfuscation. The attacker who has been keeping a low profile will not decide to cause issues in the systems to announce their presence. This is usually to distract the attention of the security teams so he can perpetuate his fundamental objectives. The following are examples of attacks at the Denial-of-Service stage:
	System shutdown
	Service stop
	Resource hijacking
	Network denial of service
	Endpoint denial of service
7. Stage 7: Actions on Objectives - Examples of attacks at this last stage of CKC include:
	Data Exfiltration over alternative protocol
	Data Exfiltration over a physical medium
	Data encrypted
	Data compressed
### Snort Rule Analysis
Use the Snort rule to answer the following questions:
Snort Rule #1
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
```
1. Break down the Sort Rule header and explain what is happening.
   - Answer: alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 . It scanning ET SCAN Potential VNC Scan 5800-5820"
2. What stage of the Cyber Kill Chain does this alert violate?
   - Answer: Weaponization
3. What kind of attack is indicated?
   - Answer: Emerging threat were founds.
Snort Rule #2
```bash
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
```
1. Break down the Sort Rule header and explain what is happening.
   - Answer: alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any. It download dll file from http
2. What layer of the Defense in Depth model does this alert violate?
   - Answer: It show a layer of Defense if ET POLICY PE EXE not working then DLL Windows file download from HTTP
3. What kind of attack is indicated?
   - Answer: DDos attack
Snort Rule #3
- Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the `msg` in the Rule Option.
    Answer: alert tcp any any -> any [444] ( msg:"Sample alert"; sid:1000001; rev:1; )
### Part 2: "Drop Zone" Lab
#### Log into the Azure `firewalld` machine
Log in using the following credentials:
- Username: `sysadmin`
- Password: `cybersecurity`
#### Uninstall `ufw`
Before getting started, you should verify that you do not have any instances of `ufw` running. This will avoid conflicts with your `firewalld` service. This also ensures that `firewalld` will be your default firewall.
- Run the command that removes any running instance of `ufw`.
    ```bash
    $ sudo apt remove ufw
    ```
#### Enable and start `firewalld`
By default, these services should be running. If not, then run the following commands:
- Run the commands that enable and start `firewalld` upon boots and reboots.
    ```bash
    $ sudo sytemctl enable firewalld
    $ sudo systemctl start firewalld
    ```
  Note: This will ensure that `firewalld` remains active after each reboot.
#### Confirm that the service is running.
- Run the command that checks whether or not the `firewalld` service is up and running.
    ```bash
    $ sudo firewall-cmd --state
    ```
#### List all firewall rules currently configured.
Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.
- Run the command that lists all currently configured firewall rules:
    ```bash
    $ sudo firewall-cmd --list-all
    ```
- Take note of what Zones and settings are configured. You many need to remove unneeded services and settings.
#### List all supported service types that can be enabled.
- Run the command that lists all currently supported services to see if the service you need is available
    ```bash
    $ sudo firewall-cmd --get-services
    ```
- We can see that the `Home` and `Drop` Zones are created by default.
#### Zone Views
- Run the command that lists all currently configured zones.
    ```bash
    $ sudo firewall-cmd --list-all-zones
    ```
- We can see that the `Public` and `Drop` Zones are created by default. Therefore, we will need to create Zones for `Web`, `Sales`, and `Mail`.
#### Create Zones for `Web`, `Sales` and `Mail`.
- Run the commands that creates Web, Sales and Mail zones.
    ```bash
    $ sudo firewalld-cmd --permanent --new-zone=Web
    $ sudo firewalld-cmd --permanent --new-zone=Sales
    $ sudo firewalld-cmd --permanent --new-zone=Mail
    ```
#### Set the zones to their designated interfaces:
- Run the commands that sets your `eth` interfaces to your zones.
    ```bash
    $ sudo firewall-cmd --zone=public --change-interface=eth0
    $ sudo firewall-cmd --zone=web --change-interface=eth1
    $ sudo firewall-cmd --zone=sales --change-interface=eth2
    $ sudo firewall-cmd --zone=mail --change-interface=eth3
    ```
#### Add services to the active zones:
- Run the commands that add services to the **public** zone, the **web** zone, the **sales** zone, and the **mail** zone.
- Public:
    ```bash
    $ sudo firewall-cmd --zone=public --add-service=http
    $ sudo firewall-cmd --zone=public --add-service=https
    $ sudo firewall-cmd --zone=public --add-service=pop3
    $ sudo firewall-cmd --zone=public --add-service=smtp
    ```
- Web:
    ```bash
    $ udo firewall-cmd --zone=Web --add-service=http
    ```
- Sales
    ```bash
    $ sudo firewall-cmd --zone=Sales --add-service=https
    ```
- Mail
    ```bash
    $ sudo firewall-cmd --zone=Mail --add-service=smtp
    $ sudo firewall-cmd --zone=Mail --add-service=pop3
    ```
- What is the status of `http`, `https`, `smtp` and `pop3`?
#### Add your adversaries to the Drop Zone.
- Run the command that will add all current and any future blacklisted IPs to the Drop Zone.
     ```bash
    $ sudo firewall-cmd --permanent --zone=drop --add-source=10.208.56.23
    $ sudo firewall-cmd --permanent --zone=drop --add-source=135.95.103.76
    $ sudo firewall-cmd --permanent --zone=drop --add-source=76.34.169.118
    ```
#### Make rules permanent then reload them:
It's good practice to ensure that your `firewalld` installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures.
- Run the command that reloads the `firewalld` configurations and writes it to memory
    ```bash
    $ sudo firewall-cmd--reload
    ```
#### View active Zones
Now, we'll want to provide truncated listings of all currently **active** zones. This a good time to verify your zone settings.
- Run the command that displays all zone services.
    ```bash
    $ sudo firewall-cmd --get-active-zones
    ```
#### Block an IP address
- Use a rich-rule that blocks the IP address `138.138.0.3`.
    ```bash
    $ sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject'
    ```
#### Block Ping/ICMP Requests
Harden your network against `ping` scans by blocking `icmp ehco` replies.
- Run the command that blocks `pings` and `icmp` requests in your `public` zone.
    ```bash
    $ sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request
    ```
#### Rule Check
Now that you've set up your brand new `firewalld` installation, it's time to verify that all of the settings have taken effect.
- Run the command that lists all  of the rule settings. Do one command at a time for each zone.
    ```bash
    $ sudo firewall-cmd --zone=public --list-all
    $ sudo firewall-cmd --zone=sales --list-all
    $ sudo firewall-cmd --zone=mail --list-all
    $ sudo firewall-cmd --zone=web --list-all
    $ sudo firewall-cmd --permanent --zone=drop --list-all
    ```
- Are all of our rules in place? If not, then go back and make the necessary modifications before checking again.

Congratulations! You have successfully configured and deployed a fully comprehensive `firewalld` installation.
---
### Part 3: IDS, IPS, DiD and Firewalls
Now, we will work in another lab. Before you start, complete the following review questions.
#### IDS vs. IPS Systems
1. Name and define two ways an IDS connects to a network.
   - Answer 1: Network Intrusion Detection Systems (NIDS)
   - Answer 2: Host-based Intrusion Detection Systems (HIDS)
2. Describe how an IPS connects to a network.
   - Answer: Perimeter
3. What type of IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks?
   - Answer: Signature Type
4. Which type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?
   - Answer:  Anomaly-based Detection
#### Defense in Depth
1. For each of the following scenarios, provide the layer of Defense in Depth that applies:
    a.  A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.
       - Answer: Physical Control
    b. A zero-day goes undetected by antivirus software.
       - Answer: Application
    c. A criminal successfully gains access to HR’s database.
       - Answer: Data
    d. A criminal hacker exploits a vulnerability within an operating system.
       - Answer: Host
    e. A hacktivist organization successfully performs a DDoS attack, taking down a government website.
       - Answer: Network
    f. Data is classified at the wrong classification level.
       - Answer: Policy, procedures, & awareness
   g. A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.
       - Answer: Perimeter
2. Name one method of protecting data-at-rest from being readable on hard drive.
   - Answer: Encryption
3. Name one method to protect data-in-transit.
   - Answer: VPN (Virtual Private Network)
4. What technology could provide law enforcement with the ability to track and recover a stolen laptop.
   - Answer: GPS or Wifi Geolocation 
5. How could you prevent an attacker from booting a stolen laptop using an external hard drive?
   - Answer: Encrypted password
#### Firewall Architectures and Methodologies
1. Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.
  - Answer: Circuit level proxy
2. Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time.
  - Answer: Stateful packet filter
3. Which type of firewall intercepts all traffic prior to being forwarded to its final destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it?
  - Answer: Application of proxy
4. Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents?
  - Answer: Packet-filtering
5. Which type of firewall filters based solely on source and destination MAC address?
  - Answer: MAC Layer Firewalls


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
