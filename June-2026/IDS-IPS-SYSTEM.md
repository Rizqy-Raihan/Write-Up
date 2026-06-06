# Network monitoring using suricata integrated with wazuh

## Overview 

This project demonstrates the implementation of network
monitoring using suricata as an IDS and IPS system. Integrated
with wazuh for centralized log management and real time alert
visualization.

---

## Goals
 - Detect threats in real-time
 - Automate alert processing
 - Support for ids/ips deployment

 ---

 ## Architecture

 ```text
Suricata →  Wazuh manager →  Wazuh dashboard
 ```
 ## Requirements

 - Windows as a attack machine
 - Ubuntu 22 LTS as a server 
 - Wazuh server 
 - Docker 
 - Nmap

---


 ## Project Structure

 ```text
 project-root/
├── wazuh-server/
│   ├── ossec.conf
│   
│
├── suricata/
    ├── suricata.yaml
    └── /var/lib/suricata/rules/local.rules/ 
 ```
 
---


## **Workflow Explanation**
**<img width="576" height="457" alt="the diagram" src="https://github.com/user-attachments/assets/20db423f-d133-4176-8796-d4d073a538e1" />**

On those topology, the windows machine acts as the attacker by performing
ping test and ip address scanning againts the ubuntu server.

Suricata running on the ubuntu server captures and analyzes the suspicious 
network activities generated from the windows machine, including icmp ping
requests and port scanning attempts. the detected events are recorded in 
the `eve.json` log file.

The `eve.json` file is then forwarded through docker integration to the wazuh
server for centralized monitoring and alert visualization. this allows security
analysts to monitor, investigate, and analyze the network activities detected 
by suricata in real time through the wazuh dashboard.

---

## Installation Guide

### Windows side 

Perform the following steps to configure the Windows machine as the attacker host for generating network traffic and security events to be detected by Suricata and monitored by Wazuh.

1. Nmap Installation
   Installing nmap for scanning network activity like
   - port scanning 
   - securrity auditing 
   - vulnerability scanning
  
   Official Microsoft Sysinternals link
   `https://nmap.org/download.html#windows`
 
   Following installation instruction

   verify installation in command prompt
   `nmap --version`
---


### Ubuntu 22 LTS as server side

1. install and Configuration Suricata
 
   install repository suricata
   `sudo add-apt-repository ppa:oisf/suricata-stable`

   install suricata using apt 
   `sudo apt install suricata`

   enable suricata service
   `sudo systemctl enable suricata.service`

   start suricata service 
   `sudo systemctl start suricata.service`

   check status suricata service 
   `sudo systemctl status suricata.service`

   configuration IDS and IPS system on suricata.yaml
   `sudo nano /etc/suricata/suricata.yaml`

   Edit the Network Configuration on Line `vars`
   HOME_NET: [CHANGING THIS LINE TO YOUR NETWORK/SUBNET]"

   **<img width="583" height="387" alt="image" src="https://github.com/user-attachments/assets/410dc633-42e0-4f46-8cc9-6a3745e1264f" />**

    adding local.rules for trigger alert ids system on `rules-file` line
   - local.rules
  
   **<img width="411" height="349" alt="image" src="https://github.com/user-attachments/assets/3b053b57-193e-4df0-8caa-34f1578f33b2" />**

   
   changing id of `cluster-id`
   cluster-id: (changing this number which is more than the 98)

   changing interfaces network suricata to your ubuntu interfaces in `af-packet` line
   - interfaces: (changing this line)
  
  **<img width="688" height="140" alt="image" src="https://github.com/user-attachments/assets/9bc69ab8-8777-4a46-901f-c10e71a3cbe7" />** 

  save and exit the suricata.yaml

  ---

  Add rules of local.rules for trigger alert
  `sudo nano /var/lib/suricata/rules/local.rules`

  ```bash
  alert http any any -> any any (msg:"Potential secret accessed"; content:"secret"; nocase; sid:1000001; rev:1;)
  alert icmp any any -> $HOME_NET any (msg:"PING DETECTED"; sid:9000001; rev:1;)                                                                                         
  alert tcp any any -> $HOME_NET any (msg:"NMAP SYN"; flags:S; sid:9000002; rev:1;)
  ```
 
  **<img width="948" height="167" alt="image" src="https://github.com/user-attachments/assets/38454267-9b02-4927-9f1c-25f36bae7e1a" />**

 running suricata configuration that enabling running on your interface ubuntu
 `sudo suricata -c /etc/suricata/suricata.yaml -i <your interface>`



2. isntall repo docker, wazuh server

install script quickly docker, just copy paste the code in the text editor
`wget https://github.com/Atlantium-AI/wazuh-n8n-lab-setup/blob/main/install-docker.sh`

running bash cript docker installation
`sudo chmod +x install-docker.sh && sudo ./install-docker.sh`

check docker installation
`docker --version`
  
goes to directory single-node
`cd single-node`
 
configuration docker-compose.yml to adding eve.json
`/var/log/suricata:/var/log/suricata:ro` 
  
running installation wazuh server
`docker compose -d -vvv`


Configuration ossec.conf the wazuh server for reading the eve.json   
Add this line on the below `<!-- Log analysis -->`  line

  ```bash
      <localfile>                                                                       
         <log_format>json</log_format>                                                     
         <location>/var/log/suricata/eve.json</location>                                   
      </localfile> 
                                                                                                                                                        
    <localfile>                                                                          
       <log_format>syslog</log_format>                                                    
       <location>/var/log/suricata/fast.log</location>                                  
    </localfile>
 ```

**<img width="555" height="285" alt="image" src="https://github.com/user-attachments/assets/d84c8d53-b9b6-4196-a144-240fdf769c34" />**

Save and restart the wazuh server

3. Lets to Test the IDS and IPS System 

open command prompt on the windows
nmap -sS <ip address of the server>
   
or ping the ip address
ping <ip address of the server>
   
looking on web app wazuh in discover menu
if the alert discovering thats mean your confuguration successfully!!!

 
  
   
  

   

   

