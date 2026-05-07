# How to Integrate Wazuh with n8n for SIEM System

---

## Overview

This project focuses on building a SIEM system using wazuh integrated by virustotal api key and
n8n for automate alert processing and send notifications
in real-time. The purpose of this project is to enhance security monitoring 
and reduce manual analysis by automating workflows.

---

## Goals

- Detect threats in real-time
- Automate alert processing
- Integrate VirusTotal for malware analysis
- Send notifications to Discord

---

## Architecture

```text
Wazuh Agent → Wazuh Manager → Wazuh API → n8n Workflow → Discord Webhook
```

---

## Requirements

| No | Component | Description |
|----|------------|-------------|
| 1 | Wazuh Agent | Collect logs and events from endpoints |
| 2 | Sysmon | Windows system monitoring tool |
| 3 | Docker | Container platform for deployment |
| 4 | Wazuh Server | Centralized SIEM server |
| 5 | VirusTotal API | Malware and hash analysis |
| 6 | Python Script | threat automation script |
| 7 | n8n | Workflow automation platform |
| 8 | HTTP Request Node | Send API requests in n8n |
| 9 | JavaScript Node | Process alert data in n8n |
| 10 | Discord Webhook URL | Send notifications to Discord |
| 11 | Discord Direct Message Node | Send direct alerts/messages |

---

## Project Structure

```text
server-side/
├── wazuh-server/
│   ├── ossec.conf
│   └── local_rules.xml
│

endpoint
├── wazuh-agents/
│   ├── ossec.conf
│   └── automation-script/
│       └── automation-py.exe
```

---

# **Workflow Explanation**

**<img width="1024" height="1024" alt="Diagram" src="https://github.com/user-attachments/assets/c1be253a-5948-4628-8ff8-383e688550e0" />**

In this system, wazuh acts as the main detection engine that captures
seccurity alers from monitored endpoints. Once an alert is generated,
the wazuh API indexer is used to retrieve and forward the alert data 
to n8n through an HTTP reques node. The n8n workflow then processes
and filtres the incoming alert information as needed. Finally, the processed
alert is delivered to discord channing using the Discord node, allowing
real-time notifications and faster incdent response.
---



# **Installation guide**
### Configure the windows endpoint using the following steps for this  SIEM Project


## 1. Sysmon Installation

Install Sysmon to retrieve system activities such as:

- Process Creation
- File Changes
- Network Connections

### Official Microsoft Sysinternals Link to Install

```bash
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
```
### Create Configuration File

Sysmon requires an XML configuration file to define which system events should be collected and written to the Windows Event Log.
In this project, the Sysmon configuration file from SwiftOnSecurity is used to provide high-quality default event tracing and comprehensive system activity monitoring.

This configuration serves as a strong starting point for monitoring system changes in a self-contained, accessible, and well-maintained package.

```bash
https://github.com/SwiftOnSecurity/sysmon-config/archive/refs/heads/master.zip
````
Apply the sysmonconfig-export.xml configuration file to Sysmon using Command Prompt with Administrator privileges.

```bash
sysmon.exe -accepteula -i sysmonconfig-export.xml
```
## 2. Wazuh agent Installation
**Replace `<ip wazuh-server>` and `<agent-name>` with your actual server IP address and Wazuh agent name in  your Powershell (run as administrator)**

```bash
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='<ip wazuh-server>' WAZUH_AGENT_NAME='<agent-name>
```   
## 3.  Integration sysmon to wazuh agent
Add the following configuration to ossec.conf to enable Wazuh Agent to collect Sysmon event logs from the Windows Event Channel.

```XML
   <localfile>
     <log_format>eventchannel</log_format>
     <location>Microsoft-Windows-Sysmon/Operational</location>
   </localfile>
```

Replace the `eventchannel` configuration above under the `<!-- Agent buffer options -->` section in the ossec.conf file, as shown in the image below.

**<img width="568" height="323" alt="log event" src="https://github.com/user-attachments/assets/3fd666b7-685b-425e-9a5b-d5e816d8e205" />**

## 4. File integrity Monitoring (FIM)
Add the following configuration to monitor important files and activities inside the Windows directory in ossec.conf.

Locate this line 
**`<directories recursion_level="0" restrict="regedit.exe$|system.ini$|win.ini$">%WINDIR%</directories>`**

Replace it with the following configuration in ossec.conf:

**NOTE**: Change `(YOUR DIRECTORY)` with the actual directory for the monitoring
```XML
<scan_on_start>yes</scan_on_start>
<alert_new_files>yes</alert_new_files>

<directories check_all="yes" realtime="yes" report_changes="yes" recursion_level="0">(YOUR DIRECTORY)</directories>

<directories check_all="yes" realtime="yes" report_changes="yes">(YOUR DIRECTORY)</directories>
```

**<img width="1155" height="203" alt="file monitored" src="https://github.com/user-attachments/assets/57c6acc6-60df-40d7-a19d-1a4ac5a07080" />**

## 5. Perform Optimize
Increase the event processing capacity by modifying the following configuration in ossec.conf:

Locate this line:
`<max_eps>50</max_eps>`

Replace with this code 
```XML
<max_eps>100</max_eps>
```

**<img width="611" height="194" alt="MAXIMUM OUTPUT" src="https://github.com/user-attachments/assets/9c0eab66-1919-4531-8e99-da31ca02cd01" />**

## 6. Create active response script automation.py 
> **Warning**  > This script is a proof of concept (PoC). Review and validate it to ensure it meets the operational and security requirements of your environment.

```PYTHON
# Copyright (C) 2015-2025, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime
import stat
import tempfile
import pathlib

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    msg_obj = message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg_obj.command = OS_INVALID
        return msg_obj

    msg_obj.alert = data
    command = data.get("command")

    if command == "add":
        msg_obj.command = ADD_COMMAND
    elif command == "delete":
        msg_obj.command = DELETE_COMMAND
    else:
        msg_obj.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return msg_obj

def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})
    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND
    else:
        write_debug_file(argv[0], "Invalid value of 'command'")
        return OS_INVALID

def secure_delete_file(filepath_str, ar_name):
    filepath = pathlib.Path(filepath_str)

    # Reject NTFS alternate data streams
    if '::' in filepath_str:
        raise Exception(f"Refusing to delete ADS or NTFS stream: {filepath_str}")

    # Reject symbolic links and reparse points
    if os.path.islink(filepath):
        raise Exception(f"Refusing to delete symbolic link: {filepath}")

    attrs = os.lstat(filepath).st_file_attributes
    if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise Exception(f"Refusing to delete reparse point: {filepath}")

    resolved_filepath = filepath.resolve()

    # Ensure it's a regular file
    if not resolved_filepath.is_file():
        raise Exception(f"Target is not a regular file: {resolved_filepath}")

  # Perform deletion
    os.remove(resolved_filepath)

def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]
        action = send_keys_and_check_message(argv, keys)

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        try:
            file_path = alert["data"]["virustotal"]["source"]["file"]
            if os.path.exists(file_path):
                secure_delete_file(file_path, argv[0])
                write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
            else:
                write_debug_file(argv[0], f"File does not exist: {file_path}")
        except OSError as error:
            write_debug_file(argv[0], json.dumps(msg.alert) + "Error removing threat")
        except Exception as e:
            write_debug_file(argv[0], f"{json.dumps(msg.alert)}: Error removing threat: {str(e)}")
    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
```

source
- [**automation.py**](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)

### convert active response automation.py into exe file in powershell (run as administrator)

```bash
pyinstaller -F \path_to_automation.py
```

### move automation.exe to the `C:\Program Files (x86)\ossec-agent\active-response\bin` directory

```bash
restart wazuh agent to apply the changes in powershell (run as administrator)
```

### Restart Wazuh agent
Restart the Wazuh Agent to apply the deployed configuration changes

### Ubuntu 22.04 LTS as Server Side
Install and configure the Wazuh Server on your server machine to allow the Wazuh Manager to receive alert data from Wazuh Agents and display it through the Wazuh Dashboard.

## 1. isntall repo docker, wazuh server and n8n
Install Docker, Wazuh Server, and n8n quickly using the installation script from the following repository:

```bash
git clone https://github.com/Atlantium-AI/wazuh-n8n-lab-setup.git
```

### Navigate to the wazuh-n8n-lab-setup directory
Navigate to the wazuh-n8n-lab-setup project directory to access the installation and configuration files.

```bash
cd wazuh-n8n-lab-setup
```

### running docker installation bash script using sudo
Run the Docker installation bash script using sudo privileges.

```bash
sudo ./install-docker.sh
```

### check docker installation using sudo
Verify the Docker installation using sudo

```bash
sudo docker --version
```

###  running bash script installation docker container wazuh server and n8n using sudo
Run the bash installation script to deploy the Docker containers for the Wazuh Server and n8n using sudo.

```bash
 sudo ./docker-spin-up.sh
 ```

 ### remove the n8n docker container
 After the installation is completed successfully, remove the n8n Docker container to modify the secure cookie and DNS configuration inside the docker-compose.yml file.

 ```bash
 cd n8n-docker
 ```

 ```bash
 sudo nano docker-compose.yml
 ```

replace it with these lines (copy-paste)

```yaml

version: "3.9"

services:
  n8n:
    image: n8nio/n8n
    restart: always
    ports:
      - "5678:5678"
    environment:
      - GENERIC_TIMEZONE=UTC
      - N8N_SECURE_COOKIE=false
    volumes:
      - n8n_data:/home/node/.n8n
    dns:
      - 8.8.8.8
    networks:
      - soc-net

volumes:
  n8n_data:

networks:
  soc-net:
    external: true
```
after exit in docker-compose.yml, running this script for installing n8n docker container using sudo

```bash
sudo docker-compose up -d
```

### Check docker container running to verify 
Check the running Docker containers to verify that all services are running properly.

```bash
docker ps -a
```

**<img width="1372" height="244" alt="docker" src="https://github.com/user-attachments/assets/8572205b-7e01-4321-bfb8-f9560f2e3f60" />**


After all Docker containers are successfully installed, open your browser to access the Wazuh Server.

It is recommended to use a browser on a Windows machine and access the Wazuh Dashboard using:

`https://<windows-ip>:9200`

**<img width="696" height="563" alt="wazuh" src="https://github.com/user-attachments/assets/9b9d6b65-3e4f-46a2-bc99-f0d344135d4d" />**

input **username:password** `(admin:SecretPassword)`

## 2. Configure VirusTotal Integration and Python Script in ossec.conf

Configure the VirusTotal integration and Python script through the Wazuh web interface to allow the Wazuh Manager to automatically detect and analyze alerts generated by Wazuh Agent endpoints.

Navigate to:

```text
Open wazuh sidebar - settings menu - edit configuration
```

**<img width="1352" height="416" alt="manager configuration of ossec conf" src="https://github.com/user-attachments/assets/ebc7176f-49cf-46fd-b1df-f688d015ffd0" />**

### Copy-paste the code
Append with these in above `</ossec_config>` line (copy-paste)

**NOTE**: Replace `(your virustotal apikey)` with the actual virustotal api key

```conf
<!-- VirusTotal Integration -->
  <integration>
    <name>virustotal</name>
    <api_key>(your virustotal apikey)</api_key>
    <rule_id>100211</rule_id>
    <alert_format>json</alert_format>
  </integration>

  <integration>
    <name>virustotal</name>
    <api_key>(your virustotal apikey)</api_key>
    <rule_id>100201</rule_id>
    <alert_format>json</alert_format>
  </integration>

  <command>
    <name>remove-threat</name>
    <executable>automation.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
  ```

  
**<img width="707" height="421" alt="oosec cong" src="https://github.com/user-attachments/assets/70f15b6d-199d-4f5e-8b84-49992e9bb513" />**

save and restart manager in tab wazuh browser

## 3. Configure Trigger Alerts in local_rules.xml
Configure custom trigger alerts to make detected events appear in the Discover menu tab on the Wazuh Dashboard.

Navigate to:

```text
open sidebar - rules - search local_rules.xml
```
**<img width="1364" height="209" alt="local_rules" src="https://github.com/user-attachments/assets/a22c7582-c97f-46b0-ade7-94ef7c8f216a" />**

### Add Custom Alert Rules to local_rules.xml
Append the following rules above the closing `</group>` line in the local_rules.xml file

Replace (your directory) with the directory path you want to monitor

```xml
 <!-- ===== Linux /root Directory Monitoring ===== -->

  <rule id="100200" level="7">
    <if_sid>550</if_sid>
    <field name="file">/root</field>
    <description>File modified in /root directory.</description>
  </rule>

  <rule id="100201" level="7">
    <if_sid>554</if_sid>
    <field name="file">/root</field>
    <description>File added to /root directory.</description>
  </rule>

  

  <!-- 🔍 Changes Detection File on Endpoint -->
  <rule id="100210" level="7">
    <if_sid>550</if_sid>
    <field name="file">(your directory)</field>
    <description>File modified in (your directory).</description>
  </rule>

 
  <!--- Create New File Detection on Endpoint -->
  <rule id="100211" level="7">
    <if_sid>554</if_sid>
    <field name="file">(your directory)</field>
    <description>File added to (your directory).</description>
  </rule>

 
  <!--- Virustotal Validation -->
  <rule id="100212" level="15">
    <if_sid>87105</if_sid>
    <field name="virustotal.positives">10</field>
    <field name="file">(your directory)</field>
    <description>Critical malware detected in (your directory) (VirusTotal confirmed)</description>
  </rule>

  <!-- SUCCESS DELETE -->
  <rule id="100213" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <field name="parameters.alert.data.virustotal.source.file">(your directory)</field>
    <description>Successfully removed malware in (your directory) </description>
  </rule>

  <!-- FAILED DELETE -->
  <rule id="100214" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <field name="parameters.alert.data.virustotal.source.file">(your directory)</field>
    <description>Failed to remove malware in (your directory)</description>
  </rule>
```

**<img width="779" height="514" alt="trigger" src="https://github.com/user-attachments/assets/6a6a27d0-65b2-46b1-8717-ebe35ca12510" />**

save and restart

# N8N Workflows 
The n8n workflow consists of the following steps:

```text
trigger manually → http request node → code in js node → discord direct message node
```

**<img width="684" height="194" alt="n8n workflow" src="https://github.com/user-attachments/assets/67c6c41a-2e48-451b-b435-b8d47bb90107" />**


For Locate node menu just nafigate to:

```text
Overview → Press N → and you can type node name 
```

**<img width="1380" height="618" alt="tips" src="https://github.com/user-attachments/assets/16ed7ca2-8349-4a30-985c-f0901cff546d" />**

## 1. Http Request Node
Configure the HTTP Request node in the n8n workflow to fetch data from an external source or API for further processing in subsequent nodes.

### set to method post
**<img width="302" height="170" alt="post" src="https://github.com/user-attachments/assets/f759dbc3-eb29-4989-9bc2-c150160445b6" />**

### Drop Wazuh Indexer API Url to URL box
**<img width="272" height="60" alt="image" src="https://github.com/user-attachments/assets/91ddbea4-d2f9-4270-b844-4df83fb58067" />**

Replace `<wazuh-server ip>` with your actual wazuh-server ip address
`https://<wazuh-server ip>/wazuh-alerts-4.x-*/_search`


### Set Authentication to: Generic Credential Type
**<img width="282" height="63" alt="image" src="https://github.com/user-attachments/assets/d43dae33-626d-4709-ab0b-0fda39fa60af" />**


### Set Generic Auth Type: Basic Authentication 
**<img width="262" height="63" alt="image" src="https://github.com/user-attachments/assets/4e29294e-a59f-4853-9215-12e1d1de0a9a" />**


### Set Basic Auth: click pen icon 
**<img width="268" height="59" alt="image" src="https://github.com/user-attachments/assets/10d440ac-49f9-496d-8764-131b558e471a" />**

### set the user:password (admin:SecretPassword)
**<img width="287" height="390" alt="image" src="https://github.com/user-attachments/assets/5e77c8b3-015a-4bec-b189-b4af943607a0" />**

### Turning on Send Body


### Set Body Content type to `JSON` and Set Specify body to `Using Json`

**<img width="284" height="179" alt="image" src="https://github.com/user-attachments/assets/4ba0b5f4-87a9-4c89-ab5b-50dbc5e2f918" />**

### Copy-paste code in below to `JSON`tab
This JSON query is used to retrieve the latest 20 documents from a data source (such as Elasticsearch) by sorting them in descending order based on the timestamp.

```JSON
{
  "query": {
    "match_all": {}
  },
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "size": 20
}
```
### Turning on Ignore SSL issues

# 2. JavaScript Node
The JavaScript (Code) node in n8n is used to process, transform, and manipulate data received from previous nodes before passing it to the next step in the workflow

### Copy-paste these code
This JavaScript code in the n8n Code node processes Wazuh alert data, formats timestamps into WIB (Asia/Jakarta timezone), and prepares a structured message for notifications.

**NOTE**: You can adjust `timeZone: "Asia/Jakarta"` to match your local timezone as needed.

```Text
const alerts = items[0].json.hits.hits;

return alerts.map(alert => {
  const src = alert._source;

  const utc = new Date(src['@timestamp']);

  const wib = utc.toLocaleString("id-ID", {
    timeZone: "Asia/Jakarta",
    hour12: false
  });

  return {
    json: {
      message: `🚨 WAZUH ALERT

📝 ${src.rule.description}
🖥 ${src.agent.name}
🌐 ${src.agent.ip || 'N/A'}
⏰ ${wib}`
    }
  };
});
```

# 3. Discord direct messages node 
Configure this node to send alerts directly to Discord via webhook integration



### Set connection type to: `Webhook`

**<img width="600" height="72" alt="image" src="https://github.com/user-attachments/assets/1d7207a6-ff0a-41a6-a019-df838ed62a9a" />**

### Set up credential for discord Webhook to: Discord webhook account ,click pen icon, and copy-paste your webhook url discord

**<img width="597" height="62" alt="image" src="https://github.com/user-attachments/assets/fffbcacc-a01c-4232-a468-34070942c40d" />**


**<img width="942" height="489" alt="image" src="https://github.com/user-attachments/assets/85f9e76d-95b8-460f-85ab-c170384cdd56" />**

### Set up Operation type to: send a Message

**<img width="611" height="73" alt="image" src="https://github.com/user-attachments/assets/6ad62e87-ca88-48c1-9fd3-b8616ecc9cc0" />**


### Drag `{{ $json.message }}` to Message box

**<img width="846" height="558" alt="image" src="https://github.com/user-attachments/assets/9f4e7e41-c179-4c4e-857b-e8c486e5ac6a" />**

  
Output must being like this
1. In n8n

**<img width="1092" height="559" alt="image" src="https://github.com/user-attachments/assets/8ca8cfc5-49e6-4854-848e-7fe1b82b84e9" />**

2. In Discord

**<img width="683" height="651" alt="image" src="https://github.com/user-attachments/assets/c46469fd-fa0c-4952-8658-675192977966" />**















