# AlgoMonitor - Advanced System Security Monitoring Service

![AlgoMonitor](https://lh3.googleusercontent.com/fife/ALs6j_E0bj4uWYOowlgJDthrzxgXYyVHCx6wLr4Vbf3KMReVw-CW0GDX4cbepiyVS0yevmqYQl9k5KJo8_9rki8G17LOu_gIZmdJz9a-y-ycXNw-ngNGRAhCXQVeDVVvPVJSyMzUzovDLPLMvLOdGGOCGL13t2YHOU7SVBMnxuscI4ML0fuwCYrL5_MfsvDUqu9ZMt41GP8SfHAJK71S5cclBDevWXFDDfM3KZCxBXAp8fzMXVdbAP7yed_bB7Bm8c7rPwts5xwvvTIXfcqGrZiYrazTbzLUN0lIzWbYjyOZiuC9kXiEvTTMcI7Ft7CDcdwk8--Xhdm2EZKvQf7MIrodu-z-UWbeeJnGu2RSytoIJUYFGZs9UOtepYPkAS2wK_dZeNRflFB2B5SUFIg6C5BtADuTFB1Kw_pjZechfhOlsjJjJ6gdBVSwPl5bmb0GI0e0DbPyZQNSPDcflVT2qHbruYyqRJ-2nTWZF6k6QuUJXkGMMjwv2xeJjjGxIDOjcDqGmBDVa86CN_HsHgYkStin4qQHEQN0UD26tgrtOQEoK1T4zqT78WFIUeHiqsSCvqtXhdz26FcssG1qUz-Zj7coQVcDzcMudodi6X-PgQJA3T-5g2RRvTvdQVWKbfIVlVRwlAsquaD1FiIyMhyK0GRG_u3gEYpWWgynTtCNnVtiGuaIobW49F9zgATf9NKIFYcUIlkHUjRs0HK9evZ1kvAFBDYzxyMJ50ZtdXC-70dZ5LE5wtYfrNvyGPTni2EIbzQ-efeW4kHvHMyEbBUQ7XxO11MhNBSWh0IrivGTFSU6pZ48WfMIIUaau-_mLG-eiC1eptzzHzEupsiGnjee7y2dT6gccsWSE-XbR8eAUvgvfCe0J3ycYUvey0mmDvcePKcN0M0qa4FrVpqkWt6NtpvJmH6tlqD4rMGKsM2gQJDcWLm068M88-h7yOKZIg69RHjRNt-_M5z_2sjjfEiEpAWn1D-4Iag1MbqrVmms3v3vxEX5aQ8qD-yhkJxSfVZ852VaWAvnIDzY5vLR5xvwrSmw72urb3oewX_EEMr_aoGAI6vduhu7-5zyJODpkJJ9gh69pjBZcXCskQtTkRBfYbQAGFSgXAsQKhy0a8ZRlYh-RVE0dJiAJ_kaRKlbOr0QKM6XcvQ26gipp_ZtXGcKrpLaeV_Bco50IinZjjt-nc6hOYsf1mQP9DMwVwvwi6_xyHO2R-WrEwh8_n8Fbp_1WjzhQp83zwJB7jlEhcJ1g4PskM93aPI5FiW8YWq7zQMiZWqweLbgaLTvybMXgVyn7QfjdNkpMry_HwygsNF3F-NdPZ1IJK_r_FRK9Cxz6O17st-oJysjm0JMsKA--yYx_lxl07nwhsUwMeLWnLfxqOO6_9gCb5dh8uIv2VF4L3SuBJirA91RXMnpGAYsnONxFCYQuhTiMXkNHhrJYODi7ED9IX4u4G9n4iYQD9XsayUnMy0ANWpvSvaUZF3QstkeueOdJzajCUvUqtGK9oz2F9GiPE3TxbxUHf8-YtK9BQc92LNAxl4yXLnmVPcGqrg8NQ8DTso5w3a4WVGrS2GfccpWti6Ce9KmWPus1m9eqR1YVupDaybEndauSrlfG73MaSMVNvfKGUjdNtbaGpwomtKAWUZWGfMnTjpW1MUVd6M=w1357-h949?auditContext=prefetch)

## Overview

AlgoMonitor is an enterprise-grade security monitoring solution that provides real-time protection for Linux systems by monitoring processes, network activity, filesystem changes, and user sessions. It actively detects and mitigates potential threats using behavioral analysis and pattern matching.

## Table of Contents

1. [Key Features](#key-features)
2. [System Requirements](#system-requirements)
3. [Installation Guide](#installation-guide)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Monitoring Components](#monitoring-components)
7. [Alert Types](#alert-types)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Uninstallation Procedure](#uninstallation-procedure)
10. [Important Notes](#important-notes)

## Key Features

- **Real-time Process Monitoring**
  - Detects suspicious process behavior
  - Identifies potential reverse shells
  - Terminates unauthorized processes

- **Network Security**
  - Monitors all network connections
  - Detects suspicious remote connections
  - Alerts on unauthorized port openings

- **Filesystem Protection**
  - Monitors critical system directories
  - Detects unauthorized file modifications
  - Tracks file integrity with hashing

- **User Activity Monitoring**
  - Logs all user logins/logouts
  - Tracks suspicious user sessions
  - Provides session auditing

## System Requirements

- **Operating System**: Linux (kernel 4.4+)
- **Python**: 3.6 or higher
- **Dependencies**:
  - `psutil`
  - `notify2`
  - [`algorithm-lib`](https://github.com/Mostafa-Algorithm/algorithm-lib)
- **RAM**: Minimum 512MB (1GB recommended)
- **Storage**: 100MB available space

## Installation Guide

1. **Download the package**:
   ```bash
   git clone https://github.com/Mostafa-Algorithm/algorithm-monitor.git
   cd algorithm-monitor
   ```
2. **Run the installer:**
   ```bash
   sudo ./install
   ```
3. **Verify installation:**
   ```bash
   sudo systemctl status algo-monitor
   ```
4. **Show service logs**
   ```bash
   sudo journalctl -u algo-monitor -f
   ```
   
## Configuration

### The configuration file is located at ```/opt/.monitor/config.json.``` Key sections:
- **Trusted Processes**
   ```json
   "TRUSTED_SYSTEM_PROCESSES": [
      "systemd",
      "sshd",
      "nginx"
   ]
   ```
- **Protected Directories**
   ```json
   "PROTECTED_DIRECTORIES": [
      "/bin/",
      "/etc/",
      "/root/"
   ]
   ```
- **Thresholds**
   ```json
   "PROCESS_THRESHOLDS": [
      "cpu_percent": 80,
      "memory_percent": 70,
      "children": 15
   ]
   ```
- **After modifying the config, restart the service:**
   ```bash
   sudo systemctl restart algo-monitor
   ```

## Service Management

### Start/Stop Service
```bash
sudo systemctl start algo-monitor
sudo systemctl stop algo-monitor
```
### Check Status
```bash
sudo systemctl status algo-monitor
```
### View Logs
```bash
# Live logs
sudo journalctl -u algo-monitor -f

# Historical logs
sudo cat /opt/.monitor/logs/alert.log
```

## Monitoring Components

### 1. Process Monitoring
- **Scan Frequency**: Every 5 seconds
- **Checks For**:
  - Unknown/unrecognized processes
  - Suspicious command patterns and arguments
  - Abnormal resource usage (CPU/Memory)
  - Unusual child process relationships
  - Potential reverse shell indicators

### 2. Network Monitoring
- **Tracking Scope**: All active connections (inbound/outbound)
- **Alerts On**:
  - Connections to known malicious IPs/Domains
  - Unauthorized port openings/listeners
  - Suspicious outbound connection patterns
  - Connections to TOR (.onion) endpoints
  - Communication with known cryptomining pools

### 3. Filesystem Monitoring
- **Scan Frequency**: Every 60 seconds
- **Verifications**:
  - File integrity via SHA-256 hashing
  - Permission/ownership changes
  - Unauthorized modifications to protected files
  - New executables in system directories
  - Changes to critical configuration files

### 4. User Session Monitoring
- **Tracking Scope**: All login/logout events
- **Logged Details**:
  - Username and UID
  - Source IP addresses
  - Session start/end timestamps
  - Terminal/access method
  - Session duration

## Alert Types

| Level     | Description                          | Example Triggers                     |
|-----------|--------------------------------------|--------------------------------------|
| INFO      | Normal system events                 | User login, Service startup          |
| WARNING   | Potential security concern           | Unknown process, Port scan detected  |
| ALERT     | Immediate security threat            | Reverse shell, Cryptominer detected  |
| ERROR     | System/Service errors                | Permission denied, Resource limits   |

### You can update logging from ```/opt/.monitor/config.json``` file:
 ```json
 "LOG_LEVELS": ["ALERT", "INFO", "WARNING", "ERROR"]
 ```

## Troubleshooting Guide

### Common Issues and Solutions

1. **Legitimate Process Terminated**
   - *Solution*: Add process name to `TRUSTED_SYSTEM_PROCESSES` array in config.json
   - *Example*:
     ```json
     "TRUSTED_SYSTEM_PROCESSES": [
       "my_custom_service",
       "development_tool"
     ]
     ```

2. **Service Fails to Start**
   - *Diagnostic Commands*:
     ```bash
     journalctl -u algo-monitor -b --no-pager
     systemctl status algo-monitor
     ```

3. **High System Resource Usage**
   - *Adjustments*:
     - Modify thresholds in `PROCESS_THRESHOLDS`
     - Exclude resource-intensive processes
     - Increase scan intervals

## Uninstallation Procedure

Complete removal command:
```bash
sudo ./uninstall
```

## Important Notes

### **This service performs active security enforcement.** Any process or connection matching threat patterns will be terminated immediately.

### Before production deployment:
1. Audit all legitimate services
2. Pre-whitelist required applications
3. Test in monitoring-only mode if available
4. Establish rollback procedures

### To whitelist blocked services:

1. Edit ```/opt/.monitor/config.json```
2. Add to appropriate whitelist arrays
3. Restart service:
  ```bash
  sudo systemctl restart algo-monitor
  ```

## Development Credits

```text
  ░█████╗░██╗░░░░░░██████╗░░█████╗░██████╗░██╗████████╗██╗░░██╗███╗░░░███╗
  ██╔══██╗██║░░░░░██╔════╝░██╔══██╗██╔══██╗██║╚══██╔══╝██║░░██║████╗░████║
  ███████║██║░░░░░██║░░██╗░██║░░██║██████╔╝██║░░░██║░░░███████║██╔████╔██║
  ██╔══██║██║░░░░░██║░░╚██╗██║░░██║██╔══██╗██║░░░██║░░░██╔══██║██║╚██╔╝██║
  ██║░░██║███████╗╚██████╔╝╚█████╔╝██║░░██║██║░░░██║░░░██║░░██║██║░╚═╝░██║
  ╚═╝░░╚═╝╚══════╝░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░░░░╚═╝

Developed with ❤️ by Mostafa Algorithm
AI Assistance provided by DeepSeek
