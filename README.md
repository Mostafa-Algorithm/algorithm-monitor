# AlgoMonitor - Advanced System Security Monitoring Service

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
8. [Troubleshooting](#troubleshooting)
9. [Uninstallation](#uninstallation)
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
   git clone https://github.com/your-repo/algo-monitor.git
   cd algo-monitor
   ```
2. **Run the installer:**
   ```bash
   sudo ./install.sh
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
   - *Common Fixes*:
     - Verify Python dependencies: `pip3 install -r requirements.txt`
     - Check config.json validity: `python3 -m json.tool /opt/.monitor/config.json`

3. **High System Resource Usage**
   - *Adjustments*:
     - Modify thresholds in `PROCESS_THRESHOLDS`
     - Exclude resource-intensive processes
     - Increase scan intervals

## Uninstallation Procedure

Complete removal command:
```bash
sudo ./uninstall.sh
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

Developed with ❤️ by [Mostafa Algorithm](https://www.linkedin.com/in/mostafa-atef-algorithm/)
AI Assistance provided by [DeepSeek](https://chat.deepseek.com/)
