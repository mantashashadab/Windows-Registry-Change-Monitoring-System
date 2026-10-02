# 🛡️ Windows Registry Change Monitoring System

A defensive Windows Registry monitoring and integrity-analysis toolkit built with Python. The system establishes Registry baselines, detects added/modified/deleted values, monitors autorun locations, identifies suspicious Registry indicators, performs SHA-256 integrity verification, calculates heuristic risk, logs events, and provides an interactive Streamlit dashboard.

> **Project Type:** Defensive Cybersecurity / Endpoint Monitoring  
> **Platform:** Windows  
> **Language:** Python  
> **Dashboard:** Streamlit

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Objectives](#-objectives)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Monitoring Workflow](#-monitoring-workflow)
- [Monitored Registry Locations](#️-monitored-registry-locations)
- [Registry Integrity Verification](#-registry-integrity-verification)
- [Risk Analysis](#-risk-analysis)
- [Event Logging](#-event-logging)
- [Continuous Monitoring](#-continuous-monitoring)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running the Project](#️-running-the-project)
- [Testing Methodology](#-testing-methodology)
- [Example Results](#-example-results)
- [Streamlit Dashboard](#️-streamlit-dashboard)
- [Deployment](#-deployment)
- [Security and Safety Design](#-security-and-safety-design)
- [Detection Philosophy](#️-detection-philosophy)
- [Limitations](#️-limitations)
- [Future Enhancements](#-future-enhancements)
- [Learning Outcomes](#-learning-outcomes)
- [Project Deliverables](#-project-deliverables)
- [Screenshots](#-screenshots)
- [Example Monitoring Pipeline](#-example-monitoring-pipeline)
- [Module Responsibilities](#-module-responsibilities)
- [Development Approach](#️-development-approach)
- [Defensive Cybersecurity Focus](#-defensive-cybersecurity-focus)
- [Author](#️-author)
- [Project Repository](#-project-repository)
- [Internship Project](#-internship-project)
- [Disclaimer](#️-disclaimer)

---

## 🔎 Overview

The **Windows Registry Change Monitoring System** is a defensive cybersecurity toolkit designed to monitor sensitive Windows Registry locations and identify changes that may require further investigation.

The Windows Registry stores important configuration information related to:

- System settings
- Application behavior
- Startup configuration
- User preferences
- Security policies
- Persistence mechanisms

Malware and unauthorized software can abuse Registry locations to establish persistence, alter security settings, or modify system behavior.

This project provides a controlled monitoring and analysis workflow for identifying such changes.

The system does **not** attempt to modify, exploit, or disable Windows security mechanisms.

---

## 🎯 Problem Statement

Unauthorized Registry modifications can be difficult to identify manually.

A monitoring system should therefore be able to:

- Establish a known-good Registry baseline
- Detect Registry additions
- Detect Registry modifications
- Detect Registry deletions
- Monitor autorun locations
- Identify potentially suspicious Registry indicators
- Verify Registry integrity
- Record monitoring events
- Prioritize findings using heuristic risk analysis
- Present results through an interactive dashboard

---

## 🎯 Objectives

The project aims to:

1. Monitor common Windows Registry startup locations.
2. Detect additions, modifications, and deletions.
3. Identify autorun Registry entries.
4. Detect potentially suspicious Registry patterns.
5. Compare current Registry state against a baseline.
6. Verify Registry integrity using SHA-256 hashing.
7. Generate timestamped monitoring logs.
8. Provide heuristic risk prioritization.
9. Provide an interactive Streamlit dashboard.
10. Support controlled and safe Registry-change testing.

---

# 🔑 Key Features

## 1. 📸 Registry Baseline Management

The system captures a snapshot of configured Registry locations and stores it as a baseline.

The baseline contains:

- Registry location
- Registry path
- Value name
- Value data
- Registry value type
- Baseline creation timestamp

The baseline is stored locally as:

```text
baselines/registry_baseline.json
```

The baseline is used as the reference point for future Registry comparisons.

---

## 2. 🔍 Registry Snapshot Collection

The Registry Collector reads configured Windows Registry locations using Python's built-in `winreg` module.

The collector:

- Opens configured Registry keys
- Enumerates Registry values
- Records value names
- Records value data
- Records value types
- Handles missing keys
- Handles permission-related errors

The collected information is converted into a structured snapshot that can be compared with the baseline.

---

## 3. 🔄 Registry Change Detection

The system compares the baseline snapshot with the current Registry snapshot.

Three types of changes are detected:

| Change Type | Description |
|---|---|
| **ADDED** | A value exists in the current snapshot but not in the baseline |
| **MODIFIED** | An existing Registry value has changed |
| **DELETED** | A baseline value is no longer present |

### Example

```text
Baseline
    TestValue = Initial Value

Current
    TestValue = Modified Value

Result
    MODIFIED
```

---

## 4. 🚀 Autorun Monitoring

The system monitors common Windows Registry startup locations.

It identifies entries that may launch applications automatically during user or system startup.

For each autorun entry, the system can display:

- Registry location
- Entry name
- Command
- Executable path
- Registry value type

Supported executable-related extensions include:

```text
.exe
.bat
.cmd
.com
.scr
.ps1
.vbs
.js
```

### Important

An autorun entry is **not automatically considered malicious**.

Many legitimate applications use Registry startup locations.

The system therefore treats autorun entries as persistence-monitoring indicators that may require further investigation.

---

## 5. 🚨 Suspicious Registry Indicator Detection

The system uses rule-based patterns to identify Registry changes associated with potentially suspicious behavior.

Current detection categories include:

### Windows Defender

Examples:

```text
Windows Defender
DisableAntiSpyware
DisableAntiVirus
DisableRealtimeMonitoring
```

### Windows Firewall

Examples:

```text
WindowsFirewall
FirewallPolicy
DisableFirewall
```

### Shell Replacement

Examples:

```text
Winlogon.*Shell
Winlogon.*Userinit
```

### UAC Bypass

Examples:

```text
ms-settings
fodhelper
DelegateExecute
SilentCleanup
```

### Security Policy

Examples include Registry paths related to:

```text
Windows Defender policies
Windows Firewall policies
Windows System policies
```

These indicators are designed to identify potentially suspicious Registry behavior.

They are **not treated as definitive proof of malware**.

---

# 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │   Windows Registry  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Registry Collector  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Baseline Manager   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Change Detector    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
           ADDED            MODIFIED         DELETED
              └────────────────┼────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Suspicious Pattern  │
                    │     Detection       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Integrity Checker   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Risk Engine      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Event Logger     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Streamlit Dashboard │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Analysis / Export   │
                    └─────────────────────┘
```

---

# 🔄 Monitoring Workflow

```text
START
  │
  ▼
Load Monitoring Configuration
  │
  ▼
Capture / Load Baseline
  │
  ▼
Collect Current Registry Snapshot
  │
  ▼
Compare With Baseline
  │
  ├──────────────┬──────────────┐
  ▼              ▼              ▼
ADDED         MODIFIED       DELETED
  │              │              │
  └──────────────┼──────────────┘
                 ▼
       Suspicious Pattern Analysis
                 │
                 ▼
        Registry Integrity Check
                 │
                 ▼
            Risk Analysis
                 │
                 ▼
            Event Logging
                 │
                 ▼
          Dashboard / Export
                 │
                 ▼
                END
```

---

# 🗂️ Monitored Registry Locations

The current implementation monitors the following Registry locations:

### HKCU Run

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### HKCU RunOnce

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### HKLM Run

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

### HKLM RunOnce

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### Controlled Test Registry Key

```text
HKCU\Software\RegistryMonitorTest
```

The test key is used for controlled **ADD, MODIFY, and DELETE** testing.

---

# 🔐 Registry Integrity Verification

The project includes SHA-256-based integrity checking.

The system serializes the Registry snapshot and calculates its SHA-256 hash.

### Baseline Hash

```text
Baseline Snapshot
       │
       ▼
   Serialize
       │
       ▼
    SHA-256
       │
       ▼
Baseline Hash
```

The same process is performed for the current Registry state:

```text
Current Snapshot
       │
       ▼
   Serialize
       │
       ▼
    SHA-256
       │
       ▼
Current Hash
```

The two hashes are then compared.

### Possible Results

#### MATCH

```text
MATCH
```

The monitored snapshot has the same hash as the baseline.

#### CHANGED

```text
CHANGED
```

The current snapshot differs from the baseline.

The integrity hash provides an additional verification layer alongside individual change detection.

---

# 📊 Risk Analysis

The project includes a heuristic risk engine.

Risk analysis considers factors such as:

- Registry changes
- Suspicious Registry indicators
- Autorun-related findings

The resulting risk level is represented as:

```text
LOW
MEDIUM
HIGH
```

The dashboard displays:

- Overall Risk Score
- Risk Level
- Change Risk
- Suspicious Risk
- Risk Findings

### Important

Risk scoring is a **heuristic prioritization mechanism**.

It should be used to determine which Registry activity may require further investigation.

A high score or suspicious indicator does not independently establish that malware is present.

---

# 📝 Event Logging

The project includes a Registry Event Logger.

Events can be stored in:

```text
logs/registry_events.json
```

Depending on the event, logged information can include:

- Timestamp
- Registry path
- Registry name
- Change type
- Value name
- Previous value
- New value
- Detection information

The Streamlit dashboard can display logged events and provide an option to download the event log.

---

# 🔄 Continuous Monitoring

The project includes a polling-based monitoring module.

The monitoring cycle follows:

```text
Collect Snapshot
       │
       ▼
Compare State
       │
       ▼
Detect Changes
       │
       ▼
Analyze Indicators
       │
       ▼
Log Results
       │
       ▼
Wait
       │
       ▼
Next Scan
```

The current implementation uses periodic scanning rather than event-driven Registry notifications.

---

# 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| `winreg` | Windows Registry access |
| Streamlit | Interactive security dashboard |
| Pandas | Data handling / dashboard support |
| JSON | Baseline and event storage |
| `hashlib` | SHA-256 integrity verification |
| Git | Version control |
| GitHub | Source-code hosting |
| PowerShell | Windows development and testing environment |

---

# 📁 Project Structure

```text
Windows-Registry-Change-Monitoring-System/
│
├── app.py
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── core/
│   ├── __init__.py
│   ├── registry_collector.py
│   └── baseline_manager.py
│
├── detection/
│   ├── __init__.py
│   ├── autorun_detector.py
│   ├── change_detector.py
│   ├── integrity_checker.py
│   └── suspicious_detector.py
│
├── scoring/
│   └── risk_engine.py
│
├── logging_system/
│   └── event_logger.py
│
├── monitor/
│   └── registry_monitor.py
│
├── tests/
│   ├── add_test_value.py
│   ├── create_test_registry.py
│   ├── delete_test_value.py
│   └── modify_test_value.py
│
├── baselines/
│
└── logs/
```

---

# 📄 Files Intentionally Excluded from Git

The following local/generated content is excluded using `.gitignore`:

```text
venv/
__pycache__/
baselines/*.json
logs/*.json
.streamlit/secrets.toml
.vscode/
```

This prevents local environment files and generated monitoring data from being committed unnecessarily.

---

# 💻 Installation

## Prerequisites

The live Registry monitoring functionality requires:

- Windows
- Python 3.x
- Git
- PowerShell or another terminal

The Streamlit dashboard can also operate in its safe demonstration/deployment mode in environments where Windows Registry access is unavailable.

## 1. Clone the Repository

```powershell
git clone https://github.com/mantashashadab/Windows-Registry-Change-Monitoring-System.git
```

## 2. Enter the Project Directory

```powershell
cd Windows-Registry-Change-Monitoring-System
```

## 3. Create a Virtual Environment

```powershell
python -m venv venv
```

## 4. Activate the Virtual Environment

```powershell
.\venv\Scripts\Activate.ps1
```

## 5. Install Dependencies

```powershell
pip install -r requirements.txt
```

The current dependency file contains:

```text
streamlit
pandas
```

Python's `winreg` module is part of the Windows Python standard library and does not need to be installed separately.

---

# ▶️ Running the Project

## Run the Main Analysis

From the project root:

```powershell
python main.py
```

This performs:

- Baseline loading
- Current Registry collection
- Autorun analysis
- Change detection
- Suspicious indicator detection
- Integrity checking
- Console reporting

---

## Run the Registry Collector

```powershell
python -m core.registry_collector
```

This displays values collected from the monitored Registry locations.

---

## Run Autorun Analysis

```powershell
python -m detection.autorun_detector
```

This analyzes the monitored autorun Registry locations.

---

## Run the Risk Engine

```powershell
python -m scoring.risk_engine
```

---

## Run the Event Logger

```powershell
python -m logging_system.event_logger
```

---

## Run Continuous Monitoring

```powershell
python -m monitor.registry_monitor
```

The monitor periodically scans the configured Registry locations.

---

# 🧪 Testing Methodology

Testing is performed using the controlled Registry location:

```text
HKCU\Software\RegistryMonitorTest
```

This allows Registry change detection to be demonstrated without intentionally modifying Windows security settings.

---

## Test 1 — Create Test Registry Key

Run:

```powershell
python tests/create_test_registry.py
```

This creates the controlled test key and an initial value.

---

## Test 2 — Add a Registry Value

Run:

```powershell
python tests/add_test_value.py
```

The monitoring system should detect:

```text
Added: 1
```

---

## Test 3 — Modify a Registry Value

Run:

```powershell
python tests/modify_test_value.py
```

The monitoring system should detect:

```text
Modified: 1
```

---

## Test 4 — Delete a Registry Value

Run:

```powershell
python tests/delete_test_value.py
```

The monitoring system should detect:

```text
Deleted: 1
```

---

## Test Coverage Demonstrated

The core change detector has been manually verified for:

```text
No Change
    ↓
Added Value
    ↓
Modified Value
    ↓
Deleted Value
```

The project also verifies:

- Autorun Registry enumeration
- Suspicious pattern scanning
- SHA-256 integrity comparison
- Event logging
- Continuous polling
- Dashboard analysis

---

# 📊 Example Results

A clean scan can produce:

```text
CHANGE DETECTION RESULTS

Added:    0
Modified: 0
Deleted:  0
Total:    0

STATUS: No Registry changes detected.
```

An example change detection result:

```text
CHANGE DETECTION RESULTS

Added:    1
Modified: 0
Deleted:  0
Total:    1

STATUS: Registry changes detected.
```

### Example Modification

```text
[MODIFIED]

Value: AddedValue

Old: This value was added for testing

New: This value has been modified
```

### Example Deletion

```text
[DELETED]

Value: AddedValue

Old: This value has been modified
```

---

# 🖥️ Streamlit Dashboard

The project includes an interactive Streamlit dashboard.

Launch it with:

```powershell
streamlit run app.py
```

The dashboard provides the following sections.

## Monitoring Environment

Displays:

- Monitoring mode
- Registry access status
- Last scan time

## Security Overview

Displays:

- Added changes
- Modified changes
- Deleted changes
- Suspicious indicators
- Autorun entries

## Registry Change Breakdown

Provides a visual summary of:

```text
Added
Modified
Deleted
```

## Risk Analysis

Displays:

- Risk score
- Risk level
- Change risk
- Suspicious risk

## Registry Integrity

Displays:

- Baseline SHA-256
- Current SHA-256
- Integrity status

Possible status:

```text
MATCH
```

or:

```text
CHANGED
```

## Detected Registry Changes

Displays a table containing:

- Registry
- Path
- Change type
- Value name
- Old value
- New value

## Suspicious Registry Indicators

Displays:

- Category
- Pattern
- Registry path
- Value
- Old value
- New value

## Autorun Registry Entries

Displays:

- Registry location
- Entry name
- Command
- Executable

## Risk Findings

Displays findings generated by the risk-analysis engine.

## Registry Event Log

Displays logged Registry monitoring events and allows the event log to be downloaded.

## Full Analysis Export

The dashboard provides an option to download the complete analysis as JSON.

---

# 🚀 Deployment

The project contains two operating modes.

## Windows Live Mode

When running on Windows:

```text
Windows
   │
   ▼
winreg
   │
   ▼
Live Registry
   │
   ▼
Registry Analysis
   │
   ▼
Streamlit Dashboard
```

This mode provides access to the local monitored Registry locations.

---

## Deployment / Demonstration Mode

Cloud hosting environments generally do not provide access to the user's local Windows Registry.

Therefore, the application includes a safe demonstration mode for environments where Windows Registry access is unavailable.

```text
Cloud Environment
       │
       ▼
Safe Demonstration Dataset
       │
       ▼
Analysis Pipeline
       │
       ▼
Streamlit Dashboard
```

This allows the dashboard interface and analysis workflow to be demonstrated without attempting to access another machine's Registry.

---

# 🔒 Security and Safety Design

This project follows a defensive monitoring approach.

The monitoring toolkit does **not intentionally**:

- Disable Windows Defender
- Disable Windows Firewall
- Modify real security policies
- Create malicious persistence
- Execute malware
- Execute Registry commands
- Launch suspicious programs
- Automatically alter protected Registry settings

Testing is performed using:

```text
HKCU\Software\RegistryMonitorTest
```

The test key is used only for controlled **ADD, MODIFY, and DELETE** demonstrations.

---

# ⚠️ Detection Philosophy

Registry entries must be interpreted in context.

For example:

```text
Autorun entry ≠ Malware
```

and:

```text
Suspicious Registry indicator ≠ Confirmed compromise
```

The project therefore separates:

- Observed Registry changes
- Behavioral indicators
- Risk prioritization

This prevents the system from treating a single Registry value as definitive proof of malicious activity.

---

# ⚠️ Limitations

The current implementation has several limitations.

## 1. Polling-Based Monitoring

The continuous monitor currently uses periodic polling rather than native event-driven Registry monitoring.

## 2. Windows Dependency

Live Registry collection depends on Windows and Python's `winreg` module.

## 3. Permissions

Some protected Registry locations may require elevated privileges.

## 4. Cloud Deployment

Cloud deployment environments cannot access the user's local Windows Registry.

The application therefore uses a safe demonstration dataset outside Windows.

## 5. Rule-Based Detection

Suspicious Registry detection currently uses predefined patterns.

It does not provide complete behavioral malware analysis.

## 6. Heuristic Risk Score

Risk scoring is designed for investigation prioritization.

It should not be interpreted as a definitive malware classification.

## 7. Legitimate Registry Activity

Legitimate software can modify Registry values and create autorun entries.

Therefore, detected changes require contextual investigation.

---

# 🔮 Future Enhancements

Potential future improvements include:

- Event-driven Registry monitoring
- Windows Event Log integration
- Additional persistence locations
- Windows Task Scheduler monitoring
- Service persistence monitoring
- Process-to-Registry correlation
- Digital signature verification
- File reputation analysis
- Improved behavioral detection
- Historical Registry-change visualization
- Advanced risk scoring
- Email alerts
- Webhook alerts
- SIEM integration
- HTML report generation
- PDF report generation
- Automated investigation summaries
- Configuration-based monitoring rules
- Expanded testing and evaluation

---

# 📚 Learning Outcomes

This project provides practical experience in:

- Windows Registry structure
- Registry persistence mechanisms
- Endpoint monitoring
- Baseline comparison
- Change detection
- Integrity verification
- SHA-256 hashing
- Security configuration monitoring
- Suspicious behavior detection
- Python cybersecurity scripting
- JSON-based logging
- Risk analysis
- Streamlit dashboard development
- Git and GitHub
- Defensive cybersecurity techniques

---

# 📦 Project Deliverables

The project is designed to provide the following internship deliverables.

## Source Code

Complete Python-based Registry monitoring toolkit.

## Dashboard

Interactive Streamlit security-monitoring dashboard.

## Baseline

Registry baseline used for integrity and change comparison.

## Monitoring Logs

Timestamped Registry event records.

## Testing

Controlled ADD, MODIFY, and DELETE Registry tests.

## Documentation

Project documentation explaining:

- Architecture
- Workflow
- Detection logic
- Testing methodology
- Limitations
- Future enhancements

## Presentation

Final project presentation covering:

- Problem statement
- Objectives
- Architecture
- Implementation
- Testing
- Results
- Dashboard
- Future work

---

# 📸 Screenshots

Screenshots of the Streamlit dashboard, Registry change detection results, baseline creation, integrity verification, and testing results can be added here as the project documentation is finalized.

Recommended screenshots:

- Streamlit dashboard overview
- Security Overview metrics
- Registry Change Breakdown
- Risk Analysis
- Registry Integrity
- Detected Registry Changes
- Autorun Registry Entries
- Continuous monitoring output
- ADD test result
- MODIFY test result
- DELETE test result

---

# 📈 Example Monitoring Pipeline

```text
Registry Snapshot
        │
        ▼
Baseline Comparison
        │
        ├───────────────┐
        ▼               ▼
Change Detection    Integrity Check
        │               │
        ▼               ▼
Suspicious Analysis   SHA-256
        │               │
        └───────┬───────┘
                ▼
          Risk Analysis
                │
                ▼
           Event Logging
                │
                ▼
        Streamlit Dashboard
                │
                ▼
          JSON Export
```

---

# 🧩 Module Responsibilities

| Module | Responsibility |
|---|---|
| `registry_collector.py` | Collects monitored Registry values |
| `baseline_manager.py` | Creates and loads Registry baselines |
| `change_detector.py` | Detects added, modified, and deleted values |
| `autorun_detector.py` | Analyzes autorun Registry entries |
| `suspicious_detector.py` | Detects predefined suspicious Registry indicators |
| `integrity_checker.py` | Calculates and compares SHA-256 snapshot hashes |
| `risk_engine.py` | Calculates heuristic risk |
| `event_logger.py` | Records Registry monitoring events |
| `registry_monitor.py` | Performs continuous polling |
| `main.py` | Runs command-line analysis |
| `app.py` | Provides Streamlit dashboard |

---

# 🛠️ Development Approach

The project was developed incrementally using modular components.

The implementation follows:

```text
Collection
    ↓
Baseline
    ↓
Comparison
    ↓
Detection
    ↓
Integrity
    ↓
Risk
    ↓
Logging
    ↓
Monitoring
    ↓
Dashboard
```

This modular architecture allows individual components to be tested and extended independently.

---

# 🔐 Defensive Cybersecurity Focus

The project demonstrates several blue-team concepts:

- Persistence monitoring
- Endpoint configuration monitoring
- Registry forensics
- Baseline-based integrity checking
- Security configuration monitoring
- Suspicious behavior detection
- Event logging
- Risk prioritization

The system focuses on detecting and analyzing Registry changes rather than modifying or exploiting systems.

---

# 👩‍💻 Author

**Mantasha Shadab**

Computer Science Engineering Student

**Cybersecurity | Web Development | Data Analysis**

GitHub:

https://github.com/mantashashadab

---

# 📌 Project Repository

GitHub Repository:

https://github.com/mantashashadab/Windows-Registry-Change-Monitoring-System

---

# 📄 Internship Project

This project was developed as part of a cybersecurity internship to demonstrate practical knowledge of:

- Windows security
- Registry monitoring
- Endpoint detection
- Python automation
- Security logging
- Integrity verification
- Dashboard development

---

# ⚠️ Disclaimer

This project is intended for educational, defensive cybersecurity, and authorized Registry-auditing purposes.

Only monitor systems and Registry locations for which you have appropriate authorization.

Registry modifications, autorun entries, or suspicious indicators should be investigated in context and should not automatically be interpreted as proof of malware or compromise.

The project does not intentionally create persistence, disable security controls, execute malware, or modify protected Windows security settings.