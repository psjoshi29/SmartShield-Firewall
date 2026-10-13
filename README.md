# SmartShield — Cyber Firewall Simulator & Rule Engine

[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg?logo=windows)](https://microsoft.com/windows)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?logo=python)](https://python.org)
[![Streamlit: 1.44+](https://img.shields.io/badge/Streamlit-1.44%2B-FF4B4B.svg?logo=streamlit)](https://streamlit.io)
[![Tests: 45 Passed](https://img.shields.io/badge/pytest-45%20passed-brightgreen.svg?logo=pytest)](https://pytest.org)
[![License: Academic / Educational](https://img.shields.io/badge/License-MIT-blue.svg)](#license)

**SmartShield** is an original, production-grade cybersecurity firewall simulation and packet inspection platform engineered for Windows 10 and 11. It provides an interactive rule engine, deterministic synthetic traffic generator, dark cybersecurity operations dashboard, forensic SQLite audit logging, threat analytics, and automated tests.

---

## 🛡️ Key Features

- **High-Performance Rule Decision Engine:**
  - Evaluates IPv4 host addresses, CIDR subnets (`192.168.1.0/24`, `10.0.0.0/16`), and wildcards.
  - Granular port filtering supporting discrete ports (`80, 443`), ranges (`1024-65535`), and wildcards.
  - Multi-protocol support (`TCP`, `UDP`, `ICMP`, `ANY`) and bidirectional flow tracking (`INBOUND`, `OUTBOUND`).
  - Strict priority-based deterministic first-match resolution.
  - Configurable fallback default action (Default-Deny `BLOCK` profile).

- **Deterministic Synthetic Packet Simulator:**
  - 6 realistic traffic scenarios: Enterprise Web/DNS egress, Authorized Admin SSH, Malicious Port Reconnaissance (Telnet 23, SMB 445, RDP 3389), WAN SSH Brute-Force, Malformed/Boundary header anomalies, and Mixed real-world flow.
  - Reproducible with deterministic pseudo-random seeds.
  - Explicit `is_simulated = True` stamping across all telemetry.

- **Forensic Event Auditing & Safe CSV Export:**
  - SQLite persistent database with Write-Ahead Logging (`WAL`) mode for high concurrency.
  - Parameterized queries to eliminate SQL injection vulnerabilities.
  - Safe CSV export with formula injection neutralization (escapes `=`, `+`, `-`, `@`, `\t`, `\r`).

- **Dark Cybersecurity Streamlit Dashboard:**
  - 7 modular views: **Overview**, **Traffic Simulator**, **Firewall Rules**, **Security Logs**, **Analytics**, **Packet Inspector**, and **Settings & About**.
  - Interactive Plotly visualizations for temporal trends, protocol breakdown, and target attack surface.
  - Real-time rule CRUD, prioritization, and toggle without server restart.

- **Automated Pytest Suite:**
  - 45 automated unit and end-to-end integration tests verifying IP/CIDR math, port bounds, evaluator priorities, atomic persistence, database queries, and CSV security.

---

## 🏗️ Architecture

```
                                +---------------------------+
                                |    Streamlit Dashboard    |
                                |  (Dark Cyber UI / Plotly) |
                                +-------------+-------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
         +-----------v-----------+                         +-----------v-----------+
         |   Packet Simulator    |                         |   Packet Inspector    |
         | (Scenarios/Generator) |                         | (Step-by-Step Trace)  |
         +-----------+-----------+                         +-----------+-----------+
                     |                                                 |
                     +------------------------+------------------------+
                                              |
                                 +------------v------------+
                                 |  Firewall Decision Core |
                                 |  - IP/CIDR Subnet Match |
                                 |  - Port Range Match     |
                                 |  - Priority First-Match |
                                 +------------+------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
         +-----------v-----------+                         +-----------v-----------+
         |     JSON Config       |                         |    SQLite Database    |
         |  (Atomic File Replace)|                         | (WAL Mode / Audit Log)|
         +-----------------------+                         +-----------------------+
```

---

## 🚀 Quick Start on Windows 10/11

### Prerequisites
- Windows 10 or Windows 11 (64-bit).
- Python 3.12+ (or Python 3.11+).

### One-Click Launch (Recommended)
Open PowerShell or Command Prompt in the repository folder:

```powershell
# Using PowerShell launcher
.\scripts\run_smartshield.ps1
```
or double-click `scripts\run_smartshield.bat`.

### Manual Setup
1. **Create and activate a virtual environment:**
   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. **Install dependencies:**
   ```powershell
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. **Run the test suite:**
   ```powershell
   pytest -v
   ```
4. **Launch the Dashboard:**
   ```powershell
   python run_app.py
   ```
5. Open your browser at **`http://127.0.0.1:8501`**.

---

## 📋 Dashboard Modules

| Page | Description |
| :--- | :--- |
| **📊 Overview** | Live KPI metric cards (Total Audited, Allowed, Blocked, Block Rate %), traffic trend timeline, transport protocol donut chart, flow direction distribution, and recent decisions. |
| **🚀 Traffic Simulator** | Scenario launcher with profile cards, record count slider (5-150), and live decision table. |
| **🛡️ Firewall Rules** | Searchable rules table, Add Rule form with live input validation, priority reordering, status toggles, deletion confirm modal, and default policy switcher. |
| **📋 Security Logs** | Complete audit log with multidimensional filters (action, protocol, direction, port, keyword), pagination, and safe CSV export. |
| **📈 Analytics** | Deep-dive threat surface charts (top 10 blocked ports, transport distribution, temporal volume). |
| **🔍 Packet Inspector** | Interactive custom packet builder showing a step-by-step trace of which conditions passed or failed for each rule, with glowing ALLOW/BLOCK cards. |
| **⚙️ Settings & About** | Global default fallback policy, baseline demo traffic seeding, database truncate with confirmation, and Windows Filtering Platform (WFP) architecture reference. |

---

## 🔒 Security & Privacy Practices

- **Zero Host Network Disruption:** Runs strictly in user-space sandbox mode without modifying host Windows Firewall settings or routing tables.
- **Atomic Configuration Persistence:** Rule modifications are written to temporary staging files before an atomic `os.replace` commits changes, preventing corruption upon sudden shutdown.
- **Parameterized SQL:** All SQLite database interactions use parameterized queries (`?`), eliminating SQL injection.
- **CSV Injection Neutralization:** Formula prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) are automatically escaped with single quotes before CSV export to safeguard spreadsheet analysts.

---

## 🧪 Running Automated Tests

SmartShield comes with 45 unit and integration tests:

```powershell
.\.venv\Scripts\pytest -v tests/
```

Test coverage includes:
- IP validation & CIDR subnet math (`ipaddress.IPv4Network`).
- TCP/UDP port boundary limits (1 to 65535, invalid port 0/65536, inverted ranges).
- First-match priority enforcement and disabled rule bypass.
- Default-deny (BLOCK) fallback and configurable defaults.
- Database query filtering, indexing, and WAL mode.
- Malformed packet sanity rejection.
- End-to-end full system lifecycle.

---

## 📚 Academic Documentation

- [Project Report (`docs/PROJECT_REPORT.md`)](docs/PROJECT_REPORT.md): Complete college-level documentation covering design, theoretical background, architecture, threat model, and evaluation.
- [Viva Questions & Answers (`docs/VIVA_QUESTIONS.md`)](docs/VIVA_QUESTIONS.md): 25+ comprehensive questions and answers for viva voce and project defense.
- [Demonstration Script (`docs/DEMO_SCRIPT.md`)](docs/DEMO_SCRIPT.md): Step-by-step 10-minute presentation walkthrough guide.
- [Troubleshooting Guide (`docs/TROUBLESHOOTING.md`)](docs/TROUBLESHOOTING.md): Solutions for common installation and execution challenges.

---

## ⚖️ License & Academic Integrity
Developed as an original college project for cybersecurity and software architecture education. Free to use for study and academic presentation.
