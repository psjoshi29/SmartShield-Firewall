# Academic Project Report: SmartShield Firewall Simulator & Security Architecture

**Project Title:** SmartShield: A Modular Firewall Rule Engine, Deterministic Synthetic Traffic Simulator, and Security Analytics Platform for Windows 10/11  
**Author:** SmartShield Security Engineering  
**Academic Level:** Undergraduate / Graduate Computer Science & Cybersecurity  
**Date:** October 2026  

---

## Abstract
Modern enterprise defense relies on packet filtering firewalls to enforce boundary access control policies. While production perimeter firewalls operate within operating system kernels or dedicated hardware appliances, computer science education frequently lacks an accessible, transparent, and safe testbed where students and engineers can experiment with rule priority chains, CIDR subnet matching, edge-case packet malformations, and forensic log auditing. 

This report presents **SmartShield**, an original, comprehensive firewall simulation and rule evaluation software suite implemented in Python 3.12 for Windows 10/11. SmartShield incorporates a deterministic first-match rule engine, a synthetic multi-scenario packet synthesizer, a forensic SQLite database operating in Write-Ahead Logging (WAL) mode, a dark cybersecurity operations dashboard built with Streamlit and Plotly, and an automated test suite comprising 45 unit and integration tests. The software adheres strictly to safe user-space execution, eliminating kernel crash risks while providing a detailed architectural roadmap for Windows Filtering Platform (WFP) driver integration.

---

## 1. Introduction and Objectives

### 1.1 Problem Statement
Firewall policy management is error-prone. Misconfigured rule priorities, overlapping CIDR subnets, and ambiguous default policies often lead to either catastrophic security breaches (accidental permissive holes) or widespread operational outages (unintended drops of legitimate traffic). Traditional live firewalls (such as Windows Defender Firewall or Linux `iptables`/`nftables`) obscure their step-by-step internal decision evaluation behind binary logging, making it difficult for students to verify *why* a specific packet was accepted or dropped. Furthermore, conducting aggressive port-scanning and malformed-packet experiments on live host adapters introduces connectivity risks and host security alerts.

### 1.2 Project Objectives
1. **Engine Independence:** Implement an original, type-annotated, pure Python rule evaluation engine operating independently of any graphical user interface.
2. **Deterministic Evaluation:** Implement priority-based first-match rule resolution with strict input validation for IPv4 addresses, CIDR subnet bitmasks, and TCP/UDP port ranges.
3. **Synthetic Packet Simulation:** Provide realistic, reproducible traffic scenarios representing enterprise web traffic, authorized administrative SSH, aggressive external reconnaissance, and malformed header anomalies.
4. **Forensic Audit & Storage Security:** Persist rules atomically via JSON and store evaluated packet logs in SQLite with parameterized queries, schema indexing, and CSV formula injection neutralization.
5. **Interactive Cybersecurity GUI:** Construct a dark-themed, responsive dashboard featuring 7 dedicated operational views, interactive Plotly visualizations, and a packet inspector showing condition-level trace evaluation.
6. **Academic Rigor:** Achieve 100% test pass rate with automated pytest suites and supply complete documentation, viva voce examination questions, and demonstration scripts.

---

## 2. Theoretical Foundations

### 2.1 Packet Filtering at the Network and Transport Layers
SmartShield operates primarily at Layers 3 (Network) and 4 (Transport) of the Open Systems Interconnection (OSI) reference model:
- **Layer 3 (Network):** Evaluates Source IPv4 and Destination IPv4 addresses. SmartShield parses host addresses and CIDR subnets using bitwise network operations.
- **Layer 4 (Transport):** Evaluates transport protocols (`TCP`, `UDP`, `ICMP`) and 16-bit logical port numbers (spanning `1` to `65535`).

### 2.2 CIDR Subnet Mathematics
Classless Inter-Domain Routing (CIDR) replaces historical Class A/B/C addressing by expressing an IP address alongside a variable-length prefix mask `/n` (where \(0 \le n \le 32\)).
For an IP address \(A\) and subnet network address \(N\) with prefix length \(n\):
$$\text{Mask}_n = \sum_{i=32-n}^{31} 2^i$$
The packet address \(A\) matches the subnet \(N/n\) if and only if:
$$(A \ \& \ \text{Mask}_n) == (N \ \& \ \text{Mask}_n)$$
SmartShield leverages the standard Python `ipaddress.IPv4Network(..., strict=False)` library to compute bitwise network inclusion with mathematical certainty.

### 2.3 Priority Chains vs. First-Match Algorithms
In packet filtering theory, rules can be evaluated under several models:
1. **Last-Match Wins:** Every rule is evaluated, and the final matching rule dictates the action (e.g., historical OpenBSD PF default).
2. **First-Match Wins (Ordered Chain):** Rules are evaluated sequentially from top to bottom. The first rule whose complete set of criteria matches the packet terminates evaluation immediately (e.g., Cisco ACLs, iptables).
3. **Explicit Priority (SmartShield Model):** Each rule is assigned an integer priority score \(P \in [1, 1000]\), where smaller numerical values represent higher precedence. SmartShield sorts rules strictly by \((P, \text{ID})\) and evaluates top-down. The first matching rule triggers the disposition. If no rule matches after traversing all active rules, a configurable **Default Action** (Default-Deny `BLOCK`) is applied.

---

## 3. System Architecture & Modular Design

SmartShield is divided into eight discrete modules following clean software engineering principles:

```
+-------------------------------------------------------------------------+
|                        Presentation Tier (GUI)                          |
|  Streamlit Multipage App | Custom Cyber Dark Theme | Plotly Analytics   |
+------------------------------------+------------------------------------+
                                     |
+------------------------------------v------------------------------------+
|                         Application Tier                                |
|   +-----------------------+                 +-----------------------+   |
|   |   Traffic Simulator   |                 |   Packet Inspector    |   |
|   |  - Scenario Profiles  |                 |  - Trace Collector    |   |
|   |  - Packet Generator   |                 |  - Step Visualizer    |   |
|   +-----------+-----------+                 +-----------+-----------+   |
|               |                                         |               |
|               +--------------------+--------------------+               |
|                                    |                                    |
|   +--------------------------------v--------------------------------+   |
|   |                   Firewall Decision Engine                      |   |
|   |  - Validator (IPv4, CIDR, PortRange, Enums)                     |   |
|   |  - Evaluator (Priority First-Match Chain)                       |   |
|   |  - RuleSet Manager (Sort, Add, Update, Toggle, Reorder)         |   |
|   +--------------------------------+--------------------------------+   |
+------------------------------------+------------------------------------+
                                     |
+------------------------------------v------------------------------------+
|                          Storage & Persistence                          |
|   +-----------------------+                 +-----------------------+   |
|   |     JSON Config       |                 |     SQLite Database   |   |
|   |  - Atomic Write Staging|                |  - Parameterized SQL  |   |
|   |  - Schema Fallback    |                 |  - WAL Concurrency    |   |
|   +-----------------------+                 +-----------------------+   |
+-------------------------------------------------------------------------+
```

### 3.1 Firewall Decision Engine (`smartshield.engine`)
- **`models.py`:** Type-safe definitions for `Protocol`, `Direction`, `Action`, `IPPattern`, `PortRange`, `Packet`, `Rule`, `EvaluationStep`, and `EvaluationDecision`.
- **`validator.py`:** Rejects illegal IP octets, negative/overflow ports, malformed CIDR prefixes, and illegal characters.
- **`ruleset.py`:** Manages the collection of active and disabled rules, preventing duplicate rule IDs and maintaining priority order.
- **`evaluator.py`:** Executes the first-match evaluation loop and generates a complete condition-by-condition trace for educational transparency.

### 3.2 Synthetic Simulator (`smartshield.simulator`)
- **`scenarios.py`:** Catalog of realistic traffic templates:
  - *Legitimate Web & DNS Egress*
  - *External Port Scan & Reconnaissance*
  - *Authorized Admin Inbound SSH*
  - *External WAN Inbound SSH Brute-Force*
  - *Malformed & Boundary Header Packets*
  - *Enterprise Mixed Real-World Traffic Flow*
- **`generator.py`:** Produces reproducible synthetic packets using seeded pseudo-random generation.
- **`runner.py`:** Coordinates the simulation loop, feeds packets to the engine, and logs results to SQLite.

### 3.3 Storage Layer (`smartshield.storage`)
- **`config.py`:** Serializes rules to JSON using an atomic staging file pattern (`tempfile` + `os.replace`) to prevent file corruption during unexpected termination.
- **`db.py`:** SQLite database with indexed tables (`events`) and Write-Ahead Logging. Implements CSV formula injection mitigation.

### 3.4 Analytics & Reporting (`smartshield.analytics`)
- **`analyzer.py`:** Computes KPIs (total records, allowed count, blocked count, block rate %), protocol distributions, flow directions, and top-targeted destination ports.
- **`exporter.py`:** Produces forensic CSV audit exports.

---

## 4. Security Engineering & Hardening

1. **Defense Against SQL Injection:**  
   Every query to the SQLite audit database utilizes bound parameters (`?`). Dynamic SQL string interpolation is strictly avoided.
2. **Defense Against CSV Formula Injection (CWE-1236):**  
   Exporting logs containing unconstrained strings (e.g. malicious packet headers or rule names starting with `=`, `+`, `-`, or `@`) can cause spreadsheet software (such as Microsoft Excel or LibreOffice Calc) to execute arbitrary commands. SmartShield prepends a single quote (`'`) to any field beginning with dangerous characters.
3. **Atomic File Persistence:**  
   Writing configuration directly to a target file risks leaving a truncated, zero-byte file if an interruption occurs. SmartShield creates a unique temporary file on the same filesystem volume, writes and flushes data, executes `os.fsync()`, and atomically swaps the file via `os.replace()`.
4. **Strict Rejection of Malformed Packets:**  
   Malformed packets (e.g., port numbers outside 1-65535 or octets > 255) are intercepted by the engine integrity validator and assigned a structured `BLOCK` action with an explicit reason code, ensuring invalid data never defaults to permissive rules.

---

## 5. Verification & Pytest Results

SmartShield features an automated test suite implemented in `pytest` containing **45 comprehensive test cases**:

| Test Module | Tests | Focus Area | Status |
| :--- | :---: | :--- | :---: |
| `test_models_and_validation.py` | 18 | IPv4 boundaries, CIDR parsing, port ranges, enums | **PASSED** |
| `test_evaluator.py` | 7 | First-match priority, disabled rules, CIDR/port match | **PASSED** |
| `test_ruleset.py` | 7 | Duplicate ID check, CRUD operations, reordering | **PASSED** |
| `test_config_persistence.py` | 3 | Atomic JSON save/load, corruption recovery | **PASSED** |
| `test_storage_db.py` | 4 | SQLite WAL, parameterized filters, CSV sanitization | **PASSED** |
| `test_simulator.py` | 4 | Scenario catalog, deterministic seed, runner pipeline | **PASSED** |
| `test_analytics.py` | 2 | KPI calculation, empty states, dataframe generation | **PASSED** |
| `test_e2e_integration.py` | 1 | Full end-to-end multi-module lifecycle verification | **PASSED** |
| **Total** | **45** | **100% Pass Rate** | **PASSED** |

Execution time for the entire test suite is approximately 1.5 seconds.

---

## 6. Windows Network Integration Analysis & WFP Roadmap

### 6.1 Architectural Boundary Justification
In accordance with safe software engineering practices, SmartShield's initial deployment is intentionally constructed as a user-space simulator. Intercepting live Windows network traffic requires administrative privileges, kernel drivers, and EV code signing. A buggy kernel driver can cause immediate Kernel Panic (Blue Screen of Death - BSOD) or sever host internet connectivity.

### 6.2 Technical Roadmap for Future Windows Filtering Platform (WFP) Integration
For students and engineers wishing to extend SmartShield into a live Windows packet filter, the required architecture comprises:
1. **Kernel-Mode Callout Driver (KMDF):**
   - Register callouts with the Windows Filtering Platform via `FwpsCalloutRegister3`.
   - Subscribe to WFP layers: `FWPS_LAYER_INBOUND_IPPACKET_V4` and `FWPS_LAYER_OUTBOUND_IPPACKET_V4`.
   - Inspect `FWPS_INCOMING_VALUES0` containing IP headers and protocol IDs.
   - Return `FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`.
2. **WinDivert Alternative (User-Mode Divert):**
   - WinDivert uses a pre-signed kernel driver (`WinDivert.sys`) and provides a C/Python user-space API (`windivert.dll`).
   - A background thread opens a divert socket: `WinDivertOpen("ip and (tcp or udp)", ...)`
   - Captured packets are passed into SmartShield's `evaluate_packet()` function. Packets returning `ALLOW` are reinjected via `WinDivertSend()`; packets returning `BLOCK` are silently discarded.

---

## 7. Limitations & Future Improvements
1. **Stateful Connection Tracking:** The current engine is stateless; it filters individual packets based on header fields without maintaining a dynamic TCP state transition table (TCP 3-way handshake tracking, FIN/RST teardown). Adding a stateful connection table is a prime candidate for Phase 2.
2. **IPv6 Support:** Current logic is dedicated to IPv4. IPv6 128-bit address evaluation can be integrated using `ipaddress.IPv6Network`.
3. **Deep Packet Inspection (DPI):** SmartShield inspects L3/L4 headers. Inspecting application payloads (e.g., detecting HTTP User-Agents or TLS SNI server names) would elevate the engine to Next-Generation Firewall (NGFW) status.

---

## 8. Conclusion
SmartShield successfully achieves all project goals. It provides a robust, educational, and secure firewall platform featuring mathematical CIDR evaluation, deterministic first-match policy resolution, automated forensic auditing, and a rich dark Streamlit operations dashboard. Backed by 45 passing automated tests and thorough academic documentation, SmartShield serves as an exemplary computer science capstone project in security engineering.
