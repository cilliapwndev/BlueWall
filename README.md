# 🔐 BlueWall – Firewall Auditor


[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Ruby](https://img.shields.io/badge/ruby-≥2.7-red.svg)](https://www.ruby-lang.org)

BlueWall is a firewall auditing tool for **pfSense** and **OPNsense** configurations.
It parses XML exports, identifies strengths and weaknesses, simulates attack scenarios, and provides compliance scoring against frameworks like **NIST CSF, CIS Controls, ISO 27001, PCI DSS, SOC 2, and COBIT 2019**.

---

## ✨ Features

* ✅ Parse **pfSense/OPNsense XML configs** (rules, NAT, aliases, schedules).
* ✅ Detect **firewall strengths & weaknesses**.
* ✅ Simulate **attack & exfiltration scenarios** (e.g., brute force, reverse shell).
* ✅ Generate a **security score (1–10)** with details.
* ✅ Map findings to **major security frameworks**.
* ✅ Export **interactive HTML reports** with graphs & charts.

---

## 📦 Installation

### From RubyGems

```bash
gem install bluewall
```

### From Source

```bash
git clone https://github.com/yourusername/bluewall.git
cd bluewall
bundle install
```

---

## 🚀 Usage

Export your firewall configuration (`config.xml`) from pfSense/OPNsense, then run:

```bash
bluewall config.xml
```

You’ll get:

* Console summary (strengths, weaknesses, score).
* Optional detailed compliance breakdown.
* Optional interactive **HTML report**.

---

## 📊 Example Output

```
██████╗ ██╗     ██╗   ██╗███████╗██╗    ██╗ █████╗ ██╗     ██╗         
██╔══██╗██║     ██║   ██║██╔════╝██║    ██║██╔══██╗██║     ██║         
██████╔╝██║     ██║   ██║█████╗  ██║ █╗ ██║███████║██║     ██║         
██╔══██╗██║     ██║   ██║██╔══╝  ██║███╗██║██╔══██║██║     ██║         
██████╔╝███████╗╚██████╔╝███████╗╚███╔███╔╝██║  ██║███████╗███████╗    
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝    
                    created by :cillia

--- BlueWall Audit Report ---
Firewall Type: PFSENSE_LIKE
Strengths:
  - Explicit 'DENY all' inbound rule on WAN detected
Weaknesses:
  - Rule allows SSH from any source on WAN (**Critical risk!**)
Overall Security Score (1–10): 5.4
```

---

## 🎯 Compliance Mapping

BlueWall maps findings against:

* **NIST Cybersecurity Framework (CSF)**
* **CIS Controls**
* **ISO/IEC 27001**
* **PCI DSS**
* **SOC 2**
* **COBIT 2019**

---
## 🛣️ Roadmap & Future Features

* **🔄 Live Firewall API Support – direct audits via pfSense/OPNsense API.**
* **📡 SIEM / Log Integration – export to Splunk, ELK, Graylog.**
* **🧪 Custom Attack Profiles – extend simulations with YAML/JSON configs.**
* **📜 JSON/Markdown Reports – lightweight and developer-friendly outputs.**
* **🌐 Web Dashboard – interactive UI for reports and history.**
* **🔒 More Frameworks – add HIPAA, GDPR, FedRAMP mappings.**
* **📊 Asset-aware Risk Scoring – weight rules by criticality.**
* **🧩 Plugin System – allow custom rules & attack modules.**

---

## 📄 License

This project is licensed under the **GNU GPL v3.0** – see [LICENSE](LICENSE) for details.

---
