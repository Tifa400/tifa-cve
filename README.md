# 🕸️ Tifa-CVE Engine (v1.0)

**Tifa-CVE** is an advanced, multi-threaded vulnerability reconnaissance and mass scanning suite. Built by **Tifa400**, this engine bridges the gap between passive OSINT and active exploit verification, providing a seamless pipeline for security researchers.



---

## ✨ Features

* **Stealth Fingerprinting:** Identifies backend technologies using **Favicon MurmurHash3**, bypassing hidden headers and WAFs.
* **Shodan Intelligence:** Automatically pulls OS, Organization, and Port data using Shodan API.
* **Active Verification:** Integrated with **Nuclei** to verify real-world exploitability (Critical/High findings).
* **Massive Performance:** Built-in multi-threading supporting hundreds of targets concurrently.
* **Persistent Storage:** Saves all findings into an **SQLite** database (`tifa_scans.db`) for long-term tracking.
* **Interactive Dashboard:** Quickly filter and view confirmed "Critical" targets directly from the terminal.

---

## 🛠️ Installation & Setup

Since modern Kali Linux environments use **PEP 668**, you must use a virtual environment to prevent system conflicts.

### 1. Clone the Project
```bash
git clone [https://github.com/Tifa400/tifa-cve.git](https://github.com/Tifa400/tifa-cve.git)
cd tifa-cve

### ​🚀 Usage Guide
​To get started with Tifa-CVE, follow these instructions:
​1. Configuration
​Before running the tool, you must set up your Shodan API Key.
​Open the tifa-cve.py file in any text editor.
​Locate the SHODAN_API_KEY variable in the configuration section.
​Replace "YOUR_SHODAN_API_KEY" with your actual key.
​A. Scan a Single Website
​To perform a full reconnaissance and vulnerability scan on a single target, use the -u or --url flag:
[python tifa-cve.py -u https://example.com)

This command will:
​Resolve the target's IP address.
​Calculate the Favicon MurmurHash3 for stealth identification.
​Fetch OS and port data from Shodan (Passive Recon).
​Run Nuclei templates to verify active vulnerabilities (Critical/High).
​Automatically save the results to your local SQLite database.

