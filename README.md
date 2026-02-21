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