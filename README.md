# IP-Blacklist-Detection-System-for-Network-Traffic-Analysis
A Python tool that detects malicious IP addresses in network traffic logs using blacklist filtering from a Suricata firewall ruleset. Scans source &amp; destination IPs, flags suspicious connections as SUSPICIOUS or CLEAN, and exports results to CSV.

##  Problem Statement

In modern network environments, thousands of connections are made every second. Manually identifying malicious IPs from large traffic logs is time-consuming and error-prone. This tool automates the process — it reads network traffic logs, checks every connection against a known blacklist, and marks suspicious traffic instantly.

---

##  Objective

- Read real-world style network traffic logs from a CSV file
- Maintain a blacklist of known malicious IPs from a Suricata ruleset
- Scan every connection's `src_ip` and `dst_ip` against the blacklist
- Flag and categorise suspicious traffic automatically
- Export the analysed results into a new CSV file

---

##  Project Structure

```
ip_blacklist_project/
│
├── step1_generate_dataset.py           # Generates sample network traffic CSV
├── step2_to_5_blacklist_detection.py   # Main detection script (Steps 2–5)
├── network_traffic.csv                 # Raw generated dataset (22 rows)
├── network_traffic_analysed.csv        # Output with status column added
└── README.md                           # Project documentation
```

---

##  Technologies Used

| Tool | Purpose |
|---|---|
| Python 3.10+ | Core programming language |
| pandas | Data loading and manipulation |
| datetime | Timestamping the analysis output |
| CSV | Data storage format |
| VS Code | Development environment |

---

##  How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/Ashish-code-lab/ip-blacklist-detection.git
cd ip-blacklist-detection
```

### 2. Install Dependencies
```bash
pip install pandas
```

### 3. Generate the Dataset
```bash
python step1_generate_dataset.py
```

**Output:**
```
[OK]  Dataset written  → network_traffic.csv
      Total rows       : 22
      Suspicious rows  : 12
      Clean rows       : 10
      Columns          : src_ip, dst_ip, port, protocol, bytes
```

### 4. Run the Detection Script
```bash
python step2_to_5_blacklist_detection.py
```

**Output:**
```
============================================================
  IP BLACKLIST DETECTION — NETWORK TRAFFIC ANALYSER
============================================================

[Step 3] Dataset loaded: network_traffic.csv
         Rows    : 22
         Columns : ['src_ip', 'dst_ip', 'port', 'protocol', 'bytes']

[Step 4] Blacklist loaded — 10 IPs from ruleset

[Step 5] Scan complete:
============================================================
  Total records scanned  : 22
  Suspicious connections : 12
  Clean connections      : 10
============================================================

SRC IP               DST IP               PORT   PROTO       BYTES  STATUS
---------------------------------------------------------------------------
185.220.101.34       91.108.4.1            443   UDP       165,511  ⚠  SUSPICIOUS (src + dst)
192.168.1.105        192.168.10.15        8080   TCP       488,453  ⚠  SUSPICIOUS (src)
10.0.0.25            172.20.10.5          3389   TCP     1,177,272  ⚠  SUSPICIOUS (src)
...

[Done] Results saved → network_traffic_analysed.csv
       Timestamp : 2026-06-25 10:30:00
============================================================
```

---

##  Blacklisted IPs (from Suricata Ruleset)

| IP Address | Threat Type |
|---|---|
| 192.168.1.105 | Known C2 server |
| 10.0.0.25 | Malware distribution node |
| 172.16.0.50 | Brute-force origin |
| 192.168.2.200 | Data exfiltration host |
| 10.10.10.10 | Port scanner |
| 203.0.113.45 | Phishing infrastructure |
| 198.51.100.22 | Ransomware beacon |
| 185.220.101.34 | Tor exit node |
| 91.108.4.1 | Botnet C2 |
| 45.142.212.100 | Exploit kit host |

---

##  Dataset Details

A sample dataset of **22 network traffic records** was generated using Python, simulating real-world network logs.

| Column | Description |
|---|---|
| `src_ip` | Source IP address of the connection |
| `dst_ip` | Destination IP address of the connection |
| `port` | Network port used (e.g. 80, 443, 22) |
| `protocol` | Transport protocol — TCP or UDP |
| `bytes` | Amount of data transferred in bytes |
| `status` | Detection result (added by detection script) |

- **12 rows** — contain at least one blacklisted IP
- **10 rows** — completely clean/benign IPs

---

##  Status Labels Explained

| Status | Meaning |
|---|---|
| `CLEAN` | No blacklisted IP involved — safe connection |
| `SUSPICIOUS (src)` | Source IP matched the blacklist |
| `SUSPICIOUS (dst)` | Destination IP matched the blacklist |
| `SUSPICIOUS (src + dst)` | Both IPs are blacklisted — most dangerous |

---

##  Steps Breakdown

| Step | Description |
|---|---|
| Step 1 | Generate sample dataset with blacklisted and clean IPs |
| Step 2 | Import required Python packages |
| Step 3 | Read `network_traffic.csv` into a pandas DataFrame |
| Step 4 | Define `BLACKLISTED_IPS` list from Suricata ruleset |
| Step 5 | Apply blacklist check on `src_ip` and `dst_ip`, mark suspicious |

---

##  Common Errors & Fixes

| Error | Fix |
|---|---|
| `ModuleNotFoundError: pandas` | Run `pip install pandas` |
| `FileNotFoundError: network_traffic.csv` | Run `step1_generate_dataset.py` first |
| `python not recognized` | Reinstall Python and tick **Add to PATH** |
| `pip not recognized` | Use `python -m pip install pandas` |

---

##  License

This project is for educational purposes only.
