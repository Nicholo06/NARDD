# 🛡️ NARDD: Network Anomaly & Rogue Device Detector

**NARDD** is a professional-grade, real-time network security monitor and Intrusion Prevention System (IPS). Designed for both home and security research environments, it provides deep visibility into network traffic, identifies devices with high accuracy, and offers active mitigation against unauthorized actors.

---

## 🚀 Key Capabilities

-   **Deep Fingerprinting**: Uses Nmap-style TTL analysis and Apple Lockdown port probing to identify iPhones, ThinkPads, and OS types even with randomized MAC addresses.
-   **Active Prevention (IPS)**: Perform bi-directional ARP poisoning to "black-hole" malicious devices. Blocks are **persistent** and automatically resume after system reboots.
-   **Smart Discovery**: Multi-protocol sniffing (ARP, DHCP, mDNS, NBNS, SSDP) combined with an **Active Network Scanner** that supports dynamic subnet detection.
-   **Status Monitoring**: Background heartbeat engine detects and visually flags online/offline devices in real-time.
-   **Forensic History**: Persistent local database stores all security alerts and device sightings for long-term analysis.
-   **Untrusted Actor Tracking**: Automatically flags suspicious moves or "Network Scanning" behavior from untrusted devices.

---

## 🛠️ Technology Stack

-   **Backend**: Python 3.10+ (FastAPI, Scapy, SQLAlchemy)
-   **Frontend**: Vanilla JS (ES6+), Tailwind CSS, WebSockets
-   **Database**: SQLite (Multi-threaded with Queue-based worker)

---

## 📥 Installation

### **1. Prerequisites**
-   **Python 3.10+**
-   **Npcap (Windows)**: Download from [npcap.com](https://npcap.com/). 
    -   *CRITICAL: Check "Install Npcap in WinPcap API-compatible Mode" during installation.*
-   **Root/Admin Privileges**: Mandatory for raw packet injection and sniffing.

### **2. Setup**
```bash
# Clone the repository
git clone https://github.com/your-username/nardd.git
cd nardd

# Install dependencies
pip install -r requirements.txt
pip install websockets requests
```

---

## 🚦 How to Use

### **1. Start the Backend**
Run the server with elevated privileges:
```bash
# Windows (Admin CMD)
python -m uvicorn backend.main:app --reload

# Linux (Kali/Ubuntu)
sudo python -m uvicorn backend.main:app --reload
```

### **2. Configuration (Linux)**
For effective blocking, ensure IP Forwarding is disabled on your host:
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

### **3. Dashboard Features**
-   **Trust System**: Mark known devices as "Trusted." Untrusted devices are monitored for suspicious activity.
-   **Scan Network**: Click the indigo button to force all "silent" devices (like iPhones) to reveal themselves.
-   **Blocking**: In Advanced Mode (Linux), use the **BLOCK** button to cut a device's internet connection. The state is saved permanently.
-   **History**: Switch to the **HISTORY** tab to view alerts from previous sessions.

---

## ⚠️ Disclaimer
This tool is for educational and authorized security monitoring purposes only. Unauthorized monitoring or disruption of a network you do not own is illegal and unethical.

---

## 📜 License
MIT License.
