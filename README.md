# 🛡️ NARDD: Network Anomaly & Rogue Device Detector

**NARDD** is a high-performance, real-time network security monitor designed to detect unauthorized devices and mitigate ARP spoofing attacks. It features a robust Python backend for low-level packet sniffing and a modern, SOC-style web dashboard for live monitoring and device management.

---

## 🚀 Core Features

-   **Real-time Discovery**: Automatically identifies every device that communicates on your local network.
-   **Advanced Threat Detection**: Monitors MAC-to-IP mappings and triggers **CRITICAL** alerts if an IP conflict (ARP Spoofing) is detected.
-   **Intelligent Alerting**: Includes a 60-second cooldown per device to prevent notification spam.
-   **Active Prevention (IPS)**: On supported hardware (Linux), enables **Active Blocking** to "black-hole" malicious devices.
-   **Persistent History**: Saves all security events to a local SQLite database for forensic analysis.
-   **High-Performance Architecture**: Uses a multi-threaded, queue-based database worker to handle busy networks without lag.

---

## 🛠️ Technology Stack

-   **Backend**: Python (FastAPI, Scapy, SQLAlchemy)
-   **Frontend**: Vanilla JS (ES6+), Tailwind CSS, WebSockets
-   **Database**: SQLite

---

## 📥 Installation

### **1. Prerequisites**
-   **Python 3.10+**
-   **Npcap (Windows)**: Download from [npcap.com](https://npcap.com/). 
    -   *CRITICAL: Check "Install Npcap in WinPcap API-compatible Mode" during installation.*
-   **Root/Admin Privileges**: Required for raw packet sniffing.

### **2. Setup**
```bash
# Clone the repository
git clone https://github.com/your-username/nardd.git
cd nardd

# Install dependencies
pip install -r requirements.txt
pip install websockets
```

---

## 🚦 How to Use

### **1. Start the Backend**
Open your terminal as **Administrator** (Windows) or use `sudo` (Linux) and run:
```bash
python -m uvicorn backend.main:app --reload
```
The server will start at `http://127.0.0.1:8000`.

### **2. Access the Dashboard**
Open your browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### **3. Monitoring & Management**
-   **Trusted Devices**: When a new device is detected, review it and click **"Trust"** if you recognize it.
-   **Live Alerts**: Watch the sidebar for **NEW_DEVICE** or **ARP_SPOOF** events.
-   **History**: Switch to the **HISTORY** tab to view past security events.
-   **Blocking (Linux only)**: Click **"BLOCK"** on an untrusted device to disconnect it from the network.

---

## ⚠️ Disclaimer
This tool is for educational and personal network security monitoring purposes only. Only use NARDD on networks you own or have explicit permission to monitor.

---

## 📜 License
MIT License. Feel free to use and improve!
