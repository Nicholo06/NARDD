NARDD: Network Anomaly & Rogue Device Detector
🎯 Project Vision
A real-time network security monitor that detects unauthorized devices and ARP spoofing attacks. The system uses a Python backend for low-level packet sniffing and a JavaScript frontend for a security operations center (SOC) style dashboard.

🏗️ Technical Architecture
1. File Structure
The project should be organized as follows:

Plaintext
nardd/
├── backend/
│   ├── main.py            # FastAPI entry point & WebSocket logic
│   ├── database.py        # SQLAlchemy engine & session config
│   ├── models.py          # SQLAlchemy ORM models
│   ├── schemas.py         # Pydantic models for API validation
│   ├── sniffer.py         # Scapy logic & background thread
│   └── crud.py            # Database helper functions
├── frontend/
│   ├── index.html         # Main dashboard UI
│   ├── app.js             # WebSocket client & State management
│   └── styles.css         # Tailwind or Custom CSS
└── requirements.txt       # scapy, fastapi, uvicorn, sqlalchemy
2. Database Schema (SQLite)
Table: devices

id: Integer (Primary Key)

mac_address: String (Unique, Indexed)

ip_address: String

hostname: String (Optional)

is_trusted: Boolean (Default: False)

last_seen: DateTime

Table: alerts

id: Integer (Primary Key)

type: String (e.g., "NEW_DEVICE", "ARP_SPOOF")

severity: String (e.g., "INFO", "CRITICAL")

message: Text

timestamp: DateTime

🧠 Logic Requirements
A. The Sniffer (sniffer.py)
Use scapy.sniff(filter="arp", store=0) to capture packets.

For every packet:

Extract psrc (Source IP) and hwsrc (Source MAC).

Query DB: Does this MAC exist?

If No: Create new entry in devices, mark is_trusted=False, and emit NEW_DEVICE alert via WebSocket.

If Yes: Compare psrc with the stored ip_address.

If IPs differ, emit ARP_SPOOFING alert (Critical).

Update last_seen timestamp.

B. The API (main.py)
Endpoint GET /devices: Returns all discovered devices.

Endpoint PATCH /devices/{mac}/trust: Updates the is_trusted status.

WebSocket /ws/alerts: Asynchronous broadcast for real-time security events.

C. The Frontend (app.js)
Connect to /ws/alerts on load.

Maintain a stateful table of devices.

Provide a "Trust" button that triggers the API call.

Play a notification sound or show a toast alert when a CRITICAL alert arrives.

🛠️ Implementation Commands for AI CLI
Step 1: Backend Scaffolding

"Generate backend/models.py and backend/database.py using SQLAlchemy for the schema defined in the README. Use a local network.db file."

Step 2: Scapy Sniffer Logic

"Generate backend/sniffer.py. Implement a Scapy sniffer that runs in a Python threading.Thread. Use the logic defined in Section 🧠 A. Ensure it calls crud.py functions to update the database."

Step 3: FastAPI Integration

"Generate backend/main.py using FastAPI. Include a lifespan event to start the sniffer thread on startup. Implement a WebSocket endpoint /ws/alerts that the sniffer can push data to."

Step 4: Frontend UI

"Build a modern, dark-themed dashboard in frontend/index.html and frontend/app.js. It should display a table of devices and a scrolling sidebar for 'Live Alerts' received via WebSockets."

⚠️ Security & Permissions
Accessing the raw network socket requires root/admin privileges.

All Python commands must be executed with sudo (Linux/Mac) or "Run as Administrator" (Windows).