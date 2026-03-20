from scapy.all import sniff, ARP, send, Ether, conf, get_if_list
import threading
import time
import platform
import queue
from datetime import datetime, timedelta
from .database import SessionLocal
from . import crud, schemas

class DatabaseWorker(threading.Thread):
    """Background thread to handle all DB writes to prevent SQLite locking."""
    def __init__(self, task_queue):
        super().__init__(daemon=True)
        self.task_queue = task_queue

    def run(self):
        print("[DB] Worker started.")
        while True:
            try:
                task = self.task_queue.get()
                if task is None: break
                
                func, args, kwargs = task
                db = SessionLocal()
                try:
                    func(db, *args, **kwargs)
                except Exception as e:
                    print(f"[DB] Error executing {func.__name__}: {e}")
                finally:
                    db.close()
                self.task_queue.task_done()
            except Exception as e:
                print(f"[DB] Worker loop error: {e}")

class ActiveBlocker:
    def __init__(self):
        self.blocked_macs = set()
        self.stop_event = threading.Event()
        self.thread = None
        self.gateway_ip = self._detect_gateway()

    def _detect_gateway(self):
        try:
            return conf.route.route("0.0.0.0")[2]
        except:
            return "192.168.1.1"

    def start(self):
        if not self.thread:
            self.stop_event.clear()
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def block(self, mac):
        self.blocked_macs.add(mac)

    def unblock(self, mac):
        if mac in self.blocked_macs:
            self.blocked_macs.remove(mac)

    def run(self):
        while not self.stop_event.is_set():
            for mac in list(self.blocked_macs):
                try:
                    # Target the device: tell it WE are the gateway
                    pkt_dev = Ether(dst=mac)/ARP(op=2, hwsrc="00:00:00:00:00:00", psrc=self.gateway_ip, hwdst=mac)
                    send(pkt_dev, verbose=False)
                except: pass
            time.sleep(2)

class NetworkSniffer:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()
        self.db_queue = queue.Queue()
        self.db_worker = DatabaseWorker(self.db_queue)
        self.db_worker.start()
        
        self.blocker = ActiveBlocker()
        self.blocker.start()
        
        self.alert_cooldown = {}
        self.interface = None # Default to Scapy's choice

    def get_interfaces(self):
        return get_if_list()

    def set_interface(self, iface):
        self.interface = iface
        print(f"[*] Sniffer interface set to: {iface}")

    def get_capabilities(self):
        return {
            "os": platform.system(),
            "is_linux": platform.system() == "Linux",
            "can_inject": True,
            "gateway": self.blocker.gateway_ip,
            "current_interface": self.interface or "Default"
        }

    def should_alert(self, key):
        now = datetime.now()
        if key in self.alert_cooldown:
            if now < self.alert_cooldown[key] + timedelta(seconds=60):
                return False
        self.alert_cooldown[key] = now
        return True

    def scan_network(self):
        """Actively scan the local network using ARP requests."""
        try:
            gw = self.blocker.gateway_ip
            prefix = ".".join(gw.split(".")[:-1])
            target = f"{prefix}.0/24"
            print(f"[*] Actively scanning {target}...")
            
            # Using srp (Send/Receive packets at Layer 2)
            from scapy.all import srp
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=False, iface=self.interface)
            
            for snd, rcv in ans:
                self.process_packet(rcv)
            return len(ans)
        except Exception as e:
            print(f"[!] Scan Error: {e}")
            return 0

    def queue_task(self, func, *args, **kwargs):
        self.db_queue.put((func, args, kwargs))

    def send_alert(self, alert_type, severity, message, extra=None):
        self.queue_task(crud.create_alert, schemas.AlertCreate(type=alert_type, severity=severity, message=message))
        if self.alert_callback:
            data = {"type": alert_type, "severity": severity, "message": message, "timestamp": datetime.utcnow().isoformat()}
            if extra: data.update(extra)
            self.alert_callback(data)

    def process_packet(self, packet):
        if not packet.haslayer(ARP): return
        psrc, hwsrc = packet[ARP].psrc, packet[ARP].hwsrc
        
        db = SessionLocal()
        try:
            device = crud.get_device_by_mac(db, hwsrc)
            if not device:
                # IMMEDIATE CREATE (No queue) for new devices to avoid race conditions
                new_dev = crud.create_device(db, schemas.DeviceCreate(mac_address=hwsrc, ip_address=psrc))
                self.send_alert("NEW_DEVICE", "INFO", f"New device: {hwsrc} ({psrc})", {"mac": hwsrc, "ip": psrc})
            else:
                if device.ip_address != psrc:
                    other = crud.get_device_by_ip(db, psrc)
                    if other and other.mac_address != hwsrc:
                        if self.should_alert(f"SPOOF_{psrc}"):
                            self.send_alert("ARP_SPOOF", "CRITICAL", f"IP Conflict: {psrc} claimed by {hwsrc} and {other.mac_address}")
                    else:
                        self.queue_task(crud.update_device_ip, hwsrc, psrc)
                else:
                    self.queue_task(crud.update_device_ip, hwsrc, psrc)
        finally:
            db.close()

    def run(self):
        print(f"Sniffer starting on {self.interface or 'default'}...")
        try:
            sniff(iface=self.interface, filter="arp", prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            print(f"[!] SNIFFER ERROR: {e}")

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.db_queue.put(None)
