from scapy.all import sniff, ARP, send, Ether, conf, get_if_list, srp, get_if_hwaddr, getmacbyip
import threading
import time
import platform
import queue
from datetime import datetime, timedelta
from .database import SessionLocal
from . import crud, schemas

class DatabaseWorker(threading.Thread):
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
                try: func(db, *args, **kwargs)
                except Exception as e: print(f"[DB] Error: {e}")
                finally: db.close()
                self.task_queue.task_done()
            except Exception as e: print(f"[DB] Loop error: {e}")

class ActiveBlocker:
    def __init__(self, interface=None):
        self.blocked_macs = set() # Store as (mac, ip) tuples
        self.stop_event = threading.Event()
        self.thread = None
        self.interface = interface
        self.gateway_ip = self._detect_gateway()
        self.gateway_mac = None
        self.local_mac = None

    def _detect_gateway(self):
        try: return conf.route.route("0.0.0.0")[2]
        except: return "192.168.1.1"

    def refresh_network_info(self, interface):
        self.interface = interface
        try:
            self.local_mac = get_if_hwaddr(self.interface or conf.iface)
            self.gateway_mac = getmacbyip(self.gateway_ip)
            print(f"[*] Blocker Init: Interface={self.interface}, GW={self.gateway_ip}, GW_MAC={self.gateway_mac}, Local_MAC={self.local_mac}")
        except Exception as e:
            print(f"[!] Blocker Info Error: {e}")

    def start(self):
        if not self.thread:
            self.stop_event.clear()
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def block(self, mac, ip):
        self.blocked_macs.add((mac, ip))
        print(f"[!] Targeting {mac} ({ip}) for disconnection.")

    def unblock(self, mac, ip):
        if (mac, ip) in self.blocked_macs:
            self.blocked_macs.remove((mac, ip))
            # Send 'Restoration' packets to fix the ARP tables
            self.restore(mac, ip)

    def restore(self, target_mac, target_ip):
        """Tell the truth to restore connection."""
        if not self.gateway_mac: return
        try:
            # Tell device the real GW MAC
            pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            # Tell GW the real device MAC
            pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=target_mac)
            send(pkt1, count=5, verbose=False, iface=self.interface)
            send(pkt2, count=5, verbose=False, iface=self.interface)
        except: pass

    def run(self):
        print("Active Blocker thread started...")
        while not self.stop_event.is_set():
            if not self.gateway_mac or not self.local_mac:
                self.refresh_network_info(self.interface)
                time.sleep(5)
                continue

            for mac, ip in list(self.blocked_macs):
                try:
                    # 1. Tell Target: "I am the Gateway"
                    pkt_target = ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.local_mac)
                    # 2. Tell Gateway: "I am the Target"
                    pkt_gw = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.local_mac)
                    
                    send(pkt_target, verbose=False, iface=self.interface)
                    send(pkt_gw, verbose=False, iface=self.interface)
                except Exception as e:
                    print(f"[!] Block send error: {e}")
            
            time.sleep(1) # High frequency for effective block

class NetworkSniffer:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()
        self.db_queue = queue.Queue()
        self.db_worker = DatabaseWorker(self.db_queue)
        self.db_worker.start()
        
        self.interface = None
        self.blocker = ActiveBlocker()
        self.blocker.start()
        
        self.alert_cooldown = {}

    def get_interfaces(self): return get_if_list()

    def set_interface(self, iface):
        self.interface = iface
        self.blocker.refresh_network_info(iface)
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
            if now < self.alert_cooldown[key] + timedelta(seconds=60): return False
        self.alert_cooldown[key] = now
        return True

    def scan_network(self):
        try:
            gw = self.blocker.gateway_ip
            prefix = ".".join(gw.split(".")[:-1])
            target = f"{prefix}.0/24"
            from scapy.all import srp
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=False, iface=self.interface)
            for snd, rcv in ans: self.process_packet(rcv)
            return len(ans)
        except Exception as e: return 0

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
                crud.create_device(db, schemas.DeviceCreate(mac_address=hwsrc, ip_address=psrc))
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
        finally: db.close()

    def run(self):
        try:
            sniff(iface=self.interface, filter="arp", prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e: print(f"[!] SNIFFER ERROR: {e}")

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.db_queue.put(None)
