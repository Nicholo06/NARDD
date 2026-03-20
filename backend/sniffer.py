from scapy.all import sniff, ARP, send, Ether, conf, get_if_list, srp, get_if_hwaddr, getmacbyip, NBNSQueryRequest, NBNSNodeStatusRequest, UDP, DNS, IP, DHCP, ICMP, sr1, get_if_addr
import threading
import time
import platform
import queue
import socket
import requests
import re
from datetime import datetime, timedelta
from .database import SessionLocal
from . import crud, schemas

class DatabaseWorker(threading.Thread):
    def __init__(self, task_queue):
        super().__init__(daemon=True)
        self.task_queue = task_queue
    def run(self):
        while True:
            try:
                task = self.task_queue.get()
                if task is None: break
                db = SessionLocal()
                try: task[0](db, *task[1], **task[2])
                except: pass
                finally: db.close()
            except: pass

class ActiveBlocker:
    def __init__(self, interface=None):
        self.blocked_macs = {} # (mac, ip) -> timestamp
        self.stop_event = threading.Event()
        self.interface = interface
        self.gateway_ip = self._detect_gateway()
        self.gateway_mac = None
        self.local_mac = None
        self._load_from_db()

    def _detect_gateway(self):
        try: return conf.route.route("0.0.0.0")[2]
        except: return "192.168.1.1"

    def _load_from_db(self):
        db = SessionLocal()
        try:
            blocked = crud.get_blocked_devices(db)
            for d in blocked:
                self.blocked_macs[(d.mac_address, d.ip_address)] = time.time()
        finally: db.close()

    def refresh_network_info(self, interface):
        self.interface = interface
        try:
            self.local_mac = get_if_hwaddr(self.interface or conf.iface)
            self.gateway_mac = getmacbyip(self.gateway_ip)
        except: pass

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def block(self, mac, ip): self.blocked_macs[(mac, ip)] = time.time()
    def unblock(self, mac, ip):
        if (mac, ip) in self.blocked_macs:
            del self.blocked_macs[(mac, ip)]
            for _ in range(5): self.restore(mac, ip)

    def restore(self, target_mac, target_ip):
        if not self.gateway_mac: return
        try:
            pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=target_mac)
            send(pkt1, verbose=False, iface=self.interface); send(pkt2, verbose=False, iface=self.interface)
        except: pass

    def run(self):
        while not self.stop_event.is_set():
            if not self.gateway_mac or not self.local_mac:
                self.refresh_network_info(self.interface); time.sleep(3); continue
            for (mac, ip) in list(self.blocked_macs.keys()):
                try:
                    p1 = ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.local_mac)
                    p2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.local_mac)
                    send(p1, verbose=False, iface=self.interface); send(p2, verbose=False, iface=self.interface)
                except: pass
            time.sleep(0.5)

class NetworkSniffer:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()
        self.db_queue = queue.Queue()
        self.db_worker = DatabaseWorker(self.db_queue); self.db_worker.start()
        self.interface = None
        self.blocker = ActiveBlocker()
        self.blocker.start()
        self.alert_cooldown = {}
        self.vendor_cache = {}
        self.scan_tracker = {}
        # Start Heartbeat Thread
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def get_interfaces(self): return get_if_list()
    def set_interface(self, iface): self.interface = iface; self.blocker.refresh_network_info(iface)
    def get_capabilities(self):
        return {"os": platform.system(), "is_linux": platform.system() == "Linux", "can_inject": True, "gateway": self.blocker.gateway_ip, "current_interface": self.interface or "Default"}

    def get_vendor(self, mac):
        if mac[1].upper() in ['2', '6', 'A', 'E']: return "Randomized (Private) Address"
        prefix = mac.upper().replace(":", "")[:6]
        if prefix in self.vendor_cache: return self.vendor_cache[prefix]
        try:
            time.sleep(0.5) # Basic rate limiting
            res = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
            if res.status_code == 200:
                self.vendor_cache[prefix] = res.text
                return res.text
        except: pass
        return "Unknown Vendor"

    def interrogate_device(self, ip, mac):
        if ip == self.blocker.gateway_ip:
            self._update_info(mac, hostname="Default Gateway", vendor="Network Router")
            return
        try:
            ans = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=False)
            if ans and ans.ttl <= 64: self._update_info(mac, vendor="Apple iOS / Linux (TTL 64)")
            elif ans and ans.ttl > 64: self._update_info(mac, vendor="Windows Device (TTL 128)")
        except: pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, 62078)) == 0: self._update_info(mac, hostname="iPhone / iPad", vendor="Apple Inc.")
        except: pass
        try:
            pkt = IP(dst=ip)/UDP(sport=137, dport=137)/NBNSNodeStatusRequest()
            ans = srp(Ether(dst=mac)/pkt, timeout=1, verbose=False, iface=self.interface)[0]
            if ans: self._update_info(mac, hostname=ans[0][1].getlayer(NBNSNodeStatusRequest).NAME.decode().strip())
        except: pass

    def scan_network(self):
        try:
            # Dynamic Subnet Detection
            local_ip = get_if_addr(self.interface or conf.iface)
            prefix = ".".join(local_ip.split(".")[:-1])
            target = f"{prefix}.0/24"
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=False, iface=self.interface)
            for _, rcv in ans: 
                self.process_packet(rcv)
                threading.Thread(target=self.interrogate_device, args=(rcv[ARP].psrc, rcv[ARP].hwsrc), daemon=True).start()
            return len(ans)
        except: return 0

    def heartbeat_loop(self):
        """Check for offline devices every 2 minutes."""
        while not self.stop_event.is_set():
            time.sleep(120)
            db = SessionLocal()
            try:
                devices = crud.get_devices(db)
                now = datetime.utcnow()
                for d in devices:
                    if d.last_seen < now - timedelta(minutes=5):
                        if d.is_online:
                            crud.update_device_online(db, d.mac_address, False)
                            if self.alert_callback: self.alert_callback({"type": "STATUS_UPDATE", "mac": d.mac_address, "online": False})
            finally: db.close()

    def queue_task(self, func, *args, **kwargs): self.db_queue.put((func, args, kwargs))
    def send_alert(self, alert_type, severity, message, extra=None):
        self.queue_task(crud.create_alert, schemas.AlertCreate(type=alert_type, severity=severity, message=message))
        if self.alert_callback:
            data = {"type": alert_type, "severity": severity, "message": message, "timestamp": datetime.utcnow().isoformat()}
            if extra: data.update(extra)
            self.alert_callback(data)

    def should_alert(self, key, cooldown=60):
        now = datetime.now()
        if key in self.alert_cooldown:
            if now < self.alert_cooldown[key] + timedelta(seconds=cooldown): return False
        self.alert_cooldown[key] = now
        return True

    def _update_info(self, mac, hostname=None, vendor=None):
        db = SessionLocal()
        try:
            device = crud.get_device_by_mac(db, mac)
            if device:
                if vendor and "Apple" in (device.vendor or "") and "Apple" not in vendor: vendor = None
                if (hostname and device.hostname != hostname) or (vendor and device.vendor != vendor):
                    crud.update_device_info(db, mac, hostname=hostname, vendor=vendor)
                    if self.alert_callback: self.alert_callback({"type": "INFO_UPDATE", "mac": mac, "hostname": hostname or device.hostname, "vendor": vendor or device.vendor})
        finally: db.close()

    def process_packet(self, packet):
        try:
            if packet.haslayer(ARP):
                psrc, hwsrc = packet[ARP].psrc, packet[ARP].hwsrc
                db = SessionLocal()
                try:
                    device = crud.get_device_by_mac(db, hwsrc)
                    if not device:
                        vendor = self.get_vendor(hwsrc)
                        try:
                            crud.create_device(db, schemas.DeviceCreate(mac_address=hwsrc, ip_address=psrc, vendor=vendor))
                            self.send_alert("NEW_DEVICE", "INFO", f"New device: {vendor} ({psrc})", {"mac": hwsrc, "ip": psrc, "vendor": vendor})
                            threading.Thread(target=self.interrogate_device, args=(psrc, hwsrc), daemon=True).start()
                        except: pass
                    else:
                        # Mark device as online if it was offline
                        if not device.is_online:
                            crud.update_device_online(db, hwsrc, True)
                            if self.alert_callback: self.alert_callback({"type": "STATUS_UPDATE", "mac": hwsrc, "online": True})
                        
                        if device.ip_address != psrc:
                            other = crud.get_device_by_ip(db, psrc)
                            if other and other.mac_address != hwsrc:
                                if self.should_alert(f"SPOOF_{psrc}"): self.send_alert("ARP_SPOOF", "CRITICAL", f"IP Conflict: {psrc}")
                            else:
                                if not device.is_trusted and self.should_alert(f"MOVE_{hwsrc}"):
                                    self.send_alert("SUSPICIOUS_MOVE", "WARNING", f"Untrusted device {hwsrc} moved to {psrc}")
                                crud.update_device_ip(db, hwsrc, psrc)
                        else:
                            # Update last_seen to keep it 'online'
                            crud.update_device_ip(db, hwsrc, psrc)
                finally: db.close()

            if packet.haslayer(DHCP):
                mac = packet[Ether].src; options = packet[DHCP].options
                for opt in options:
                    if isinstance(opt, tuple):
                        if opt[0] == 'hostname': self._update_info(mac, hostname=opt[1].decode())
                        if opt[0] == 'vendor_class_id': self._update_info(mac, vendor=f"OS: {opt[1].decode()}")
            if packet.haslayer(NBNSQueryRequest):
                name = packet[NBNSQueryRequest].QUESTION_NAME.decode().strip()
                if name: self._update_info(packet[Ether].src, hostname=name)
        except: pass

    def run(self):
        try:
            filter_str = "arp or port 67 or port 68 or port 137 or port 5353 or port 1900"
            sniff(iface=self.interface, filter=filter_str, prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e: print(f"[!] SNIFFER ERROR: {e}")

    def start(self): threading.Thread(target=self.run, daemon=True).start()
    def stop(self): self.stop_event.set(); self.db_queue.put(None)
