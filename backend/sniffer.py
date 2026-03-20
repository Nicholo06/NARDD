from scapy.all import sniff, ARP, send, Ether, conf, get_if_list, srp, get_if_hwaddr, getmacbyip, NBNSQueryRequest, UDP, DNS, IP, DHCP, BOOTP
import threading
import time
import platform
import queue
import os
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
        self.blocked_macs = set()
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
        except: pass

    def start(self):
        if not self.thread:
            self.stop_event.clear()
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def block(self, mac, ip): self.blocked_macs.add((mac, ip))
    def unblock(self, mac, ip):
        if (mac, ip) in self.blocked_macs:
            self.blocked_macs.remove((mac, ip))
            for _ in range(5): self.restore(mac, ip)

    def restore(self, target_mac, target_ip):
        if not self.gateway_mac: return
        try:
            pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=target_mac)
            send(pkt1, verbose=False, iface=self.interface)
            send(pkt2, verbose=False, iface=self.interface)
        except: pass

    def run(self):
        while not self.stop_event.is_set():
            if not self.gateway_mac or not self.local_mac:
                self.refresh_network_info(self.interface)
                time.sleep(3)
                continue
            for mac, ip in list(self.blocked_macs):
                try:
                    p1 = ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.local_mac)
                    p2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.local_mac)
                    send(p1, verbose=False, iface=self.interface)
                    send(p2, verbose=False, iface=self.interface)
                except: pass
            time.sleep(0.5)

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
        self.vendor_cache = {}

    def get_interfaces(self): return get_if_list()
    def set_interface(self, iface):
        self.interface = iface
        self.blocker.refresh_network_info(iface)

    def get_capabilities(self):
        return {
            "os": platform.system(), "is_linux": platform.system() == "Linux",
            "can_inject": True, "gateway": self.blocker.gateway_ip,
            "current_interface": self.interface or "Default"
        }

    def get_vendor(self, mac):
        # Check for Randomized MAC (Private Wi-Fi Address)
        # If the second character of MAC is 2, 6, A, or E, it's a randomized MAC
        second_char = mac[1].upper()
        if second_char in ['2', '6', 'A', 'E']:
            return "Randomized (Private) Address"

        prefix = mac.upper().replace(":", "")[:6]
        if prefix in self.vendor_cache: return self.vendor_cache[prefix]
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
            if response.status_code == 200:
                self.vendor_cache[prefix] = response.text
                return response.text
        except: pass
        return "Unknown Vendor"

    def scan_network(self):
        try:
            gw = self.blocker.gateway_ip
            prefix = ".".join(gw.split(".")[:-1])
            target = f"{prefix}.0/24"
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=False, iface=self.interface)
            for _, rcv in ans: self.process_packet(rcv)
            return len(ans)
        except: return 0

    def queue_task(self, func, *args, **kwargs):
        self.db_queue.put((func, args, kwargs))

    def send_alert(self, alert_type, severity, message, extra=None):
        self.queue_task(crud.create_alert, schemas.AlertCreate(type=alert_type, severity=severity, message=message))
        if self.alert_callback:
            data = {"type": alert_type, "severity": severity, "message": message, "timestamp": datetime.utcnow().isoformat()}
            if extra: data.update(extra)
            self.alert_callback(data)

    def _update_info(self, mac, hostname=None, vendor=None):
        db = SessionLocal()
        try:
            device = crud.get_device_by_mac(db, mac)
            if device:
                # Avoid redundant updates
                if (hostname and device.hostname != hostname) or (vendor and device.vendor != vendor):
                    crud.update_device_info(db, mac, hostname=hostname, vendor=vendor)
                    if self.alert_callback:
                        self.alert_callback({"type": "INFO_UPDATE", "mac": mac, "hostname": hostname or device.hostname, "vendor": vendor or device.vendor})
        finally: db.close()

    def process_packet(self, packet):
        # 1. ARP: Base Discovery
        if packet.haslayer(ARP):
            psrc, hwsrc = packet[ARP].psrc, packet[ARP].hwsrc
            db = SessionLocal()
            try:
                device = crud.get_device_by_mac(db, hwsrc)
                if not device:
                    vendor = self.get_vendor(hwsrc)
                    crud.create_device(db, schemas.DeviceCreate(mac_address=hwsrc, ip_address=psrc, vendor=vendor))
                    self.send_alert("NEW_DEVICE", "INFO", f"New device: {vendor} ({psrc})", {"mac": hwsrc, "ip": psrc, "vendor": vendor})
                else:
                    if device.ip_address != psrc:
                        other = crud.get_device_by_ip(db, psrc)
                        if other and other.mac_address != hwsrc:
                            if self.should_alert(f"SPOOF_{psrc}"):
                                self.send_alert("ARP_SPOOF", "CRITICAL", f"IP Conflict: {psrc}")
                        else: self.queue_task(crud.update_device_ip, hwsrc, psrc)
                    else: self.queue_task(crud.update_device_ip, hwsrc, psrc)
            finally: db.close()

        # 2. DHCP: High-Accuracy Discovery (Names + OS)
        if packet.haslayer(DHCP):
            mac = packet[Ether].src
            hostname = None
            options = packet[DHCP].options
            for opt in options:
                if isinstance(opt, tuple):
                    if opt[0] == 'hostname':
                        hostname = opt[1].decode()
                    if opt[0] == 'vendor_class_id':
                        v_id = opt[1].decode()
                        self._update_info(mac, vendor=f"OS: {v_id}")
            if hostname:
                self._update_info(mac, hostname=hostname)

        # 3. mDNS (UDP 5353) / NBNS (UDP 137)
        if packet.haslayer(NBNSQueryRequest):
            name = packet[NBNSQueryRequest].QUESTION_NAME.decode().strip()
            mac = packet[Ether].src
            if name: self._update_info(mac, hostname=name)

        if packet.haslayer(UDP) and packet[UDP].dport == 5353:
            mac = packet[Ether].src
            if packet.haslayer(DNS) and packet[DNS].ancount > 0:
                for i in range(packet[DNS].ancount):
                    res = packet[DNS].an[i]
                    if res.type == 12: # PTR
                        name = res.rdata.decode().split(".")[0]
                        if name: self._update_info(mac, hostname=name)

        # 4. SSDP (UPnP) Discovery - UDP 1900
        if packet.haslayer(UDP) and packet[UDP].dport == 1900:
            mac = packet[Ether].src
            payload = str(packet[UDP].payload)
            if "SERVER:" in payload:
                server_info = re.search(r"SERVER: (.*)\r\n", payload)
                if server_info:
                    self._update_info(mac, vendor=server_info.group(1))

    def run(self):
        try:
            # Sniff ARP, DHCP, NBNS, mDNS, SSDP
            filter_str = "arp or port 67 or port 68 or port 137 or port 5353 or port 1900"
            sniff(iface=self.interface, filter=filter_str, prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e: print(f"[!] SNIFFER ERROR: {e}")

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.db_queue.put(None)
