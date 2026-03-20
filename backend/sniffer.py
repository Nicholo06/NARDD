from scapy.all import sniff, ARP, send, Ether, conf, get_if_list, srp, get_if_hwaddr, getmacbyip
import threading
import time
import platform
import queue
import os
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
            # Check IP Forwarding on Linux
            if platform.system() == "Linux":
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    if f.read().strip() == "1":
                        print("\n[⚠️] WARNING: IP Forwarding is ENABLED on your Kali laptop.")
                        print("[⚠️] Your laptop is FORWARDING blocked traffic instead of dropping it.")
                        print("[⚠️] Run this to fix: sudo sysctl -w net.ipv4.ip_forward=0\n")

            self.local_mac = get_if_hwaddr(self.interface or conf.iface)
            print(f"[*] Resolving Gateway MAC for {self.gateway_ip}...")
            self.gateway_mac = getmacbyip(self.gateway_ip)
            
            if not self.gateway_mac:
                # Fallback: Try a broadcast ARP to find gateway
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.gateway_ip), timeout=2, verbose=False, iface=self.interface)
                if ans: self.gateway_mac = ans[0][1].hwsrc

            print(f"[*] BLOCKER STATUS: GW_MAC={self.gateway_mac}, Local_MAC={self.local_mac}, Iface={self.interface or 'Default'}")
        except Exception as e:
            print(f"[!] Blocker Init Error: {e}")

    def start(self):
        if not self.thread:
            self.stop_event.clear()
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def block(self, mac, ip):
        self.blocked_macs.add((mac, ip))
        print(f"[🔥] BLOCKING START: {mac} ({ip})")

    def unblock(self, mac, ip):
        if (mac, ip) in self.blocked_macs:
            self.blocked_macs.remove((mac, ip))
            print(f"[✅] BLOCKING STOP: {mac} ({ip})")
            for _ in range(5): # Send restoration burst
                self.restore(mac, ip)

    def restore(self, target_mac, target_ip):
        if not self.gateway_mac: return
        try:
            pkt1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            pkt2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip, hwsrc=target_mac)
            send(pkt1, verbose=False, iface=self.interface)
            send(pkt2, verbose=False, iface=self.interface)
        except: pass

    def run(self):
        print("Active Blocker engine online.")
        while not self.stop_event.is_set():
            if not self.gateway_mac or not self.local_mac:
                self.refresh_network_info(self.interface)
                time.sleep(3)
                continue

            for mac, ip in list(self.blocked_macs):
                try:
                    # High-Intensity Bi-directional Poisoning
                    # Tell Target we are the Gateway
                    p1 = ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.local_mac)
                    # Tell Gateway we are the Target
                    p2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.local_mac)
                    
                    send(p1, verbose=False, iface=self.interface)
                    send(p2, verbose=False, iface=self.interface)
                except: pass
            
            time.sleep(0.5) # Fast 500ms cycle to beat modern ARP protections

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
    def get_capabilities(self):
        return {
            "os": platform.system(), "is_linux": platform.system() == "Linux",
            "can_inject": True, "gateway": self.blocker.gateway_ip,
            "current_interface": self.interface or "Default"
        }

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
                            self.send_alert("ARP_SPOOF", "CRITICAL", f"IP Conflict: {psrc}")
                    else: self.queue_task(crud.update_device_ip, hwsrc, psrc)
                else: self.queue_task(crud.update_device_ip, hwsrc, psrc)
        finally: db.close()

    def run(self):
        try: sniff(iface=self.interface, filter="arp", prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except: pass
    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
    def stop(self):
        self.stop_event.set()
        self.db_queue.put(None)
