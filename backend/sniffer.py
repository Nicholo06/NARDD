from scapy.all import sniff, ARP, send, Ether
import threading
import time
import platform
from datetime import datetime, timedelta
from .database import SessionLocal
from . import crud, schemas

class ActiveBlocker:
    def __init__(self):
        self.blocked_macs = set()
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        if not self.thread:
            self.stop_event.clear()
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def block(self, mac):
        self.blocked_macs.add(mac)
        print(f"[!] Active Blocking enabled for: {mac}")

    def unblock(self, mac):
        if mac in self.blocked_macs:
            self.blocked_macs.remove(mac)
            print(f"[!] Active Blocking disabled for: {mac}")

    def run(self):
        print("Active Blocker thread started...")
        while not self.stop_event.is_set():
            for mac in list(self.blocked_macs):
                try:
                    # Broadcast a 'fake' ARP reply saying this MAC is now at a dead-end
                    pkt = Ether(dst=mac)/ARP(op=2, hwsrc="00:00:00:00:00:00", psrc="192.168.1.1", hwdst=mac)
                    send(pkt, verbose=False)
                except:
                    pass
            time.sleep(2)

class NetworkSniffer:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()
        self.blocker = ActiveBlocker()
        self.blocker.start()
        # Track last alert per MAC to avoid spamming (60-second cooldown)
        self.alert_cooldown = {} 

    def get_capabilities(self):
        return {
            "os": platform.system(),
            "is_linux": platform.system() == "Linux",
            "can_inject": True 
        }

    def should_alert(self, key):
        now = datetime.now()
        if key in self.alert_cooldown:
            if now < self.alert_cooldown[key] + timedelta(seconds=60):
                return False
        self.alert_cooldown[key] = now
        return True

    def send_alert(self, db, alert_type, severity, message, extra=None):
        alert_in = schemas.AlertCreate(type=alert_type, severity=severity, message=message)
        crud.create_alert(db, alert_in)
        if self.alert_callback:
            data = {"type": alert_type, "severity": severity, "message": message}
            if extra: data.update(extra)
            self.alert_callback(data)

    def process_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        psrc = packet[ARP].psrc  # IP
        hwsrc = packet[ARP].hwsrc  # MAC
        
        db = SessionLocal()
        try:
            device = crud.get_device_by_mac(db, hwsrc)
            
            # Case 1: Brand New Device
            if not device:
                new_device = schemas.DeviceCreate(mac_address=hwsrc, ip_address=psrc, is_trusted=False)
                crud.create_device(db, new_device)
                self.send_alert(db, "NEW_DEVICE", "INFO", f"New device detected: {hwsrc} at {psrc}", {"mac": hwsrc, "ip": psrc})
                return

            # Case 2: Known Device, Different IP (Potential DHCP or IP Change)
            if device.ip_address != psrc:
                # Check for IP CONFLICT (Another MAC claiming the same IP)
                other_device = crud.get_device_by_ip(db, psrc)
                
                if other_device and other_device.mac_address != hwsrc:
                    # REAL ARP SPOOF: Two MACs claiming one IP
                    if self.should_alert(f"SPOOF_{psrc}"):
                        self.send_alert(db, "ARP_SPOOF", "CRITICAL", 
                            f"SECURITY ALERT: IP Conflict detected! {psrc} is claimed by both {other_device.mac_address} and {hwsrc}",
                            {"mac": hwsrc, "conflict_with": other_device.mac_address, "ip": psrc})
                else:
                    # NORMAL IP CHANGE (Likely DHCP)
                    # We don't alert on this anymore (unless you want 'INFO')
                    # Just update the record silently.
                    crud.update_device_ip(db, hwsrc, psrc)
            
            # Update last_seen regardless
            crud.update_device_ip(db, hwsrc, psrc)

        finally:
            db.close()

    def run(self):
        print("Sniffer started...")
        try:
            sniff(filter="arp", prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            print(f"\n[!] SNIFFER ERROR: {e}")

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
