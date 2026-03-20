from scapy.all import sniff, ARP
import threading
from .database import SessionLocal
from . import crud, schemas
from datetime import datetime

class NetworkSniffer:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.stop_event = threading.Event()

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            psrc = packet[ARP].psrc  # Source IP
            hwsrc = packet[ARP].hwsrc  # Source MAC
            
            db = SessionLocal()
            try:
                device = crud.get_device_by_mac(db, hwsrc)
                if not device:
                    # NEW_DEVICE detected
                    new_device = schemas.DeviceCreate(
                        mac_address=hwsrc,
                        ip_address=psrc,
                        is_trusted=False
                    )
                    crud.create_device(db, new_device)
                    
                    alert = schemas.AlertCreate(
                        type="NEW_DEVICE",
                        severity="INFO",
                        message=f"New device detected: MAC={hwsrc}, IP={psrc}"
                    )
                    crud.create_alert(db, alert)
                    
                    if self.alert_callback:
                        self.alert_callback({
                            "type": "NEW_DEVICE",
                            "severity": "INFO",
                            "message": alert.message,
                            "mac": hwsrc,
                            "ip": psrc
                        })
                else:
                    # Check for ARP_SPOOFING
                    if device.ip_address != psrc:
                        alert = schemas.AlertCreate(
                            type="ARP_SPOOF",
                            severity="CRITICAL",
                            message=f"ARP Spoofing alert: MAC={hwsrc} was {device.ip_address}, now claiming {psrc}"
                        )
                        crud.create_alert(db, alert)
                        
                        if self.alert_callback:
                            self.alert_callback({
                                "type": "ARP_SPOOF",
                                "severity": "CRITICAL",
                                "message": alert.message,
                                "mac": hwsrc,
                                "old_ip": device.ip_address,
                                "new_ip": psrc
                            })
                    
                    # Update last seen and current IP (in case of legitimate DHCP change, 
                    # but logic here is simple: if it's already known but IP changed it flags spoof, 
                    # in a real app we might handle IP changes differently if trusted)
                    crud.update_device_ip(db, hwsrc, psrc)
            finally:
                db.close()

    def run(self):
        print("Sniffer started...")
        sniff(filter="arp", prn=self.process_packet, store=0, stop_filter=lambda x: self.stop_event.is_set())

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
