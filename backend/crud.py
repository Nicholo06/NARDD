from sqlalchemy.orm import Session
from datetime import datetime
from . import models, schemas

def get_device_by_mac(db: Session, mac_address: str):
    return db.query(models.Device).filter(models.Device.mac_address == mac_address).first()

def create_device(db: Session, device: schemas.DeviceCreate):
    db_device = models.Device(**device.model_dump())
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device

def update_device_ip(db: Session, mac_address: str, ip_address: str):
    db_device = get_device_by_mac(db, mac_address)
    if db_device:
        db_device.ip_address = ip_address
        db_device.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(db_device)
    return db_device

def update_device_trust(db: Session, mac_address: str, is_trusted: bool):
    db_device = get_device_by_mac(db, mac_address)
    if db_device:
        db_device.is_trusted = is_trusted
        db.commit()
        db.refresh(db_device)
    return db_device

def get_devices(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Device).offset(skip).limit(limit).all()

def create_alert(db: Session, alert: schemas.AlertCreate):
    db_alert = models.Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

def get_alerts(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Alert).order_by(models.Alert.timestamp.desc()).offset(skip).limit(limit).all()
