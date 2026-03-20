from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from datetime import datetime
from .database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String, unique=True, index=True)
    ip_address = Column(String)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    is_trusted = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    is_online = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    severity = Column(String)
    message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
