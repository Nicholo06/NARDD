from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class DeviceBase(BaseModel):
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    is_trusted: bool = False

class DeviceCreate(DeviceBase):
    pass

class Device(DeviceBase):
    id: int
    last_seen: datetime

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    type: str
    severity: str
    message: str

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True
