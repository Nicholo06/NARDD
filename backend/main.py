from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import asyncio
import json
from . import models, crud, schemas, database, sniffer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

models.Base.metadata.create_all(bind=database.engine)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except: pass

manager = ConnectionManager()
main_loop = None

def alert_callback(alert_data):
    global main_loop
    if main_loop:
        asyncio.run_coroutine_threadsafe(manager.broadcast(alert_data), main_loop)

net_sniffer = sniffer.NetworkSniffer(alert_callback=alert_callback)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    net_sniffer.start()
    yield
    net_sniffer.stop()

app = FastAPI(lifespan=lifespan)

# Hardened CORS: Only allow local access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/config")
def get_config():
    return net_sniffer.get_capabilities()

@app.get("/interfaces")
def get_interfaces():
    return net_sniffer.get_interfaces()

@app.post("/interfaces/set")
def set_interface(iface: str):
    net_sniffer.stop()
    net_sniffer.set_interface(iface)
    net_sniffer.start()
    return {"message": f"Interface changed to {iface}"}

@app.post("/devices/{mac}/block")
def block_device(mac: str, ip: str):
    net_sniffer.blocker.block(mac, ip)
    return {"message": f"Blocking {mac} ({ip})"}

@app.post("/devices/{mac}/unblock")
def unblock_device(mac: str, ip: str):
    net_sniffer.blocker.unblock(mac, ip)
    return {"message": f"Unblocking {mac} ({ip})"}

@app.get("/blocked")
def get_blocked():
    return list(net_sniffer.blocker.blocked_macs)

@app.post("/scan")
def scan_network():
    count = net_sniffer.scan_network()
    return {"message": f"Scan complete. Found {count} devices."}

@app.get("/devices", response_model=list[schemas.Device])
def get_devices(db: Session = Depends(database.get_db)):
    return crud.get_devices(db)

@app.patch("/devices/{mac}/trust", response_model=schemas.Device)
def update_device_trust(mac: str, is_trusted: bool, db: Session = Depends(database.get_db)):
    device = crud.update_device_trust(db, mac, is_trusted)
    return device

@app.get("/alerts", response_model=list[schemas.Alert])
def get_alerts(db: Session = Depends(database.get_db)):
    return crud.get_alerts(db)

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_path, "index.html"))
