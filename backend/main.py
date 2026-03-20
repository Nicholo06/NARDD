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

# Initialize DB
models.Base.metadata.create_all(bind=database.engine)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WS] Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[WS] Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        print(f"[WS] Broadcasting alert: {message.get('type')}")
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                print(f"Error broadcasting to a client: {e}")

manager = ConnectionManager()

main_loop = None

def alert_callback(alert_data):
    global main_loop
    if main_loop:
        # Safely schedule the broadcast on the main event loop from the sniffer thread
        asyncio.run_coroutine_threadsafe(manager.broadcast(alert_data), main_loop)

net_sniffer = sniffer.NetworkSniffer(alert_callback=alert_callback)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    # Start sniffer on startup
    net_sniffer.start()
    yield
    # Stop sniffer on shutdown
    net_sniffer.stop()

app = FastAPI(lifespan=lifespan)

# Allow CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes
@app.get("/config")
def get_config():
    return net_sniffer.get_capabilities()

@app.post("/devices/{mac}/block")
def block_device(mac: str):
    net_sniffer.blocker.block(mac)
    return {"message": f"Blocking device {mac}"}

@app.post("/devices/{mac}/unblock")
def unblock_device(mac: str):
    net_sniffer.blocker.unblock(mac)
    return {"message": f"Unblocking device {mac}"}

@app.get("/blocked")
def get_blocked():
    return list(net_sniffer.blocker.blocked_macs)

@app.get("/devices", response_model=list[schemas.Device])
def get_devices(db: Session = Depends(database.get_db)):
    return crud.get_devices(db)

@app.patch("/devices/{mac}/trust", response_model=schemas.Device)
def update_device_trust(mac: str, is_trusted: bool, db: Session = Depends(database.get_db)):
    device = crud.update_device_trust(db, mac, is_trusted)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@app.get("/alerts", response_model=list[schemas.Alert])
def get_alerts(db: Session = Depends(database.get_db)):
    return crud.get_alerts(db)

# WebSocket Endpoint
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Serve Frontend
# Make sure the frontend folder exists relative to where you run uvicorn
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_path, "index.html"))
