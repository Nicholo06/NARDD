from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from contextlib import asynccontextmanager
import asyncio
import json
from . import models, crud, schemas, database, sniffer

# Initialize DB
models.Base.metadata.create_all(bind=database.engine)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                print(f"Error broadcasting to a client: {e}")

manager = ConnectionManager()

def alert_callback(alert_data):
    # This runs in the sniffer thread, so we need to use asyncio.run_coroutine_threadsafe 
    # if we want to bridge to the main event loop for WebSockets.
    # However, standard FastAPI WebSockets are usually tied to the main event loop.
    # We will use a queue or similar if needed, but for simplicity here,
    # let's assume we can push it.
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(alert_data), loop)

net_sniffer = sniffer.NetworkSniffer(alert_callback=alert_callback)

@asynccontextmanager
async def lifespan(app: FastAPI):
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

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
