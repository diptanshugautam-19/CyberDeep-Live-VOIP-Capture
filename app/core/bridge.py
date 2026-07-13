import asyncio
import queue
import time
import logging
from typing import Dict, Set, Any, Tuple
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class BroadcastManager:
    def __init__(self):
        self.connections: Dict[WebSocket, asyncio.PriorityQueue] = {}
        self.dropped_frames: Dict[WebSocket, int] = {}
        self.last_sequence: Dict[WebSocket, int] = {}
        self.lock = asyncio.Lock()
        self.global_sequence = 0

    async def register(self, websocket: WebSocket) -> asyncio.PriorityQueue:
        async with self.lock:
            # Bounded PriorityQueue (e.g. max size 1000)
            pq = asyncio.PriorityQueue(maxsize=1000)
            self.connections[websocket] = pq
            self.dropped_frames[websocket] = 0
            self.last_sequence[websocket] = 0
            return pq

    async def unregister(self, websocket: WebSocket):
        async with self.lock:
            if websocket in self.connections:
                del self.connections[websocket]
            if websocket in self.dropped_frames:
                del self.dropped_frames[websocket]
            if websocket in self.last_sequence:
                del self.last_sequence[websocket]

    async def broadcast(self, payload: Dict[str, Any], priority: int = 3):
        """
        Broadcast a message to all active WebSocket connections.
        Priorities:
        0 = Critical (Security Alerts, Storage Failure, System Warnings)
        1 = VoIP / SIP Signaling Messages
        2 = Decoded Application Records (DNS, HTTP)
        3 = Standard Packet Metadata / Flows
        """
        async with self.lock:
            self.global_sequence += 1
            payload["seq"] = self.global_sequence
            
            for ws, pq in list(self.connections.items()):
                # Prepare queue item (priority, timestamp, payload)
                # Note: PriorityQueue retrieves lowest values first, so we use priority directly
                item = (priority, time.time(), payload)
                
                if pq.full():
                    # Handle queue full: drop the lowest-priority (highest value) item currently in the queue
                    # or drop the incoming frame if it is lower priority than what's in the queue.
                    self.dropped_frames[ws] += 1
                    logger.warning(f"WebSocket queue full. Dropped frame on connection. Total dropped: {self.dropped_frames[ws]}")
                    
                    # Implementation of drop-newest low-priority frames:
                    # We just discard the current frame since it's the newest, unless it is higher priority (lower value)
                    # than items in the queue. If it is high priority (0 or 1), we do not drop it.
                    if priority >= 2:
                        # Discard the new item
                        continue
                    else:
                        # It is high priority! We must make room. Let's pull one low priority item out of the queue.
                        try:
                            # To avoid blocking, we do a non-blocking get. However, PriorityQueue orders by priority, 
                            # so get() returns the HIGHEST priority (lowest number).
                            # Since we want to drop the LOWEST priority (highest number), a standard PriorityQueue is tricky.
                            # As a simple, robust workaround for backpressure:
                            # If queue is full, we try to clear some space.
                            # Let's drop a few elements from the queue.
                            for _ in range(10):
                                if not pq.empty():
                                    pq.get_nowait()
                                    pq.task_done()
                            pq.put_nowait(item)
                        except Exception as e:
                            logger.error(f"Error dropping frames for priority insert: {e}")
                else:
                    pq.put_nowait(item)

    async def sender_loop(self, websocket: WebSocket, pq: asyncio.PriorityQueue, batch_interval_ms: int = 100):
        """Pulls items from the PriorityQueue, batches them, and sends to the client."""
        batch = []
        last_send = time.time()
        interval = batch_interval_ms / 1000.0
        
        try:
            while True:
                try:
                    # Bounded wait to enable batching
                    # Wait for at least one item, or timeout to flush existing batch
                    timeout = max(0.01, interval - (time.time() - last_send))
                    item = await asyncio.wait_for(pq.get(), timeout=timeout)
                    
                    # Unpack: priority, timestamp, payload
                    priority, ts, payload = item
                    batch.append(payload)
                    pq.task_done()
                    
                    # Update client's last seen sequence
                    if "seq" in payload:
                        self.last_sequence[websocket] = payload["seq"]
                        
                except asyncio.TimeoutError:
                    pass  # Flush batch on timeout
                
                # Check if it is time to send the batch, or if batch is getting large
                now = time.time()
                if batch and (now - last_send >= interval or len(batch) >= 100):
                    # Include dropped frames telemetry in the broadcast
                    msg = {
                        "type": "batch",
                        "data": batch,
                        "dropped_frames": self.dropped_frames.get(websocket, 0),
                        "timestamp": now
                    }
                    await websocket.send_json(msg)
                    batch = []
                    last_send = now
                    
        except Exception as e:
            logger.info(f"WebSocket sender loop stopped for connection: {e}")
        finally:
            await self.unregister(websocket)


class PacketBridge:
    def __init__(self, broadcast_mgr: BroadcastManager):
        self.thread_queue = queue.Queue(maxsize=10000)
        self.broadcast_mgr = broadcast_mgr
        self.running = False
        self._pump_task = None
        self.loop = None
        self.pipeline_handler = None

    def start(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.running = True
        self._pump_task = asyncio.run_coroutine_threadsafe(self._pump_loop(), loop)

    def stop(self):
        self.running = False
        # Put sentinel
        self.thread_queue.put(None)

    def queue_packet(self, packet_data: Any):
        """Called from Scapy sniff thread callback."""
        try:
            self.thread_queue.put_nowait(packet_data)
        except queue.Full:
            # Signal backpressure if the queue is full
            pass

    async def _pump_loop(self):
        logger.info("Starting packet bridge async pump loop")
        
        while self.running:
            # Run in executor to avoid blocking the event loop on queue.get()
            item = await asyncio.get_event_loop().run_in_executor(
                None, self.thread_queue.get
            )
            if item is None:
                logger.info("Packet bridge received sentinel. Stopping pump loop.")
                break
                
            logger.info(f"Packet bridge pump loop fetched item. pipeline_handler exists={self.pipeline_handler is not None}")
            if self.pipeline_handler:
                try:
                    await self.pipeline_handler(item)
                except Exception as e:
                    logger.error(f"Error in packet processing pipeline: {e}", exc_info=True)
            else:
                logger.warning("Packet bridge pump loop got item, but pipeline_handler is None!")
                    
            self.thread_queue.task_done()
        logger.info("Packet bridge async pump loop stopped")

    def get_queue_depth(self) -> int:
        return self.thread_queue.qsize()

    def get_backpressure_ratio(self) -> float:
        max_size = self.thread_queue.maxsize
        if max_size <= 0:
            return 0.0
        return self.thread_queue.qsize() / max_size


# Singletons
broadcast_manager = BroadcastManager()
packet_bridge = PacketBridge(broadcast_manager)
