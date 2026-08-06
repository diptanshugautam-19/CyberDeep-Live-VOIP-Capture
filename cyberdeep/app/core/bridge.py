import asyncio
import queue
import time
import logging
import threading
from typing import Dict, Set, Any, Tuple
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class BroadcastManager:
    """WebSocket broadcast with priority queuing and graceful backpressure."""

    def __init__(self):
        self.connections: Dict[WebSocket, asyncio.PriorityQueue] = {}
        self.dropped_frames: Dict[WebSocket, int] = {}
        self.last_sequence: Dict[WebSocket, int] = {}
        self.lock = asyncio.Lock()
        self.global_sequence = 0

    async def register(self, websocket: WebSocket) -> asyncio.PriorityQueue:
        async with self.lock:
            pq = asyncio.PriorityQueue(maxsize=2000)
            self.connections[websocket] = pq
            self.dropped_frames[websocket] = 0
            self.last_sequence[websocket] = 0
            return pq

    async def unregister(self, websocket: WebSocket):
        async with self.lock:
            self.connections.pop(websocket, None)
            self.dropped_frames.pop(websocket, None)
            self.last_sequence.pop(websocket, None)

    async def broadcast(self, payload: Dict[str, Any], priority: int = 3):
        """
        Priorities:
          0 = Critical (Security Alerts, Storage Failure)
          1 = VoIP / SIP Signaling
          2 = Decoded Application Records (DNS, HTTP)
          3 = Standard Packet Metadata / Flows
        """
        async with self.lock:
            self.global_sequence += 1
            payload["seq"] = self.global_sequence
            targets = list(self.connections.items())

        ts = time.time()
        for ws, pq in targets:
            item = (priority, ts, payload)
            try:
                pq.put_nowait(item)
            except asyncio.QueueFull:
                self.dropped_frames[ws] = self.dropped_frames.get(ws, 0) + 1
                if priority <= 1:
                    evicted = 0
                    temp_items = []
                    try:
                        while not pq.empty() and evicted < 20:
                            temp_items.append(pq.get_nowait())
                            evicted += 1
                        for temp in temp_items[1:]:
                            pq.put_nowait(temp)
                        pq.put_nowait(item)
                    except Exception as e:
                        logger.error(f"Error dropping frames for priority insert: {e}")

    async def sender_loop(self, websocket: WebSocket, pq: asyncio.PriorityQueue, batch_interval_ms: int = 20):
        batch = []
        last_send = time.time()
        interval = batch_interval_ms / 1000.0

        try:
            while True:
                try:
                    timeout = max(0.005, interval - (time.time() - last_send))
                    item = await asyncio.wait_for(pq.get(), timeout=timeout)
                    priority, ts, payload = item
                    batch.append(payload)
                    pq.task_done()

                    if "seq" in payload:
                        self.last_sequence[websocket] = payload["seq"]
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                if batch and (now - last_send >= interval or len(batch) >= 100):
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
            logger.info(f"WebSocket sender loop stopped: {e}")
        finally:
            await self.unregister(websocket)


class PacketBridge:
    def __init__(self, broadcast_mgr: BroadcastManager):
        # 100K queue size (10x boost)
        self.thread_queue = queue.Queue(maxsize=100_000)
        self.broadcast_mgr = broadcast_mgr
        self.running = False
        self._pump_thread = None
        self.loop = None
        self.pipeline_handler = None

    def start(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.running = True
        # Dedicated consumer thread instead of run_in_executor per item
        self._pump_thread = threading.Thread(target=self._dedicated_pump_loop, daemon=True)
        self._pump_thread.start()

    def stop(self):
        self.running = False
        self.thread_queue.put(None)

    def queue_packet(self, packet_data: Any):
        try:
            self.thread_queue.put_nowait(packet_data)
        except queue.Full:
            pass

    def _dedicated_pump_loop(self):
        logger.info("[*] PacketBridge dedicated consumer thread started.")
        while self.running:
            try:
                item = self.thread_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if item is None:
                break

            if self.pipeline_handler and self.loop and self.loop.is_running():
                try:
                    asyncio.run_coroutine_threadsafe(self.pipeline_handler(item), self.loop)
                except Exception as e:
                    logger.error(f"Error submitting pipeline item: {e}")

            self.thread_queue.task_done()

        logger.info("[*] PacketBridge dedicated consumer thread stopped.")

    def get_queue_depth(self) -> int:
        return self.thread_queue.qsize()

    def get_backpressure_ratio(self) -> float:
        max_size = self.thread_queue.maxsize
        if max_size <= 0:
            return 0.0
        return self.thread_queue.qsize() / max_size


broadcast_manager = BroadcastManager()
packet_bridge = PacketBridge(broadcast_manager)
