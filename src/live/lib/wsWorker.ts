// WebSocket worker thread to consume and batch live packet stream
let socket: WebSocket | null = null;
let packetBuffer: any[] = [];
let alertBuffer: any[] = [];
let running = false;

// Helper to request frame cadence inside worker (falls back to setTimeout)
function requestFrame(callback: () => void) {
  if (typeof self.requestAnimationFrame === 'function') {
    self.requestAnimationFrame(callback);
  } else {
    setTimeout(callback, 16.6); // ~60fps
  }
}

self.onmessage = (event: MessageEvent) => {
  const { action, url, ticket } = event.data;

  if (action === "connect") {
    if (socket) {
      socket.close();
    }

    const wsUrl = `${url}?ticket=${ticket}`;
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      self.postMessage({ type: "status", data: "connected" });
      
      // Start requestAnimationFrame render loop
      running = true;
      requestFrame(flushLoop);
    };

    socket.onmessage = (msg) => {
      try {
        const payload = JSON.parse(msg.data);
        
        if (payload.type === "batch") {
          // Surface dropped frames count to the main thread
          if (typeof payload.dropped_frames === "number") {
            self.postMessage({ type: "dropped_frames", count: payload.dropped_frames });
          }

          const batchData = payload.data || [];
          for (const item of batchData) {
            if (item.type === "packet") {
              packetBuffer.push(item);
            } else if (item.type === "alert") {
              alertBuffer.push(item.alert);
            } else if (item.type === "voip_update") {
              self.postMessage({ type: "voip", data: item.session });
            } else if (item.type === "enrichment") {
              self.postMessage({ type: "enrichment", data: item });
            } else if (item.type === "sync_response") {
              self.postMessage({ type: "sync", data: item });
            }
          }
        }
      } catch (err) {
        console.error("Worker failed to parse WS frame:", err);
      }
    };

    socket.onclose = () => {
      self.postMessage({ type: "status", data: "disconnected" });
      running = false;
    };

    socket.onerror = (err) => {
      self.postMessage({ type: "status", data: "error", error: err });
    };
  }

  if (action === "sync") {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ action: "sync" }));
    }
  }

  if (action === "disconnect") {
    if (socket) {
      socket.close();
      socket = null;
    }
    running = false;
  }
};

function flushLoop() {
  if (!running) return;
  
  if (packetBuffer.length > 0 || alertBuffer.length > 0) {
    self.postMessage({
      type: "batch",
      packets: packetBuffer,
      alerts: alertBuffer
    });
    packetBuffer = [];
    alertBuffer = [];
  }
  
  requestFrame(flushLoop);
}
