// ============================================
// CyberRange Backend Server
// ============================================
// Receives telemetry from agent(s) and broadcasts
// to connected dashboard clients via WebSocket.
//
// SETUP:
//   1. Create a folder: mkdir backend && cd backend
//   2. Run: npm init -y
//   3. Add "type": "module" to package.json
//   4. Run: npm install ws express cors
//   5. Copy this file as server.js
//   6. Run: node server.js
//
// Architecture:
//   Agent --ws:4001--> Backend --ws:4001--> Dashboard
// ============================================

import { WebSocketServer } from "ws";

const PORT = 4001;
const wss = new WebSocketServer({ port: PORT });

const agents = new Set();
const dashboards = new Set();

console.log(`🚀 CyberRange Backend running on ws://localhost:${PORT}`);
console.log("   Waiting for agent and dashboard connections...\n");

wss.on("connection", (socket, req) => {
  console.log(`🔌 New connection from ${req.socket.remoteAddress}`);

  // By default treat as dashboard until agent identifies itself
  dashboards.add(socket);

  socket.on("message", (msg) => {
    try {
      const data = JSON.parse(msg.toString());

      // Agent handshake
      if (data.type === "agent_connect") {
        dashboards.delete(socket);
        agents.add(socket);
        console.log(`🤖 Agent registered: ${data.hostname} watching ${data.watchPath}`);

        // Notify dashboards
        broadcast({
          type: "agent_status",
          status: "connected",
          hostname: data.hostname,
          watchPath: data.watchPath,
          time: Date.now()
        });
        return;
      }

      // File events from agent → broadcast to all dashboards
      if (data.type === "file_event") {
        console.log(`📡 ${data.event.padEnd(10)} ${data.path}`);
        broadcast(data);
      }
    } catch (err) {
      console.error("Failed to parse message:", err.message);
    }
  });

  socket.on("close", () => {
    if (agents.has(socket)) {
      agents.delete(socket);
      console.log("🤖 Agent disconnected");
      broadcast({ type: "agent_status", status: "disconnected", time: Date.now() });
    } else {
      dashboards.delete(socket);
      console.log("📊 Dashboard disconnected");
    }
  });

  socket.on("error", (err) => {
    console.error("Socket error:", err.message);
  });
});

function broadcast(data) {
  const msg = JSON.stringify(data);
  for (const client of dashboards) {
    if (client.readyState === 1) {
      client.send(msg);
    }
  }
}

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Backend shutting down...");
  wss.close();
  process.exit(0);
});
