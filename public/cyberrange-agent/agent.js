// ============================================
// CyberRange Real-Time Agent
// ============================================
// This agent monitors your local file system and sends
// real-time telemetry to the backend via WebSocket.
//
// SETUP:
//   1. Create a folder: mkdir agent && cd agent
//   2. Run: npm init -y
//   3. Add "type": "module" to package.json
//   4. Run: npm install chokidar ws
//   5. Copy this file as agent.js
//   6. Run: node agent.js
//
// ⚠️ IMPORTANT: Only use in isolated VM/test environments!
// ============================================

import chokidar from "chokidar";
import WebSocket from "ws";

const BACKEND_URL = "ws://localhost:4001";
const WATCH_PATH = process.argv[2] || "./test-files"; // Default: watch a local test folder

let ws;
let reconnectTimer;

function connect() {
  ws = new WebSocket(BACKEND_URL);

  ws.on("open", () => {
    console.log("✅ Connected to backend at", BACKEND_URL);
    // Send handshake
    ws.send(JSON.stringify({
      type: "agent_connect",
      hostname: process.env.COMPUTERNAME || process.env.HOSTNAME || "unknown",
      watchPath: WATCH_PATH,
      time: Date.now()
    }));
  });

  ws.on("close", () => {
    console.log("❌ Disconnected. Reconnecting in 3s...");
    reconnectTimer = setTimeout(connect, 3000);
  });

  ws.on("error", (err) => {
    console.error("WebSocket error:", err.message);
  });
}

// Start connection
connect();

// Watch file system
console.log(`👁️  Watching: ${WATCH_PATH}`);
console.log("   (Create/modify/delete files to generate telemetry)\n");

const watcher = chokidar.watch(WATCH_PATH, {
  ignoreInitial: true,
  persistent: true,
  depth: 10,
  awaitWriteFinish: {
    stabilityThreshold: 200,
    pollInterval: 100
  }
});

watcher.on("all", (event, filePath) => {
  const data = {
    type: "file_event",
    event,        // add, addDir, change, unlink, unlinkDir
    path: filePath,
    time: Date.now()
  };

  // Send to backend
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }

  // Local log
  const icon = {
    add: "📄+",
    addDir: "📁+",
    change: "📝",
    unlink: "🗑️",
    unlinkDir: "🗑️📁"
  }[event] || "❓";

  console.log(`${icon} ${event.padEnd(10)} ${filePath}`);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Agent shutting down...");
  watcher.close();
  ws?.close();
  clearTimeout(reconnectTimer);
  process.exit(0);
});
