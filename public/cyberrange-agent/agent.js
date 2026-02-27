// ============================================
// CyberRange Real-Time Agent (Cloud Edition)
// ============================================
// Monitors your local file system and sends telemetry
// directly to the cloud backend via HTTP POST.
//
// NO local backend/server needed!
//
// SETUP:
//   1. Create a folder: mkdir agent && cd agent
//   2. Run: npm init -y
//   3. Add "type": "module" to package.json
//   4. Run: npm install chokidar
//   5. Copy this file as agent.js
//   6. Run: node agent.js
//
// ⚠️ IMPORTANT: Only use in isolated VM/test environments!
// ============================================

import chokidar from "chokidar";

// ── CONFIGURATION ──────────────────────────────────
// Your Lovable Cloud edge function URL
const EDGE_FUNCTION_URL =
  "https://tnnglbdsxuqchechqwvz.supabase.co/functions/v1/agent-telemetry";

const ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRubmdsYmRzeHVxY2hlY2hxd3Z6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY0MTMzMDAsImV4cCI6MjA4MTk4OTMwMH0.4zclQMgyCDEXbZGwgMfs_IkYgRHZVgGPBPLy_zxR5rE";

const WATCH_PATH = process.argv[2] || "./test-files";
const HOSTNAME =
  process.env.COMPUTERNAME || process.env.HOSTNAME || "unknown";

// ── SEND TELEMETRY ─────────────────────────────────
async function sendEvent(event, filePath) {
  try {
    const res = await fetch(EDGE_FUNCTION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ANON_KEY}`,
        apikey: ANON_KEY,
      },
      body: JSON.stringify({
        event,
        path: filePath,
        hostname: HOSTNAME,
      }),
    });

    if (!res.ok) {
      const text = await res.text();
      console.error(`❌ Send failed (${res.status}): ${text}`);
    }
  } catch (err) {
    console.error("❌ Network error:", err.message);
  }
}

// ── WATCH FILE SYSTEM ──────────────────────────────
console.log(`👁️  Watching: ${WATCH_PATH}`);
console.log(`📡 Sending to: Cloud backend`);
console.log("   (Create/modify/delete files to generate telemetry)\n");

const watcher = chokidar.watch(WATCH_PATH, {
  ignoreInitial: true,
  persistent: true,
  depth: 10,
  awaitWriteFinish: {
    stabilityThreshold: 200,
    pollInterval: 100,
  },
});

watcher.on("all", (event, filePath) => {
  const icon =
    {
      add: "📄+",
      addDir: "📁+",
      change: "📝",
      unlink: "🗑️",
      unlinkDir: "🗑️📁",
    }[event] || "❓";

  console.log(`${icon} ${event.padEnd(10)} ${filePath}`);
  sendEvent(event, filePath);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Agent shutting down...");
  watcher.close();
  process.exit(0);
});
