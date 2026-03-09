// ============================================
// CyberRange Real-Time Agent (Cloud Edition)
// ============================================
// Monitors your local file system and sends telemetry
// directly to the cloud backend via HTTP POST.
//
// NO local backend/server needed!
//
// SETUP:
//   1. Create a folder: mkdir cyber-agent && cd cyber-agent
//   2. Run: npm init -y
//   3. Add "type": "module" to package.json
//   4. Run: npm install chokidar
//   5. Copy this file as agent.js
//   6. Create test folder: mkdir test-files
//   7. Run: node agent.js
//
// ⚠️ IMPORTANT: Only use in isolated VM/test environments!
// ============================================

import chokidar from "chokidar";

// ── CONFIGURATION ──────────────────────────────────
// Your Lovable Cloud edge function URL
const BACKEND_URL =
  "https://tnnglbdsxuqchechqwvz.supabase.co/functions/v1/agent-telemetry";

const SUPABASE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRubmdsYmRzeHVxY2hlY2hxd3Z6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY0MTMzMDAsImV4cCI6MjA4MTk4OTMwMH0.4zclQMgyCDEXbZGwgMfs_IkYgRHZVgGPBPLy_zxR5rE";

// Folder to watch
const WATCH_FOLDER = process.argv[2] || "./test-files";
const HOSTNAME =
  process.env.COMPUTERNAME || process.env.HOSTNAME || "local-agent";

// ── SEND EVENT TO CLOUD ────────────────────────────
async function sendEvent(event, path) {
  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SUPABASE_KEY}`,
        apikey: SUPABASE_KEY,
      },
      body: JSON.stringify({
        event,
        path,
        hostname: HOSTNAME,
        time: new Date().toISOString(),
        agent: "local-agent",
      }),
    });

    if (res.ok) {
      console.log("✅ Event sent to cloud backend");
    } else {
      const text = await res.text();
      console.error(`❌ Send failed (${res.status}): ${text}`);
    }
  } catch (err) {
    console.error("❌ Network error:", err.message);
  }
}

// ── WATCH FILE SYSTEM ──────────────────────────────
console.log(`👁️  Watching: ${WATCH_FOLDER}`);
console.log(`📡 Sending to: Cloud backend`);
console.log("   (Create/modify/delete files to generate telemetry)\n");

const watcher = chokidar.watch(WATCH_FOLDER, {
  persistent: true,
  ignoreInitial: false,
  depth: 10,
});

watcher
  .on("add", (path) => {
    console.log("📄+ add", path);
    sendEvent("add", path);
  })
  .on("change", (path) => {
    console.log("📝 change", path);
    sendEvent("change", path);
  })
  .on("unlink", (path) => {
    console.log("🗑️ delete", path);
    sendEvent("delete", path);
  })
  .on("addDir", (path) => {
    console.log("📁+ addDir", path);
    sendEvent("addDir", path);
  })
  .on("unlinkDir", (path) => {
    console.log("🗑️📁 unlinkDir", path);
    sendEvent("unlinkDir", path);
  });

console.log("✅ Agent running...");

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Agent shutting down...");
  watcher.close();
  process.exit(0);
});
