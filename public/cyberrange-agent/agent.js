// ============================================
// CyberRange Real-Time Agent (Cloud Edition)
// ============================================
// Monitors your local file system and sends telemetry
// directly to the cloud backend via HTTP POST.
// Now includes PROCESS DETECTION via ps-list or Sysmon.
//
// SETUP:
//   1. Create a folder: mkdir cyber-agent && cd cyber-agent
//   2. Run: npm init -y
//   3. Add "type": "module" to package.json
//   4. Run: npm install chokidar ps-list
//   5. Copy this file as agent.js
//   6. Create test folder: mkdir test-files
//   7. Run: node agent.js
//
// OPTIONAL (Windows - exact process via Sysmon):
//   1. Download Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
//   2. Install: sysmon64.exe -i
//   3. The agent will auto-detect Sysmon and use it for precise process info.
//
// ⚠️ IMPORTANT: Only use in isolated VM/test environments!
// ============================================

import chokidar from "chokidar";
import psList from "ps-list";
import { exec } from "child_process";
import { platform } from "os";

// ── CONFIGURATION ──────────────────────────────────
const BACKEND_URL =
  "https://tnnglbdsxuqchechqwvz.supabase.co/functions/v1/agent-telemetry";

const SUPABASE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRubmdsYmRzeHVxY2hlY2hxd3Z6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY0MTMzMDAsImV4cCI6MjA4MTk4OTMwMH0.4zclQMgyCDEXbZGwgMfs_IkYgRHZVgGPBPLy_zxR5rE";

const WATCH_FOLDER = process.argv[2] || "./test-files";
const HOSTNAME =
  process.env.COMPUTERNAME || process.env.HOSTNAME || "local-agent";

const IS_WINDOWS = platform() === "win32";
let sysmonAvailable = false;

// ── CHECK SYSMON AVAILABILITY (Windows only) ───────
if (IS_WINDOWS) {
  exec('powershell Get-WinEvent -MaxEvents 1 -LogName "Microsoft-Windows-Sysmon/Operational" 2>$null', (err) => {
    if (!err) {
      sysmonAvailable = true;
      console.log("🔒 Sysmon detected — using kernel-level process tracking");
    } else {
      console.log("⚡ Sysmon not found — using ps-list for process detection");
    }
  });
}

// ── GET PROCESS INFO ───────────────────────────────
async function getProcessInfo(filePath) {
  // Method 1: Sysmon (Windows, exact process-file mapping)
  if (IS_WINDOWS && sysmonAvailable) {
    return new Promise((resolve) => {
      const cmd = `powershell "Get-WinEvent -MaxEvents 5 -LogName 'Microsoft-Windows-Sysmon/Operational' | Where-Object { $_.Id -eq 11 } | Select-Object -First 1 -ExpandProperty Message"`;
      exec(cmd, (err, stdout) => {
        if (err || !stdout) return resolve(null);
        // Extract process image from Sysmon event
        const imageMatch = stdout.match(/Image:\s*(.+)/i);
        if (imageMatch) {
          const fullPath = imageMatch[1].trim();
          const processName = fullPath.split("\\").pop();
          resolve(processName);
        } else {
          resolve(null);
        }
      });
    });
  }

  // Method 2: ps-list (cross-platform, top active processes)
  try {
    const processes = await psList();
    // Filter for common file-modifying processes
    const fileProcesses = processes.filter(p => 
      /notepad|code|vim|nano|explorer|cmd|powershell|python|node|bash|sh|cat|echo|cp|mv/i.test(p.name)
    );
    if (fileProcesses.length > 0) {
      return fileProcesses.slice(0, 3).map(p => p.name).join(", ");
    }
    // Fallback: return top 3 CPU-active processes
    return processes.slice(0, 3).map(p => p.name).join(", ");
  } catch {
    return null;
  }
}

// ── SEND EVENT TO CLOUD ────────────────────────────
async function sendEvent(event, path) {
  try {
    const processInfo = await getProcessInfo(path);

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
        process: processInfo || "unknown",
        hostname: HOSTNAME,
        time: new Date().toISOString(),
        agent: "local-agent",
      }),
    });

    if (res.ok) {
      console.log(`✅ Event sent: ${event} ${path} [process: ${processInfo || "unknown"}]`);
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
console.log(`🖥️  Platform: ${platform()}`);
console.log("   (Create/modify/delete files to generate telemetry)\n");

const watcher = chokidar.watch(WATCH_FOLDER, {
  ignored: /(^|[\/\\])\../,
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

console.log("✅ Agent running with process detection...");

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Agent shutting down...");
  watcher.close();
  process.exit(0);
});
