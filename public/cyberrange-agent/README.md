# CyberRange Real-Time Agent & Backend

## Quick Setup

### 1. Backend (receives telemetry, broadcasts to dashboard)

```bash
mkdir backend && cd backend
npm init -y
# Add "type": "module" to package.json
npm install ws express cors
# Copy server.js here
node server.js
```

### 2. Agent (monitors file system, sends telemetry)

```bash
mkdir agent && cd agent
npm init -y
# Add "type": "module" to package.json
npm install chokidar ws
# Copy agent.js here
node agent.js
```

By default the agent watches `./test-files`. Create that folder and add/modify/delete files to generate telemetry.

To watch a different path:
```bash
node agent.js "C:/Users/YourName/Desktop/test-folder"
```

### 3. Dashboard

Go to your CyberRange page → Click **"Connect Agent"** → It connects to `ws://localhost:4001`.

## Architecture

```
[Agent] --ws:4001--> [Backend Server] --ws:4001--> [Dashboard Browser]
     watches files        relays events         displays in real-time
```

⚠️ **Only run in isolated test environments (VMs)!**
