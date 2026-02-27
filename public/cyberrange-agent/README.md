# CyberRange Real-Time Agent (Cloud Edition)

## Quick Setup

### 1. Agent (monitors file system, sends telemetry to cloud)

```bash
mkdir agent && cd agent
npm init -y
# Add "type": "module" to package.json
npm install chokidar
# Copy agent.js here
node agent.js
```

**No local backend/server needed!** The agent sends data directly to the cloud.

By default the agent watches `./test-files`. Create that folder and add/modify/delete files to generate telemetry.

To watch a different path:
```bash
node agent.js "C:/Users/YourName/Desktop/test-folder"
```

### 2. Dashboard

Go to your CyberRange page → Click **"Connect Agent"** → Events appear in real-time.

## Architecture

```
[Agent on your PC] --HTTPS--> [Cloud Backend] --Realtime--> [Dashboard Browser]
   watches files         stores events          displays live
```

⚠️ **Only run in isolated test environments (VMs)!**
