# CyberRange Real-Time Agent (Cloud Edition)

## Quick Setup

```bash
mkdir cyber-agent && cd cyber-agent
npm init -y
```

Add `"type": "module"` to your package.json, then:

```bash
npm install chokidar
```

Copy `agent.js` into the folder, create a test folder, and run:

```bash
mkdir test-files
node agent.js
```

**No local backend/server needed!** The agent sends data directly to the cloud.

To watch a different path:
```bash
node agent.js "C:/Users/YourName/Desktop/test-folder"
```

## Dashboard

Go to your CyberRange page → Click **"Connect Agent"** → Events appear in real-time.

## Architecture

```
[Agent on your PC] --HTTPS--> [Cloud Backend] --Realtime--> [Dashboard Browser]
   watches files         stores events          displays live
```

⚠️ **Only run in isolated test environments (VMs)!**
