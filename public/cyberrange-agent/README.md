# CyberRange Real-Time Agent (Cloud Edition)

## Features
- **File system monitoring** via chokidar
- **Process detection** via ps-list (cross-platform)
- **Sysmon integration** (Windows, optional) for exact process-file mapping

## Quick Setup

```bash
mkdir cyber-agent && cd cyber-agent
npm init -y
```

Add `"type": "module"` to your package.json, then:

```bash
npm install chokidar ps-list
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

## Optional: Sysmon (Windows — exact process tracking)

For kernel-level process-file mapping:

1. Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Install (PowerShell as Admin): `sysmon64.exe -i`
3. The agent auto-detects Sysmon and uses it for precise process info.

## Dashboard

Go to your CyberRange page → Click **"Connect Agent"** → Events appear in real-time with process info.

## What You'll See

```
FILE EVENT
  File: test-files/a.txt
  Action: change
  Process: notepad.exe
  Time: 12:35
```

## Architecture

```
[Agent on PC] --HTTPS--> [Cloud Backend] --Realtime--> [Dashboard Browser]
  watches files            stores events          displays live
  detects process          + process info         with process info
```

⚠️ **Only run in isolated test environments (VMs)!**
