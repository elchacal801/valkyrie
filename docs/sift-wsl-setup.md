# VALKYRIE — SIFT WSL Setup Guide

Step-by-step guide to get VALKYRIE running on SIFT Workstation via WSL2 on Windows 11.

---

## Step 1: Install/Verify WSL2 with Ubuntu 22.04

Open PowerShell as Administrator:

```powershell
# Check if WSL is installed
wsl --version

# If not installed:
wsl --install -d Ubuntu-22.04

# If already installed but need Ubuntu 22.04:
wsl --install -d Ubuntu-22.04

# Verify
wsl -l -v
```

You should see Ubuntu-22.04 running on VERSION 2. If it says VERSION 1, upgrade it:

```powershell
wsl --set-version Ubuntu-22.04 2
```

Launch Ubuntu:

```powershell
wsl -d Ubuntu-22.04
```

Set up your user when prompted (or it may already exist).

---

## Step 2: Install SIFT Workstation in WSL

Inside the Ubuntu WSL shell:

```bash
# Elevate to root
sudo su -

# Update the system
apt update && apt upgrade -y

# Install cast (SIFT installer)
# Get the latest release URL from: https://github.com/ekristen/cast/releases
CAST_VERSION="0.15.0"  # Check for latest
curl -fsSL "https://github.com/ekristen/cast/releases/download/v${CAST_VERSION}/cast_v${CAST_VERSION}_linux_amd64.deb" -o /tmp/cast.deb
dpkg -i /tmp/cast.deb

# Install SIFT (server mode — no GUI needed)
cast install --mode=server teamdfir/sift-saltstack

# This takes 15-30 minutes. It installs:
#   - sleuthkit (mmls, fls, icat, etc.)
#   - volatility3
#   - plaso (log2timeline, psort)
#   - yara
#   - regripper
#   - hundreds of other forensic tools

# Exit root
exit
```

Verify the key tools are installed:

```bash
which mmls fls icat yara strings
vol --help 2>&1 | head -3
log2timeline.py --version 2>&1 | head -1
rip.pl -h 2>&1 | head -3
```

---

## Step 3: Install Python Dependencies and Claude Code

```bash
# Python 3.10+ should already be installed with Ubuntu 22.04
python3 --version

# Install pip if needed
sudo apt install -y python3-pip python3-venv

# Install Claude Code
# Follow: https://claude.ai/code for the latest install instructions
# Typically:
npm install -g @anthropic-ai/claude-code
# Or via the direct installer if npm isn't available

# Verify
claude --version
```

---

## Step 4: Set Up VALKYRIE

Your Windows files are accessible in WSL at `/mnt/c/`. No file copying needed.

```bash
# Create a symlink for convenience
ln -s "/mnt/c/Users/anon/Documents/anon/find_evil/find-evil-agent" ~/valkyrie

# Navigate to the project
cd ~/valkyrie

# Run the installer (it handles venv, settings, hooks)
chmod +x install.sh
./install.sh
```

If you prefer a manual setup instead of the installer:

```bash
cd ~/valkyrie

# Create venv and install MCP SDK
python3 -m venv .venv
source .venv/bin/activate
pip install mcp

# Verify the MCP server
cd mcp-server
python3 -c "
import sys; sys.path.insert(0, '.')
import denylist
from parsers.common import compute_sha256
print('OK: denylist has', len(denylist.BLOCKED_BINARIES), 'blocked binaries')
print('OK: SHA256 works:', compute_sha256('test')[:16])
"

# Make hooks executable
chmod +x ~/valkyrie/.claude/hooks/*.sh
```

---

## Step 5: Prepare Test Evidence

The SRL case data is on your Windows filesystem. WSL can read it directly.

### Option A: Test with a single memory dump (fastest)

```bash
# Create a case directory
sudo mkdir -p /cases/TEST-001/evidence
sudo chown -R $(whoami) /cases/TEST-001

# Extract one memory dump (pick the smallest workstation)
# The .7z files are at:
#   /mnt/c/Users/anon/Documents/anon/find_evil/HACKATHON-2026/Compromised APT Attack Scenarios/SRL-2018-Compromised Enterprise Network/SRL-2018/

SRL_DIR="/mnt/c/Users/anon/Documents/anon/find_evil/HACKATHON-2026/Compromised APT Attack Scenarios/SRL-2018-Compromised Enterprise Network/SRL-2018"

# Install 7z if needed
sudo apt install -y p7zip-full

# Extract the smallest workstation memory dump (~626 MB compressed)
7z x "$SRL_DIR/base-wkstn-05-memory.7z" -o/cases/TEST-001/evidence/

# See what we got
ls -lh /cases/TEST-001/evidence/
```

You should see a `.raw` or `.vmem` memory dump file.

### Option B: Test with a disk image (full pipeline)

```bash
# Create case directory
sudo mkdir -p /cases/TEST-002/evidence
sudo chown -R $(whoami) /cases/TEST-002

SRL_2015="/mnt/c/Users/anon/Documents/anon/find_evil/HACKATHON-2026/Compromised APT Attack Scenarios/SRL-2015-Compromised Enterprise Network"

# Extract the smallest disk image (~12 GB compressed)
# WARNING: This will be large when extracted. Make sure you have disk space.
# The XP image will extract to a .E01 or raw image.
unzip "$SRL_2015/xp-tdungan-10.3.58.7.zip" -d /cases/TEST-002/evidence/

ls -lh /cases/TEST-002/evidence/
```

---

## Step 6: Run Your First Investigation

### Memory-only test (Option A):

```bash
cd ~/valkyrie

# Set the case directory
export VALKYRIE_CASE_DIR=/cases/TEST-001
export VALKYRIE_EVIDENCE_PATH=/cases/TEST-001/evidence

# Launch Claude Code
claude

# In Claude Code, run:
/investigate memory --evidence-path /cases/TEST-001/evidence/
```

This will exercise:
- Evidence collector (inventory the memory dump, compute SHA256)
- Triage (pslist + netscan quick look)
- Memory analysis technique (full protocol)
- Layer 1 self-correction (verify PIDs exist)

### Full guided investigation (Option B):

```bash
cd ~/valkyrie
export VALKYRIE_CASE_DIR=/cases/TEST-002
export VALKYRIE_EVIDENCE_PATH=/cases/TEST-002/evidence

claude

# In Claude Code:
/investigate --guided --evidence-path /cases/TEST-002/evidence/
```

This runs the full 6-phase pipeline.

---

## Step 7: Review Results

After the investigation completes, check the case directory:

```bash
# Phase outputs
ls -la /cases/TEST-001/
cat /cases/TEST-001/inventory.json | python3 -m json.tool | head -30
cat /cases/TEST-001/triage.json | python3 -m json.tool | head -30

# Analysis technique outputs
ls -la /cases/TEST-001/analysis/

# Self-correction results
ls -la /cases/TEST-001/corrections/
cat /cases/TEST-001/corrections/validation-summary.json | python3 -m json.tool

# Audit trail
wc -l /cases/TEST-001/logs/tool-execution.jsonl
head -5 /cases/TEST-001/logs/tool-execution.jsonl | python3 -m json.tool

# Report
cat /cases/TEST-001/report/investigation-report.md
```

---

## Troubleshooting

### "vol: command not found"
Volatility 3 may be installed as `vol.py` or `volatility3` on SIFT. The MCP server tries all three names automatically.

### "Permission denied" on evidence files
WSL mounts Windows drives with specific permissions. If you get permission errors:
```bash
# Remount with proper permissions
sudo umount /mnt/c
sudo mount -t drvfs C: /mnt/c -o metadata,uid=$(id -u),gid=$(id -g)
```

### MCP server import errors
Make sure you're using the venv Python:
```bash
source ~/valkyrie/.venv/bin/activate
cd ~/valkyrie/mcp-server
python3 -c "import denylist; print('OK')"
```

### "log2timeline.py takes too long"
Plaso on large disk images can take 30+ minutes. Use `--lean` mode for faster triage, or filter by date range in the technique protocol.

### WSL running out of disk space
WSL2 uses a virtual disk (ext4.vhdx) that grows dynamically but defaults to 256 GB max. Check space:
```bash
df -h /
```
If tight, extract evidence to the Windows filesystem instead:
```bash
mkdir -p /mnt/c/cases/TEST-001/evidence
# Extract there instead of /cases/
```

---

## Quick Reference

| Item | Value |
|------|-------|
| VALKYRIE repo | `~/valkyrie` → `/mnt/c/Users/anon/Documents/anon/find_evil/find-evil-agent` |
| Case data (SRL-2018) | `/mnt/c/Users/anon/.../HACKATHON-2026/Compromised APT Attack Scenarios/SRL-2018-Compromised Enterprise Network/SRL-2018/` |
| Case data (SRL-2015) | `/mnt/c/Users/anon/.../HACKATHON-2026/Compromised APT Attack Scenarios/SRL-2015-Compromised Enterprise Network/` |
| Case working dir | `/cases/TEST-XXX/` |
| SIFT credentials | `sansforensics` / `forensics` |
| Python venv | `~/valkyrie/.venv/` |
| MCP server | `~/valkyrie/mcp-server/server.py` |
| Audit logs | `/cases/TEST-XXX/logs/tool-execution.jsonl` |
