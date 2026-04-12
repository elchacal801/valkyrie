#!/usr/bin/env bash
# ============================================================================
# VALKYRIE — Installer for SIFT Workstation
#
# Validates prerequisites, installs the MCP server dependencies, deploys
# Claude Code settings and hooks, and verifies the installation.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/elchacal801/find-evil-agent/main/install.sh | bash
#
#   Or locally:
#   chmod +x install.sh && ./install.sh
#
# Prerequisites:
#   - SIFT Workstation (https://sans.org/tools/sift-workstation)
#   - Claude Code CLI (https://claude.ai/code)
#   - Python 3.10+
#   - pip
# ============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- Configuration ---
INSTALL_DIR="${VALKYRIE_INSTALL_DIR:-/opt/valkyrie}"
CLAUDE_CONFIG_DIR="${HOME}/.claude"
VENV_DIR="${INSTALL_DIR}/.venv"

# --- Helpers ---
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}\n"; }

check_tool() {
    local name="$1"
    local required="${2:-true}"
    if command -v "$name" &>/dev/null; then
        success "$name found: $(command -v "$name")"
        return 0
    else
        if [ "$required" = "true" ]; then
            fail "$name NOT FOUND (required)"
            return 1
        else
            warn "$name not found (optional)"
            return 0
        fi
    fi
}

# --- Banner ---
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║                                                       ║"
echo "  ║   ██╗   ██╗ █████╗ ██╗     ██╗  ██╗██╗   ██╗██████╗  ║"
echo "  ║   ██║   ██║██╔══██╗██║     ██║ ██╔╝╚██╗ ██╔╝██╔══██╗ ║"
echo "  ║   ██║   ██║███████║██║     █████╔╝  ╚████╔╝ ██████╔╝ ║"
echo "  ║   ╚██╗ ██╔╝██╔══██║██║     ██╔═██╗   ╚██╔╝  ██╔══██╗ ║"
echo "  ║    ╚████╔╝ ██║  ██║███████╗██║  ██╗   ██║   ██║  ██║ ║"
echo "  ║     ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ║"
echo "  ║                                                       ║"
echo "  ║   Autonomous IR Agent for SIFT Workstation            ║"
echo "  ║   SANS Find Evil! Hackathon 2026                      ║"
echo "  ║                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# ============================================================================
header "Phase 1: Prerequisite Validation"
# ============================================================================

ERRORS=0

# --- Python ---
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
        success "Python $PY_VERSION"
    else
        fail "Python $PY_VERSION found but 3.10+ required"
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "Python 3 NOT FOUND"
    ERRORS=$((ERRORS + 1))
fi

# --- pip ---
check_tool "pip3" "true" || ERRORS=$((ERRORS + 1))

# --- Claude Code ---
if command -v claude &>/dev/null; then
    success "Claude Code CLI found"
else
    warn "Claude Code CLI not found — install from https://claude.ai/code"
    warn "VALKYRIE can still be installed; Claude Code is needed to run investigations"
fi

# --- Core SIFT forensic tools ---
info "Checking SIFT Workstation forensic tools..."
echo ""

check_tool "mmls"           "true"  || ERRORS=$((ERRORS + 1))
check_tool "fls"            "true"  || ERRORS=$((ERRORS + 1))
check_tool "icat"           "true"  || ERRORS=$((ERRORS + 1))
check_tool "yara"           "true"  || ERRORS=$((ERRORS + 1))
check_tool "strings"        "true"  || ERRORS=$((ERRORS + 1))

# Volatility 3 — check multiple possible names
VOL_FOUND=false
for vol_bin in vol vol.py volatility3; do
    if command -v "$vol_bin" &>/dev/null; then
        success "Volatility 3 found: $(command -v "$vol_bin")"
        VOL_FOUND=true
        break
    fi
done
if [ "$VOL_FOUND" = "false" ]; then
    fail "Volatility 3 NOT FOUND (checked: vol, vol.py, volatility3)"
    ERRORS=$((ERRORS + 1))
fi

# Plaso (log2timeline) — check multiple possible names
PLASO_FOUND=false
for plaso_bin in log2timeline.py log2timeline; do
    if command -v "$plaso_bin" &>/dev/null; then
        success "Plaso found: $(command -v "$plaso_bin")"
        PLASO_FOUND=true
        break
    fi
done
if [ "$PLASO_FOUND" = "false" ]; then
    warn "Plaso (log2timeline) not found — timeline generation will be limited"
fi

# Optional tools
check_tool "MFTECmd"        "false"
check_tool "analyzeMFT.py"  "false"
check_tool "rip.pl"         "false"
check_tool "RECmd"           "false"
check_tool "floss"           "false"
check_tool "ewfverify"      "false"

echo ""
if [ "$ERRORS" -gt 0 ]; then
    fail "$ERRORS required tool(s) missing. Install them and re-run this script."
    fail "On SIFT Workstation, most tools are pre-installed."
    fail "  Install SIFT: https://sans.org/tools/sift-workstation"
    exit 1
fi
success "All required prerequisites satisfied"

# ============================================================================
header "Phase 2: Install VALKYRIE"
# ============================================================================

# --- Clone or locate the repo ---
if [ -d "$INSTALL_DIR" ]; then
    info "VALKYRIE directory exists at $INSTALL_DIR"
    info "Updating..."
    cd "$INSTALL_DIR"
    if [ -d ".git" ]; then
        git pull --ff-only 2>/dev/null || warn "Git pull failed — using existing files"
    fi
else
    info "Installing VALKYRIE to $INSTALL_DIR..."
    # If running from the repo directory, copy instead of clone
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/mcp-server/server.py" ]; then
        info "Installing from local repo..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
        sudo cp -r "$SCRIPT_DIR"/.claude "$INSTALL_DIR/" 2>/dev/null || true
        sudo cp "$SCRIPT_DIR"/.gitignore "$INSTALL_DIR/" 2>/dev/null || true
        sudo chown -R "$(whoami):$(id -gn)" "$INSTALL_DIR"
    else
        info "Cloning from GitHub..."
        sudo mkdir -p "$(dirname "$INSTALL_DIR")"
        sudo git clone https://github.com/elchacal801/valkyrie.git "$INSTALL_DIR"
        sudo chown -R "$(whoami):$(id -gn)" "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"
fi

success "VALKYRIE installed at $INSTALL_DIR"

# --- Create Python virtual environment and install dependencies ---
info "Setting up Python virtual environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet mcp
success "Python dependencies installed (mcp SDK)"

# ============================================================================
header "Phase 3: Deploy Claude Code Configuration"
# ============================================================================

# --- Create Claude Code config directory ---
mkdir -p "$CLAUDE_CONFIG_DIR"

# --- Deploy hooks ---
HOOKS_DIR="$INSTALL_DIR/.claude/hooks"
chmod +x "$HOOKS_DIR/pre-tool-use.sh" 2>/dev/null || true
chmod +x "$HOOKS_DIR/post-tool-use.sh" 2>/dev/null || true
success "Hooks deployed at $HOOKS_DIR"

# --- Generate settings.local.json pointing to the installed location ---
SETTINGS_FILE="$INSTALL_DIR/.claude/settings.local.json"
info "MCP server configuration at $SETTINGS_FILE"

# Update the server command to use the venv Python
cat > "$SETTINGS_FILE" << SETTINGS_EOF
{
  "mcpServers": {
    "valkyrie": {
      "command": "${VENV_DIR}/bin/python3",
      "args": ["${INSTALL_DIR}/mcp-server/server.py"],
      "description": "VALKYRIE MCP Server - Safe forensic tool integration for SIFT Workstation"
    }
  },
  "permissions": {
    "allow": [
      "mcp__valkyrie__get_partition_layout",
      "mcp__valkyrie__list_files",
      "mcp__valkyrie__extract_file",
      "mcp__valkyrie__generate_timeline",
      "mcp__valkyrie__extract_mft",
      "mcp__valkyrie__analyze_memory",
      "mcp__valkyrie__get_registry_key",
      "mcp__valkyrie__check_persistence",
      "mcp__valkyrie__scan_yara",
      "mcp__valkyrie__extract_strings",
      "Bash(sha256sum *)",
      "Bash(ls *)",
      "Bash(file *)",
      "Bash(stat *)",
      "Bash(wc *)",
      "Bash(head *)",
      "Bash(mount -o ro*)"
    ],
    "deny": [
      "Bash(rm *)",
      "Bash(rm -*)",
      "Bash(dd *)",
      "Bash(shred *)",
      "Bash(wget *)",
      "Bash(curl *)",
      "Bash(ssh *)",
      "Bash(scp *)",
      "Bash(rsync *)",
      "Bash(nc *)",
      "Bash(ncat *)",
      "Bash(mkfs *)",
      "Bash(fdisk *)",
      "Bash(mount -o rw*)",
      "Bash(mount -o remount*)",
      "WebFetch(*)",
      "WebSearch(*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "description": "Block writes to evidence directories",
        "hooks": [
          {
            "command": "${INSTALL_DIR}/.claude/hooks/pre-tool-use.sh",
            "timeout_seconds": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "description": "Audit log all tool executions with SHA256",
        "hooks": [
          {
            "command": "${INSTALL_DIR}/.claude/hooks/post-tool-use.sh",
            "timeout_seconds": 5
          }
        ]
      }
    ]
  }
}
SETTINGS_EOF

success "Claude Code settings configured"

# --- Create default cases directory ---
sudo mkdir -p /cases
sudo chown "$(whoami):$(id -gn)" /cases
success "Case directory created at /cases"

# ============================================================================
header "Phase 4: Verification"
# ============================================================================

# --- Verify MCP server can import ---
info "Testing MCP server imports..."
cd "$INSTALL_DIR/mcp-server"
if "$VENV_DIR/bin/python3" -c "
import sys
sys.path.insert(0, '.')
import denylist
from parsers.common import compute_sha256, safe_subprocess, build_tool_response
print('Internal imports: OK')
print(f'Denylist: {len(denylist.BLOCKED_BINARIES)} blocked binaries')
print(f'SHA256 test: {compute_sha256(\"valkyrie\")[:16]}...')
" 2>&1; then
    success "MCP server imports verified"
else
    fail "MCP server import failed — check Python environment"
    exit 1
fi

# --- Verify denylist ---
info "Testing denylist enforcement..."
"$VENV_DIR/bin/python3" -c "
import sys; sys.path.insert(0, '.')
import denylist
# These should be blocked
for cmd in ['rm', 'dd', 'shred', 'wget', 'curl', 'ssh']:
    result = denylist.check_binary(cmd)
    assert result is not None, f'{cmd} should be blocked!'

# These should be allowed
for cmd in ['mmls', 'fls', 'icat', 'vol', 'yara', 'strings']:
    result = denylist.check_binary(cmd)
    assert result is None, f'{cmd} should be allowed!'

print('Denylist: all checks passed')
"
success "Denylist enforcement verified"

# --- Verify skill files exist ---
info "Verifying skill framework..."
MISSING=0
for f in \
    "skills/ir-analysis/SKILL.md" \
    "skills/ir-analysis/protocols/orchestrator.md" \
    "skills/ir-analysis/protocols/self-correction.md" \
    "skills/ir-analysis/protocols/evidence-collector.md" \
    "skills/ir-analysis/protocols/techniques/timeline-reconstruction.md" \
    "skills/ir-analysis/protocols/techniques/artifact-correlation.md" \
    "skills/ir-analysis/protocols/techniques/hypothesis-testing.md" \
    "skills/ir-analysis/protocols/techniques/memory-analysis.md" \
    "skills/ir-analysis/protocols/techniques/persistence-enumeration.md" \
    "skills/ir-analysis/protocols/techniques/log-analysis.md" \
    "skills/ir-analysis/protocols/techniques/malware-triage.md" \
    "skills/ir-analysis/templates/investigation-report.md" \
    "skills/ir-analysis/templates/finding-template.json" \
    "skills/ir-analysis/templates/correction-template.json" \
    "skills/ir-analysis/templates/accuracy-report.md" \
; do
    if [ ! -f "$INSTALL_DIR/$f" ]; then
        fail "Missing: $f"
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -eq 0 ]; then
    success "All 15 skill files present"
else
    fail "$MISSING skill file(s) missing"
fi

# ============================================================================
header "Installation Complete"
# ============================================================================

echo ""
echo -e "${GREEN}${BOLD}VALKYRIE is ready.${NC}"
echo ""
echo -e "  ${BOLD}Install location:${NC}  $INSTALL_DIR"
echo -e "  ${BOLD}Case directory:${NC}    /cases"
echo -e "  ${BOLD}Python venv:${NC}       $VENV_DIR"
echo ""
echo -e "  ${BOLD}To start an investigation:${NC}"
echo -e "    cd $INSTALL_DIR"
echo -e "    claude"
echo -e "    /investigate --guided --evidence-path /cases/CASE-001/evidence/"
echo ""
echo -e "  ${BOLD}Quick triage:${NC}"
echo -e "    /investigate --lean --evidence-path /path/to/evidence"
echo ""
echo -e "  ${BOLD}Documentation:${NC}"
echo -e "    README:       $INSTALL_DIR/README.md"
echo -e "    Architecture: $INSTALL_DIR/docs/architecture-diagram.md"
echo ""
