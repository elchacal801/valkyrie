#!/usr/bin/env python3
"""
VALKYRIE MCP Server — Forensic Tool Integration for SIFT Workstation

A lean, purpose-built MCP server that exposes typed forensic tool functions
over stdio transport. The server's job is safety (denylist, shell=False,
read-only evidence) and data translation (binary artifacts → structured JSON).
All analytical reasoning lives in the skill framework, not here.

Architecture:
    Claude Code → stdio JSON-RPC → this server → subprocess(shell=False) → SIFT tools

Security model:
    1. Only typed functions are exposed — no generic shell access
    2. Denylist blocks destructive binaries before subprocess execution
    3. All subprocess calls use shell=False — no shell injection
    4. Evidence paths are registered as write-protected at startup
    5. Every tool call is logged with SHA256 hash of output

Usage:
    Configured in .claude/settings.local.json as:
    {
        "mcpServers": {
            "valkyrie": {
                "command": "python3",
                "args": ["mcp-server/server.py"]
            }
        }
    }
"""

import asyncio
import json
import logging
import os
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Add the mcp-server directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import disk, memory, registry, scanner, timeline
from parsers.common import ToolExecutionError
import denylist

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for JSON-RPC; logs go to stderr
)
logger = logging.getLogger("valkyrie")

# The active case directory, set via VALKYRIE_CASE_DIR env var or tool call
CASE_DIR = os.environ.get("VALKYRIE_CASE_DIR", "")

# Register evidence path if provided
evidence_path = os.environ.get("VALKYRIE_EVIDENCE_PATH", "")
if evidence_path:
    denylist.register_evidence_path(evidence_path)


def get_case_dir() -> str | None:
    """Get the active case directory for audit logging."""
    return CASE_DIR if CASE_DIR else None


# --- Tool Registry ---
# Each tool is a typed function with a clear name, description, and JSON schema.
# The LLM sees these definitions and can call them by name.

TOOLS: list[Tool] = [
    # --- Disk Tools (sleuthkit) ---
    Tool(
        name="get_partition_layout",
        description=(
            "Display the partition table of a disk image. Returns partition type, "
            "start sector, end sector, size, and description for each partition. "
            "Uses mmls from The Sleuth Kit."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the disk image file (.E01, .raw, .dd, .img)",
                },
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="list_files",
        description=(
            "List files and directories in a disk image at a given path. "
            "Returns file name, type (file/directory), inode number, and metadata. "
            "Uses fls from The Sleuth Kit."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the disk image file",
                },
                "path": {
                    "type": "string",
                    "description": "Directory path within the image to list (e.g., '/Windows/Temp')",
                    "default": "/",
                },
                "partition_offset": {
                    "type": "integer",
                    "description": "Partition offset in sectors (from get_partition_layout). Required for multi-partition images.",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "List files recursively",
                    "default": False,
                },
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="extract_file",
        description=(
            "Extract a file from a disk image by inode number. The file is written "
            "to the case working directory (never to the evidence directory). "
            "Returns the extracted file path and SHA256 hash. Uses icat from The Sleuth Kit."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the disk image file",
                },
                "inode": {
                    "type": "integer",
                    "description": "Inode number of the file to extract (from list_files output)",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write the extracted file to (must be in case working directory)",
                },
                "output_name": {
                    "type": "string",
                    "description": "Filename for the extracted file",
                },
                "partition_offset": {
                    "type": "integer",
                    "description": "Partition offset in sectors",
                },
            },
            "required": ["image_path", "inode", "output_dir", "output_name"],
        },
    ),
    # --- Timeline Tools (log2timeline/plaso + MFTECmd) ---
    Tool(
        name="generate_timeline",
        description=(
            "Generate a super timeline from a disk image using log2timeline/plaso. "
            "Aggregates timestamps from MFT, event logs, prefetch, registry, browser "
            "history, and other temporal artifacts. Returns parsed timeline entries "
            "(truncated to prevent context overflow). Use date filters to narrow results."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the disk image file",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write the plaso storage and CSV output",
                },
                "start_date": {
                    "type": "string",
                    "description": "Filter: only include entries after this date (YYYY-MM-DD)",
                },
                "end_date": {
                    "type": "string",
                    "description": "Filter: only include entries before this date (YYYY-MM-DD)",
                },
                "filter_path": {
                    "type": "string",
                    "description": "Filter: only include entries matching this path substring",
                },
            },
            "required": ["image_path", "output_dir"],
        },
    ),
    Tool(
        name="extract_mft",
        description=(
            "Parse the MFT (Master File Table) from a disk image using MFTECmd. "
            "Returns file entries with full MACB timestamps (Modified, Accessed, "
            "Changed, Born). Use date and path filters to narrow results."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Path to the disk image or extracted $MFT file",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write the parsed MFT CSV output",
                },
                "start_date": {
                    "type": "string",
                    "description": "Filter: entries after this date (YYYY-MM-DD)",
                },
                "end_date": {
                    "type": "string",
                    "description": "Filter: entries before this date (YYYY-MM-DD)",
                },
                "filter_path": {
                    "type": "string",
                    "description": "Filter: entries matching this path substring (e.g., 'Windows\\Temp')",
                },
            },
            "required": ["image_path", "output_dir"],
        },
    ),
    # --- Memory Tools (Volatility 3) ---
    Tool(
        name="analyze_memory",
        description=(
            "Analyze a memory dump using Volatility 3. Runs a specified plugin "
            "and returns parsed structured output. Only allowlisted plugins can be "
            "executed. Pool-scanning plugins (psscan, netscan, filescan) work even "
            "when ISF symbols are missing. Use 'banners' to check OS identification."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Path to the memory dump file (.raw, .vmem, .lime, .dmp)",
                },
                "plugin": {
                    "type": "string",
                    "description": "Volatility 3 plugin to run",
                    "enum": [
                        "pslist", "psscan", "pstree", "cmdline", "envars",
                        "malfind", "ldrmodules", "ssdt", "vadinfo",
                        "handles", "dlllist", "netscan", "svcscan",
                        "filescan", "hivelist", "timeliner", "banners",
                    ],
                },
                "pid": {
                    "type": "integer",
                    "description": "Optional: filter to a specific process ID",
                },
                "extra_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional safe arguments to pass to the plugin",
                },
            },
            "required": ["dump_path", "plugin"],
        },
    ),
    Tool(
        name="dump_process_memory",
        description=(
            "Dump a process's memory regions from a memory image for FLOSS/YARA "
            "analysis. Writes dumped files to the specified output directory (must "
            "NOT be in the evidence directory). Use this to extract suspicious "
            "process memory before running extract_strings or scan_yara on it."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "dump_path": {
                    "type": "string",
                    "description": "Path to the memory dump file",
                },
                "pid": {
                    "type": "integer",
                    "description": "Process ID to dump",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write dumped files (e.g., /cases/CASE-001/analysis/dumps/)",
                },
            },
            "required": ["dump_path", "pid", "output_dir"],
        },
    ),
    # --- Registry Tools (RegRipper / RECmd) ---
    Tool(
        name="get_registry_key",
        description=(
            "Read a specific registry key and its values from a registry hive file. "
            "Returns the key path, last modified time, values (name, type, data), "
            "and subkeys. Uses RegRipper or RECmd."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hive_path": {
                    "type": "string",
                    "description": "Path to the registry hive file (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY)",
                },
                "key_path": {
                    "type": "string",
                    "description": "Registry key path to read (e.g., 'Microsoft\\Windows\\CurrentVersion\\Run')",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Include subkeys recursively",
                    "default": False,
                },
            },
            "required": ["hive_path", "key_path"],
        },
    ),
    Tool(
        name="check_persistence",
        description=(
            "Check common Windows persistence locations in registry hive files. "
            "Scans Run/RunOnce keys, Services, Scheduled Tasks, Winlogon, and "
            "other known persistence mechanisms. Returns all entries found."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hive_path": {
                    "type": "string",
                    "description": "Path to the registry hive file (typically NTUSER.DAT or SOFTWARE)",
                },
                "hive_type": {
                    "type": "string",
                    "description": "Type of hive to scan",
                    "enum": ["ntuser", "software", "system", "sam"],
                },
            },
            "required": ["hive_path", "hive_type"],
        },
    ),
    # --- Scanner Tools (YARA + strings) ---
    Tool(
        name="scan_yara",
        description=(
            "Scan a file or directory with YARA rules. Returns matching rule names, "
            "matched strings, and file offsets. Useful for detecting known malware "
            "signatures, suspicious patterns, and IOCs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Path to the file or directory to scan",
                },
                "rules_path": {
                    "type": "string",
                    "description": "Path to the YARA rules file (.yar)",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Scan directory recursively",
                    "default": False,
                },
            },
            "required": ["target_path", "rules_path"],
        },
    ),
    Tool(
        name="extract_strings",
        description=(
            "Extract printable strings from a file. Useful for identifying URLs, "
            "IP addresses, file paths, commands, and other text indicators in "
            "binary files. Uses the 'strings' utility or FLOSS for advanced "
            "string extraction."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file to extract strings from",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length to extract",
                    "default": 6,
                },
                "encoding": {
                    "type": "string",
                    "description": "String encoding to search for",
                    "enum": ["ascii", "unicode", "both"],
                    "default": "both",
                },
            },
            "required": ["file_path"],
        },
    ),
]


# --- Tool Dispatch ---

async def handle_tool_call(name: str, arguments: dict) -> str:
    """Dispatch a tool call to the appropriate handler module.

    Returns JSON string with the tool response envelope.
    """
    case_dir = get_case_dir()

    try:
        if name == "get_partition_layout":
            result = disk.get_partition_layout(
                image_path=arguments["image_path"],
                case_dir=case_dir,
            )
        elif name == "list_files":
            result = disk.list_files(
                image_path=arguments["image_path"],
                path=arguments.get("path", "/"),
                partition_offset=arguments.get("partition_offset"),
                recursive=arguments.get("recursive", False),
                case_dir=case_dir,
            )
        elif name == "extract_file":
            result = disk.extract_file(
                image_path=arguments["image_path"],
                inode=arguments["inode"],
                output_dir=arguments["output_dir"],
                output_name=arguments["output_name"],
                partition_offset=arguments.get("partition_offset"),
                case_dir=case_dir,
            )
        elif name == "generate_timeline":
            result = timeline.generate_timeline(
                image_path=arguments["image_path"],
                output_dir=arguments["output_dir"],
                start_date=arguments.get("start_date"),
                end_date=arguments.get("end_date"),
                filter_path=arguments.get("filter_path"),
                case_dir=case_dir,
            )
        elif name == "extract_mft":
            result = timeline.extract_mft(
                image_path=arguments["image_path"],
                output_dir=arguments["output_dir"],
                start_date=arguments.get("start_date"),
                end_date=arguments.get("end_date"),
                filter_path=arguments.get("filter_path"),
                case_dir=case_dir,
            )
        elif name == "analyze_memory":
            result = memory.analyze_memory(
                dump_path=arguments["dump_path"],
                plugin=arguments["plugin"],
                pid=arguments.get("pid"),
                extra_args=arguments.get("extra_args", []),
                case_dir=case_dir,
            )
        elif name == "dump_process_memory":
            result = memory.dump_process_memory(
                dump_path=arguments["dump_path"],
                pid=arguments["pid"],
                output_dir=arguments["output_dir"],
                case_dir=case_dir,
            )
        elif name == "get_registry_key":
            result = registry.get_registry_key(
                hive_path=arguments["hive_path"],
                key_path=arguments["key_path"],
                recursive=arguments.get("recursive", False),
                case_dir=case_dir,
            )
        elif name == "check_persistence":
            result = registry.check_persistence(
                hive_path=arguments["hive_path"],
                hive_type=arguments["hive_type"],
                case_dir=case_dir,
            )
        elif name == "scan_yara":
            result = scanner.scan_yara(
                target_path=arguments["target_path"],
                rules_path=arguments["rules_path"],
                recursive=arguments.get("recursive", False),
                case_dir=case_dir,
            )
        elif name == "extract_strings":
            result = scanner.extract_strings(
                file_path=arguments["file_path"],
                min_length=arguments.get("min_length", 6),
                encoding=arguments.get("encoding", "both"),
                case_dir=case_dir,
            )
        else:
            result = {"status": "error", "error": f"Unknown tool: {name}"}

    except ToolExecutionError as e:
        result = {
            "status": "error",
            "tool": name,
            "error": str(e),
            "exit_code": e.exit_code,
        }
    except Exception as e:
        logger.exception("Unexpected error in tool %s", name)
        result = {
            "status": "error",
            "tool": name,
            "error": f"Unexpected error: {type(e).__name__}: {e}",
        }

    return json.dumps(result, indent=2, default=str)


# --- MCP Server Setup ---

app = Server("valkyrie")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    result = await handle_tool_call(name, arguments)
    return [TextContent(type="text", text=result)]


async def main():
    logger.info("VALKYRIE MCP Server starting (stdio transport)")
    logger.info("Case directory: %s", CASE_DIR or "(not set)")
    logger.info("Evidence path: %s", evidence_path or "(not set)")
    logger.info("Registered %d tools", len(TOOLS))

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
