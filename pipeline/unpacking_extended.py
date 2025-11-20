"""
Extended Unpacking Module
Supports multiple packers with various unpacking methods.
Includes support for Unipacker (Python-based multi-packer tool).
"""
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Check if Unipacker is available
UNIPACKER_AVAILABLE = False
try:
    import unipacker
    UNIPACKER_AVAILABLE = True
    logger.info("[Unpacking] Unipacker library is available")
except ImportError:
    logger.debug("[Unpacking] Unipacker library not installed (pip install unipacker)")


# Packer-specific unpacking tools and methods
# Unipacker supports: UPX, ASPack, FSG, MEW, MPRESS, PEtite, YZPack
UNIPACKER_SUPPORTED = ["UPX", "ASPack", "FSG", "MEW", "MPRESS", "PEtite", "YZPack"]

UNPACKER_TOOLS = {
    "UPX": {
        "tool": "upx.exe",
        "method": "command_line",
        "command": ["upx", "-d", "{input}", "-o", "{output}"],
        "description": "UPX has built-in unpacking support",
        "unipacker_supported": True
    },
    "ASPack": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "FSG": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "MEW": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "MPRESS": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "PEtite": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "YZPack": {
        "tool": "unipacker",
        "method": "python_unipacker",
        "command": None,
        "description": "Supported by Unipacker (pip install unipacker)",
        "unipacker_supported": True
    },
    "PECompact": {
        "tool": "pecompact_unpacker.exe",
        "method": "command_line",
        "command": None,
        "description": "Requires specialized tools or manual unpacking",
        "unipacker_supported": False
    },
    "Armadillo": {
        "tool": None,
        "method": "manual",
        "command": None,
        "description": "Requires manual unpacking with debuggers (OllyDbg/x64dbg) or specialized tools",
        "unipacker_supported": False
    },
    "VMProtect": {
        "tool": None,
        "method": "manual",
        "command": None,
        "description": "Very difficult to unpack, requires advanced techniques",
        "unipacker_supported": False
    },
    "Themida": {
        "tool": None,
        "method": "manual",
        "command": None,
        "description": "Commercial protector, requires specialized unpacking tools",
        "unipacker_supported": False
    },
    "Enigma": {
        "tool": None,
        "method": "manual",
        "command": None,
        "description": "Requires manual unpacking with debuggers",
        "unipacker_supported": False
    },
    "Obsidium": {
        "tool": None,
        "method": "manual",
        "command": None,
        "description": "Requires specialized unpacking tools",
        "unipacker_supported": False
    }
}


def unpack_with_unipacker(file_path: str, packer_type: str, output_file: str, timeout: int = 180) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Attempt to unpack using Unipacker (Python library).
    
    Args:
        file_path: Path to packed file
        packer_type: Detected packer type
        output_file: Output file path
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success, output_path, error_message)
    """
    if not UNIPACKER_AVAILABLE:
        return False, None, "Unipacker library not installed. Install with: pip install unipacker"
    
    if packer_type not in UNIPACKER_SUPPORTED:
        return False, None, f"Unipacker does not support {packer_type}. Supported: {', '.join(UNIPACKER_SUPPORTED)}"
    
    try:
        # Unipacker can be used via command line or Python API
        # Try command line first (more reliable)
        unipacker_cmd = [sys.executable, "-m", "unipacker", file_path, "-o", output_file]
        
        logger.info(f"[Unipacker] Attempting to unpack {packer_type} with Unipacker")
        result = subprocess.run(
            unipacker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0 and os.path.isfile(output_file):
            logger.info(f"[Unipacker] Successfully unpacked {packer_type} to {output_file}")
            return True, output_file, None
        else:
            # Try Python API as fallback
            try:
                from unipacker import Unpacker
                unpacker = Unpacker(file_path)
                unpacker.unpack(output_file)
                if os.path.isfile(output_file):
                    logger.info(f"[Unipacker] Successfully unpacked {packer_type} using Python API")
                    return True, output_file, None
                else:
                    error_msg = result.stderr or result.stdout or "Unipacker failed (no output file created)"
                    return False, None, f"Unipacker failed: {error_msg}"
            except Exception as api_error:
                error_msg = result.stderr or result.stdout or str(api_error)
                return False, None, f"Unipacker failed: {error_msg}"
                
    except subprocess.TimeoutExpired:
        return False, None, f"Unipacker timed out after {timeout} seconds"
    except Exception as e:
        return False, None, f"Unipacker error: {str(e)}"


def find_unpacker_tool(tool_name: str) -> Optional[str]:
    """
    Find unpacker tool in common locations.
    
    Args:
        tool_name: Name of the tool to find
        
    Returns:
        Path to tool or None
    """
    # Check current directory
    if os.path.isfile(tool_name):
        return os.path.abspath(tool_name)
    
    # Check tools directory
    tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
    tool_path = os.path.join(tools_dir, tool_name)
    if os.path.isfile(tool_path):
        return tool_path
    
    # Check PATH
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path
    
    return None


def unpack_with_tool(file_path: str, packer_type: str, output_file: str, timeout: int = 120) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Attempt to unpack using a specific tool.
    
    Args:
        file_path: Path to packed file
        packer_type: Detected packer type
        output_file: Output file path
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (success, output_path, error_message)
    """
    packer_info = UNPACKER_TOOLS.get(packer_type)
    if not packer_info:
        return False, None, f"No unpacking method defined for {packer_type}"
    
    if packer_info["method"] == "manual":
        return False, None, f"{packer_type} requires manual unpacking: {packer_info['description']}"
    
    # Try Unipacker first if supported
    if packer_info.get("unipacker_supported") and packer_info["method"] == "python_unipacker":
        logger.info(f"[Unpacking] Attempting {packer_type} unpacking with Unipacker")
        success, output_path, error = unpack_with_unipacker(file_path, packer_type, output_file, timeout)
        if success:
            return success, output_path, error
        # If Unipacker fails, continue to other methods if available
        logger.warning(f"[Unpacking] Unipacker failed for {packer_type}: {error}")
    
    if packer_info["method"] not in ["command_line", "python_unipacker"]:
        return False, None, f"Unsupported unpacking method: {packer_info['method']}"
    
    tool_name = packer_info.get("tool")
    if not tool_name:
        return False, None, f"No tool specified for {packer_type}"
    
    tool_path = find_unpacker_tool(tool_name)
    if not tool_path:
        return False, None, f"Unpacking tool not found: {tool_name}. {packer_info['description']}"
    
    command = packer_info.get("command")
    if not command:
        return False, None, f"No command defined for {packer_type}"
    
    # Replace placeholders in command
    cmd = [c.replace("{input}", file_path).replace("{output}", output_file) for c in command]
    cmd[0] = tool_path  # Replace first element with full tool path
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0 and os.path.isfile(output_file):
            return True, output_file, None
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            return False, None, f"Unpacking failed: {error_msg}"
    except subprocess.TimeoutExpired:
        return False, None, f"Unpacking timed out after {timeout} seconds"
    except Exception as e:
        return False, None, f"Unpacking error: {str(e)}"


def get_unpacking_guidance(packer_type: str) -> Dict[str, str]:
    """
    Get manual unpacking guidance for packers that can't be automatically unpacked.
    
    Args:
        packer_type: Detected packer type
        
    Returns:
        Dictionary with unpacking guidance
    """
    guidance = {
        "Armadillo": """
        **Armadillo Unpacking Guide:**
        
        1. **Tools Required:**
           - OllyDbg or x64dbg
           - Armadillo Find Protected / Armadillo Killer (if available)
           - Process Monitor (ProcMon)
        
        2. **Method:**
           - Load file in debugger
           - Set breakpoints on VirtualAlloc, VirtualProtect
           - Find OEP (Original Entry Point)
           - Dump memory at OEP
           - Fix imports using Import Reconstructor
        
        3. **Alternative:**
           - Use specialized tools like Armadillo Find Protected
           - Or use automated unpackers if available
        
        4. **Difficulty**: High - Armadillo has anti-debugging features
        """,
        
        "VMProtect": """
        **VMProtect Unpacking Guide:**
        
        1. **Tools Required:**
           - x64dbg or IDA Pro
           - VMProtect unpacker scripts (if available)
        
        2. **Method:**
           - VMProtect uses virtualization - very difficult to unpack
           - Requires finding VM handlers
           - Manual reconstruction of original code
           - Often requires specialized knowledge
        
        3. **Difficulty**: Very High - VMProtect is one of the strongest protectors
        """,
        
        "Themida": """
        **Themida Unpacking Guide:**
        
        1. **Tools Required:**
           - x64dbg
           - Themida unpacker scripts
           - Process Monitor
        
        2. **Method:**
           - Load in debugger
           - Bypass anti-debugging
           - Find OEP
           - Dump and fix imports
        
        3. **Difficulty**: Very High - Commercial protector with strong anti-debugging
        """,
        
        "Enigma": """
        **Enigma Protector Unpacking Guide:**
        
        1. **Tools Required:**
           - OllyDbg or x64dbg
           - Enigma unpacker scripts
        
        2. **Method:**
           - Load in debugger
           - Find OEP
           - Dump memory
           - Fix imports
        
        3. **Difficulty**: High
        """,
        
        "Obsidium": """
        **Obsidium Unpacking Guide:**
        
        1. **Tools Required:**
           - x64dbg
           - Obsidium unpacker tools (if available)
        
        2. **Method:**
           - Load in debugger
           - Bypass protection
           - Find OEP
           - Dump and reconstruct
        
        3. **Difficulty**: High
        """,
        
        "FSG": """
        **FSG Unpacking Guide:**
        
        1. **Tools Required:**
           - OllyDbg or x64dbg
           - FSG unpacker scripts
        
        2. **Method:**
           - Load in debugger
           - Set breakpoint on GetProcAddress
           - Find OEP
           - Dump memory
           - Fix imports
        
        3. **Difficulty**: Medium
        """,
        
        "ASPack": """
        **ASPack Unpacking Guide:**
        
        1. **Tools Required:**
           - ASPack unpacker tools
           - Or OllyDbg with ASPack unpacker scripts
        
        2. **Method:**
           - Use specialized ASPack unpacker if available
           - Or manual unpacking in debugger
           - Find OEP and dump
        
        3. **Difficulty**: Medium
        """,
        
        "PECompact": """
        **PECompact Unpacking Guide:**
        
        1. **Tools Required:**
           - PECompact unpacker tools
           - Or OllyDbg/x64dbg
        
        2. **Method:**
           - Use PECompact unpacker if available
           - Or manual unpacking in debugger
        
        3. **Difficulty**: Medium
        """
    }
    
    return {
        "packer_type": packer_type,
        "guidance": guidance.get(packer_type, "No specific guidance available for this packer"),
        "difficulty": {
            "Armadillo": "High",
            "VMProtect": "Very High",
            "Themida": "Very High",
            "Enigma": "High",
            "Obsidium": "High",
            "FSG": "Medium",
            "ASPack": "Medium",
            "PECompact": "Medium"
        }.get(packer_type, "Unknown")
    }


def unpack_file_extended(file_path: str, packer_type: Optional[str] = None, output_dir: Optional[str] = None) -> Dict:
    """
    Extended unpacking function supporting multiple packers.
    
    Args:
        file_path: Path to the packed file
        packer_type: Detected packer type
        output_dir: Directory to place unpacked file
        
    Returns:
        Dictionary with unpacking results including guidance
    """
    result = {
        "success": False,
        "unpacked_path": None,
        "packer_type": packer_type,
        "error": None,
        "unpacking_method": None,
        "guidance": None,
        "difficulty": None
    }
    
    if not os.path.isfile(file_path):
        result["error"] = f"File not found: {file_path}"
        return result
    
    if not packer_type:
        result["error"] = "Packer type not specified"
        return result
    
    # Determine output directory
    if output_dir is None:
        output_dir = os.path.dirname(file_path)
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output filename
    base_name = os.path.basename(file_path)
    base, ext = os.path.splitext(base_name)
    output_file = os.path.join(output_dir, base + f".unpacked_{packer_type}" + ext)
    
    # Get packer info
    packer_info = UNPACKER_TOOLS.get(packer_type, {})
    method = packer_info.get("method", "unknown")
    
    result["unpacking_method"] = method
    result["difficulty"] = get_unpacking_guidance(packer_type).get("difficulty", "Unknown")
    
    # Try automatic unpacking for supported packers
    # First try Unipacker if supported
    if method == "python_unipacker" and packer_info.get("unipacker_supported"):
        logger.info(f"[Unpacking] Attempting automatic unpacking for {packer_type} with Unipacker")
        success, unpacked_path, error = unpack_with_unipacker(file_path, packer_type, output_file)
        result["success"] = success
        result["unpacked_path"] = unpacked_path
        result["error"] = error
        if success:
            logger.info(f"[Unpacking] Successfully unpacked {packer_type} file with Unipacker")
            return result
        # If Unipacker fails, try command line tool if available
        logger.warning(f"[Unpacking] Unipacker failed, trying alternative method")
    
    # Try command line tools (e.g., UPX)
    if method == "command_line":
        logger.info(f"[Unpacking] Attempting automatic unpacking for {packer_type} with command line tool")
        success, unpacked_path, error = unpack_with_tool(file_path, packer_type, output_file)
        result["success"] = success
        result["unpacked_path"] = unpacked_path
        result["error"] = error
        if success:
            logger.info(f"[Unpacking] Successfully unpacked {packer_type} file")
            return result
    
    # For manual unpacking or failed automatic, provide guidance
    if method == "manual" or not result["success"]:
        logger.warning(f"[Unpacking] {packer_type} requires manual unpacking or automatic unpacking failed")
        guidance_data = get_unpacking_guidance(packer_type)
        result["guidance"] = guidance_data.get("guidance", "No guidance available")
        result["difficulty"] = guidance_data.get("difficulty", "Unknown")
        
        if not result["error"]:
            result["error"] = f"{packer_type} requires manual unpacking. See guidance for instructions."
    
    return result

