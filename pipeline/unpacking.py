"""
Unpacking module for malware analysis.

Provides functionality to unpack packed executables.
"""
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def find_upx_executable() -> Optional[str]:
    """
    Try to find UPX executable in common locations.
    
    Returns:
        Path to UPX executable, or None if not found
    """
    # Common UPX executable names
    upx_names = ["upx.exe", "upx"]
    
    # Check current directory
    for name in upx_names:
        if os.path.isfile(name):
            return os.path.abspath(name)
    
    # Check PATH
    for name in upx_names:
        upx_path = shutil.which(name)
        if upx_path:
            return upx_path
    
    # Check common installation paths (Windows)
    if os.name == "nt":
        common_paths = [
            "C:\\Program Files\\upx\\upx.exe",
            "C:\\Program Files (x86)\\upx\\upx.exe",
            os.path.expanduser("~\\upx\\upx.exe"),
        ]
        for path in common_paths:
            if os.path.isfile(path):
                return path
    
    return None


def unpack_upx(packed_file: str, output_file: Optional[str] = None, timeout: int = 60) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Unpack a UPX-packed file.
    
    Args:
        packed_file: Path to the packed file
        output_file: Optional output path (if None, creates temp file)
        timeout: Timeout in seconds for unpacking operation
        
    Returns:
        Tuple of (success: bool, output_path: str | None, error_message: str | None)
    """
    if not os.path.isfile(packed_file):
        return False, None, f"File not found: {packed_file}"
    
    upx_path = find_upx_executable()
    if not upx_path:
        return False, None, "UPX executable not found. Please install UPX and ensure it's in PATH."
    
    # Determine output file
    if output_file is None:
        # Create output in same directory with .unpacked suffix
        base, ext = os.path.splitext(packed_file)
        output_file = base + ".unpacked" + ext
    
    try:
        # Run UPX unpacking: upx -d input -o output
        result = subprocess.run(
            [upx_path, "-d", packed_file, "-o", output_file],
            capture_output=True,
            timeout=timeout,
            text=True
        )
        
        if result.returncode == 0 and os.path.isfile(output_file):
            return True, output_file, None
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            return False, None, f"UPX unpacking failed: {error_msg}"
            
    except subprocess.TimeoutExpired:
        return False, None, f"UPX unpacking timed out after {timeout} seconds"
    except Exception as e:
        return False, None, f"UPX unpacking error: {str(e)}"


def unpack_file(file_path: str, packer_type: Optional[str] = None, output_dir: Optional[str] = None) -> Dict:
    """
    Attempt to unpack a file based on detected packer type.
    Now supports multiple packers with extended unpacking methods.
    
    Args:
        file_path: Path to the packed file
        packer_type: Detected packer type (e.g., "UPX", "Armadillo")
        output_dir: Directory to place unpacked file (if None, uses same dir as input)
        
    Returns:
        Dictionary with unpacking results:
        {
            "success": bool,
            "unpacked_path": str | None,
            "packer_type": str | None,
            "error": str | None,
            "unpacking_method": str | None,
            "guidance": str | None,
            "difficulty": str | None
        }
    """
    # Import extended unpacking module
    try:
        from .unpacking_extended import unpack_file_extended, get_unpacking_guidance
        # Use extended unpacking for all packers
        return unpack_file_extended(file_path, packer_type, output_dir)
    except ImportError:
        # Fallback to basic UPX-only unpacking
        logger.warning("[Unpacking] Extended unpacking module not available, using basic UPX-only unpacking")
    
    # Basic UPX-only unpacking (fallback)
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
    
    # Determine output directory
    if output_dir is None:
        output_dir = os.path.dirname(file_path)
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output filename
    base_name = os.path.basename(file_path)
    base, ext = os.path.splitext(base_name)
    output_file = os.path.join(output_dir, base + ".unpacked" + ext)
    
    # Try unpacking based on packer type
    if packer_type == "UPX" or (packer_type and "UPX" in packer_type.upper()):
        success, unpacked_path, error = unpack_upx(file_path, output_file)
        result["success"] = success
        result["unpacked_path"] = unpacked_path
        result["error"] = error
        result["unpacking_method"] = "command_line"
        if success:
            result["packer_type"] = "UPX"
    else:
        # For non-UPX packers, provide guidance
        result["unpacking_method"] = "manual"
        result["error"] = f"Unpacking not supported for packer type: {packer_type}"
        
        # Try to get guidance if extended module is available
        try:
            from .unpacking_extended import get_unpacking_guidance
            guidance_data = get_unpacking_guidance(packer_type)
            result["guidance"] = guidance_data.get("guidance", "")
            result["difficulty"] = guidance_data.get("difficulty", "Unknown")
        except ImportError:
            result["guidance"] = f"{packer_type} requires manual unpacking. Install extended unpacking module for detailed guidance."
    
    return result


def is_upx_available() -> bool:
    """
    Check if UPX is available for unpacking.
    
    Returns:
        True if UPX executable is found
    """
    return find_upx_executable() is not None

