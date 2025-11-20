"""
Step 4: File Format Detection
Uses tools (python-magic, pefile) to detect actual file format and confirm if it's an executable.
"""
import logging
import os
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def _try_import_magic():
    """Try to import python-magic library."""
    try:
        import magic  # type: ignore
        return magic
    except ImportError:
        return None


def _try_import_pefile():
    """Try to import pefile library."""
    try:
        import pefile  # type: ignore
        return pefile
    except ImportError:
        return None


def detect_file_format(file_path: str) -> Dict[str, str]:
    """
    Detect file format using available tools.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with format detection results
    """
    result = {
        "detected_by": None,
        "file_type": None,
        "is_pe": False,
        "is_exe": False,
        "magic_bytes": None
    }
    
    # Try python-magic first
    MAGIC = _try_import_magic()
    if MAGIC is not None:
        try:
            m = MAGIC.Magic(mime=False)
            file_type = m.from_file(file_path)
            result["detected_by"] = "python-magic"
            result["file_type"] = file_type
            result["is_pe"] = "PE" in file_type or "executable" in file_type.lower()
            result["is_exe"] = result["is_pe"] or file_path.lower().endswith('.exe')
            logger.info(f"[Step 4] Detected format via python-magic: {file_type}")
            return result
        except Exception as e:
            logger.warning(f"[Step 4] python-magic detection failed: {e}")
    
    # Try pefile for PE detection
    PEFILE = _try_import_pefile()
    if PEFILE is not None:
        try:
            pe = PEFILE.PE(file_path, fast_load=True)
            result["detected_by"] = "pefile"
            result["file_type"] = "PE executable"
            result["is_pe"] = True
            result["is_exe"] = file_path.lower().endswith('.exe')
            pe.close()
            logger.info(f"[Step 4] Detected format via pefile: PE executable")
            return result
        except Exception:
            pass  # Not a PE file, continue to fallback
    
    # Fallback: Check magic bytes and extension
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(4)
            result["magic_bytes"] = magic_bytes.hex()
            
            # Check for PE signature (MZ header)
            if magic_bytes[:2] == b"MZ":
                result["detected_by"] = "magic_bytes"
                result["file_type"] = "PE executable"
                result["is_pe"] = True
                result["is_exe"] = file_path.lower().endswith('.exe')
                logger.info(f"[Step 4] Detected format via magic bytes: PE executable")
                return result
            
            # Check for ELF signature
            if magic_bytes == b"\x7fELF":
                result["detected_by"] = "magic_bytes"
                result["file_type"] = "ELF executable"
                result["is_pe"] = False
                result["is_exe"] = False
                logger.info(f"[Step 4] Detected format via magic bytes: ELF executable")
                return result
    except Exception as e:
        logger.warning(f"[Step 4] Magic bytes check failed: {e}")
    
    # Final fallback: Check extension
    file_ext = os.path.splitext(file_path)[1].lower()
    if file_ext == ".exe":
        result["detected_by"] = "extension"
        result["file_type"] = "PE executable (by extension)"
        result["is_pe"] = True
        result["is_exe"] = True
        logger.info(f"[Step 4] Detected format via extension: PE executable")
    else:
        result["detected_by"] = "extension"
        result["file_type"] = f"Unknown (extension: {file_ext})"
        result["is_pe"] = False
        result["is_exe"] = False
        logger.warning(f"[Step 4] Could not determine file format")
    
    return result


def analyze_format(file_path: str) -> Dict:
    """
    Step 4: Detect file format using tools and confirm if it's an executable.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary with format detection results
    """
    logger.info(f"[Step 4] Starting file format detection for: {file_path}")
    
    result = {
        "step": 4,
        "step_name": "File Format Detection",
        "file_path": file_path,
        "apparent_format": os.path.splitext(file_path)[1].lower() or "unknown",
        "actual_format": None,
        "is_pe_executable": False,
        "is_exe": False,
        "format_match": True,
        "detection_method": None,
        "error": None
    }
    
    try:
        # Detect file format
        format_info = detect_file_format(file_path)
        
        result["actual_format"] = format_info.get("file_type", "Unknown")
        result["is_pe_executable"] = format_info.get("is_pe", False)
        result["is_exe"] = format_info.get("is_exe", False)
        result["detection_method"] = format_info.get("detected_by", "unknown")
        
        # Check if format matches extension
        apparent = result["apparent_format"]
        if apparent == ".exe":
            result["format_match"] = result["is_exe"]
        elif apparent in [".dll", ".sys", ".drv", ".scr"]:
            result["format_match"] = result["is_pe_executable"]
        else:
            # For other extensions, just check if detected format makes sense
            result["format_match"] = True  # Assume match if we can't determine
        
        logger.info(f"[Step 4] Format detection completed: {result['actual_format']}, is_exe={result['is_exe']}, is_pe={result['is_pe_executable']}")
    
    except Exception as e:
        logger.error(f"[Step 4] Error during format detection: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

