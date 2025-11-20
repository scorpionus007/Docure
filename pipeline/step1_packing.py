"""
Step 1: Packing Detection & Unpacking
Detects if file is packed and attempts to unpack it.
"""
import logging
import os
from typing import Dict, Optional

from .packing import detect_packing
from .unpacking import unpack_file

logger = logging.getLogger(__name__)


def analyze_packing(file_path: str, output_dir: Optional[str] = None) -> Dict:
    """
    Step 1: Analyze if file is packed and attempt unpacking.
    
    Args:
        file_path: Path to the file to analyze
        output_dir: Directory for unpacked files
        
    Returns:
        Dictionary with packing analysis results
    """
    logger.info(f"[Step 1] Starting packing detection for: {file_path}")
    
    result = {
        "step": 1,
        "step_name": "Packing Detection & Unpacking",
        "file_path": file_path,
        "is_packed": False,
        "packer_type": None,
        "packing_confidence": "none",
        "packing_indicators": [],
        "entropy": 0.0,
        "unpacked": {
            "success": False,
            "unpacked_path": None,
            "error": None
        }
    }
    
    try:
        # Detect packing
        packing_info = detect_packing(file_path)
        
        result["is_packed"] = packing_info.get("is_packed", False)
        result["packer_type"] = packing_info.get("packer_type")
        result["packing_confidence"] = packing_info.get("confidence", "none")
        result["packing_indicators"] = packing_info.get("indicators", [])
        result["entropy"] = packing_info.get("entropy", 0.0)
        
        logger.info(f"[Step 1] Packing detection: is_packed={result['is_packed']}, "
                   f"packer_type={result['packer_type']}, confidence={result['packing_confidence']}")
        
        # Attempt unpacking if packed
        if result["is_packed"] and result["packer_type"]:
            logger.info(f"[Step 1] Attempting to unpack file (packer: {result['packer_type']})")
            
            unpack_result = unpack_file(
                file_path,
                packer_type=result["packer_type"],
                output_dir=output_dir
            )
            
            result["unpacked"] = {
                "success": unpack_result.get("success", False),
                "unpacked_path": unpack_result.get("unpacked_path"),
                "error": unpack_result.get("error"),
                "unpacking_method": unpack_result.get("unpacking_method"),
                "guidance": unpack_result.get("guidance"),
                "difficulty": unpack_result.get("difficulty")
            }
            
            if result["unpacked"]["success"]:
                logger.info(f"[Step 1] Successfully unpacked to: {result['unpacked']['unpacked_path']}")
            else:
                if result["unpacked"].get("guidance"):
                    logger.info(f"[Step 1] Unpacking requires manual method. Difficulty: {result['unpacked'].get('difficulty', 'Unknown')}")
                logger.warning(f"[Step 1] Unpacking failed: {result['unpacked']['error']}")
        else:
            logger.info("[Step 1] File is not packed or packer type unknown, skipping unpacking")
            
    except Exception as e:
        logger.error(f"[Step 1] Error during packing analysis: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

