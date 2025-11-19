"""
Packing detection module for malware analysis.

Provides entropy calculation and packer detection capabilities.
"""
import math
import os
from typing import Dict, List, Optional, Tuple

from .pe_analysis import analyze_pe_file, is_pe_file

# Try to import yara, but don't fail if not available
try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    
    High entropy (>7.0) typically indicates compression or encryption,
    which is a strong indicator of packing.
    
    Args:
        data: Byte sequence to analyze
        
    Returns:
        Entropy value between 0.0 and 8.0
    """
    if not data or len(data) == 0:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def calculate_file_entropy(file_path: str, max_bytes: int = 1024 * 1024) -> Tuple[float, Optional[float]]:
    """
    Calculate entropy of a file (overall and first section if PE).
    
    Args:
        file_path: Path to the file
        max_bytes: Maximum bytes to read for entropy calculation
        
    Returns:
        Tuple of (overall_entropy, section_entropy)
        section_entropy is None for non-PE files or if analysis fails
    """
    overall_entropy = 0.0
    section_entropy = None
    
    try:
        size = os.path.getsize(file_path)
        read_size = min(size, max_bytes)
        
        with open(file_path, "rb") as f:
            data = f.read(read_size)
        
        overall_entropy = calculate_entropy(data)
        
        # For PE files, also check first section entropy (often where packer code is)
        if is_pe_file(file_path):
            try:
                pe_info = analyze_pe_file(file_path)
                if pe_info and pe_info.get("sections"):
                    first_section = pe_info["sections"][0]
                    section_data = first_section.get("raw_data")
                    if section_data:
                        section_entropy = calculate_entropy(section_data)
            except Exception:
                pass  # Fallback to overall entropy only
                
    except Exception:
        pass
    
    return overall_entropy, section_entropy


def _load_yara_rules() -> Optional[object]:
    """
    Load YARA rules for packer detection.
    
    Returns:
        Compiled YARA rules object, or None if YARA is not available
    """
    if not YARA_AVAILABLE:
        return None
    
    try:
        # Try to find yara rules file
        rules_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "yara_rules",
            "packers.yar"
        )
        
        if os.path.isfile(rules_path):
            return yara.compile(filepath=rules_path)
        
        # Try alternative path (if running from different location)
        alt_path = os.path.join(os.getcwd(), "yara_rules", "packers.yar")
        if os.path.isfile(alt_path):
            return yara.compile(filepath=alt_path)
            
    except Exception:
        pass
    
    return None


def detect_packer_with_yara(file_path: str) -> Optional[Dict]:
    """
    Detect packer using YARA rules.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary with YARA detection results, or None if no match:
        {
            "packer_type": str,
            "rule_name": str,
            "severity": str
        }
    """
    if not YARA_AVAILABLE:
        return None
    
    try:
        rules = _load_yara_rules()
        if not rules:
            return None
        
        matches = rules.match(file_path)
        if matches:
            # Get the first match (most specific)
            match = matches[0]
            meta = match.meta
            
            return {
                "packer_type": meta.get("packer_type", "Unknown"),
                "rule_name": match.rule,
                "severity": meta.get("severity", "medium"),
                "description": meta.get("description", ""),
            }
    except Exception:
        pass
    
    return None


def detect_packing(file_path: str, entropy_threshold: float = 7.0) -> Dict:
    """
    Detect if a file is likely packed based on entropy and other heuristics.
    
    Args:
        file_path: Path to the file to analyze
        entropy_threshold: Entropy threshold above which file is considered suspicious
        
    Returns:
        Dictionary with packing detection results:
        {
            "is_packed": bool,
            "entropy": float,
            "section_entropy": float | None,
            "packer_type": str | None,
            "confidence": str,  # "high", "medium", "low", "none"
            "indicators": List[str]
        }
    """
    result = {
        "is_packed": False,
        "entropy": 0.0,
        "section_entropy": None,
        "packer_type": None,
        "confidence": "none",
        "indicators": []
    }
    
    try:
        # Calculate entropy
        overall_entropy, section_entropy = calculate_file_entropy(file_path)
        result["entropy"] = overall_entropy
        result["section_entropy"] = section_entropy
        
        # Check entropy thresholds
        if overall_entropy >= entropy_threshold:
            result["is_packed"] = True
            result["confidence"] = "high"
            result["indicators"].append(f"High entropy ({overall_entropy:.2f})")
        
        # YARA-based packer detection (most reliable)
        yara_result = detect_packer_with_yara(file_path)
        if yara_result:
            result["is_packed"] = True
            packer_type = yara_result.get("packer_type")
            if packer_type and packer_type != "Unknown":
                result["packer_type"] = packer_type
                result["confidence"] = "high"
                severity = yara_result.get("severity", "medium")
                if severity == "high":
                    result["confidence"] = "high"
                result["indicators"].append(f"YARA: {yara_result.get('description', packer_type)}")
        
        # For PE files, use pefile analysis for packer detection (fallback/enhancement)
        if is_pe_file(file_path):
            pe_info = analyze_pe_file(file_path)
            if pe_info:
                # Check for UPX (only if not already detected by YARA)
                if pe_info.get("is_upx") and not result.get("packer_type"):
                    result["is_packed"] = True
                    result["packer_type"] = "UPX"
                    if result["confidence"] != "high":
                        result["confidence"] = "high"
                    result["indicators"].append("UPX packer detected (PE analysis)")
                
                # Check for detected packer from PE analysis
                detected_packer = pe_info.get("detected_packer")
                if detected_packer and not result.get("packer_type"):
                    result["is_packed"] = True
                    result["packer_type"] = detected_packer
                    result["confidence"] = "high"
                    result["indicators"].append(f"{detected_packer} packer detected (PE analysis)")
                
                # Check for other packer indicators
                if pe_info.get("suspicious_sections"):
                    result["is_packed"] = True
                    if result["confidence"] == "none":
                        result["confidence"] = "medium"
                    result["indicators"].extend(pe_info.get("suspicious_sections", []))
                
                # Check entry point characteristics
                if pe_info.get("suspicious_entry_point"):
                    if result["confidence"] == "none":
                        result["confidence"] = "low"
                    result["indicators"].append("Suspicious entry point")
                
                # Check section entropy
                if section_entropy and section_entropy >= entropy_threshold:
                    if not result["is_packed"]:
                        result["is_packed"] = True
                        result["confidence"] = "medium"
                    result["indicators"].append(f"High section entropy ({section_entropy:.2f})")
        
        # Adjust confidence based on number of indicators
        if result["is_packed"]:
            indicator_count = len(result["indicators"])
            if indicator_count >= 2 and result["confidence"] != "high":
                result["confidence"] = "medium"
            elif indicator_count == 1 and result["confidence"] == "none":
                result["confidence"] = "low"
        
    except Exception as e:
        # On error, return safe defaults
        pass
    
    return result

