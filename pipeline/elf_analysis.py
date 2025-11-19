"""
ELF (Executable and Linkable Format) file analysis module.

Provides detailed analysis of ELF files using lief library.
"""
import os
from typing import Dict, List, Optional

# Try to import lief, but don't fail if not available
try:
    import lief  # type: ignore
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = None


def is_elf_file(file_path: str) -> bool:
    """
    Check if a file is an ELF executable.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file appears to be an ELF file
    """
    if not LIEF_AVAILABLE:
        # Fallback: check file extension and magic bytes
        lower = file_path.lower()
        if lower.endswith((".so", ".elf", ".bin")) or not lower.endswith((".exe", ".dll")):
            try:
                with open(file_path, "rb") as f:
                    magic = f.read(4)
                    return magic == b"\x7fELF"
            except Exception:
                pass
        return False
    
    try:
        binary = lief.parse(file_path)
        return binary is not None
    except Exception:
        return False


def analyze_elf_file(file_path: str) -> Optional[Dict]:
    """
    Perform detailed analysis of an ELF file.
    
    Args:
        file_path: Path to the ELF file
        
    Returns:
        Dictionary with ELF analysis results, or None if analysis fails
    """
    if not LIEF_AVAILABLE:
        return None
    
    if not is_elf_file(file_path):
        return None
    
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return None
        
        result: Dict = {
            "is_elf": True,
            "format": None,
            "architecture": None,
            "entry_point": None,
            "sections": [],
            "segments": [],
            "imports": [],
            "exports": [],
            "symbols": [],
            "suspicious_indicators": [],
        }
        
        # Basic ELF info
        try:
            result["format"] = str(binary.format)
            result["architecture"] = str(binary.header.machine_type)
            result["entry_point"] = hex(binary.entrypoint) if binary.entrypoint else None
        except Exception:
            pass
        
        # Analyze sections
        try:
            for section in binary.sections:
                section_info = {
                    "name": section.name if section.name else "",
                    "type": str(section.type),
                    "flags": hex(section.flags) if hasattr(section, "flags") else None,
                    "size": section.size,
                    "virtual_address": hex(section.virtual_address) if section.virtual_address else None,
                    "entropy": None,
                }
                
                # Calculate section entropy if we have data
                try:
                    if section.content:
                        from .packing import calculate_entropy
                        section_info["entropy"] = round(calculate_entropy(bytes(section.content)), 4)
                except Exception:
                    pass
                
                result["sections"].append(section_info)
                
                # Check for suspicious section names (packers, etc.)
                section_name = section_info["name"].upper()
                suspicious_names = ["UPX", "PACK", "NSPACK", "ASPack", "FSG", "MEW"]
                for sus_name in suspicious_names:
                    if sus_name in section_name:
                        result["suspicious_indicators"].append(f"Suspicious section: {section.name}")
        except Exception:
            pass
        
        # Analyze segments
        try:
            for segment in binary.segments:
                segment_info = {
                    "type": str(segment.type),
                    "flags": hex(segment.flags) if hasattr(segment, "flags") else None,
                    "virtual_address": hex(segment.virtual_address) if segment.virtual_address else None,
                    "virtual_size": segment.virtual_size,
                    "file_size": segment.physical_size,
                }
                result["segments"].append(segment_info)
        except Exception:
            pass
        
        # Extract imports
        try:
            if hasattr(binary, "imported_functions"):
                for func in binary.imported_functions:
                    lib_name = func.library.name if hasattr(func, "library") and func.library else "unknown"
                    func_name = func.name if hasattr(func, "name") else "unknown"
                    result["imports"].append(f"{lib_name}!{func_name}")
        except Exception:
            pass
        
        # Extract exports/symbols
        try:
            if hasattr(binary, "exported_functions"):
                for func in binary.exported_functions:
                    result["exports"].append(func.name if hasattr(func, "name") else "unknown")
        except Exception:
            pass
        
        # Extract symbols
        try:
            if hasattr(binary, "symbols"):
                for symbol in binary.symbols:
                    if symbol.name:
                        result["symbols"].append(symbol.name)
        except Exception:
            pass
        
        # Check for suspicious characteristics
        try:
            # Check entry point (suspicious if very low, common in packers)
            if binary.entrypoint and binary.entrypoint < 0x1000:
                result["suspicious_indicators"].append("Suspicious entry point")
            
            # Check for high entropy sections (packing indicator)
            high_entropy_sections = [s for s in result["sections"] if s.get("entropy") and s.get("entropy", 0) >= 7.0]
            if high_entropy_sections:
                result["suspicious_indicators"].append(f"High entropy sections detected ({len(high_entropy_sections)})")
        except Exception:
            pass
        
        return result
        
    except Exception:
        return None


def get_elf_imports(file_path: str) -> List[str]:
    """
    Extract import list from an ELF file.
    
    Args:
        file_path: Path to the ELF file
        
    Returns:
        List of imports in format "library!function"
    """
    elf_info = analyze_elf_file(file_path)
    if elf_info:
        return elf_info.get("imports", [])
    return []


def get_elf_exports(file_path: str) -> List[str]:
    """
    Extract export list from an ELF file.
    
    Args:
        file_path: Path to the ELF file
        
    Returns:
        List of exported function names
    """
    elf_info = analyze_elf_file(file_path)
    if elf_info:
        return elf_info.get("exports", [])
    return []


def detect_elf_packing(file_path: str) -> Dict:
    """
    Detect if an ELF file is likely packed.
    
    Args:
        file_path: Path to the ELF file
        
    Returns:
        Dictionary with packing detection results
    """
    result = {
        "is_packed": False,
        "packer_type": None,
        "confidence": "none",
        "indicators": []
    }
    
    elf_info = analyze_elf_file(file_path)
    if not elf_info:
        return result
    
    # Check for suspicious indicators
    suspicious = elf_info.get("suspicious_indicators", [])
    if suspicious:
        result["is_packed"] = True
        result["confidence"] = "medium"
        result["indicators"].extend(suspicious)
    
    # Check section names for packer signatures
    for section in elf_info.get("sections", []):
        section_name = section.get("name", "").upper()
        if "UPX" in section_name:
            result["is_packed"] = True
            result["packer_type"] = "UPX"
            result["confidence"] = "high"
            result["indicators"].append("UPX section detected")
            break
        elif any(packer in section_name for packer in ["PACK", "NSPACK", "ASPack", "FSG", "MEW"]):
            result["is_packed"] = True
            if not result["packer_type"]:
                result["packer_type"] = "Generic"
            result["confidence"] = "medium"
            result["indicators"].append(f"Packer section: {section.get('name')}")
    
    # Check for high entropy
    high_entropy_sections = [s for s in elf_info.get("sections", []) if s.get("entropy") and s.get("entropy", 0) >= 7.0]
    if high_entropy_sections:
        result["is_packed"] = True
        if result["confidence"] == "none":
            result["confidence"] = "medium"
        result["indicators"].append(f"High entropy sections: {len(high_entropy_sections)}")
    
    return result

