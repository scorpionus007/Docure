"""
PE (Portable Executable) file analysis module.

Provides detailed analysis of PE files using pefile library.
"""
import os
from typing import Dict, List, Optional

# Try to import pefile, but don't fail if not available
try:
    import pefile  # type: ignore
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None


def is_pe_file(file_path: str) -> bool:
    """
    Check if a file is a PE executable.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file appears to be a PE file
    """
    if not PEFILE_AVAILABLE:
        # Fallback: check file extension and magic bytes
        lower = file_path.lower()
        if lower.endswith((".exe", ".dll", ".sys", ".scr", ".drv", ".ocx")):
            try:
                with open(file_path, "rb") as f:
                    magic = f.read(2)
                    return magic == b"MZ"
            except Exception:
                pass
        return False
    
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.close()
        return True
    except Exception:
        return False


def analyze_pe_file(file_path: str) -> Optional[Dict]:
    """
    Perform detailed analysis of a PE file.
    
    Args:
        file_path: Path to the PE file
        
    Returns:
        Dictionary with PE analysis results, or None if analysis fails
    """
    if not PEFILE_AVAILABLE:
        return None
    
    if not is_pe_file(file_path):
        return None
    
    try:
        pe = pefile.PE(file_path, fast_load=True)
        
        result: Dict = {
            "is_pe": True,
            "is_upx": False,
            "suspicious_sections": [],
            "suspicious_entry_point": False,
            "sections": [],
            "imports": [],
            "exports": [],
            "entry_point": None,
            "machine": None,
            "compile_time": None,
        }
        
        # Basic PE info
        try:
            result["entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            result["machine"] = pe.FILE_HEADER.Machine
            result["compile_time"] = pe.FILE_HEADER.TimeDateStamp
        except Exception:
            pass
        
        # Analyze sections
        try:
            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                # Calculate section entropy manually (pefile's get_entropy may not be available)
                section_entropy = None
                section_data = None
                try:
                    section_data = section.get_data()
                    if section_data:
                        # Import entropy calculation from packing module
                        from .packing import calculate_entropy
                        section_entropy = calculate_entropy(section_data)
                except Exception:
                    pass
                
                section_info = {
                    "name": section_name,
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": section_entropy,
                    "raw_data": section_data,  # Store raw data for later use
                }
                
                result["sections"].append(section_info)
                
                # Check for UPX
                if "UPX" in section_name.upper():
                    result["is_upx"] = True
                    result["suspicious_sections"].append(f"UPX section: {section_name}")
                
                # Check for other packer section names
                packer_signatures = {
                    "ASPack": ["ASPack", "aspack"],
                    "PECompact": ["PECompact", "PEC2", "PEC2MO"],
                    "NSPack": ["NSPack", "nspack"],
                    "UPack": ["UPack", "UPack v"],
                    "MEW": ["MEW", "MEW11"],
                    "FSG": ["FSG", "FSG!"],
                    "Petite": ["Petite", "petite"],
                    "RLPack": ["RLPack", "RLPack!"],
                    "VMProtect": ["VMProtect"],
                    "Themida": ["Themida", "TMD"],
                    "Enigma": ["Enigma", "Enigma Protector"],
                    "Armadillo": ["Armadillo"],
                    "Obsidium": ["Obsidium", "OBSIDIUM"],
                }
                
                for packer_name, signatures in packer_signatures.items():
                    for sig in signatures:
                        if sig.upper() in section_name.upper():
                            result["suspicious_sections"].append(f"{packer_name} section: {section_name}")
                            # Set packer type if not already set
                            if not result.get("detected_packer"):
                                result["detected_packer"] = packer_name
                            break
                
                # Check section characteristics
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    if section.Characteristics & 0x40000000:  # IMAGE_SCN_MEM_WRITE
                        result["suspicious_sections"].append(f"Writable executable section: {section_name}")
        except Exception:
            pass
        
        # Check entry point
        try:
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            # Suspicious if entry point is in first section (common in packers)
            if entry_point < 0x1000:
                result["suspicious_entry_point"] = True
        except Exception:
            pass
        
        # Extract imports
        try:
            pe.parse_data_directories()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode("utf-8", errors="ignore")
                            result["imports"].append(f"{dll_name}!{import_name}")
        except Exception:
            pass
        
        # Extract exports
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode("utf-8", errors="ignore")
                        result["exports"].append(export_name)
        except Exception:
            pass
        
        pe.close()
        return result
        
    except Exception:
        return None


def get_pe_imports(file_path: str) -> List[str]:
    """
    Extract import list from a PE file.
    
    Args:
        file_path: Path to the PE file
        
    Returns:
        List of imports in format "dll!function"
    """
    pe_info = analyze_pe_file(file_path)
    if pe_info:
        return pe_info.get("imports", [])
    return []


def get_pe_exports(file_path: str) -> List[str]:
    """
    Extract export list from a PE file.
    
    Args:
        file_path: Path to the PE file
        
    Returns:
        List of exported function names
    """
    pe_info = analyze_pe_file(file_path)
    if pe_info:
        return pe_info.get("exports", [])
    return []

