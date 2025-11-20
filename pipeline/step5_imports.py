"""
Step 5: Import/Export Analysis
Analyzes DLL imports/exports using PEView or pefile.
"""
import logging
import os
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def find_peview() -> Optional[str]:
    """
    Find PEView executable.
    
    Returns:
        Path to PEView executable or None
    """
    common_paths = [
        "PEView.exe",
        os.path.join(os.getcwd(), "tools", "PEView.exe"),
        "C:\\Program Files\\PEView\\PEView.exe",
        "C:\\Program Files (x86)\\PEView\\PEView.exe",
    ]
    
    for path in common_paths:
        if os.path.isfile(path):
            return path
    
    return None


def analyze_imports_exports_pefile(file_path: str) -> Dict:
    """
    Analyze imports/exports using pefile (fallback method).
    
    Args:
        file_path: Path to the PE file
        
    Returns:
        Dictionary with imports/exports analysis
    """
    result = {
        "imports": [],
        "exports": [],
        "import_count": 0,
        "export_count": 0,
        "suspicious_imports": []
    }
    
    try:
        import pefile
        
        pe = pefile.PE(file_path)
        
        # Extract imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports_list = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports_list.append(f"{dll_name}!{func_name}")
            
            result["imports"] = imports_list
            result["import_count"] = len(imports_list)
            
            # Check for suspicious imports
            suspicious_keywords = [
                "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
                "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute",
                "socket", "connect", "send", "recv", "WSAStartup"
            ]
            
            for imp in imports_list:
                for keyword in suspicious_keywords:
                    if keyword.lower() in imp.lower():
                        result["suspicious_imports"].append(imp)
                        break
        
        # Extract exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports_list = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    func_name = exp.name.decode('utf-8', errors='ignore')
                    exports_list.append(func_name)
            
            result["exports"] = exports_list
            result["export_count"] = len(exports_list)
    
    except Exception as e:
        logger.warning(f"pefile import/export analysis failed: {e}")
    
    return result


def analyze_imports_exports(file_path: str) -> Dict:
    """
    Step 5: Analyze DLL imports/exports using PEView or pefile.
    
    Args:
        file_path: Path to the PE file to analyze
        
    Returns:
        Dictionary with import/export analysis results
    """
    logger.info(f"[Step 5] Starting import/export analysis for: {file_path}")
    
    result = {
        "step": 5,
        "step_name": "Import/Export Analysis",
        "file_path": file_path,
        "imports": [],
        "exports": [],
        "import_count": 0,
        "export_count": 0,
        "suspicious_imports": [],
        "method": None,
        "error": None
    }
    
    try:
        peview = find_peview()
        
        if not peview:
            logger.info("[Step 5] PEView not found, using pefile fallback")
            # Use pefile as fallback
            pefile_result = analyze_imports_exports_pefile(file_path)
            result.update(pefile_result)
            result["method"] = "pefile (fallback)"
            logger.info(f"[Step 5] Found {result['import_count']} imports, {result['export_count']} exports using pefile")
        else:
            # PEView is GUI-based, so we'll use pefile for CLI analysis
            logger.info("[Step 5] PEView found but is GUI tool, using pefile for analysis")
            pefile_result = analyze_imports_exports_pefile(file_path)
            result.update(pefile_result)
            result["method"] = "pefile"
            logger.info(f"[Step 5] Found {result['import_count']} imports, {result['export_count']} exports")
        
        if result["suspicious_imports"]:
            logger.warning(f"[Step 5] Found {len(result['suspicious_imports'])} suspicious imports")
    
    except Exception as e:
        logger.error(f"[Step 5] Error during import/export analysis: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

