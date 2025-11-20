"""
Step 3: Resource Analysis
Analyzes PE file resources using Resource Hacker CLI tool.
"""
import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def find_resource_hacker() -> Optional[str]:
    """
    Find Resource Hacker executable.
    
    Returns:
        Path to Resource Hacker executable or None
    """
    # Common Resource Hacker locations
    common_paths = [
        "ResourceHacker.exe",
        "ResHacker.exe",
        os.path.join(os.getcwd(), "tools", "ResourceHacker.exe"),
        os.path.join(os.getcwd(), "tools", "ResHacker.exe"),
        "C:\\Program Files\\Resource Hacker\\ResourceHacker.exe",
        "C:\\Program Files (x86)\\Resource Hacker\\ResourceHacker.exe",
    ]
    
    # Check PATH
    for name in ["ResourceHacker.exe", "ResHacker.exe"]:
        path = os.path.join(os.getcwd(), name)
        if os.path.isfile(path):
            return path
    
    # Check common paths
    for path in common_paths:
        if os.path.isfile(path):
            return path
    
    return None


def analyze_resources(file_path: str) -> Dict:
    """
    Step 3: Analyze PE file resources using Resource Hacker.
    
    Args:
        file_path: Path to the PE file to analyze
        
    Returns:
        Dictionary with resource analysis results
    """
    logger.info(f"[Step 3] Starting resource analysis for: {file_path}")
    
    result = {
        "step": 3,
        "step_name": "Resource Analysis",
        "file_path": file_path,
        "resources": [],
        "resource_count": 0,
        "method": None,
        "error": None
    }
    
    try:
        res_hacker = find_resource_hacker()
        
        if not res_hacker:
            logger.warning("[Step 3] Resource Hacker not found, using pefile fallback")
            # Fallback to pefile for basic resource info
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    resources = []
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        type_name = pefile.RESOURCE_TYPE.get(resource_type.id, f"Type_{resource_type.id}")
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                resources.append({
                                    "type": type_name,
                                    "id": resource_id.id,
                                    "language": resource_lang.id,
                                    "size": resource_lang.data.struct.Size,
                                    "offset": resource_lang.data.struct.OffsetToData
                                })
                    
                    result["resources"] = resources
                    result["resource_count"] = len(resources)
                    result["method"] = "pefile (fallback)"
                    logger.info(f"[Step 3] Found {len(resources)} resources using pefile")
                else:
                    result["resources"] = []
                    result["resource_count"] = 0
                    result["method"] = "pefile (fallback)"
                    logger.info("[Step 3] No resources found")
            except Exception as e:
                logger.warning(f"[Step 3] pefile fallback failed: {e}")
                result["error"] = "Resource Hacker not found and pefile analysis failed"
        else:
            # Use Resource Hacker CLI
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    script_file = os.path.join(tmpdir, "extract_script.txt")
                    output_file = os.path.join(tmpdir, "resources.txt")
                    
                    # Create Resource Hacker script
                    # Resource Hacker needs quoted paths and proper script format
                    script_content = f'open "{file_path}"\n'
                    script_content += f'save "{output_file}"\n'
                    script_content += 'close\n'
                    
                    with open(script_file, "w", encoding="utf-8") as f:
                        f.write(script_content)
                    
                    # Run Resource Hacker with CREATE_NO_WINDOW flag to suppress GUI
                    startupinfo = None
                    if os.name == 'nt':
                        startupinfo = subprocess.STARTUPINFO()
                        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        startupinfo.wShowWindow = subprocess.SW_HIDE
                    
                    # Run Resource Hacker
                    cmd = [res_hacker, "-script", script_file]
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                    )
                    
                    if proc.returncode == 0:
                        # Parse output (simplified - Resource Hacker output format may vary)
                        resources = []
                        if os.path.exists(output_file):
                            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                # Basic parsing (adjust based on actual output format)
                                lines = content.split("\n")
                                for line in lines:
                                    if line.strip():
                                        resources.append({"raw": line.strip()})
                        
                        result["resources"] = resources
                        result["resource_count"] = len(resources)
                        result["method"] = "Resource Hacker"
                        logger.info(f"[Step 3] Found {len(resources)} resources using Resource Hacker")
                    else:
                        logger.warning(f"[Step 3] Resource Hacker failed: {proc.stderr}, falling back to pefile")
                        # Fallback to pefile
                        try:
                            import pefile
                            pe = pefile.PE(file_path)
                            
                            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                                resources = []
                                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                                    type_name = pefile.RESOURCE_TYPE.get(resource_type.id, f"Type_{resource_type.id}")
                                    for resource_id in resource_type.directory.entries:
                                        for resource_lang in resource_id.directory.entries:
                                            resources.append({
                                                "type": type_name,
                                                "id": resource_id.id,
                                                "language": resource_lang.id,
                                                "size": resource_lang.data.struct.Size,
                                                "offset": resource_lang.data.struct.OffsetToData
                                            })
                                
                                result["resources"] = resources
                                result["resource_count"] = len(resources)
                                result["method"] = "pefile (fallback after Resource Hacker failed)"
                                logger.info(f"[Step 3] Found {len(resources)} resources using pefile fallback")
                            else:
                                result["resources"] = []
                                result["resource_count"] = 0
                                result["method"] = "pefile (fallback after Resource Hacker failed)"
                                logger.info("[Step 3] No resources found using pefile fallback")
                        except Exception as pe_err:
                            result["error"] = f"Resource Hacker failed and pefile fallback also failed: {str(pe_err)}"
                            logger.error(f"[Step 3] Both Resource Hacker and pefile failed: {pe_err}")
                        
            except subprocess.TimeoutExpired:
                logger.warning("[Step 3] Resource Hacker timed out, falling back to pefile")
                # Fallback to pefile on timeout
                try:
                    import pefile
                    pe = pefile.PE(file_path)
                    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                        resources = []
                        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                            type_name = pefile.RESOURCE_TYPE.get(resource_type.id, f"Type_{resource_type.id}")
                            for resource_id in resource_type.directory.entries:
                                for resource_lang in resource_id.directory.entries:
                                    resources.append({
                                        "type": type_name,
                                        "id": resource_id.id,
                                        "language": resource_lang.id,
                                        "size": resource_lang.data.struct.Size,
                                        "offset": resource_lang.data.struct.OffsetToData
                                    })
                        result["resources"] = resources
                        result["resource_count"] = len(resources)
                        result["method"] = "pefile (fallback after Resource Hacker timeout)"
                        logger.info(f"[Step 3] Found {len(resources)} resources using pefile fallback")
                    else:
                        result["resources"] = []
                        result["resource_count"] = 0
                        result["method"] = "pefile (fallback after Resource Hacker timeout)"
                except Exception as pe_err:
                    result["error"] = f"Resource Hacker timed out and pefile fallback failed: {str(pe_err)}"
            except Exception as e:
                logger.warning(f"[Step 3] Resource Hacker error: {e}, falling back to pefile")
                # Fallback to pefile on any error
                try:
                    import pefile
                    pe = pefile.PE(file_path)
                    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                        resources = []
                        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                            type_name = pefile.RESOURCE_TYPE.get(resource_type.id, f"Type_{resource_type.id}")
                            for resource_id in resource_type.directory.entries:
                                for resource_lang in resource_id.directory.entries:
                                    resources.append({
                                        "type": type_name,
                                        "id": resource_id.id,
                                        "language": resource_lang.id,
                                        "size": resource_lang.data.struct.Size,
                                        "offset": resource_lang.data.struct.OffsetToData
                                    })
                        result["resources"] = resources
                        result["resource_count"] = len(resources)
                        result["method"] = "pefile (fallback after Resource Hacker error)"
                        logger.info(f"[Step 3] Found {len(resources)} resources using pefile fallback")
                    else:
                        result["resources"] = []
                        result["resource_count"] = 0
                        result["method"] = "pefile (fallback after Resource Hacker error)"
                except Exception as pe_err:
                    result["error"] = f"Resource Hacker error and pefile fallback failed: {str(e)} -> {str(pe_err)}"
                    logger.error(f"[Step 3] Both Resource Hacker and pefile failed: {e} -> {pe_err}", exc_info=True)
    
    except Exception as e:
        logger.error(f"[Step 3] Error during resource analysis: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

