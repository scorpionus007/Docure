"""
Step 8: Metadata Extraction
Extracts comprehensive metadata from the executable file.
"""
import logging
import os
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def extract_metadata(file_path: str) -> Dict:
    """
    Step 8: Extract comprehensive metadata from the file.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary with metadata extraction results
    """
    logger.info(f"[Step 8] Starting metadata extraction for: {file_path}")
    
    result = {
        "step": 8,
        "step_name": "Metadata Extraction",
        "file_path": file_path,
        "metadata": {},
        "error": None
    }
    
    try:
        metadata = {}
        
        # Basic file metadata
        stat_info = os.stat(file_path)
        metadata["file_size"] = stat_info.st_size
        metadata["created_time"] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
        metadata["modified_time"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        metadata["accessed_time"] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
        metadata["file_name"] = os.path.basename(file_path)
        metadata["file_extension"] = os.path.splitext(file_path)[1]
        metadata["full_path"] = os.path.abspath(file_path)
        
        # PE-specific metadata
        try:
            import pefile
            
            pe = pefile.PE(file_path)
            
            # PE Headers
            metadata["pe_info"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "timestamp_readable": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else None,
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
            }
            
            # Optional Header
            if hasattr(pe, 'OPTIONAL_HEADER'):
                opt_header = pe.OPTIONAL_HEADER
                metadata["pe_info"]["optional_header"] = {
                    "magic": hex(opt_header.Magic),
                    "entry_point": hex(opt_header.AddressOfEntryPoint),
                    "image_base": hex(opt_header.ImageBase),
                    "section_alignment": opt_header.SectionAlignment,
                    "file_alignment": opt_header.FileAlignment,
                    "size_of_image": opt_header.SizeOfImage,
                    "size_of_headers": opt_header.SizeOfHeaders,
                    "subsystem": opt_header.Subsystem,
                    "dll_characteristics": hex(opt_header.DllCharacteristics),
                }
            
            # Sections
            if hasattr(pe, 'sections'):
                sections = []
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    sections.append({
                        "name": section_name,
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "characteristics": hex(section.Characteristics),
                    })
                metadata["pe_info"]["sections"] = sections
                metadata["pe_info"]["section_count"] = len(sections)
            
            # Version info (if available)
            if hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    for entry in file_info:
                        if hasattr(entry, 'StringTable'):
                            for st_entry in entry.StringTable:
                                for key, value in list(st_entry.entries.items()):
                                    if key not in metadata:
                                        metadata[key] = value.decode('utf-8', errors='ignore')
            
        except Exception as e:
            logger.warning(f"[Step 8] PE metadata extraction failed: {e}")
            metadata["pe_info"] = {"error": str(e)}
        
        # File type detection
        try:
            import magic
            m = magic.Magic(mime=False)
            metadata["file_type"] = m.from_file(file_path)
        except Exception:
            try:
                metadata["file_type"] = "PE executable" if file_path.lower().endswith(('.exe', '.dll')) else "Unknown"
            except Exception:
                metadata["file_type"] = "Unknown"
        
        result["metadata"] = metadata
        logger.info(f"[Step 8] Metadata extraction completed: {len(metadata)} fields extracted")
    
    except Exception as e:
        logger.error(f"[Step 8] Error during metadata extraction: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

