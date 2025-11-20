"""
Step 2: File Hash Calculation
Calculates MD5, SHA1, and SHA256 hashes using CLI tools (Get-FileHash or certutil).
"""
import logging
import os
import subprocess
from typing import Dict, Optional

logger = logging.getLogger(__name__)


def calculate_hash_powershell(file_path: str) -> Optional[Dict[str, str]]:
    """
    Calculate file hashes using PowerShell Get-FileHash.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with MD5, SHA1, SHA256 hashes or None on error
    """
    try:
        # PowerShell command to get all three hashes
        ps_cmd = f"""
        $file = '{file_path}'
        $md5 = (Get-FileHash -Path $file -Algorithm MD5).Hash
        $sha1 = (Get-FileHash -Path $file -Algorithm SHA1).Hash
        $sha256 = (Get-FileHash -Path $file -Algorithm SHA256).Hash
        Write-Output "$md5|$sha1|$sha256"
        """
        
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            parts = result.stdout.strip().split("|")
            if len(parts) == 3:
                return {
                    "md5": parts[0].strip(),
                    "sha1": parts[1].strip(),
                    "sha256": parts[2].strip()
                }
    except Exception as e:
        logger.warning(f"PowerShell Get-FileHash failed: {e}")
    
    return None


def calculate_hash_certutil(file_path: str) -> Optional[Dict[str, str]]:
    """
    Calculate file hashes using certutil (fallback method).
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with MD5, SHA1, SHA256 hashes or None on error
    """
    hashes = {}
    
    for algo in ["MD5", "SHA1", "SHA256"]:
        try:
            result = subprocess.run(
                ["certutil", "-hashfile", file_path, algo],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    # Hash is usually on the second line
                    if line and len(line) == (64 if algo == "SHA256" else 40 if algo == "SHA1" else 32):
                        hashes[algo.lower()] = line
                        break
        except Exception as e:
            logger.warning(f"certutil {algo} hash calculation failed: {e}")
    
    if len(hashes) == 3:
        return hashes
    
    return None


def calculate_hash_python(file_path: str) -> Dict[str, str]:
    """
    Calculate file hashes using Python hashlib (fallback).
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with MD5, SHA1, SHA256 hashes
    """
    import hashlib
    
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception as e:
        logger.error(f"Python hash calculation failed: {e}")
        return {}


def analyze_hash(file_path: str) -> Dict:
    """
    Step 2: Calculate file hashes using CLI tools or Python fallback.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary with hash analysis results
    """
    logger.info(f"[Step 2] Starting hash calculation for: {file_path}")
    
    result = {
        "step": 2,
        "step_name": "File Hash Calculation",
        "file_path": file_path,
        "hashes": {},
        "method": None,
        "error": None
    }
    
    try:
        # Try PowerShell Get-FileHash first (most reliable on Windows)
        hashes = calculate_hash_powershell(file_path)
        if hashes:
            result["hashes"] = hashes
            result["method"] = "PowerShell Get-FileHash"
            logger.info(f"[Step 2] Hashes calculated using PowerShell: MD5={hashes['md5'][:16]}...")
        else:
            # Try certutil as fallback
            hashes = calculate_hash_certutil(file_path)
            if hashes:
                result["hashes"] = hashes
                result["method"] = "certutil"
                logger.info(f"[Step 2] Hashes calculated using certutil: MD5={hashes['md5'][:16]}...")
            else:
                # Fallback to Python hashlib
                hashes = calculate_hash_python(file_path)
                if hashes:
                    result["hashes"] = hashes
                    result["method"] = "Python hashlib"
                    logger.info(f"[Step 2] Hashes calculated using Python: MD5={hashes['md5'][:16]}...")
                else:
                    result["error"] = "Failed to calculate hashes using all methods"
                    logger.error("[Step 2] Failed to calculate hashes")
        
    except Exception as e:
        logger.error(f"[Step 2] Error during hash calculation: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

