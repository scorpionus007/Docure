"""
Step 7: Digital Signature Checking
Checks file digital signature using VirusTotal API.
"""
import logging
import os
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

VT_API_ENDPOINT = "https://www.virustotal.com/api/v3/files/{hash}"


def check_signature_virustotal(file_hash: str) -> Dict:
    """
    Check file signature and reputation using VirusTotal API.
    
    Args:
        file_hash: SHA256 hash of the file
        
    Returns:
        Dictionary with VirusTotal analysis results
    """
    logger.info(f"[Step 7] Checking signature on VirusTotal for hash: {file_hash[:16]}...")
    
    result = {
        "step": 7,
        "step_name": "Digital Signature Checking",
        "hash": file_hash,
        "found": False,
        "signature_info": {},
        "reputation": {},
        "error": None
    }
    
    try:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            result["error"] = "VIRUSTOTAL_API_KEY not set in environment"
            logger.error("[Step 7] VIRUSTOTAL_API_KEY not set")
            return result
        
        headers = {
            "x-apikey": api_key,
        }
        
        url = VT_API_ENDPOINT.format(hash=file_hash)
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            file_data = data.get("data", {}).get("attributes", {})
            
            result["found"] = True
            
            # Extract signature information
            signature_info = file_data.get("signature_info", {})
            result["signature_info"] = {
                "signed": bool(signature_info),
                "signer": signature_info.get("signer", {}).get("name") if signature_info else None,
                "issuer": signature_info.get("signer", {}).get("issuer") if signature_info else None,
                "valid": signature_info.get("verified", False) if signature_info else False,
            }
            
            # Extract reputation/scan results
            last_analysis_stats = file_data.get("last_analysis_stats", {})
            result["reputation"] = {
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "total": sum(last_analysis_stats.values()) if last_analysis_stats else 0
            }
            
            # Get permalink
            result["permalink"] = file_data.get("permalink", f"https://www.virustotal.com/gui/file/{file_hash}")
            
            logger.info(f"[Step 7] VirusTotal check completed: "
                       f"malicious={result['reputation']['malicious']}, "
                       f"signed={result['signature_info']['signed']}")
        
        elif response.status_code == 404:
            result["found"] = False
            result["error"] = "File not found in VirusTotal database"
            logger.info("[Step 7] File not found in VirusTotal database")
        else:
            result["error"] = f"VirusTotal API error: HTTP {response.status_code}"
            logger.error(f"[Step 7] VirusTotal API error: {response.status_code} - {response.text}")
    
    except Exception as e:
        logger.error(f"[Step 7] Error during signature check: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result

