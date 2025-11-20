"""
Step 6: String Extraction & AI Analysis
Extracts strings using strings64 and analyzes with Google Gemini API for malicious patterns.
"""
import logging
import os
import shutil
import subprocess
import time
from typing import Dict, List, Optional

from google import genai
from google.genai import errors

logger = logging.getLogger(__name__)

# Use stable model
GEMINI_MODEL = "gemini-pro"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


def find_strings64() -> Optional[str]:
    """
    Find strings64 executable.
    
    Returns:
        Path to strings64 executable or None
    """
    # Check current directory and common locations
    common_paths = [
        "strings64.exe",
        "strings.exe",
        os.path.join(os.getcwd(), "strings64.exe"),
        os.path.join(os.getcwd(), "strings.exe"),
        os.path.join(os.getcwd(), "tools", "strings64.exe"),
        os.path.join(os.getcwd(), "tools", "strings.exe"),
    ]
    
    for path in common_paths:
        if os.path.isfile(path):
            return path
    
    # Check if strings is in PATH (Unix-like systems)
    import shutil
    strings_path = shutil.which("strings")
    if strings_path:
        return strings_path
    
    return None


def extract_strings_tool(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract strings using strings64 or strings tool.
    
    Args:
        file_path: Path to the file
        min_length: Minimum string length
        
    Returns:
        List of extracted strings
    """
    strings_tool = find_strings64()
    
    if not strings_tool:
        logger.warning("[Step 6] strings64 not found, using Python fallback")
        # Fallback to Python string extraction
        return extract_strings_python(file_path, min_length)
    
    try:
        # Run strings tool
        result = subprocess.run(
            [strings_tool, "-n", str(min_length), file_path],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            strings = [s.strip() for s in result.stdout.split("\n") if s.strip()]
            logger.info(f"[Step 6] Extracted {len(strings)} strings using {os.path.basename(strings_tool)}")
            return strings
        else:
            logger.warning(f"[Step 6] strings tool failed, using Python fallback: {result.stderr}")
            return extract_strings_python(file_path, min_length)
    
    except subprocess.TimeoutExpired:
        logger.warning("[Step 6] strings tool timed out, using Python fallback")
        return extract_strings_python(file_path, min_length)
    except Exception as e:
        logger.warning(f"[Step 6] strings tool error, using Python fallback: {e}")
        return extract_strings_python(file_path, min_length)


def extract_strings_python(file_path: str, min_length: int = 4) -> List[str]:
    """
    Extract strings using Python (fallback method).
    
    Args:
        file_path: Path to the file
        min_length: Minimum string length
        
    Returns:
        List of extracted strings
    """
    from .utils import PRINTABLE_RE, UTF16_RE
    
    strings = []
    
    try:
        max_bytes = 10 * 1024 * 1024  # 10MB max
        size = os.path.getsize(file_path)
        read_size = min(size, max_bytes)
        
        with open(file_path, "rb") as f:
            data = f.read(read_size)
        
        # Extract ASCII strings
        for match in PRINTABLE_RE.finditer(data):
            s = match.group().decode("utf-8", errors="ignore")
            if len(s) >= min_length:
                strings.append(s)
        
        # Extract UTF-16 strings
        for match in UTF16_RE.finditer(data):
            try:
                s = match.group().decode("utf-16le", errors="ignore")
                if len(s) >= min_length:
                    strings.append(s)
            except Exception:
                pass
        
        # Deduplicate
        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)
        
        logger.info(f"[Step 6] Extracted {len(unique_strings)} strings using Python fallback")
        return unique_strings[:2000]  # Limit to 2000 strings
    
    except Exception as e:
        logger.error(f"[Step 6] Python string extraction failed: {e}")
        return []


def analyze_strings_with_ai(strings: List[str], file_path: str) -> Dict:
    """
    Analyze extracted strings using Google Gemini API for malicious patterns.
    
    Args:
        strings: List of extracted strings
        file_path: Path to the file
        
    Returns:
        Dictionary with string analysis results
    """
    logger.info(f"[Step 6] Starting AI string analysis for {len(strings)} strings")
    
    result = {
        "step": 6,
        "step_name": "String Extraction & AI Analysis",
        "file_path": file_path,
        "strings_count": len(strings),
        "malicious_patterns": [],
        "suspicious_strings": [],
        "iocs": {},
        "analysis": None,
        "error": None
    }
    
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            result["error"] = "GEMINI_API_KEY not set in environment"
            logger.error("[Step 6] GEMINI_API_KEY not set")
            return result
        
        # Limit strings for API call (take most interesting ones)
        # Prioritize longer strings and those with suspicious keywords
        suspicious_keywords = [
            "http://", "https://", "cmd.exe", "powershell", "reg add",
            "CreateFile", "WriteFile", "VirtualAlloc", "LoadLibrary",
            "socket", "connect", "send", "recv", "download", "upload"
        ]
        
        prioritized_strings = []
        for s in strings:
            if any(kw.lower() in s.lower() for kw in suspicious_keywords):
                prioritized_strings.append(s)
        
        # Take top 100 suspicious + 100 random others
        analysis_strings = prioritized_strings[:100] + [s for s in strings if s not in prioritized_strings][:100]
        
        strings_text = "\n".join(analysis_strings[:200])  # Limit to 200 for API
        
        # Initialize Gemini client
        client = genai.Client(api_key=api_key)
        
        # Build combined prompt (all content in single string)
        contents = f"""You are a malware analyst expert. Analyze extracted strings from a potentially malicious file. Identify malicious patterns, suspicious code snippets, IOCs (URLs, IPs, domains), and provide a risk assessment.

Analyze the following extracted strings from file: {os.path.basename(file_path)}

Extracted Strings ({len(analysis_strings)} total, showing first 200):
{strings_text}

Please provide:
1. List of malicious patterns detected
2. Suspicious strings that indicate malicious behavior
3. IOCs (URLs, IP addresses, domains)
4. Risk assessment
5. Recommended actions

Respond in JSON format with fields: malicious_patterns (array), suspicious_strings (array), iocs (object with urls, ips, domains), risk_level, analysis, recommendations.
"""
        
        # Call Gemini API with retry logic
        response = None
        for attempt in range(MAX_RETRIES):
            try:
                response = client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=contents,
                )
                
                if response and hasattr(response, 'text') and response.text:
                    content = response.text
                    result["analysis"] = content
                    
                    # Try to extract JSON from response
                    try:
                        import json
                        import re
                        json_match = re.search(r'\{[^{}]*"malicious_patterns"[^{}]*\}', content, re.DOTALL)
                        if json_match:
                            parsed = json.loads(json_match.group())
                            result["malicious_patterns"] = parsed.get("malicious_patterns", [])
                            result["suspicious_strings"] = parsed.get("suspicious_strings", [])
                            result["iocs"] = parsed.get("iocs", {})
                    except Exception:
                        pass
                    
                    logger.info(f"[Step 6] AI analysis completed: found {len(result['malicious_patterns'])} malicious patterns")
                    break
                else:
                    result["error"] = "No response content from Gemini API"
                    logger.error(f"[Step 6] Gemini API returned no content")
                    break
                    
            except errors.ServerError as e:
                if "overloaded" in str(e).lower() or "503" in str(e):
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"[Step 6] Model overloaded (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        result["error"] = f"Model overloaded after {MAX_RETRIES} attempts. Please try again later."
                        logger.error(f"[Step 6] Model overloaded after {MAX_RETRIES} attempts")
                else:
                    result["error"] = str(e)
                    logger.error(f"[Step 6] Gemini API error: {e}")
                    break
            except Exception as e:
                result["error"] = str(e)
                logger.error(f"[Step 6] Error during string analysis: {e}", exc_info=True)
                break
    
    except Exception as e:
        logger.error(f"[Step 6] Error during string analysis: {e}", exc_info=True)
        result["error"] = str(e)
    
    return result


def analyze_strings(file_path: str) -> Dict:
    """
    Step 6: Extract strings and analyze with AI.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary with string extraction and analysis results
    """
    logger.info(f"[Step 6] Starting string extraction for: {file_path}")
    
    # Extract strings
    strings = extract_strings_tool(file_path)
    
    # Analyze with AI
    result = analyze_strings_with_ai(strings, file_path)
    result["strings"] = strings[:500]  # Store first 500 strings in result
    
    return result

