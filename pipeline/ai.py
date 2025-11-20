import json
import os
import time
from typing import Dict, List, Optional, Tuple

from google import genai
from google.genai import errors


# Use stable model
GEMINI_MODEL = "gemini-pro"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


def _truncate(text: str, max_chars: int = 6000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 50] + "\n...[truncated]"


def _build_prompt(item: Dict) -> List[Dict[str, str]]:
    system = (
        "You are a senior malware analyst. Provide precise, actionable findings, cite specific behaviors, "
        "and avoid speculation. If uncertain, say so."
    )
    # Build compact user content
    def fmt_list(name: str, arr: List[str], limit: int = 30) -> str:
        if not arr:
            return f"{name}: []"
        use = arr[:limit]
        return name + ":\n- " + "\n- ".join(use)

    path = item.get("rel_path") or item.get("path") or "(unknown)"
    hashes = item.get("hashes", {})
    imports = item.get("imports", [])
    strings = item.get("strings", [])
    iocs = item.get("iocs", {})
    reasons = item.get("reasons", [])
    pseudocode_snippets = item.get("pseudocode", [])

    pseudo_joined = "\n\n".join([_truncate(s, 2000) for s in pseudocode_snippets])

    user = f"""
Target file: {path}
Hashes: md5={hashes.get('md5')} sha1={hashes.get('sha1')} sha256={hashes.get('sha256')}
File type: {item.get('file_type')}
Size: {item.get('size')} bytes
Suspicious reasons: {', '.join(reasons) if reasons else '(none)'}

Top imports (subset):\n- """ + "\n- ".join(imports[:40]) + "\n\n" + \
        fmt_list("IOC URLs", iocs.get("urls", []), 20) + "\n" + \
        fmt_list("IOC IPs", iocs.get("ips", []), 20) + "\n" + \
        fmt_list("IOC Domains", iocs.get("domains", []), 20) + "\n\n" + \
        "Pseudocode snippets (truncated):\n" + pseudo_joined + "\n\n" + \
        "Please analyze and return: (1) concise executive summary; (2) likely behaviors; (3) risk level (Low/Medium/High/Critical); " + \
        "(4) concrete IOCs; (5) MITRE ATT&CK techniques; (6) recommended actions; (7) a short JSON block with fields: summary, risk, behaviors, iocs, mitre, actions."

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": _truncate(user, 12000)},
    ]


def analyze_with_gemini(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    api_key = api_key or os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")
    model = model or GEMINI_MODEL

    # Initialize Gemini client
    client = genai.Client(api_key=api_key)

    results: List[Dict] = []
    for item in items:
        # Build prompt and combine system/user messages
        messages = _build_prompt(item)
        # Combine system and user messages into single contents string
        combined_text = ""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                combined_text += f"{content}\n\n"
            elif role == "user":
                combined_text += f"{content}\n"
        
        # Call Gemini API with retry logic
        response = None
        for attempt in range(MAX_RETRIES):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=combined_text,
                )
                
                if response and hasattr(response, 'text') and response.text:
                    content = response.text
                else:
                    content = ""
                
                results.append({"item": item, "analysis": content})
                break
                
            except errors.ServerError as e:
                if "overloaded" in str(e).lower() or "503" in str(e):
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        time.sleep(wait_time)
                        continue
                    else:
                        results.append({"error": f"Model overloaded after {MAX_RETRIES} attempts", "detail": str(e), "item": item})
                else:
                    results.append({"error": str(e), "detail": f"ServerError: {e}", "item": item})
                    break
            except Exception as e:
                results.append({"error": str(e), "detail": f"Exception: {e}", "item": item})
                break
    
    return results

# Alias for backward compatibility
def analyze_with_deepseek(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    return analyze_with_gemini(items, api_key, endpoint, model)


