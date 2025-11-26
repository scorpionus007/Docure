import json
import os
import time
from typing import Dict, List, Optional, Tuple

# Load .env file if present
try:
    from dotenv import load_dotenv  # type: ignore
    import pathlib
    # Try to find .env file in project root (parent of pipeline directory)
    env_path = pathlib.Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Fallback to default location (current working directory)
        load_dotenv()
except Exception:
    pass

from anthropic import Anthropic
try:
    from anthropic import APIError
except ImportError:
    # Fallback if APIError doesn't exist
    APIError = Exception


# Use Claude model - try haiku first (most widely available), fallback to others if needed
# Available models: "claude-3-haiku-20240307", "claude-3-sonnet-20240229", "claude-3-opus-20240229"
CLAUDE_MODEL = "claude-3-haiku-20240307"
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


def analyze_with_claude(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    model = model or CLAUDE_MODEL

    # Initialize Anthropic Claude client
    client = Anthropic(api_key=api_key)

    results: List[Dict] = []
    for item in items:
        # Build prompt and separate system/user messages
        messages = _build_prompt(item)
        
        # Extract system and user content
        system_content = ""
        user_content = ""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                system_content = content
            elif role == "user":
                user_content = content
        
        # Call Claude API with retry logic
        response = None
        for attempt in range(MAX_RETRIES):
            try:
                # Build messages list for Claude API
                api_messages = [{"role": "user", "content": user_content}]
                
                response = client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=system_content if system_content else None,
                    messages=api_messages,
                )
                
                if response and hasattr(response, 'content') and response.content:
                    # Extract text from response content (list of content blocks)
                    content_blocks = response.content
                    content = ""
                    for block in content_blocks:
                        if hasattr(block, 'text'):
                            content += block.text
                        elif isinstance(block, dict) and block.get('type') == 'text':
                            content += block.get('text', '')
                    
                    results.append({"item": item, "analysis": content})
                    break
                else:
                    results.append({"error": "No response content from Claude API", "item": item})
                    break
                
            except APIError as e:
                status_code = getattr(e, 'status_code', None)
                if status_code == 503 or "overloaded" in str(e).lower():
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        time.sleep(wait_time)
                        continue
                    else:
                        results.append({"error": f"Model overloaded after {MAX_RETRIES} attempts", "detail": str(e), "item": item})
                else:
                    results.append({"error": str(e), "detail": f"APIError: {e}", "item": item})
                    break
            except Exception as e:
                results.append({"error": str(e), "detail": f"Exception: {e}", "item": item})
                break
    
    return results

# Alias for backward compatibility
def analyze_with_grok(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    return analyze_with_claude(items, api_key, endpoint, model)

# Alias for backward compatibility
def analyze_with_groq(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    return analyze_with_claude(items, api_key, endpoint, model)

# Alias for backward compatibility
def analyze_with_gemini(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    return analyze_with_claude(items, api_key, endpoint, model)

# Alias for backward compatibility
def analyze_with_deepseek(items: List[Dict], api_key: Optional[str] = None, endpoint: Optional[str] = None, model: Optional[str] = None) -> List[Dict]:
    return analyze_with_claude(items, api_key, endpoint, model)


