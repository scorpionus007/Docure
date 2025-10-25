import json
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .utils import (
    PRINTABLE_RE,
    UTF16_RE,
    hash_file,
)


def _try_import_magic():
    try:
        import magic  # type: ignore
        return magic
    except Exception:
        return None


MAGIC = _try_import_magic()


def detect_file_type(path: str) -> str:
    if MAGIC is not None:
        try:
            m = MAGIC.Magic(mime=False)
            desc = m.from_file(path)
            return str(desc)
        except Exception:
            pass
    # Fallback using simple heuristics by extension
    lower = path.lower()
    if lower.endswith((".exe", ".dll")):
        return "PE executable (heuristic)"
    if lower.endswith((".so", ".elf")):
        return "ELF shared object (heuristic)"
    if lower.endswith((".sh", ".bash")):
        return "POSIX shell script (heuristic)"
    if lower.endswith((".py", ".pyw")):
        return "Python script (heuristic)"
    return "unknown"


def is_probably_executable(path: str, file_type_desc: str, is_executable_bit: bool) -> bool:
    ft = file_type_desc.lower()
    if any(k in ft for k in ["pe32", "pe executable", "elf", "mach-o", "executable"]):
        return True
    if any(k in ft for k in ["script", "python", "shell", "bash"]):
        return True
    if is_executable_bit:
        return True
    # Shebang check
    try:
        with open(path, "rb") as f:
            head = f.read(64)
        if head.startswith(b"#!"):
            return True
    except Exception:
        pass
    return False


def extract_strings(path: str, max_bytes: int = 8 * 1024 * 1024, max_strings: int = 2000) -> List[str]:
    strings: List[str] = []
    try:
        size = os.path.getsize(path)
        read_size = min(size, max_bytes)
        with open(path, "rb") as f:
            buf = f.read(read_size)
        for m in PRINTABLE_RE.finditer(buf):
            s = m.group().decode("utf-8", errors="ignore")
            strings.append(s)
        for m in UTF16_RE.finditer(buf):
            try:
                s = m.group().decode("utf-16le", errors="ignore")
                strings.append(s)
            except Exception:
                pass
    except Exception:
        pass
    # Deduplicate while preserving order
    seen = set()
    uniq: List[str] = []
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
        if len(uniq) >= max_strings:
            break
    return uniq


IOC_URL_RE = re.compile(r"https?://[\w\-\.]+(?:\:[0-9]{2,5})?(?:/[^\s'\"]*)?", re.IGNORECASE)
IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN_RE = re.compile(r"\b[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.[a-z\.]{2,}\b", re.IGNORECASE)


SUSPICIOUS_IMPORT_KEYWORDS = [
    # Windows
    "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory", "LoadLibrary", "GetProcAddress", "WinExec",
    # POSIX/ELF
    "execve", "system", "ptrace", "dlopen", "mprotect",
    # Networking
    "socket", "connect", "send", "recv", "WSAStartup",
]


def compute_hashes_and_metadata(rootfs: str, rel_path: str) -> Dict:
    abs_path = os.path.join(rootfs, rel_path)
    md5, sha1, sha256 = hash_file(abs_path)
    try:
        st = os.lstat(abs_path)
        mode = oct(st.st_mode & 0o777)
        size = int(st.st_size)
    except Exception:
        mode = "0"
        size = 0
    file_type = detect_file_type(abs_path)
    is_exec_bit = False
    try:
        is_exec_bit = bool(os.stat(abs_path).st_mode & 0o111)
    except Exception:
        pass
    return {
        "rel_path": rel_path.replace("\\", "/"),
        "abs_path": abs_path,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "size": size,
        "mode": mode,
        "file_type": file_type,
        "is_executable": is_exec_bit,
    }


def identify_candidates(manifest: Dict, rootfs: str, max_files: int = 200, max_size_mb: int = 50) -> List[str]:
    root = manifest.get("root") or rootfs
    candidates: List[str] = []
    for entry in manifest.get("files", []):
        if entry.get("kind") != "file":
            continue
        rel = entry.get("path")
        abs_path = os.path.join(root, rel)
        size = int(entry.get("size", 0))
        if size <= 0 or (size // (1024 * 1024)) > max_size_mb:
            continue
        desc = detect_file_type(abs_path)
        is_exec_bit = bool(entry.get("is_executable"))
        if is_probably_executable(abs_path, desc, is_exec_bit):
            candidates.append(rel)
        if len(candidates) >= max_files:
            break
    return candidates


def collect_iocs(strings: List[str]) -> Dict[str, List[str]]:
    urls = []
    ips = []
    domains = []
    for s in strings:
        urls.extend(IOC_URL_RE.findall(s))
        ips.extend(IOC_IP_RE.findall(s))
        domains.extend(IOC_DOMAIN_RE.findall(s))
    # Dedup simple
    def _dedup(items: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for i in items:
            if i in seen:
                continue
            seen.add(i)
            out.append(i)
        return out
    return {
        "urls": _dedup(urls)[:100],
        "ips": _dedup(ips)[:100],
        "domains": _dedup(domains)[:100],
    }


def suspicion_score(static_meta: Dict, top_strings: List[str], imports: Optional[List[str]] = None) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    # Imports
    if imports:
        for name in imports:
            for kw in SUSPICIOUS_IMPORT_KEYWORDS:
                if kw.lower() in name.lower():
                    score += 4
                    reasons.append(f"suspicious import: {name}")
                    break
    # Strings-based IOCs
    iocs = collect_iocs(top_strings)
    if any(iocs.values()):
        score += 3
        reasons.append("ioc-like strings present")
    # Executable marker
    if is_probably_executable(static_meta.get("abs_path", ""), static_meta.get("file_type", ""), bool(static_meta.get("is_executable"))):
        score += 1
    return score, reasons


def write_static_artifact(out_path: str, data: Dict):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


