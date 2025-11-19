import json
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .utils import (
    PRINTABLE_RE,
    UTF16_RE,
    hash_file,
)
from .packing import detect_packing, calculate_file_entropy
from .pe_analysis import analyze_pe_file, get_pe_imports
from .elf_analysis import analyze_elf_file, get_elf_imports, detect_elf_packing


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

    # Calculate entropy and detect packing
    entropy, section_entropy = calculate_file_entropy(abs_path)
    packing_info = detect_packing(abs_path)

    # Get PE imports if it's a PE file
    pe_imports: List[str] = []
    pe_info: Optional[Dict] = None
    try:
        pe_info = analyze_pe_file(abs_path)
        if pe_info:
            pe_imports = pe_info.get("imports", [])
    except Exception:
        pass

    # Get ELF imports if it's an ELF file
    elf_imports: List[str] = []
    elf_info: Optional[Dict] = None
    try:
        elf_info = analyze_elf_file(abs_path)
        if elf_info:
            elf_imports = elf_info.get("imports", [])
            # Enhance packing detection with ELF-specific analysis
            elf_packing = detect_elf_packing(abs_path)
            if elf_packing.get("is_packed") and not packing_info.get("packer_type"):
                packing_info["is_packed"] = True
                packing_info["packer_type"] = elf_packing.get("packer_type")
                packing_info["confidence"] = elf_packing.get("confidence", "medium")
                packing_info["indicators"].extend(elf_packing.get("indicators", []))
    except Exception:
        pass

    result = {
        "rel_path": rel_path.replace("\\", "/"),
        "abs_path": abs_path,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "size": size,
        "mode": mode,
        "file_type": file_type,
        "is_executable": is_exec_bit,
        "entropy": round(entropy, 4),
        "section_entropy": round(section_entropy, 4) if section_entropy else None,
        "is_packed": packing_info.get("is_packed", False),
        "packer_type": packing_info.get("packer_type"),
        "packing_confidence": packing_info.get("confidence", "none"),
        "packing_indicators": packing_info.get("indicators", []),
    }

    # Add PE-specific information if available
    if pe_info:
        result["pe_info"] = {
            "entry_point": pe_info.get("entry_point"),
            "machine": pe_info.get("machine"),
            "compile_time": pe_info.get("compile_time"),
            "sections_count": len(pe_info.get("sections", [])),
            "imports_count": len(pe_info.get("imports", [])),
            "exports_count": len(pe_info.get("exports", [])),
        }
        # Add PE imports to result (used by suspicion_score)
        result["pe_imports"] = pe_imports

    # Add ELF-specific information if available
    if elf_info:
        result["elf_info"] = {
            "format": elf_info.get("format"),
            "architecture": elf_info.get("architecture"),
            "entry_point": elf_info.get("entry_point"),
            "sections_count": len(elf_info.get("sections", [])),
            "segments_count": len(elf_info.get("segments", [])),
            "imports_count": len(elf_info.get("imports", [])),
            "exports_count": len(elf_info.get("exports", [])),
            "symbols_count": len(elf_info.get("symbols", [])),
        }
        # Add ELF imports to result (used by suspicion_score)
        result["elf_imports"] = elf_imports

    # Use ELF imports if PE imports not available
    if not pe_imports and elf_imports:
        result["pe_imports"] = elf_imports  # Reuse field name for compatibility

    return result


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

    # Use PE/ELF imports if available, otherwise use provided imports
    if not imports:
        if static_meta.get("pe_imports"):
            imports = static_meta.get("pe_imports")
        elif static_meta.get("elf_imports"):
            imports = static_meta.get("elf_imports")

    # Imports
    if imports:
        for name in imports:
            for kw in SUSPICIOUS_IMPORT_KEYWORDS:
                if kw.lower() in name.lower():
                    score += 4
                    reasons.append(f"suspicious import: {name}")
                    break

    # Packing detection - high suspicion indicator
    if static_meta.get("is_packed"):
        score += 5
        packer_type = static_meta.get("packer_type", "unknown")
        confidence = static_meta.get("packing_confidence", "none")
        reasons.append(f"packed file detected (packer: {packer_type}, confidence: {confidence})")

    # High entropy (even if not explicitly packed)
    entropy = static_meta.get("entropy", 0.0)
    if entropy >= 7.5:
        score += 3
        reasons.append(f"very high entropy ({entropy:.2f}) - possible encryption/packing")
    elif entropy >= 7.0:
        score += 2
        reasons.append(f"high entropy ({entropy:.2f}) - possible compression/packing")

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


