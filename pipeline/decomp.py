import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict, Iterable, List, Optional, Tuple


def _resolve_ghidra_home(ghidra_home: Optional[str] = None) -> str:
    ghidra_home = ghidra_home or os.getenv("GHIDRA_HOME")
    if not ghidra_home or not os.path.isdir(ghidra_home):
        raise RuntimeError("GHIDRA_HOME not set or invalid. Provide --ghidra-home or set GHIDRA_HOME.")
    return ghidra_home


def _analyze_headless_cmd(ghidra_home: str) -> str:
    bat = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
    if not os.path.isfile(bat):
        raise RuntimeError(f"analyzeHeadless.bat not found under {ghidra_home}")
    return bat


def decompile_with_ghidra(
    input_files: List[str],
    out_dir: str,
    ghidra_home: Optional[str] = None,
    max_funcs: int = 300,
    max_pcode: int = 5,
    timeout_s: int = 300,
    verbose: bool = False,
) -> Dict[str, Optional[str]]:
    os.makedirs(out_dir, exist_ok=True)
    ghidra_home = _resolve_ghidra_home(ghidra_home)
    ah = _analyze_headless_cmd(ghidra_home)

    results: Dict[str, Optional[str]] = {}
    log_dir = os.path.join(out_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    for abs_path in input_files:
        if not os.path.isfile(abs_path):
            results[abs_path] = None
            continue
        with tempfile.TemporaryDirectory(prefix="ghidra-proj-") as proj_dir:
            out_json = os.path.join(out_dir, os.path.basename(abs_path) + ".json")
            cmd = [
                ah,
                proj_dir,
                "proj",
                "-import",
                abs_path,
                "-readOnly",
                "-scriptPath",
                os.path.abspath(os.path.join(os.getcwd(), "ghidra_scripts")),
                "-postScript",
                "DumpArtifacts.java",
                f"outJson={out_json}",
                f"maxFuncs={int(max_funcs)}",
                f"maxPcode={int(max_pcode)}",
                "-deleteProject",
            ]
            if verbose:
                print(f"[decomp] Running analyzeHeadless for: {abs_path}")
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_s, check=False)
                # Write logs per file
                log_path = os.path.join(log_dir, os.path.basename(abs_path) + ".log")
                try:
                    with open(log_path, "wb") as lf:
                        lf.write(b"CMD: " + " ".join(cmd).encode("utf-8", errors="ignore") + b"\n\n")
                        lf.write(b"STDOUT:\n")
                        lf.write(proc.stdout or b"")
                        lf.write(b"\n\nSTDERR:\n")
                        lf.write(proc.stderr or b"")
                except Exception:
                    pass
            except subprocess.TimeoutExpired:
                results[abs_path] = None
                if verbose:
                    print(f"[decomp] Timeout for: {abs_path}")
                continue
            if os.path.isfile(out_json):
                results[abs_path] = out_json
                if verbose:
                    print(f"[decomp] OK -> {out_json}")
            else:
                results[abs_path] = None
                if verbose:
                    print(f"[decomp] FAILED to produce JSON for: {abs_path}")
    return results


