import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Dict, Tuple


PRINTABLE_RE = re.compile(rb"[ -~]{4,}")  # ASCII strings length >=4
UTF16_RE = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")  # UTF-16LE ASCII subset


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def is_within_directory(directory: str, target: str) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])
    except ValueError:
        return False


def safe_extract_tarfile(tf: tarfile.TarFile, dest_dir: str):
    for member in tf.getmembers():
        _safe_extract_member(tf, member, dest_dir)


def _safe_extract_member(tf: tarfile.TarFile, member: tarfile.TarInfo, dest_dir: str):
    member_path = os.path.join(dest_dir, member.name.lstrip("./"))
    if not is_within_directory(dest_dir, member_path):
        raise RuntimeError(f"Unsafe tar member path: {member.name}")
    if member.isdir():
        ensure_dir(member_path)
        return
    # Ensure parent exists
    ensure_dir(os.path.dirname(member_path))

    if member.isreg():
        with tf.extractfile(member) as src, open(member_path, "wb") as dst:
            if src:
                shutil.copyfileobj(src, dst, length=1 << 20)
        try:
            os.chmod(member_path, member.mode & 0o777)
        except Exception:
            pass
    elif member.issym() or member.islnk():
        # Create symlinks only if safe and supported
        link_target = member.linkname
        # Best-effort: skip unsafe absolute links
        if link_target and not os.path.isabs(link_target):
            try:
                if os.path.exists(member_path):
                    os.remove(member_path)
                os.symlink(link_target, member_path)
            except Exception:
                # Symlinks often require admin on Windows; skip if not possible
                pass
    else:
        # Other special files are ignored on Windows
        pass


def hash_file(path: str) -> Tuple[str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def file_kind_from_lstat(st: os.stat_result) -> str:
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "special"


def harden_directory_windows(path: str):
    # Optional: tighten ACLs to current user only (requires admin/permissions).
    # Best effort, non-fatal if it fails.
    try:
        import subprocess
        # Remove inheritance and grant only current user full control
        subprocess.run(["icacls", path, "/inheritance:r"], check=False, capture_output=True)
        subprocess.run(["icacls", path, "/grant", f"{os.getlogin()}:F", "/T"], check=False, capture_output=True)
    except Exception:
        pass


def write_json(path: str, data: Dict):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


