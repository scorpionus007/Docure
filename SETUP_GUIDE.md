# Malware Analysis Pipeline – Setup Guide (Windows)

This guide walks you through configuring the pipeline to ingest a single executable (EXE/DLL/bin) directly and run static analysis, packing detection, optional unpacking, and optional AI / VirusTotal enrichment. No Docker or Ghidra is required.

---

## 📋 Prerequisites

1. **Python 3.10+**
   - https://www.python.org/downloads/
   - Enable “Add Python to PATH” during install
   - Verify: `python --version`
2. **Virtual environment (recommended)**
   - `python -m venv venv`
   - `.\venv\Scripts\Activate.ps1`
   - If blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
3. **Python dependencies**
   - `pip install -r requirements.txt`
4. **Optional tools**
   - [UPX](https://upx.github.io/) if you want automatic unpacking
   - VirusTotal & Gemini API keys for cloud enrichment (`.env` file)

---

## 🔐 Environment Variables (`.env`)

Create `.env` in the repo root:

```env
VIRUSTOTAL_API_KEY=your-key   # optional
GEMINI_API_KEY=your-key     # optional
SANDBOX_BASE_DIR=C:\malware-sandboxes  # optional override
```

Never commit `.env` to source control.

---

## 🚀 Usage

### 1. Ingest only
```powershell
py cli_ingest.py --file C:\samples\malware.exe --out outputs
```
Outputs `outputs/ingestion_manifest.json` pointing at the sandbox.

### 2. Full pipeline
```powershell
py cli_analyze.py --file C:\samples\malware.exe --out outputs --verbose
```
Creates:
- `outputs/static/` – per-file metadata, hashes, packing info
- `outputs/unpacked/` – unpacked payloads (if UPX succeeds)
- `outputs/ai/` – Gemini summaries (when enabled)
- `outputs/report.{md,json}` – summarized findings

To rerun analysis without re-ingesting:
```powershell
py cli_analyze.py --from-manifest outputs\ingestion_manifest.json --out outputs
```

---

## ✅ Verification Checklist

1. `python --version` shows 3.10+
2. `pip install -r requirements.txt` finishes without errors
3. `py cli_ingest.py --file <sample> --out outputs` creates a sandbox + manifest
4. `py cli_analyze.py --file <sample> --out outputs --no-deepseek` produces `report.md`

---

## 🔧 Troubleshooting

- **`python-magic` ImportError**
  ```powershell
  pip uninstall python-magic python-magic-bin
  pip install python-magic-bin
  ```
- **Sandbox permission errors**
  - Run PowerShell as Administrator, or
  - Set `SANDBOX_BASE_DIR` to a directory you own:
    ```powershell
    $env:SANDBOX_BASE_DIR="C:\Users\Admin\Desktop\sandboxes"
    ```
- **API key missing**
  - Ensure `.env` contains `VIRUSTOTAL_API_KEY` / `GEMINI_API_KEY`, or
    ```powershell
    $env:VIRUSTOTAL_API_KEY="..."
    $env:GEMINI_API_KEY="..."
    ```
- **UPX not found**
  - Install UPX and add it to `PATH`, or place `upx.exe` beside the repo.

---

## 📁 Project Structure (excerpt)

```
Docure/
├── pipeline/
│   ├── ingestion.py       # copy sample into sandbox & build manifest
│   ├── static_analysis.py # hashing, metadata, strings, imports
│   ├── packing.py         # entropy + packer detection
│   ├── unpacking.py       # UPX helpers
│   ├── elf_analysis.py    # ELF metadata
│   ├── pe_analysis.py     # PE metadata
│   ├── ai.py              # Gemini client
│   ├── report.py          # Markdown/JSON reporting
│   └── orchestrator.py    # end-to-end coordinator
├── cli_ingest.py
├── cli_analyze.py
├── requirements.txt
└── outputs/               # created automatically
```

---

## 📝 Best Practices

- Run inside a dedicated VM or lab machine; files are never executed but caution is key.
- Clean up old sandboxes: `Remove-Item -Recurse -Force .\sandboxes\*`
- Respect VirusTotal free-tier limits (4 requests/min).
- Use `--verbose` when debugging pipeline issues.

---

## 📚 Helpful Links

- UPX: https://upx.github.io/
- VirusTotal API: https://developers.virustotal.com/
- Gemini Platform: https://aistudio.google.com/app/apikey

Need more help? Re-run with `--verbose`, capture the traceback, and share along with OS/Python versions.

