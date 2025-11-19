# Malware Analysis Pipeline - Local Setup Guide (Windows)

This guide will help you set up the malware analysis pipeline on your Windows 10/11 system.

---

## 📋 Prerequisites

### Required Software

1. **Python 3.10+**
   - Download from: https://www.python.org/downloads/
   - During installation, check "Add Python to PATH"
   - Verify installation:
     ```powershell
     python --version
     # Should show Python 3.10.x or higher
     ```

2. **Docker Desktop**
   - Download from: https://www.docker.com/products/docker-desktop/
   - Install and start Docker Desktop
   - **Important:** Switch to Linux containers (Settings → General → Use WSL 2 based engine)
   - Verify installation:
     ```powershell
     docker info
     # Should show Docker daemon information without errors
     ```

3. **Java JDK (for Ghidra)**
   - Download Java 11 or higher from: https://adoptium.net/
   - Install and verify:
     ```powershell
     java -version
     ```

4. **Ghidra** (Optional but recommended)
   - Download from: https://ghidra-sre.org/
   - Extract to a location like `C:\ghidra_10.x.x`
   - Note: You don't need to run Ghidra GUI, only the headless analyzer is used

---

## 🚀 Setup Steps

### Step 1: Clone/Navigate to Project Directory

```powershell
cd C:\Users\Admin\OneDrive\Desktop\Docure
```

### Step 2: Create Virtual Environment (Recommended)

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# If you get an execution policy error, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 3: Install Python Dependencies

```powershell
# Make sure virtual environment is activated (you'll see (venv) in prompt)
pip install -r requirements.txt
```

**Note:** On Windows, `python-magic-bin` will be automatically installed (handled by requirements.txt).

### Step 4: Configure Environment Variables

Create a `.env` file in the project root directory:

```powershell
# Create .env file
New-Item -Path .env -ItemType File
```

Edit `.env` and add your API keys:

```env
# VirusTotal API Key
VIRUSTOTAL_API_KEY=b315b77bc3436c79f86034d2883646b073bab5a9666a32260f3622c1ff66e612

# DeepSeek API Key
DEEPSEEK_API_KEY=sk-be27fa2e278042b3b1cfa3b381ad746d

# Ghidra Installation Path (Optional - can also use --ghidra-home flag)
GHIDRA_HOME=C:\ghidra_10.4

# Sandbox Base Directory (Optional - defaults to ./sandboxes)
SANDBOX_BASE_DIR=C:\Users\Admin\OneDrive\Desktop\Docure\sandboxes
```

**Important:** Never commit `.env` file to version control!

### Step 5: Verify Docker is Running

```powershell
# Check Docker daemon
docker info

# If you see connection errors:
# 1. Start Docker Desktop
# 2. Ensure "Linux containers" is selected (not Windows containers)
# 3. Wait for Docker to fully start (whale icon in system tray)
```

### Step 6: Test Ghidra Installation (Optional)

If you installed Ghidra, verify the headless analyzer:

```powershell
# Set Ghidra path (if not in .env)
$env:GHIDRA_HOME="C:\ghidra_10.4"

# Test (adjust version number)
& "$env:GHIDRA_HOME\support\analyzeHeadless.bat" --help
```

---

## ✅ Verification Tests

### Test 1: Ingestion Phase

```powershell
# Test with a simple Docker image
py cli_ingest.py --image alpine:latest --out outputs
```

**Expected Output:**
- Sandbox directory created
- RootFS extracted
- `outputs/ingestion_manifest.json` created

### Test 2: Full Analysis Pipeline

```powershell
# Run full analysis (without Ghidra if not installed)
py cli_analyze.py --image alpine:latest --out outputs --no-deepseek

# Or with Ghidra and DeepSeek (requires Ghidra and API keys)
py cli_analyze.py --image alpine:latest --out outputs --ghidra-home C:\ghidra_10.4
```

**Expected Output:**
- Static analysis artifacts in `outputs/static/`
- Decompilation results in `outputs/decomp/` (if Ghidra enabled)
- AI analysis in `outputs/ai/` (if DeepSeek enabled)
- Final report in `outputs/report.md` and `outputs/report.json`

---

## 🔧 Troubleshooting

### Issue 1: Docker Connection Error

**Error:** `CreateFile ... The system cannot find the file specified`

**Solution:**
1. Start Docker Desktop
2. Verify Docker is running: `docker info`
3. Check Docker service in Windows Services
4. Ensure you're in the `docker-users` group:
   - Run `lusrmgr.msc`
   - Add your user to `docker-users` group
   - Sign out and sign back in

### Issue 2: Python Magic Import Error

**Error:** `ImportError: Failed to find libmagic`

**Solution:**
```powershell
# Reinstall python-magic-bin
pip uninstall python-magic python-magic-bin
pip install python-magic-bin
```

### Issue 3: Ghidra Not Found

**Error:** `GHIDRA_HOME not set or invalid`

**Solution:**
- Option 1: Set in `.env` file: `GHIDRA_HOME=C:\ghidra_10.4`
- Option 2: Use CLI flag: `--ghidra-home C:\ghidra_10.4`
- Option 3: Skip Ghidra: `--no-deepseek` (analysis will work, but no decompilation)

### Issue 4: Permission Denied on Sandbox

**Error:** Access denied when creating sandbox directory

**Solution:**
```powershell
# Run PowerShell as Administrator, or
# Set SANDBOX_BASE_DIR to a location you have write access to
$env:SANDBOX_BASE_DIR="C:\Users\Admin\Desktop\sandboxes"
py cli_ingest.py --image alpine:latest --out outputs
```

### Issue 5: API Key Errors

**Error:** `DEEPSEEK_API_KEY not set` or `VIRUSTOTAL_API_KEY not set`

**Solution:**
1. Create `.env` file in project root
2. Add API keys (see Step 4 above)
3. Or set environment variables:
   ```powershell
   $env:DEEPSEEK_API_KEY="sk-be27fa2e278042b3b1cfa3b381ad746d"
   $env:VIRUSTOTAL_API_KEY="b315b77bc3436c79f86034d2883646b073bab5a9666a32260f3622c1ff66e612"
   ```

---

## 📁 Project Structure

```
Docure/
├── pipeline/
│   ├── __init__.py
│   ├── ingestion.py       # Docker extraction
│   ├── static_analysis.py # Static analysis & hashing
│   ├── decomp.py          # Ghidra integration
│   ├── ai.py              # DeepSeek API
│   ├── report.py          # Report generation
│   ├── orchestrator.py    # Main pipeline orchestrator
│   └── utils.py           # Utility functions
├── ghidra_scripts/
│   └── DumpArtifacts.java # Ghidra script for decompilation
├── cli_ingest.py          # CLI for ingestion
├── cli_analyze.py         # CLI for full analysis
├── requirements.txt       # Python dependencies
├── README.md             # Original README
├── .env                   # API keys (create this)
└── outputs/               # Analysis results (created automatically)
```

---

## 🎯 Quick Start Example

```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Ingest a Docker image
py cli_ingest.py --image ubuntu:20.04 --out outputs

# 3. Analyze the ingested image
py cli_analyze.py --from-manifest outputs/ingestion_manifest.json --out outputs --verbose

# 4. View results
# - outputs/report.md (human-readable)
# - outputs/report.json (machine-readable)
# - outputs/static/ (static analysis artifacts)
# - outputs/decomp/ (decompilation results if Ghidra enabled)
# - outputs/ai/ (AI analysis if DeepSeek enabled)
```

---

## 📝 Notes

1. **Sandbox Cleanup:** Sandboxes are created in temporary directories. You may want to clean them up periodically:
   ```powershell
   # Default location: .\sandboxes\
   Remove-Item -Recurse -Force .\sandboxes\*
   ```

2. **API Rate Limits:**
   - VirusTotal: Free tier has 4 requests/minute limit
   - DeepSeek: Check your API plan for rate limits

3. **Ghidra Performance:**
   - Large binaries may take 5-10 minutes to analyze
   - Use `--ghidra-timeout-s` to adjust timeout (default: 300 seconds)

4. **Security:**
   - Never analyze malware directly on your main system
   - Use isolated VMs or cloud environments for actual malware analysis
   - This pipeline extracts files but does NOT execute them

---

## 🔐 Security Best Practices

1. **API Keys:**
   - Never commit `.env` file to git
   - Rotate keys if accidentally exposed
   - Use environment variables in production

2. **Sandbox Isolation:**
   - Sandboxes are created with restricted permissions
   - Files are extracted but never executed
   - Delete sandboxes after analysis

3. **Network Access:**
   - VirusTotal and DeepSeek APIs require internet access
   - Ensure firewall allows outbound HTTPS connections

---

## 📚 Additional Resources

- **Docker Documentation:** https://docs.docker.com/
- **Ghidra Documentation:** https://ghidra-sre.org/
- **VirusTotal API:** https://developers.virustotal.com/
- **DeepSeek API:** https://platform.deepseek.com/

---

## 🆘 Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review error messages carefully
3. Verify all prerequisites are installed
4. Check that Docker Desktop is running
5. Ensure API keys are correctly set in `.env`

For verbose debugging, use the `--verbose` flag:
```powershell
py cli_analyze.py --image alpine:latest --out outputs --verbose
```



