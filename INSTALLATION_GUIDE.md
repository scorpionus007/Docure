# Installation Guide - 8-Step Malware Analysis Pipeline

This guide lists all tools and dependencies needed to run the pipeline.

## ✅ Required (Must Install)

### 1. Python 3.10 or Higher
- **Download**: https://www.python.org/downloads/
- **Installation**: 
  - Check "Add Python to PATH" during installation
  - Verify: `python --version` (should show 3.10+)

### 2. Python Dependencies
All dependencies are in `requirements.txt`. Install with:

```powershell
pip install -r requirements.txt
```

**Dependencies installed:**
- `requests` - HTTP library for API calls
- `python-magic-bin` - File type detection (Windows)
- `yara-python` - YARA rule matching for packer detection
- `pefile` - PE file analysis
- `lief` - ELF/PE/Mach-O parsing
- `python-dotenv` - Environment variable management

### 3. API Keys (Required for AI Features)

#### Gemini API Key
- **Required for**: Steps 4, 6, and all AI reports
- **Get it**: 
  1. Sign up at https://aistudio.google.com/app/apikey
  2. Go to API section
  3. Create an API key
- **Add to `.env`**: `GEMINI_API_KEY=sk-...`

#### VirusTotal API Key
- **Required for**: Step 7 (signature checking)
- **Get it**:
  1. Sign up at https://www.virustotal.com/
  2. Go to Account Settings → API Key
  3. Copy your API key
- **Add to `.env`**: `VIRUSTOTAL_API_KEY=your_key_here`

**Create `.env` file in project root:**
```env
GEMINI_API_KEY=sk-your_deepseek_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

---

## 🔧 Optional Tools (Recommended for Enhanced Analysis)

These tools are **optional** - the pipeline will work without them but uses fallback methods. Installing them provides better analysis.

### 1. UPX (Ultimate Packer for eXecutables)
**Purpose**: Unpack UPX-packed files in Step 1

**Download**:
- Windows: https://upx.github.io/
- Direct download: https://github.com/upx/upx/releases

**Installation**:
1. Download `upx-4.x.x-win64.zip`
2. Extract `upx.exe`
3. Place in one of these locations:
   - Project root directory: `C:\Users\harin\OneDrive\Desktop\Docure\upx.exe`
   - Or add to Windows PATH

**Verify**:
```powershell
upx --version
```

**Note**: Without UPX, Step 1 will detect packing but won't unpack files.

---

### 2. Resource Hacker
**Purpose**: Enhanced resource analysis in Step 3

**Download**: http://www.angusj.com/resourcehacker/

**Installation**:
1. Download `ResourceHacker.zip`
2. Extract `ResourceHacker.exe`
3. Place in one of these locations:
   - Project root: `C:\Users\harin\OneDrive\Desktop\Docure\ResourceHacker.exe`
   - Or in `tools/` subdirectory: `C:\Users\harin\OneDrive\Desktop\Docure\tools\ResourceHacker.exe`

**Note**: Without Resource Hacker, Step 3 uses `pefile` fallback (basic resource extraction).

---

### 3. PEView
**Purpose**: Import/Export analysis in Step 5

**Download**: 
- Available from various sources (search "PEView download")
- Alternative: Use `pefile` (already included, works as fallback)

**Installation**:
1. Download PEView
2. Place `PEView.exe` in project directory or `tools/` folder

**Note**: PEView is a GUI tool. The pipeline uses `pefile` as fallback, which works fine for CLI analysis.

---

### 4. Strings64 (Sysinternals)
**Purpose**: Fast string extraction in Step 6

**Download**: 
- Part of Sysinternals Suite: https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- Direct: https://docs.microsoft.com/en-us/sysinternals/downloads/strings

**Installation**:
1. Download Sysinternals Suite or just `strings.exe`
2. Extract `strings.exe` or `strings64.exe`
3. Place in one of these locations:
   - Project root: `C:\Users\harin\OneDrive\Desktop\Docure\strings64.exe`
   - Or in `tools/` subdirectory

**Note**: Without strings64, Step 6 uses Python fallback (slower but functional).

---

## 📋 Quick Installation Checklist

### Minimum Setup (Required)
- [ ] Python 3.10+ installed
- [ ] Run `pip install -r requirements.txt`
- [ ] Create `.env` file with API keys
- [ ] Test: `py cli_analyze.py --file sample.exe --out outputs`

### Enhanced Setup (Optional)
- [ ] UPX installed (for unpacking)
- [ ] Resource Hacker installed (for resource analysis)
- [ ] Strings64 installed (for faster string extraction)
- [ ] PEView installed (optional, pefile works fine)

---

## 🚀 Installation Steps

### Step 1: Install Python Dependencies

```powershell
# Navigate to project directory
cd C:\Users\harin\OneDrive\Desktop\Docure

# Create virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Set Up API Keys

Create `.env` file in project root:

```powershell
# Create .env file
New-Item -Path .env -ItemType File
```

Edit `.env` and add:
```env
GEMINI_API_KEY=sk-your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

### Step 3: Install Optional Tools (Recommended)

#### Install UPX:
```powershell
# Download from https://upx.github.io/
# Extract upx.exe to project directory
# Or download directly:
# Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip" -OutFile "upx.zip"
# Expand-Archive upx.zip
# Move upx.exe to project root
```

#### Install Resource Hacker:
```powershell
# Download from http://www.angusj.com/resourcehacker/
# Extract ResourceHacker.exe to project directory or tools/ folder
```

#### Install Strings64:
```powershell
# Download Sysinternals Suite
# Extract strings64.exe to project directory or tools/ folder
```

### Step 4: Verify Installation

```powershell
# Test Python dependencies
python -c "import pefile, yara, requests; print('Dependencies OK')"

# Test API keys (if set)
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('Gemini:', 'Set' if os.getenv('GEMINI_API_KEY') else 'Not Set')"

# Test optional tools
if (Test-Path "upx.exe") { Write-Host "UPX: Found" } else { Write-Host "UPX: Not Found (optional)" }
if (Test-Path "ResourceHacker.exe") { Write-Host "Resource Hacker: Found" } else { Write-Host "Resource Hacker: Not Found (optional)" }
if (Test-Path "strings64.exe") { Write-Host "Strings64: Found" } else { Write-Host "Strings64: Not Found (optional)" }
```

---

## 🔍 Tool Detection

The pipeline automatically detects tools in this order:

1. **Current directory** (project root)
2. **`tools/` subdirectory**
3. **Windows PATH**
4. **Fallback to Python implementations**

You can place tools anywhere in the project directory structure.

---

## ⚠️ Troubleshooting

### "Module not found" errors
```powershell
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### "API key not found" errors
- Check `.env` file exists in project root
- Verify API keys are correct (no extra spaces)
- Restart terminal after creating `.env`

### "Tool not found" warnings
- These are **not errors** - pipeline continues with fallbacks
- Install optional tools for enhanced analysis
- Check tool is in correct location (project root or `tools/` folder)

### PowerShell execution policy error
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📦 Complete Tool List Summary

| Tool | Required? | Purpose | Fallback |
|------|-----------|---------|----------|
| Python 3.10+ | ✅ Yes | Runtime | None |
| pip packages | ✅ Yes | Dependencies | None |
| Gemini API Key | ✅ Yes | AI analysis | None (required) |
| VirusTotal API Key | ✅ Yes | Signature check | None (required) |
| UPX | ⚠️ Optional | Unpacking | Detection only |
| Resource Hacker | ⚠️ Optional | Resources | pefile |
| PEView | ⚠️ Optional | Imports/Exports | pefile |
| Strings64 | ⚠️ Optional | String extraction | Python |

---

## ✅ Quick Start (Minimum Setup)

If you just want to get started quickly:

1. **Install Python dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

2. **Create `.env` file:**
   ```env
   GEMINI_API_KEY=your_key
   VIRUSTOTAL_API_KEY=your_key
   ```

3. **Run analysis:**
   ```powershell
   py cli_analyze.py --file sample.exe --out outputs
   ```

The pipeline will work with Python fallbacks for all optional tools!

---

## 📚 Additional Resources

- **Python**: https://www.python.org/downloads/
- **Gemini API**: https://aistudio.google.com/app/apikey
- **VirusTotal API**: https://www.virustotal.com/
- **UPX**: https://upx.github.io/
- **Resource Hacker**: http://www.angusj.com/resourcehacker/
- **Sysinternals**: https://docs.microsoft.com/en-us/sysinternals/

---

**Note**: All optional tools have Python fallbacks, so the pipeline will work even without them. Install them for better performance and more detailed analysis.

