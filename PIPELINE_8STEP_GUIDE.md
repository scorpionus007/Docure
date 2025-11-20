# 8-Step Static Malware Analysis Pipeline - Complete Guide

## Overview

This pipeline performs comprehensive static analysis of executable files (.exe) through 8 sequential steps, with AI-powered reporting for each step.

## Pipeline Architecture

```
Input: .exe file
    ↓
Step 1: Packing Detection & Unpacking
    ↓ (if unpacked, use unpacked file for subsequent steps)
Step 2: File Hash Calculation
    ↓
Step 3: Resource Analysis
    ↓
Step 4: AI File Format Analysis
    ↓
Step 5: Import/Export Analysis
    ↓
Step 6: String Extraction & AI Analysis
    ↓
Step 7: Digital Signature Checking (uses hash from Step 2)
    ↓
Step 8: Metadata Extraction
    ↓
Output: Complete analysis results + AI reports
```

## Step-by-Step Details

### Step 1: Packing Detection & Unpacking

**Purpose**: Detect if the file is packed and attempt to unpack it.

**Methods**:
- Entropy analysis (high entropy = likely packed)
- YARA rules for packer signatures
- PE section analysis
- UPX detection

**Tools**:
- Python libraries: `pefile`, `yara-python`
- External: UPX (if available)

**Output**:
- `is_packed`: Boolean
- `packer_type`: Detected packer (e.g., "UPX")
- `packing_confidence`: "high", "medium", "low", "none"
- `unpacked`: Success status and path to unpacked file

**AI Report**: Analyzes packing indicators and risk assessment.

---

### Step 2: File Hash Calculation

**Purpose**: Calculate cryptographic hashes for file identification and verification.

**Methods** (in order of preference):
1. PowerShell `Get-FileHash` (most reliable on Windows)
2. `certutil` (Windows built-in)
3. Python `hashlib` (fallback)

**Hashes Calculated**:
- MD5
- SHA1
- SHA256

**Output**:
- `hashes`: Dictionary with MD5, SHA1, SHA256
- `method`: Tool used for calculation

**AI Report**: Explains hash values and their significance for malware identification.

---

### Step 3: Resource Analysis

**Purpose**: Extract and analyze PE file resources (icons, strings, version info, etc.).

**Methods**:
- Resource Hacker CLI (if available)
- `pefile` library (fallback)

**Resources Analyzed**:
- Icons
- Version information
- String tables
- Dialogs
- Menus
- Other embedded resources

**Output**:
- `resources`: List of extracted resources
- `resource_count`: Number of resources found
- `method`: Tool used

**AI Report**: Analyzes resources for suspicious content or obfuscation.

---

### Step 4: AI File Format Analysis

**Purpose**: Use AI to determine actual file format vs apparent format.

**Method**: Gemini API analysis of file header and magic bytes.

**Analysis**:
- Reads first 512 bytes (file header)
- Compares with apparent format (from extension)
- Detects format mismatches (e.g., .pdf that's actually .zip)

**Output**:
- `apparent_format`: Format from extension
- `actual_format`: Format detected by AI
- `is_mismatch`: Boolean indicating format mismatch
- `format_analysis`: AI-generated analysis

**AI Report**: Explains format detection and any mismatches that could indicate obfuscation.

---

### Step 5: Import/Export Analysis

**Purpose**: Analyze DLL imports and exports to identify suspicious functions.

**Methods**:
- PEView (if available, GUI tool)
- `pefile` library (fallback, CLI-friendly)

**Analysis**:
- Lists all imported DLLs and functions
- Lists all exported functions
- Identifies suspicious imports:
  - `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`
  - `LoadLibrary`, `GetProcAddress`
  - `WinExec`, `ShellExecute`
  - Network functions: `socket`, `connect`, `send`, `recv`

**Output**:
- `imports`: List of imported functions
- `exports`: List of exported functions
- `import_count`: Number of imports
- `export_count`: Number of exports
- `suspicious_imports`: List of flagged suspicious imports

**AI Report**: Analyzes imports/exports for malicious behavior patterns.

---

### Step 6: String Extraction & AI Analysis

**Purpose**: Extract strings and analyze them for malicious patterns and IOCs.

**Methods**:
- `strings64` tool (Sysinternals, if available)
- Python implementation (fallback)

**String Extraction**:
- ASCII strings (minimum 4 characters)
- UTF-16 strings
- Deduplication

**AI Analysis** (Gemini API):
- Identifies malicious patterns
- Extracts IOCs (URLs, IPs, domains)
- Risk assessment
- Suspicious code snippets

**Output**:
- `strings`: Extracted strings (first 500 stored)
- `strings_count`: Total number of strings
- `malicious_patterns`: AI-identified patterns
- `suspicious_strings`: Flagged suspicious strings
- `iocs`: Extracted IOCs (URLs, IPs, domains)
- `analysis`: AI-generated analysis

**AI Report**: Comprehensive analysis of strings for malicious indicators.

---

### Step 7: Digital Signature Checking

**Purpose**: Check file digital signature and reputation using VirusTotal.

**Method**: VirusTotal API query using SHA256 hash from Step 2.

**Analysis**:
- Digital signature verification
- Signer information
- Reputation scores:
  - Malicious detections
  - Suspicious detections
  - Harmless detections
  - Undetected

**Output**:
- `found`: Whether file exists in VT database
- `signature_info`: Digital signature details
  - `signed`: Boolean
  - `signer`: Signer name
  - `issuer`: Certificate issuer
  - `valid`: Signature validity
- `reputation`: Detection statistics
- `permalink`: Link to VT analysis page

**AI Report**: Interprets signature and reputation data for risk assessment.

---

### Step 8: Metadata Extraction

**Purpose**: Extract comprehensive metadata from the executable.

**Method**: `pefile` library + file system metadata.

**Metadata Extracted**:
- File system metadata:
  - File size
  - Creation/modification/access times
  - File name and extension
- PE Headers:
  - Machine type
  - Number of sections
  - Timestamp
  - Characteristics
- Optional Header:
  - Entry point
  - Image base
  - Section alignment
  - Subsystem
- Sections:
  - Section names
  - Virtual addresses
  - Sizes
  - Characteristics
- Version Information (if available):
  - Product name
  - Version
  - Company
  - Description

**Output**:
- `metadata`: Comprehensive metadata dictionary
- `pe_info`: PE-specific information

**AI Report**: Summarizes metadata and identifies suspicious characteristics.

---

## Output Structure

```
outputs/
├── steps/
│   ├── step1_packing.json          # Step 1 JSON results
│   ├── step1_report.md              # Step 1 AI report
│   ├── step2_hash.json
│   ├── step2_report.md
│   ├── ...                          # All 8 steps
│   ├── step8_metadata.json
│   └── step8_report.md
├── unpacked/                        # Unpacked files (if any)
│   └── sample.unpacked.exe
├── logs/                            # Analysis logs
│   └── analysis_YYYYMMDD_HHMMSS.log
└── complete_analysis.json          # Complete results
```

## API Keys Required

### Gemini API Key
- **Required for**: Steps 4, 6, and all AI reports
- **Get it**: https://aistudio.google.com/app/apikey
- **Usage**: AI analysis and report generation

### VirusTotal API Key
- **Required for**: Step 7 (signature checking)
- **Get it**: https://www.virustotal.com/
- **Usage**: File reputation and signature verification

## Optional Tools

### UPX
- **Purpose**: Unpacking UPX-packed files (Step 1)
- **Download**: https://upx.github.io/
- **Place**: Project directory or add to PATH

### Resource Hacker
- **Purpose**: Enhanced resource analysis (Step 3)
- **Download**: http://www.angusj.com/resourcehacker/
- **Place**: Project directory or `tools/` subdirectory

### PEView
- **Purpose**: Import/export analysis (Step 5)
- **Note**: GUI tool, pipeline uses `pefile` fallback
- **Download**: Available from various sources

### strings64
- **Purpose**: String extraction (Step 6)
- **Download**: Sysinternals Suite
- **Place**: Project directory or add to PATH

## Logging

All steps generate comprehensive logs:
- **File**: `outputs/logs/analysis_YYYYMMDD_HHMMSS.log`
- **Console**: Real-time progress
- **Verbose**: `--verbose` flag for detailed debugging

Log format:
```
YYYY-MM-DD HH:MM:SS [LEVEL] [MODULE] Message
```

## Error Handling

- Each step is independent and continues even if previous steps fail
- Errors are logged and stored in `complete_analysis.json`
- Missing tools fall back to Python implementations
- Missing API keys skip AI features but continue analysis

## Performance

Typical analysis time:
- **Without AI reports**: 30-60 seconds
- **With AI reports**: 2-5 minutes (depends on API response time)
- **Large files**: May take longer for string extraction

## Security Best Practices

1. **Isolation**: Run analysis in isolated VMs
2. **No Execution**: Files are never executed, only statically analyzed
3. **Sandboxing**: Use sandbox environments for actual malware
4. **API Keys**: Never commit `.env` file to version control
5. **Network**: Ensure firewall allows outbound HTTPS for APIs

## Troubleshooting

### Step fails with API error
- Check API key in `.env` file
- Verify internet connection
- Check API rate limits

### Tool not found warnings
- Pipeline continues with fallback methods
- Install optional tools for enhanced analysis

### Timeout errors
- Large files may timeout on string extraction
- Increase timeout values in code if needed

## Example Usage

```powershell
# Basic analysis
py cli_analyze.py --file C:\samples\malware.exe --out outputs

# With verbose logging
py cli_analyze.py --file C:\samples\malware.exe --out outputs --verbose

# Without AI reports (faster)
py cli_analyze.py --file C:\samples\malware.exe --out outputs --no-ai-reports
```

## Next Steps

After analysis:
1. Review `complete_analysis.json` for all results
2. Read individual step reports in `steps/step*_report.md`
3. Check logs in `logs/` for detailed execution information
4. Use unpacked files in `unpacked/` for further analysis if needed

