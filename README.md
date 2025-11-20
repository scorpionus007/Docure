# 8-Step Static Malware Analysis Pipeline

A comprehensive static malware analysis pipeline that performs 8 sequential analysis steps on executable files (.exe) with AI-powered reporting.

## Features

- **8 Sequential Analysis Steps**: Packing detection, hashing, resource analysis, format analysis, imports/exports, string extraction, signature checking, and metadata extraction
- **AI-Powered Reports**: Google Gemini API generates detailed reports for each step
- **CLI Tool Integration**: Uses native Windows tools (Get-FileHash, certutil) and external tools (Resource Hacker, PEView, strings64)
- **Comprehensive Logging**: Detailed logging for debugging and audit trails
- **Structured Output**: JSON results and Markdown reports for each step

## Pipeline Steps

1. **Packing Detection & Unpacking**: Detects if file is packed and attempts unpacking (UPX support)
2. **File Hash Calculation**: Calculates MD5, SHA1, SHA256 using PowerShell Get-FileHash or certutil
3. **Resource Analysis**: Analyzes PE file resources using Resource Hacker or pefile
4. **AI File Format Analysis**: Uses Google Gemini API to detect actual vs apparent file format
5. **Import/Export Analysis**: Analyzes DLL imports/exports using PEView or pefile
6. **String Extraction & AI Analysis**: Extracts strings using strings64 and analyzes with AI for malicious patterns
7. **Digital Signature Checking**: Checks file signature and reputation using VirusTotal API
8. **Metadata Extraction**: Extracts comprehensive metadata from the executable

## Requirements

### Required
- Python 3.10+
- Windows (for native CLI tools)

### Optional Tools (for enhanced analysis)
- **UPX**: For unpacking UPX-packed files
- **Resource Hacker**: For detailed resource analysis (falls back to pefile)
- **PEView**: For import/export analysis (falls back to pefile)
- **strings64**: For string extraction (falls back to Python implementation)

### API Keys (Required for AI features)
- **Google Gemini API Key**: For AI analysis and report generation
- **VirusTotal API Key**: For signature checking in Step 7

## Installation

1. Clone the repository:
```powershell
cd C:\Users\harin\OneDrive\Desktop\Docure
```

2. Create a virtual environment:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

3. Install dependencies:
```powershell
pip install -r requirements.txt
```

4. Create `.env` file in the project root:
```env
GEMINI_API_KEY=your_gemini_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

## Usage

### Basic Analysis

```powershell
py cli_analyze.py --file C:\malware\sample.exe --out outputs
```

### With Verbose Logging

```powershell
py cli_analyze.py --file C:\malware\sample.exe --out outputs --verbose
```

### Without AI Reports (faster, but no AI analysis)

```powershell
py cli_analyze.py --file C:\malware\sample.exe --out outputs --no-ai-reports
```

## Output Structure

After running the analysis, you'll find:

```
outputs/
├── steps/
│   ├── step1_packing.json          # Step 1 results
│   ├── step1_report.md              # AI-generated report for Step 1
│   ├── step2_hash.json              # Step 2 results
│   ├── step2_report.md              # AI-generated report for Step 2
│   ├── ...                          # Results and reports for all 8 steps
│   └── step8_metadata.json
├── unpacked/                        # Unpacked files (if any)
│   └── sample.unpacked.exe
├── logs/                            # Analysis logs
│   └── analysis_YYYYMMDD_HHMMSS.log
└── complete_analysis.json          # Complete analysis results
```

## Step Details

### Step 1: Packing Detection & Unpacking
- Detects packing using entropy analysis, YARA rules, and PE analysis
- Attempts to unpack if UPX is detected and UPX tool is available
- Uses unpacked file for subsequent analysis if unpacking succeeds

### Step 2: File Hash Calculation
- Uses PowerShell `Get-FileHash` (preferred)
- Falls back to `certutil` if PowerShell fails
- Falls back to Python `hashlib` if both fail
- Calculates MD5, SHA1, and SHA256

### Step 3: Resource Analysis
- Uses Resource Hacker CLI if available
- Falls back to `pefile` for basic resource extraction
- Extracts all PE resources (icons, strings, version info, etc.)

### Step 4: AI File Format Analysis
- Uses Google Gemini API to analyze file header
- Compares actual format vs apparent format
- Detects format mismatches (e.g., .pdf that's actually .zip)

### Step 5: Import/Export Analysis
- Uses PEView if available (GUI tool, falls back to pefile)
- Extracts all DLL imports and exports
- Identifies suspicious imports (VirtualAlloc, CreateRemoteThread, etc.)

### Step 6: String Extraction & AI Analysis
- Extracts strings using strings64 tool
- Falls back to Python implementation if tool not available
- Analyzes strings with Google Gemini API for malicious patterns
- Identifies IOCs (URLs, IPs, domains)

### Step 7: Digital Signature Checking
- Queries VirusTotal API using file hash
- Checks digital signature information
- Retrieves reputation scores (malicious, suspicious, harmless)

### Step 8: Metadata Extraction
- Extracts comprehensive file metadata
- PE headers, sections, timestamps
- File system metadata (size, dates, etc.)

## Logging

Comprehensive logging is enabled by default:
- **File logging**: `outputs/logs/analysis_YYYYMMDD_HHMMSS.log`
- **Console output**: Real-time progress and results
- **Verbose mode**: `--verbose` flag for detailed debug information

## API Keys Setup

1. **Google Gemini API Key**:
   - Get your API key from https://aistudio.google.com/app/apikey
   - Add to `.env`: `GEMINI_API_KEY=your_key_here`

2. **VirusTotal API Key**:
   - Sign up at https://www.virustotal.com/
   - Get your API key from your account settings
   - Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`

## Troubleshooting

### "GEMINI_API_KEY not set"
- Ensure `.env` file exists in project root
- Check that API key is correctly set: `GEMINI_API_KEY=your_key_here`

### "VIRUSTOTAL_API_KEY not set"
- Required for Step 7 (signature checking)
- Add to `.env` file

### "UPX executable not found"
- Step 1 will still detect packing but won't unpack
- Download UPX from https://upx.github.io/
- Place `upx.exe` in project directory or add to PATH

### "Resource Hacker not found"
- Step 3 will use pefile fallback (basic resource extraction)
- Download Resource Hacker from http://www.angusj.com/resourcehacker/
- Place in project directory or specify path

### "strings64 not found"
- Step 6 will use Python fallback (slower but functional)
- Download strings64 from Sysinternals or place in project directory

## Security Notes

- **Never analyze malware on production systems**
- Use isolated VMs or dedicated analysis environments
- Files are never executed, only statically analyzed
- Sandbox isolation is recommended for actual malware samples

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]
