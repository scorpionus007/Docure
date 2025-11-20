# Test Script for 8-Step Malware Analysis Pipeline
# This script verifies setup and provides test commands

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Pipeline Setup Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[*] Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[-] Python not found! Install Python 3.10+" -ForegroundColor Red
    exit 1
}

# Check dependencies
Write-Host "`n[*] Checking Python dependencies..." -ForegroundColor Yellow
$deps = @("pefile", "yara", "requests", "dotenv")
$allDeps = $true
foreach ($dep in $deps) {
    try {
        python -c "import $dep" 2>&1 | Out-Null
        Write-Host "[+] $dep : Installed" -ForegroundColor Green
    } catch {
        Write-Host "[-] $dep : Not installed" -ForegroundColor Red
        $allDeps = $false
    }
}

if (-not $allDeps) {
    Write-Host "`n[!] Installing missing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
}

# Check API keys
Write-Host "`n[*] Checking API keys..." -ForegroundColor Yellow
if (Test-Path ".env") {
    $envContent = Get-Content ".env" -Raw
    if ($envContent -match "GEMINI_API_KEY") {
        Write-Host "[+] Gemini API Key: Found" -ForegroundColor Green
    } else {
        Write-Host "[-] Gemini API Key: Not set in .env" -ForegroundColor Red
    }
    if ($envContent -match "VIRUSTOTAL_API_KEY") {
        Write-Host "[+] VirusTotal API Key: Found" -ForegroundColor Green
    } else {
        Write-Host "[-] VirusTotal API Key: Not set in .env" -ForegroundColor Red
    }
} else {
    Write-Host "[-] .env file not found! Create it with API keys." -ForegroundColor Red
    Write-Host "    Create .env file with:" -ForegroundColor Yellow
    Write-Host "    GEMINI_API_KEY=your_key" -ForegroundColor Yellow
    Write-Host "    VIRUSTOTAL_API_KEY=your_key" -ForegroundColor Yellow
}

# Check tools
Write-Host "`n[*] Checking optional tools..." -ForegroundColor Yellow
$tools = @(
    @{Name="UPX"; Path="tools\upx.exe"},
    @{Name="Resource Hacker"; Path="tools\ResourceHacker.exe"},
    @{Name="Strings64"; Path="tools\strings64.exe"}
)

foreach ($tool in $tools) {
    if (Test-Path $tool.Path) {
        Write-Host "[+] $($tool.Name): Found" -ForegroundColor Green
    } else {
        Write-Host "[!] $($tool.Name): Not found (optional - will use fallback)" -ForegroundColor Yellow
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test command
Write-Host "To test the pipeline, run:" -ForegroundColor Cyan
Write-Host "  py cli_analyze.py --file <path_to_exe> --out outputs --verbose" -ForegroundColor White
Write-Host ""
Write-Host "Example:" -ForegroundColor Cyan
Write-Host "  py cli_analyze.py --file C:\samples\test.exe --out outputs --verbose" -ForegroundColor White
Write-Host ""

