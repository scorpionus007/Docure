# PowerShell Script to Download and Install Optional Tools for Malware Analysis Pipeline
# Run this script from the project root directory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Downloading Optional Analysis Tools" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create tools directory
$toolsDir = Join-Path $PSScriptRoot "tools"
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir | Out-Null
    Write-Host "[+] Created tools directory: $toolsDir" -ForegroundColor Green
}

# Create temp directory for downloads
$tempDir = Join-Path $PSScriptRoot "temp_downloads"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

# Function to download file
function Download-File {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$ToolName
    )
    
    Write-Host "[*] Downloading $ToolName..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Successfully downloaded $ToolName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[-] Failed to download $ToolName : $_" -ForegroundColor Red
        return $false
    }
}

# Function to extract ZIP file
function Extract-Zip {
    param(
        [string]$ZipPath,
        [string]$ExtractPath
    )
    
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
        Write-Host "[+] Extracted archive to $ExtractPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[-] Failed to extract: $_" -ForegroundColor Red
        return $false
    }
}

# 1. Download UPX
Write-Host "`n[1/4] UPX (Ultimate Packer for eXecutables)" -ForegroundColor Cyan
$upxZip = Join-Path $tempDir "upx.zip"
$upxUrl = "https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip"

if (Download-File -Url $upxUrl -OutputPath $upxZip -ToolName "UPX") {
    $upxExtract = Join-Path $tempDir "upx"
    if (Extract-Zip -ZipPath $upxZip -ExtractPath $upxExtract) {
        # Find upx.exe in extracted folder
        $upxExe = Get-ChildItem -Path $upxExtract -Filter "upx.exe" -Recurse | Select-Object -First 1
        if ($upxExe) {
            Copy-Item $upxExe.FullName -Destination (Join-Path $toolsDir "upx.exe") -Force
            Copy-Item $upxExe.FullName -Destination (Join-Path $PSScriptRoot "upx.exe") -Force
            Write-Host "[+] UPX installed to tools/upx.exe and project root" -ForegroundColor Green
        }
    }
}

# 2. Download Resource Hacker
Write-Host "`n[2/4] Resource Hacker" -ForegroundColor Cyan
$reshackerZip = Join-Path $tempDir "reshacker.zip"
$reshackerUrl = "http://www.angusj.com/resourcehacker/resource_hacker.zip"

if (Download-File -Url $reshackerUrl -OutputPath $reshackerZip -ToolName "Resource Hacker") {
    $reshackerExtract = Join-Path $tempDir "reshacker"
    if (Extract-Zip -ZipPath $reshackerZip -ExtractPath $reshackerExtract) {
        # Find ResourceHacker.exe
        $reshackerExe = Get-ChildItem -Path $reshackerExtract -Filter "ResourceHacker.exe" -Recurse | Select-Object -First 1
        if (-not $reshackerExe) {
            $reshackerExe = Get-ChildItem -Path $reshackerExtract -Filter "*.exe" | Select-Object -First 1
        }
        if ($reshackerExe) {
            Copy-Item $reshackerExe.FullName -Destination (Join-Path $toolsDir "ResourceHacker.exe") -Force
            Copy-Item $reshackerExe.FullName -Destination (Join-Path $PSScriptRoot "ResourceHacker.exe") -Force
            Write-Host "[+] Resource Hacker installed to tools/ResourceHacker.exe and project root" -ForegroundColor Green
        }
    }
}

# 3. Download Strings64 (Sysinternals)
Write-Host "`n[3/4] Strings64 (Sysinternals)" -ForegroundColor Cyan
$stringsUrl = "https://download.sysinternals.com/files/Strings.zip"
$stringsZip = Join-Path $tempDir "strings.zip"

if (Download-File -Url $stringsUrl -OutputPath $stringsZip -ToolName "Strings64") {
    $stringsExtract = Join-Path $tempDir "strings"
    if (Extract-Zip -ZipPath $stringsZip -ExtractPath $stringsExtract) {
        # Find strings64.exe or strings.exe
        $stringsExe = Get-ChildItem -Path $stringsExtract -Filter "strings64.exe" | Select-Object -First 1
        if (-not $stringsExe) {
            $stringsExe = Get-ChildItem -Path $stringsExtract -Filter "strings.exe" | Select-Object -First 1
        }
        if ($stringsExe) {
            Copy-Item $stringsExe.FullName -Destination (Join-Path $toolsDir "strings64.exe") -Force
            Copy-Item $stringsExe.FullName -Destination (Join-Path $PSScriptRoot "strings64.exe") -Force
            Write-Host "[+] Strings64 installed to tools/strings64.exe and project root" -ForegroundColor Green
        }
    }
}

# 4. Download PEView (optional - try alternative source)
Write-Host "`n[4/4] PEView (Note: May need manual download)" -ForegroundColor Cyan
Write-Host "[!] PEView download may require manual steps:" -ForegroundColor Yellow
Write-Host "    1. Visit: https://www.mzrst.com/posts/peview/" -ForegroundColor Yellow
Write-Host "    2. Or search for 'PEView download' online" -ForegroundColor Yellow
Write-Host "    3. Place PEView.exe in tools/ folder" -ForegroundColor Yellow
Write-Host "[*] Note: PEView is optional - pefile library works as fallback" -ForegroundColor Cyan

# Cleanup temp directory
Write-Host "`n[*] Cleaning up temporary files..." -ForegroundColor Yellow
if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force
    Write-Host "[+] Cleaned up temporary files" -ForegroundColor Green
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Installation Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$tools = @(
    @{Name="UPX"; Path=(Join-Path $toolsDir "upx.exe")},
    @{Name="Resource Hacker"; Path=(Join-Path $toolsDir "ResourceHacker.exe")},
    @{Name="Strings64"; Path=(Join-Path $toolsDir "strings64.exe")}
)

foreach ($tool in $tools) {
    if (Test-Path $tool.Path) {
        Write-Host "[+] $($tool.Name): Installed" -ForegroundColor Green
    }
    else {
        Write-Host "[-] $($tool.Name): Not found" -ForegroundColor Red
    }
}

Write-Host "`n[*] Tools are installed in:" -ForegroundColor Cyan
Write-Host "    - tools/ folder (organized)" -ForegroundColor White
Write-Host "    - Project root (for direct access)" -ForegroundColor White
Write-Host "`n[*] The pipeline will automatically detect tools in both locations" -ForegroundColor Cyan
Write-Host ""

