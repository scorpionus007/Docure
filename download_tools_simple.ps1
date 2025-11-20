# Simple PowerShell Script - Download All Tools
# Run: .\download_tools_simple.ps1

# Create tools folder
New-Item -ItemType Directory -Force -Path "tools" | Out-Null
Write-Host "Created tools/ folder" -ForegroundColor Green

# Download UPX
Write-Host "`nDownloading UPX..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip" -OutFile "upx.zip"
Expand-Archive -Path "upx.zip" -DestinationPath "temp_upx" -Force
$upxExe = Get-ChildItem -Path "temp_upx" -Filter "upx.exe" -Recurse | Select-Object -First 1
Copy-Item $upxExe.FullName -Destination "tools\upx.exe"
Copy-Item $upxExe.FullName -Destination "upx.exe"
Write-Host "UPX installed!" -ForegroundColor Green
Start-Sleep -Seconds 1
Remove-Item -Path "temp_upx" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "upx.zip" -Force -ErrorAction SilentlyContinue

# Download Resource Hacker
Write-Host "`nDownloading Resource Hacker..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "http://www.angusj.com/resourcehacker/resource_hacker.zip" -OutFile "reshacker.zip"
Expand-Archive -Path "reshacker.zip" -DestinationPath "temp_reshacker" -Force
$reshackerExe = Get-ChildItem -Path "temp_reshacker" -Filter "ResourceHacker.exe" -Recurse | Select-Object -First 1
if (-not $reshackerExe) { $reshackerExe = Get-ChildItem -Path "temp_reshacker" -Filter "*.exe" | Select-Object -First 1 }
Copy-Item $reshackerExe.FullName -Destination "tools\ResourceHacker.exe"
Copy-Item $reshackerExe.FullName -Destination "ResourceHacker.exe"
Write-Host "Resource Hacker installed!" -ForegroundColor Green
Start-Sleep -Seconds 1
Remove-Item -Path "temp_reshacker" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "reshacker.zip" -Force -ErrorAction SilentlyContinue

# Download Strings64
Write-Host "`nDownloading Strings64..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Strings.zip" -OutFile "strings.zip"
Expand-Archive -Path "strings.zip" -DestinationPath "temp_strings" -Force
$stringsExe = Get-ChildItem -Path "temp_strings" -Filter "strings64.exe" | Select-Object -First 1
if (-not $stringsExe) { $stringsExe = Get-ChildItem -Path "temp_strings" -Filter "strings.exe" | Select-Object -First 1 }
Copy-Item $stringsExe.FullName -Destination "tools\strings64.exe"
Copy-Item $stringsExe.FullName -Destination "strings64.exe"
Write-Host "Strings64 installed!" -ForegroundColor Green

# Cleanup with error handling
Write-Host "`nCleaning up temporary files..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
try {
    Remove-Item -Path "temp_strings" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "strings.zip" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] Some temp files couldn't be removed (this is OK - tools are installed)" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "All tools downloaded and installed!" -ForegroundColor Green
Write-Host "Location: tools/ folder and project root" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

