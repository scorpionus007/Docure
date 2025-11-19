# PowerShell script to run cli_analyze.py with the virtual environment
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

# Activate virtual environment
& "$PSScriptRoot\venv\Scripts\Activate.ps1"

# Run the script with all passed arguments
& python "$PSScriptRoot\cli_analyze.py" $Arguments


