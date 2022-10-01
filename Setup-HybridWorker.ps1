# Install hybrid worker requirements

# Install PowerShell 7
Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.2.6/PowerShell-7.2.6-win-x64.msi -OutFile "C:\temp\PowerShell7.msi"
msiexec.exe /i "C:\temp\PowerShell7.msi" /quiet

# Install required PowerShell modules
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module Az.Storage -Force -Scope AllUsers -AllowClobber
Install-Module Az.KeyVault -Force -Scope AllUsers -AllowClobber
Install-Module Az.Accounts -Force -Scope AllUsers -AllowClobber
Install-Module Az.Resources -Force -Scope AllUsers -AllowClobber
Install-Module Az.Automation -Force -Scope AllUsers -AllowClobber

# Create staging directories in preperation
New-Item -ItemType Directory -Path "C:\VIR"

# Download the data collection module
New-Item -ItemType Directory -Path "C:\Modules"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Dylan-J/Microsoft-365-Defender-Insights-Report/main/MD.psm1" -OutFile "C:\Modules\MD.psm1"