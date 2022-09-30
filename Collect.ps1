# Basic script to initiate data collection of M365D data for the analysis in PowerBI
[CmdletBinding()]
param (
    [switch]$Local
)
Import-Module Az.Storage
Import-Module Az.KeyVault
Import-Module Az.Resources
Import-Module Az.Accounts

if ($Local) {
    # Connect to Azure with credentials
    $Context = Get-AzContext 
    if (!$Context) {
        Write-Host "ACTION | Connect to your Azure account" -ForegroundColor Yellow
        Connect-AzAccount
    }
} else {
    # Connect to Azure with system-assigned managed identity
    $Context = (Connect-AzAccount -Identity).context
    Set-AzContext -Context $Context
    Import-Module "MD.psm1"
}

# Setup prep: collect required secrets/keys for the tenant
$TenantId = "<< CHANGE ME >>"
$AppId = "<< CHANGE ME >>"
$KeyVaultName = "<< CHANGE ME >>"
$AppSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "AppRegistrationSecret" -AsPlainText

# Storage account and local path
$StorageAccount = "<< CHANGE ME >>" # This must be all lowercase or upload will fail
$StorageContainer = "data"
$Path = "C:\VIR"
$StorageKey = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "StorageAccountKey" -AsPlainText

# Step 1: Get CVE Data
Get-CVEData -Path $Path 

# # Step 2: Get device information
Get-MDDevices -Path $Path -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret

# Step 3: Get vulnerability data
Get-MDVulnerabilities -Path $Path -ExportType "bulk" -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret
Get-MDSoftwareInventory -Path $Path -ExportType "bulk" -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret
Get-MDSecurityConfig -Path $Path -ExportType "bulk" -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret
Get-MDAVInfo -Path $Path -ExportType "api" -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret # Bulk export is in BETA, use only API export option for now
Get-MDSecurityBaselines -Path $Path -ExportType "bulk" -TenantId $TenantId -AppId $AppId -AppSecret $AppSecret

# Step 4: Upload data to blob storage
Invoke-DataUpload -Path $Path -StorageAccount $StorageAccount -StorageKey $StorageKey -StorageContainer $StorageContainer