# This script performs the setup of the required Azure AD application registration and supported infrastructure
# It will also provision the minimum required Azure resources, including resource group, storage account, automation account and key vault.

param (
    [string]
    [validateset('australiaeast', 'australiasoutheast', 'australiacentral', 'australiacentral2')]
    $Location = 'australiaeast',
    [Parameter(Mandatory = $true)]
    $ResourceGroupName = 'MDEPBI',
    [switch] $AppRegistration,
    [switch] $Azure
)

# Check to see if required PowerShell modules exist
$Modules = @("Az.Resources", "Az.Storage", "Az.Accounts", "Az.KeyVault") 

foreach ($m in $Modules) {
    if (-not (Get-Module $m -ListAvailable)) {
        Write-Host "PowerShell module $m not installed. Attempting to install it."
        Install-Module $m -AllowClobber -Force
    }
}

# Checking for existing Azure session
$Context = Get-AzContext 
if (!$Context) {
    Write-Host "ACTION | Connect to your Azure account" -ForegroundColor Yellow
    Connect-AzAccount
}

if ($Azure) {
    $UniqueID = "$ResourceGroupName$(((New-Guid) -replace '-', '').ToString().Substring(0, 10))"
    Write-Host "Provisioning | Resource Group: $ResourceGroupName"
    if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    }
    
    $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName | Where-Object { $_.kind -eq 'BlobStorage' }
    $StorageAccountName = $UniqueID.ToLower()
    Write-Host "Provisioning | Storage Account: $StorageAccountName"
    if (-not $StorageAccount) {
        $storageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Location $Location -SkuName "Standard_LRS" -Kind "BlobStorage" -AccessTier Hot
    }
    else {
        $StorageAccountName = $StorageAccount.StorageAccountName
    }
    $storageAccountContext = $storageAccount.Context
    $ContainerName = "data"
    Write-Host "Provisioning | Storage Container: $ContainerName"
    if (-not (Get-AzStorageContainer -Name $containerName -Context $storageAccountContext -ErrorAction SilentlyContinue)) {
        New-AzStorageContainer -Name $containerName -Context $storageAccountContext -Permission blob | Out-Null
        Set-AzStorageContainerAcl -Name $ContainerName -Context $storageAccountContext -Permission Off  | Out-Null
    }
    $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | where { $_.KeyName -eq "key1" }).value
    $EncSAK = ConvertTo-SecureString $StorageAccountKey -AsPlainText -Force

    # Create automation account
    Write-Host "Provisioning | Automation Account: $UniqueID"
    New-AzAutomationAccount -Name $UniqueID -Location $Location -ResourceGroupName $ResourceGroupName | Out-Null
    
    # Create key vault
    Write-Host "Provisioning | Key Vault: $UniqueID"
    New-AzKeyVault -VaultName $UniqueID -ResourceGroupName $ResourceGroupName -Location $Location | Out-Null
    # Add storage key to Key Vault
    $KVStorage = Set-AzKeyVaultSecret -VaultName $UniqueID -Name "StorageAccountKey" -SecretValue $EncSAK
    if ($true -eq $KVStorage.Enabled) {
        Write-Host "Provisioning | Key Vault: StorageAccountKey secret stored"
    }
    else {
        Write-Host "Provisioning | Key Vault: There was an issue adding the StorageAccountKey to key vault." -ForegroundColor Yellow
        Write-Host "Please store the StorageAccountKey manually." -ForegroundColor Yellow
        Write-Host "Storage Account Key: $StorageAccountKey"
    }
}

if ($AppRegistration) {
    $AAD = @{
        ResourceAppId  = "00000003-0000-0000-c000-000000000000"; # Microsoft Graph Application ID
        ResourceAccess = @(
            @{
                Id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d";
                Type = "Scope"
            }
        )
    }
    $MDE = @{
        ResourceAppId  = "fc780465-2017-40d4-a0c5-307022471b92"; # Microsoft Defender for Endpoint Application ID
        ResourceAccess = @(
            @{
                Id   = "e870c0c1-c1a2-41ca-948e-a33912d2d3f0";
                Type = "Role"
            },
            @{
                Id   = "227f2ea0-c2c2-4428-b7af-9ff40f1a720e";
                Type = "Role"
            },
            @{
                Id   = "6a33eedf-ba73-4e5a-821b-f057ef63853a";
                Type = "Role"
            },
            @{
                Id   = "02b005dd-f804-43b4-8fc7-078460413f74";
                Type = "Role"
            },
            @{
                Id   = "41269fc5-d04d-4bfd-bce7-43a51cea049a";
                Type = "Role"
            },
            @{
                Id   = "37f71c98-d198-41ae-964d-2c49aab74926";
                Type = "Role"
            },
            @{
                Id   = "6443965c-7dd2-4cfd-b38f-bb7772bee163";
                Type = "Role"
            },
            @{
                Id   = "71fe6b80-7034-4028-9ed8-0f316df9c3ff";
                Type = "Role"
            },
            @{
                Id   = "a833834a-4cf1-4732-8acf-bbcfa13fb610";
                Type = "Role"
            },
            @{
                Id   = "47bf842d-354b-49ef-b741-3a6dd815bc13";
                Type = "Role"
            },
            @{
                Id   = "721af526-ffa8-42d7-9b84-1a56244dd99d";
                Type = "Role"
            }, 
            @{
                Id   = "8788f1a9-beca-4e26-ba58-10513f3b896f";
                Type = "Role"
            },
            @{
                Id   = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79";
                Type = "Role"
            },
            # @{
            #     Id   = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"; # Advanced hunting - not required at the moment.
            #     Type = "Role"
            # },
            @{
                Id   = "528ca142-c849-4a5b-935e-10b8b9c38a84";
                Type = "Role"
            }
        )
    }
    $M365D = @{
        ResourceAppId  = "8ee8fdad-f234-4243-8f3b-15c294843740"; # Microsoft 365 Defender Application ID
        ResourceAccess = @(
            @{
                Id   = "a9790345-4595-42e4-971a-ccdc79f19b7c";
                Type = "Role"
            }
            # @{
            #     Id   = "7734e8e5-8dde-42fc-b5ae-6eafea078693"; # Advanced Hunting - not required at the moment.
            #     Type = "Role"
            # }
        )
    }
    Write-Host "Provisioning | Azure Application Registration: MDE PowerBI API"
    $AppReg = New-AzADApplication -DisplayName "MDE PowerBI API" -AvailableToOtherTenants $false -RequiredResourceAccess @($AAD, $MDE, $M365D)

    # Grant admin consent for the tenant (required)
    $AppId = $AppReg.AppId
    $azcontext = Get-AzContext
    $TenantId = $azcontext.Tenant.Id

    # Generate credentials to store in Key Vault
    Write-Host "Provisioning | Azure Application Secret"
    $AppSecret = New-AzADAppCredential -ApplicationId $AppId -StartDate (Get-Date) -EndDate (Get-date).AddDays(365)
    $key = $AppSecret.SecretText
    $EncSAK = ConvertTo-SecureString $Key -AsPlainText -Force

    # Big thanks to my colleague Sven Aelterman for the below function
    # https://stackoverflow.com/a/71299382
    function Set-AdminConsent {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]$applicationId,
            # The Azure Context]
            [Parameter(Mandatory)]
            [object]$context
        )

        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")
        $headers = @{
            'Authorization'          = 'Bearer ' + $token.AccessToken
            'X-Requested-With'       = 'XMLHttpRequest'
            'x-ms-client-request-id' = [guid]::NewGuid()
            'x-ms-correlation-id'    = [guid]::NewGuid()
        }

        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$applicationId/Consent?onBehalfOfAll=true"
        Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
    }
    Write-Host "Provisioning | Admin Consent for: MDE PowerBI API. This will take 30 seconds."
    Start-Sleep -Seconds 30 # sleep due to Azure AD app registration provision period
    Set-AdminConsent -applicationId $AppId -context $azcontext
    # Output
    Write-Host "Tenant ID: $TenantId"
    if (Get-AzResourceGroup -ResourceGroupName $ResourceGroupName) {
        $kvname = (Get-AzKeyVault -ResourceGroupName $ResourceGroupName)
        if ($kvname.count -gt 1) {
            Write-Verbose "Multiple Key Vaults detected. Manual key vault entry required"
        }
        else {
            $KVStorage = Set-AzKeyVaultSecret -VaultName $kvname.VaultName -Name "AppRegistrationSecret" -SecretValue $EncSAK
        }
        Write-Host "App ID: $AppId"
        Write-Host "App Secret: Stored in Key Vault $($kvname.VaultName)"
    }
    else {
        Write-Host "Ensure you store the credentials below in Key Vault. These are required for the data collection module." -ForegroundColor Yellow
        Write-Host "App ID: $AppId"
        Write-Host "App Secret: $key"
    }
}