using namespace System.Text.Json
#Region './Classes/MDCveData.ps1' 0
class CveData {
    [string] $RunTime
    [string] $CveId
    [string] $CveVersion
    [string] $Assigner
    [string] $Description
    [string] $PublishedDate
    [string] $ModifiedDate
}
#EndRegion './Classes/MDCveData.ps1' 10
#Region './Classes/MDCveRef.ps1' 0
class CveRef {
    [string] $RunTime
    [string] $CveId
    [string] $Url
    [string] $Name
    [string] $Tags
    [string] $Source
    [bool] $IsExploit
}
#EndRegion './Classes/MDCveRef.ps1' 10
#Region './Classes/MDCVSS.ps1' 0
class Cvss {
    [string] $RunTime
    [string] $CveId
    [string] $CvssScore
    [string] $CvssSeverity
    [string] $CvssVersion
    [string] $Vector
    [string] $attackVector
    [string] $attackComplexity
    [string] $privilegesRequired
    [string] $userInteraction
    [string] $confidentialityImpact
    [string] $integrityImpact
    [string] $availabilityImpact
    [string] $impactScore
    [string] $exploitabilityScore
}
#EndRegion './Classes/MDCVSS.ps1' 18
#Region './Classes/MDDevices.ps1' 0
class Devices {
    [string] $RunTime
    [string] $TenantId
    [string] $deviceId
    [string] $DeviceName
    [string] $FirstSeenTimestamp
    [string] $LastSeenTimestamp 
    [string] $osPlatform
    [string] $osProcessor
    [string] $version
    [string] $osBuild
    [string] $lastIpAddress
    [string] $lastExternalIpAddress
    [string] $healthStatus
    [string] $rbacGroupName
    [int32] $rbacGroupId
    [string] $riskScore
    [string] $exposureScore
    [string] $exposureLevel
    [string] $deviceValue
    [string] $machineTags
    [string] $managedBy
    [string] $aadJoined
    [string] $aadDeviceId
    [string] $onboardingStatus
    [string] $defenderAvStatus
}
#EndRegion './Classes/MDDevices.ps1' 28
#Region './Public/Get-AccessToken.ps1' 0
function Get-AccessToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $TenantId,
        [Parameter(Mandatory = $true)]
        [string] $AppId,
        [Parameter(Mandatory = $true)]
        [string] $appSecret
    )
    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    $oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
    $body = [Ordered] @{
        resource      = "$resourceAppIdUri"
        client_id     = "$appId"
        client_secret = "$appSecret"
        grant_type    = 'client_credentials'
    }
    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
    $token = $response.access_token
    return $token
}
#EndRegion './Public/Get-AccessToken.ps1' 23
#Region './Public/Get-CVEData.ps1' 0
function Get-CVEData {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$Leo
    )
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $CVEYears = @(
        '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009', '2010', '2011',
        '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022'
    )
    # $CVEYears = @(
    #     '2021', '2022'
    # )
    # Download each CVE list for the respective year
    $Output = "$Path\Output"
    $OutTemp = "$Path\CVEData"
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    Write-Host "Processing: NIST CVE Data"
    foreach ($Year in $CVEYears) {
        $ProgressPreference = 'SilentlyContinue'
        $filename = "$($Year).json.gz"
        $url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$($Year).json.gz"
        Invoke-RestMethod -Uri $url -OutFile "$OutTemp\$filename"
        Invoke-UnGz -infile "$OutTemp\$filename"
    }
    $CveData = New-Object System.Collections.Generic.List[CveData]
    $CveRef = New-Object System.Collections.Generic.List[CveRef]
    $CveCvss = New-Object System.Collections.Generic.List[Cvss]
    $cveobj = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
    foreach ($File in $cveobj) {
        Write-Verbose "Processing file: $($File.Name)"
        $Data = [System.IO.File]::ReadAllText("$OutTemp\$($File.name)") | ConvertFrom-Json
        $Data = $Data.CVE_Items
        foreach ($item in $Data) {
            $cveno = $Item.cve.CVE_data_meta.id
            $Vuln = [CveData]::new()
            $Vuln.RunTime = $Runtime
            $Vuln.CveVersion = $item.configurations.CVE_data_version
            $Vuln.PublishedDate = $item.publishedDate
            $Vuln.ModifiedDate = $item.lastModifiedDate
            $Vuln.CveId = $Item.cve.CVE_data_meta.id
            $Vuln.Assigner = $Item.cve.CVE_data_meta.ASSIGNER
            $Vuln.Description = ($item.cve.description.description_data | where { $_.lang -eq "en" }).value
            $CveData.Add($Vuln) | Out-Null
            foreach ($cref in $item.cve.references.reference_data) {
                $Ref = [CveRef]::new()
                $Ref.RunTime = $Runtime
                $Ref.CveId = $item.cve.CVE_data_meta.id
                $Ref.Source = $cref.refsource
                $Ref.Name = $cref.Name
                $Ref.Url = $cref.Url
                if ($cref.tags -contains "exploit") {
                    $Ref.IsExploit = $true
                }
                else {
                    $Ref.IsExploit = $false
                }
                $CveRef.Add($Ref) | Out-Null
            }
            foreach ($cves in $item.impact.baseMetricV3){
                $vs = [Cvss]::new()
                $vs.RunTime = $Runtime
                $vs.CveId = $cveno
                $vs.CvssVersion = $cves.cvssV3.version
                $vs.CvssScore = $cves.cvssV3.baseScore
                $vs.CvssSeverity = $cves.cvssV3.baseSeverity
                $vs.impactScore = $cves.impactScore
                $vs.exploitabilityScore = $cves.exploitabilityScore
                $vs.Vector = $cves.cvssV3.vectorString
                $vs.attackVector = $cves.cvssV3.attackVector
                $vs.attackComplexity = $cves.cvssV3.attackComplexity
                $vs.privilegesRequired = $cves.cvssV3.privilegesRequired
                $vs.userInteraction = $cves.cvssV3.userInteraction
                $vs.confidentialityImpact = $cves.cvssV3.confidentialityImpact
                $vs.integrityImpact = $cves.cvssV3.integrityImpact
                $vs.availabilityImpact = $cves.cvssV3.availabilityImpact
                $CveCvss.Add($vs) | Out-Null
            }
        }
    }
    $CveData | ConvertTo-Json | Out-File "$OutTemp\CveData.json"
    $CveRef | ConvertTo-Json | Out-File "$OutTemp\CveReferences.json"
    $CveCvss | ConvertTo-Json | Out-File "$OutTemp\CvssData.json"
    Invoke-Gz -infile "$OutTemp\CveData.json" -OutPath $Output
    Invoke-Gz -infile "$OutTemp\CveReferences.json" -OutPath $Output
    Invoke-Gz -infile "$OutTemp\CvssData.json" -OutPath $Output
    # Clean up 
    if ($Leo) {
        Write-Verbose "Leaving the API output, a child-like mess"
        # Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
    } else {
        Write-Verbose "Removing staging folder: $OutTemp"
        Remove-Item $OutTemp -Recurse -Force | Out-Null
    }
}
#EndRegion './Public/Get-CVEData.ps1' 114
#Region './Public/Get-MDAVInfo.ps1' 0
#using namespace System.Text.Json
function Get-MDAVInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateSet('api', 'bulk')]
        $ExportType,
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [switch] $Archive,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret,
        [switch] $Leo
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    } 

    $ArchivePath = "$Path\Archive"
    $OutTemp = "$Path\DeviceAVInfo"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Content = @()
    Write-Host "Processing: Defender AV Information"
    if ($ExportType -eq "api") {
        $completed = $null
        $url = "https://api.securitycenter.microsoft.com/api/deviceavinfo"
        while (-not $Completed) {
            Write-Verbose "Downloading device antivirus information"
            $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            $nextlink = ($data).'@odata.nextLink'
            foreach ($item in $data.value) {
                $Content += $item | ConvertTo-Json -Depth 10 -Compress
            }
            $url = $nextlink
            if ($null -eq $url) {
                $Completed = $true
            }
        }
        Write-Verbose "Saving output: $Output"
        $Content | Out-File "$OutTemp\DeviceAVInfo.json"
        Invoke-Gz -infile "$OutTemp\DeviceAVInfo.json" -OutPath $Output
        if ($Archive) {
            if (!(Test-Path($ArchivePath))) { 
                Try {
                    mkdir $ArchivePath -ErrorAction:Stop | Out-Null 
                }
                catch {
                    Write-Host "Cannot create output folder $($ArchivePath)"
                    break
                }
            }
            $Content | ConvertTo-Json | Out-File "$ArchivePath\$($rtid)_DeviceAVInfo.gz"
        }
    }
    elseif ($ExportType -eq "bulk") {
        $url = "https://api.securitycenter.microsoft.com/api/machines/InfoGatheringExport"
        Write-Verbose "Export Type: $exportType"
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        $data = $response.exportFiles
        $count = $data.count
        $c = 0
        $filearr = @()
        $urlcount = 0
        foreach ($file in $data) {
            $urlcount++
            $a = @{
                "Url"        = $file
                "FileNumber" = $urlcount
            }
            $filearr += New-Object PSObject -Property $a
        }
        Write-Verbose "Exporting blob URL data"
        $filearr | Export-Csv "$Output\DeviceAVDataURLs.csv" -NoTypeInformation -Force
        # Download exported software inventory data from Azure blob
        Write-Verbose "Remove existing gz files to prevent duplicate entries"
        Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | Remove-Item | Out-Null
        foreach ($dl in $filearr) {
            $c++
            $FileName = "DeviceAVInfo-$($dl.FileNumber)"
            Write-Verbose "Downloading file: $($dl.FileNumber)/$count"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            } 
            catch {
                $errordata = $_.ErrorDetails.Message
                $errormsg = $errordata.error.message
                $errorcode = $errordata.error.code
                $weberror = $errorcode
                Write-Verbose "Failed on: $($FileName) | File count: $c"
                Write-Verbose "Retrying file: $($FileName) | $c/$count"
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            }
        }
        # Extract each JSON
        $gzfiles = Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | sort Length -Descending
        $excount = 0
        foreach ($file in $gzfiles) {
            $excount++
            Write-Verbose "Extracting file: $excount/$count"
            Invoke-UnGz -infile "$OutTemp\$($File.Name)" -outfile "$OutTemp\$($File.BaseName).json"
        }

        $NewPath = "$OutTemp\DeviceAVInfo.json"
        if ((Test-Path($NewPath))) { 
            Try {
                Remove-Item $NewPath -Force
            }
            catch {
                Write-Host "Unable to remove existing file"
                break
            }
        }
        $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
        $sw = [System.IO.StreamWriter]::new($NewPath)
        foreach ($file in $jsonfiles) {
            $sr = New-Object System.IO.StreamReader("$($file.FullName)")
            while (($readeachline = $sr.ReadLine()) -ne $null) {
                $sw.WriteLine("$readeachline")
                $eachlinenumber++
            }
            $sr.Dispose()
        }
        $sw.close()

        Invoke-Gz -infile $NewPath -OutPath $Output

        if ($Leo) {
            Write-Verbose "Leaving the API output, a child-like mess"
        } else {
            Write-Verbose "Removing staging folder: $OutTemp"
            Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
        }
    }
}
#EndRegion './Public/Get-MDAVInfo.ps1' 162
#Region './Public/Get-MDDevices.ps1' 0
function Get-MDDevices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    }  
    
    Write-Host "Processing: Device Information"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Devices = New-Object System.Collections.Generic.List[Devices]
    $completed = $null
    $url = "https://api.securitycenter.microsoft.com/api/machines"
    while (-not $Completed) {
        Write-Verbose "Downloading machine information"
        $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $nextlink = ($data).'@odata.nextLink'
        foreach ($item in $data.value) {
            $dev = [Devices]::new()
            $dev.RunTime = $Runtime
            $dev.TenantId = $tenantId
            $dev.DeviceId = $item.id
            $dev.DeviceName = $item.computerDnsName
            $dev.healthStatus = $item.healthStatus
            $dev.defenderAvStatus = $item.defenderAvStatus
            $dev.onboardingStatus = $item.onboardingStatus
            $newfsd = $item.firstSeen | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $newlsd = $item.lastSeen | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $dev.FirstSeenTimestamp = $newfsd
            $dev.LastSeenTimestamp = $newlsd
            $dev.osPlatform = $item.osPlatform
            $dev.osProcessor = $item.osProcessor
            $dev.osBuild = $item.osBuild
            $dev.RbacGroupName = $item.RbacGroupName
            $dev.RbacGroupId = $item.RbacGroupId
            $dev.Version = $item.version
            $dev.exposureScore = $item.riskScore
            $dev.exposureLevel = $item.exposureLevel
            $dev.deviceValue = $item.deviceValue
            $dev.managedBy = $item.managedBy
            $dev.machineTags = $item.machineTags
            $dev.lastIpAddress = $item.lastIpAddress
            $dev.lastExternalIpAddress = $item.lastExternalIpAddress
            $Devices.Add($dev) | Out-Null
        }
        $url = $nextlink
        if ($null -eq $url) {
            $Completed = $true
            Write-Verbose "Saving output:"
            $Devices | Export-csv "$Output\Devices.csv" -NoTypeInformation -Force
        }
    }
}
#EndRegion './Public/Get-MDDevices.ps1' 74
#Region './Public/Get-MDSecurityBaselines.ps1' 0
#using namespace System.Text.Json
function Get-MDSecurityBaselines {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateSet('api', 'bulk')]
        $ExportType,
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [switch] $Archive,
        [switch] $ParseData,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret,
        [switch] $Leo
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    } 

    $ArchivePath = "$Path\Archive"
    $OutTemp = "$Path\SecurityBaselines"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Content = @()
    Write-Host "Processing: Security Baselines"
    if ($ExportType -eq "api") {
        $completed = $null
        $url = "https://api.securitycenter.microsoft.com/api/machines/BaselineComplianceAssessmentByMachine"
        while (-not $Completed) {
            Write-Verbose "Downloading security baselines information"
            $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            $nextlink = ($data).'@odata.nextLink'
            foreach ($item in $data.value) {
                $Content += $item | ConvertTo-Json -Depth 10 -Compress
            }
            $url = $nextlink
            if ($null -eq $url) {
                $Completed = $true
            }
        }
        Write-Verbose "Saving output: $Output"
        $Content | Out-File "$OutTemp\SecurityBaselines.json"
        Invoke-Gz -infile "$OutTemp\SecurityBaselines.json" -OutPath $Output
        if ($Archive) {
            if (!(Test-Path($ArchivePath))) { 
                Try {
                    mkdir $ArchivePath -ErrorAction:Stop | Out-Null 
                }
                catch {
                    Write-Host "Cannot create output folder $($ArchivePath)"
                    break
                }
            }
            $Content | ConvertTo-Json | Out-File "$ArchivePath\$($rtid)_SecurityBaselines.gz"
        }
    }
    elseif ($ExportType -eq "bulk") {
        $url = "https://api.securitycenter.microsoft.com/api/machines/BaselineComplianceAssessmentExport"
        Write-Verbose "Export Type: $exportType"
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        $data = $response.exportFiles
        $count = $data.count
        $c = 0
        $filearr = @()
        $urlcount = 0
        foreach ($file in $data) {
            $urlcount++
            $a = @{
                "Url"        = $file
                "FileNumber" = $urlcount
            }
            $filearr += New-Object PSObject -Property $a
        }
        Write-Verbose "Exporting blob URL data"
        $filearr | Export-Csv "$Output\SecurityBaselinesDataURLs.csv" -NoTypeInformation -Force
        # Download exported software inventory data from Azure blob
        Write-Verbose "Remove existing gz files to prevent duplicate entries"
        Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | Remove-Item | Out-Null
        foreach ($dl in $filearr) {
            $c++
            $FileName = "SecurityBaselines-$($dl.FileNumber)"
            Write-Verbose "Downloading file: $($dl.FileNumber)/$count"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            } 
            catch {
                $errordata = $_.ErrorDetails.Message
                $errormsg = $errordata.error.message
                $errorcode = $errordata.error.code
                $weberror = $errorcode
                Write-Verbose "Failed on: $($FileName) | File count: $c"
                Write-Verbose "Retrying file: $($FileName) | $c/$count"
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            }
        }
        # Extract each JSON
        $gzfiles = Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | sort Length -Descending
        $excount = 0
        foreach ($file in $gzfiles) {
            $excount++
            Write-Verbose "Extracting file: $excount/$count"
            Invoke-UnGz -infile "$OutTemp\$($File.Name)" -outfile "$OutTemp\$($File.BaseName).json"
        }
        # $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending

        $NewPath = "$OutTemp\SecurityBaselines.json"
        if ((Test-Path($NewPath))) { 
            Try {
                Remove-Item $NewPath -Force
            }
            catch {
                Write-Host "Unable to remove existing file"
                break
            }
        }
        $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
        $sw = [System.IO.StreamWriter]::new($NewPath)
        foreach ($file in $jsonfiles) {
            $sr = New-Object System.IO.StreamReader("$($file.FullName)")
            while (($readeachline = $sr.ReadLine()) -ne $null) {
                $sw.WriteLine("$readeachline")
                $eachlinenumber++
            }
            $sr.Dispose()
        }
        $sw.close()

        Invoke-Gz -infile $NewPath -OutPath $Output

        if ($Leo) {
            Write-Verbose "Leaving the API output, a child-like mess"
        } else {
            Write-Verbose "Removing staging folder: $OutTemp"
            Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
        }
    }
}
#EndRegion './Public/Get-MDSecurityBaselines.ps1' 164
#Region './Public/Get-MDSecurityConfig.ps1' 0
#using namespace System.Text.Json
function Get-MDSecurityConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateSet('api', 'bulk')]
        $ExportType,
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [switch] $Archive,
        [switch] $ParseData,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret,
        [switch] $Leo
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    } 

    $ArchivePath = "$Path\Archive"
    $OutTemp = "$Path\SecurityConfig"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Content = @()
    Write-Host "Processing: Security Configuration"
    if ($ExportType -eq "api") {
        $completed = $null
        $url = "https://api.securitycenter.microsoft.com/api/machines/SecureConfigurationsAssessmentByMachine"
        while (-not $Completed) {
            Write-Verbose "Downloading security config information"
            $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            $nextlink = ($data).'@odata.nextLink'
            foreach ($item in $data.value) {
                $Content += $item | ConvertTo-Json -Depth 10 -Compress
            }
            $url = $nextlink
            if ($null -eq $url) {
                $Completed = $true
            }
        }
        Write-Verbose "Saving output: $Output"
        $Content | Out-File "$OutTemp\SecurityConfig.json"
        Invoke-Gz -infile "$OutTemp\SecurityConfig.json" -OutPath $Output
        if ($Archive) {
            if (!(Test-Path($ArchivePath))) { 
                Try {
                    mkdir $ArchivePath -ErrorAction:Stop | Out-Null 
                }
                catch {
                    Write-Host "Cannot create output folder $($ArchivePath)"
                    break
                }
            }
            $Content | ConvertTo-Json | Out-File "$ArchivePath\$($rtid)_SecurityConfig.gz"
        }
    }
    elseif ($ExportType -eq "bulk") {
        $url = "https://api.securitycenter.microsoft.com/api/machines/SecureConfigurationsAssessmentExport"
        Write-Verbose "Export Type: $exportType"
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        $data = $response.exportFiles
        $count = $data.count
        $c = 0
        $filearr = @()
        $urlcount = 0
        foreach ($file in $data) {
            $urlcount++
            $a = @{
                "Url"        = $file
                "FileNumber" = $urlcount
            }
            $filearr += New-Object PSObject -Property $a
        }
        Write-Verbose "Exporting blob URL data"
        $filearr | Export-Csv "$Output\SecDataURLs.csv" -NoTypeInformation -Force
        # Download exported software inventory data from Azure blob
        Write-Verbose "Remove existing gz files to prevent duplicate entries"
        Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | Remove-Item | Out-Null
        foreach ($dl in $filearr) {
            $c++
            $FileName = "SecurityConfig-$($dl.FileNumber)"
            Write-Verbose "Downloading file: $($dl.FileNumber)/$count"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            } 
            catch {
                $errordata = $_.ErrorDetails.Message
                $errormsg = $errordata.error.message
                $errorcode = $errordata.error.code
                $weberror = $errorcode
                Write-Verbose "Failed on: $($FileName) | File count: $c"
                Write-Verbose "Retrying file: $($FileName) | $c/$count"
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            }
        }
        # Extract each JSON
        $gzfiles = Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | sort Length -Descending
        $excount = 0
        foreach ($file in $gzfiles) {
            $excount++
            Write-Verbose "Extracting file: $excount/$count"
            Invoke-UnGz -infile "$OutTemp\$($File.Name)" -outfile "$OutTemp\$($File.BaseName).json"
        }
        # $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending

        $NewPath = "$OutTemp\SecurityConfig.json"
        if ((Test-Path($NewPath))) { 
            Try {
                Remove-Item $NewPath -Force
            }
            catch {
                Write-Host "Unable to remove existing file"
                break
            }
        }
        $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
        $sw = [System.IO.StreamWriter]::new($NewPath)
        foreach ($file in $jsonfiles) {
            $sr = New-Object System.IO.StreamReader("$($file.FullName)")
            while (($readeachline = $sr.ReadLine()) -ne $null) {
                $sw.WriteLine("$readeachline")
                $eachlinenumber++
            }
            $sr.Dispose()
        }
        $sw.close()

        Invoke-Gz -infile $NewPath -OutPath $Output

        if ($Leo) {
            Write-Verbose "Leaving the API output, a child-like mess"
        } else {
            Write-Verbose "Removing staging folder: $OutTemp"
            Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
        }

        # if ($ParseData) {
        #     # Parse vulnerability data
        #     $jsonfiles = Get-ChildItem $Output -Include ('*.json') -Recurse | sort Length -Descending
        #     $c = 0
        #     foreach ($file in $jsonfiles) {
        #         $Content = New-Object System.Collections.Generic.List[VulnData]
        #         $c++
        #         Write-Host "Processing file: $($file.Name) | Count $c"
        #         $StreamReader = [System.IO.StreamReader]::new("$Output\$($file.Name)")
        #         While (-not $StreamReader.EndOfStream ) { 
        #             $Line = $StreamReader.ReadLine()
        #             $Content.add([JsonSerializer]::Deserialize($Line, [VulnData]))
        #         }
        #         $StreamReader.Close()
        #         # foreach ($v in $Content) {
        #         #     $v.RunTime = $Runtime
        #         #     $v.TenantId = $tenantId
        #         # }
        #         # $Content | ConvertTo-Json | Out-File "$Output\Vulnerabilities-$c.json"
        #     }
        #     # Set tenantId and RunTime values
        #     Write-Verbose "Deleting processed JSON files"
        #     Get-ChildItem $Output -Include ('*.json') -Recurse | Remove-Item | Out-Null
        # }
    }
}
#EndRegion './Public/Get-MDSecurityConfig.ps1' 189
#Region './Public/Get-MDSoftwareInventory.ps1' 0
#using namespace System.Text.Json
function Get-MDSoftwareInventory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateSet('api', 'bulk')]
        $ExportType,
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [switch] $Archive,
        [switch] $ParseData,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret,
        [switch] $Leo
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    } 

    $ArchivePath = "$Path\Archive"
    $OutTemp = "$Path\SoftwareInventory"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Content = @()
    Write-Host "Processing: Software Inventory"
    if ($ExportType -eq "api") {
        $completed = $null
        $url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareInventoryByMachine"
        while (-not $Completed) {
            Write-Verbose "Downloading software inventory information"
            $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            $nextlink = ($data).'@odata.nextLink'
            foreach ($item in $data.value) {
                $Content += $item | ConvertTo-Json -Depth 10 -Compress
            }
            $url = $nextlink
            if ($null -eq $url) {
                $Completed = $true
            }
        }
        Write-Verbose "Saving output: $Output"
        $Content | Out-File "$OutTemp\SoftwareInventory.json"
        Invoke-Gz -infile "$OutTemp\SoftwareInventory.json" -OutPath $Output
        if ($Archive) {
            if (!(Test-Path($ArchivePath))) { 
                Try {
                    mkdir $ArchivePath -ErrorAction:Stop | Out-Null 
                }
                catch {
                    Write-Host "Cannot create output folder $($ArchivePath)"
                    break
                }
            }
            $Content | ConvertTo-Json | Out-File "$ArchivePath\$($rtid)_SoftwareInventory.gz"
        }
    }
    elseif ($ExportType -eq "bulk") {
        $url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareInventoryExport"
        Write-Verbose "Export Type: $exportType"
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        $data = $response.exportFiles
        $count = $data.count
        $c = 0
        $filearr = @()
        $urlcount = 0
        foreach ($file in $data) {
            $urlcount++
            $a = @{
                "Url"        = $file
                "FileNumber" = $urlcount
            }
            $filearr += New-Object PSObject -Property $a
        }
        Write-Verbose "Exporting blob URL data"
        $filearr | Export-Csv "$Output\SoftwareDataURLs.csv" -NoTypeInformation -Force
        # Download exported software inventory data from Azure blob
        Write-Verbose "Remove existing gz files to prevent duplicate entries"
        Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | Remove-Item | Out-Null
        foreach ($dl in $filearr) {
            $c++
            $FileName = "SoftwareExport-$($dl.FileNumber)"
            Write-Verbose "Downloading file: $($dl.FileNumber)/$count"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            } 
            catch {
                $errordata = $_.ErrorDetails.Message
                $errormsg = $errordata.error.message
                $errorcode = $errordata.error.code
                $weberror = $errorcode
                Write-Verbose "Failed on: $($FileName) | File count: $c"
                Write-Verbose "Retrying file: $($FileName) | $c/$count"
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            }
        }
        # Extract each JSON
        $gzfiles = Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | sort Length -Descending
        $excount = 0
        foreach ($file in $gzfiles) {
            $excount++
            Write-Verbose "Extracting file: $excount/$count"
            Invoke-UnGz -infile "$OutTemp\$($File.Name)" -outfile "$OutTemp\$($File.BaseName).json"
        }

        $NewPath = "$OutTemp\SoftwareInventory.json"
        if ((Test-Path($NewPath))) { 
            Try {
                Remove-Item $NewPath -Force
            }
            catch {
                Write-Host "Unable to remove existing file"
                break
            }
        }
        $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
        $sw = [System.IO.StreamWriter]::new($NewPath)
        foreach ($file in $jsonfiles) {
            $sr = New-Object System.IO.StreamReader("$($file.FullName)")
            while (($readeachline = $sr.ReadLine()) -ne $null) {
                $sw.WriteLine("$readeachline")
                $eachlinenumber++
            }
            $sr.Dispose()
        }
        $sw.close()

        Invoke-Gz -infile $NewPath -OutPath $Output

        if ($Leo) {
            Write-Verbose "Leaving the API output, a child-like mess"
        } else {
            Write-Verbose "Removing staging folder: $OutTemp"
            Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
        }
    }
}
#EndRegion './Public/Get-MDSoftwareInventory.ps1' 163
#Region './Public/Get-MDVulnerabilities.ps1' 0
#using namespace System.Text.Json
function Get-MDVulnerabilities {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [ValidateSet('api', 'bulk')]
        $ExportType,
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [switch] $Archive,
        [switch] $ParseData,
        [string] $TenantId,
        [string] $AppId,
        [string] $AppSecret,
        [switch] $Leo
    )

    $token = Get-AccessToken -TenantId $tenantId -AppId $AppId -appSecret $appSecret
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    } 

    $ArchivePath = "$Path\Archive"
    $OutTemp = "$Path\Vulnerabilities"
    $Output = "$Path\Output"
    $Runtime = Get-Date -Format "yyyy-MM-dd HH:mm:ss" -AsUTC
    $Rtid = Get-Date -Format "yyyyMMdd_HHmmss" -AsUTC
    if (!(Test-Path($OutTemp))) { 
        Try {
            mkdir $OutTemp -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($OutTemp)"
            break
        }
    }
    if (!(Test-Path($Output))) { 
        Try {
            mkdir $Output -ErrorAction:Stop | Out-Null 
        }
        catch {
            Write-Host "Cannot create output folder $($Output)"
            break
        }
    }
    $Content = @()
    Write-Host "Processing: Device Vulnerabilities"
    if ($ExportType -eq "api") {
        $completed = $null
        $url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine"
        while (-not $Completed) {
            Write-Verbose "Downloading vulnerability information"
            $data = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
            $nextlink = ($data).'@odata.nextLink'
            foreach ($item in $data.value) {
                $Content += $item | ConvertTo-Json -Depth 10 -Compress
            }
            $url = $nextlink
            if ($null -eq $url) {
                $Completed = $true
            }
        }
        Write-Verbose "Saving output: $Output"
        $Content | Out-File "$OutTemp\Vulnerabilities.json"
        Invoke-Gz -infile "$OutTemp\Vulnerabilities.json" -OutPath $Output
        if ($Archive) {
            if (!(Test-Path($ArchivePath))) { 
                Try {
                    mkdir $ArchivePath -ErrorAction:Stop | Out-Null 
                }
                catch {
                    Write-Host "Cannot create output folder $($ArchivePath)"
                    break
                }
            }
            $Content | ConvertTo-Json | Out-File "$ArchivePath\$($rtid)_Vulnerabilities.gz"
        }
    }
    elseif ($ExportType -eq "bulk") {
        $url = "https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport"
        Write-Verbose "Export Type: $exportType"
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        $data = $response.exportFiles
        $count = $data.count
        $c = 0
        $filearr = @()
        $urlcount = 0
        foreach ($file in $data) {
            $urlcount++
            $a = @{
                "Url"        = $file
                "FileNumber" = $urlcount
            }
            $filearr += New-Object PSObject -Property $a
        }
        Write-Verbose "Exporting blob URL data"
        $filearr | Export-Csv "$Output\VulnDataURLs.csv" -NoTypeInformation -Force
        # Download exported vulnerability data from Azure blob
        Write-Verbose "Remove existing gz files to prevent duplicate entries"
        Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | Remove-Item | Out-Null
        foreach ($dl in $filearr) {
            $c++
            $FileName = "VulnExport-$($dl.FileNumber)"
            Write-Verbose "Downloading file: $($dl.FileNumber)/$count"
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            } 
            catch {
                $errordata = $_.ErrorDetails.Message
                $errormsg = $errordata.error.message
                $errorcode = $errordata.error.code
                $weberror = $errorcode
                Write-Verbose "Failed on: $($FileName) | File count: $c"
                Write-Verbose "Retrying file: $($FileName) | $c/$count"
                Invoke-RestMethod -Method Get -Uri $dl.Url -OutFile "$OutTemp\$FileName.gz"
            }
        }
        # Extract each JSON
        $gzfiles = Get-ChildItem $OutTemp -Include ('*.gz') -Recurse | sort Length -Descending
        $excount = 0
        foreach ($file in $gzfiles) {
            $excount++
            Write-Verbose "Extracting file: $excount/$count"
            Invoke-UnGz -infile "$OutTemp\$($File.Name)" -outfile "$OutTemp\$($File.BaseName).json"
        }
        # $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending

        $NewPath = "$OutTemp\Vulnerabilities.json"
        if ((Test-Path($NewPath))) { 
            Try {
                Remove-Item $NewPath -Force
            }
            catch {
                Write-Host "Unable to remove existing file"
                break
            }
        }
        
        $jsonfiles = Get-ChildItem $OutTemp -Include ('*.json') -Recurse | sort Length -Descending
        $sw = [System.IO.StreamWriter]::new($NewPath)
        foreach ($file in $jsonfiles) {
            $sr = New-Object System.IO.StreamReader("$($file.FullName)")
            while (($readeachline = $sr.ReadLine()) -ne $null) {
                $sw.WriteLine("$readeachline")
                $eachlinenumber++
            }
            $sr.Dispose()
        }
        $sw.close()

        Invoke-Gz -infile $NewPath -OutPath $Output

        if ($Leo) {
            Write-Verbose "Leaving the API output, a child-like mess"
        } else {
            Write-Verbose "Removing staging folder: $OutTemp"
            Get-ChildItem $OutTemp -Include ('*.json') -Recurse | Remove-Item | Out-Null
        }

        # if ($ParseData) {
        #     # Parse vulnerability data
        #     $jsonfiles = Get-ChildItem $Output -Include ('*.json') -Recurse | sort Length -Descending
        #     $c = 0
        #     foreach ($file in $jsonfiles) {
        #         $Content = New-Object System.Collections.Generic.List[VulnData]
        #         $c++
        #         Write-Host "Processing file: $($file.Name) | Count $c"
        #         $StreamReader = [System.IO.StreamReader]::new("$Output\$($file.Name)")
        #         While (-not $StreamReader.EndOfStream ) { 
        #             $Line = $StreamReader.ReadLine()
        #             $Content.add([JsonSerializer]::Deserialize($Line, [VulnData]))
        #         }
        #         $StreamReader.Close()
        #         # foreach ($v in $Content) {
        #         #     $v.RunTime = $Runtime
        #         #     $v.TenantId = $tenantId
        #         # }
        #         # $Content | ConvertTo-Json | Out-File "$Output\Vulnerabilities-$c.json"
        #     }
        #     # Set tenantId and RunTime values
        #     Write-Verbose "Deleting processed JSON files"
        #     Get-ChildItem $Output -Include ('*.json') -Recurse | Remove-Item | Out-Null
        # }
    }
}
#EndRegion './Public/Get-MDVulnerabilities.ps1' 190
#Region './Public/Invoke-DataUpload.ps1' 0
function Invoke-DataUpload {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$StorageAccount,
        [string]$StorageKey,
        [string]$StorageContainer
    )

    Import-Module Az.Storage
    $Output = "$Path\Output"
    if (!(Test-Path($Output))) { 
        Write-Host "Path does not exist."
        break
    }

    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccount -StorageAccountKey $storagekey

    $Files = Get-ChildItem $Output -Recurse
    Write-Host "Processing: Uploading content to storage container"
    $Files | ForEach-Object -Parallel {
        $container = $using:storagecontainer
        $context = $using:storageContext
        Set-AzStorageBlobContent -File $_.FullName -Blob "$($_.name)" -Container $container -BlobType "Block" -Context $context -Force | Out-Null
    } -ThrottleLimit 10
}
#EndRegion './Public/Invoke-DataUpload.ps1' 27
#Region './Public/Invoke-Gz.ps1' 0
function Invoke-Gz {
    param(
        [Parameter(Mandatory = $true)]
        [string] $infile,
        [Parameter(Mandatory = $true)]
        [string] $OutPath
    )
    if (!(Test-Path("$infile"))) { 
        Write-Host "Input file not found. Please use the full path."
        break
    }
    $srcFile = Get-Item -Path $infile
    $newFile = "$OutPath\$($srcFile.BaseName).gz"
 
    try {
        $srcFileStream = New-Object System.IO.FileStream($srcFile.FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read))
        $dstFileStream = New-Object System.IO.FileStream($newFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None))
        $gzip = New-Object System.IO.Compression.GZipStream($dstFileStream, [System.IO.Compression.CompressionMode]::Compress)
        $srcFileStream.CopyTo($gzip)
    } 
    catch {
        Write-Host "$_.Exception.Message" -ForegroundColor Red
    }
    finally {
        $gzip.Dispose()
        $srcFileStream.Dispose()
        $dstFileStream.Dispose()
    }
}
#EndRegion './Public/Invoke-Gz.ps1' 30
#Region './Public/Invoke-UnGz.ps1' 0
function Invoke-UnGz {
    Param(
        $infile,
        $outfile = ($infile -replace '\.gz$', '')
    )
    if (!(Test-Path("$infile"))) { 
        Write-Host "Input file not found. Please use the full path."
        break
    }
    $readfile = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gzipStream = New-Object System.IO.Compression.GzipStream $readfile, ([IO.Compression.CompressionMode]::Decompress)
    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0) { break }
        $output.Write($buffer, 0, $read)
    }
    $gzipStream.Close()
    $output.Close()
    $readfile.Close()
}
#EndRegion './Public/Invoke-UnGz.ps1' 23

