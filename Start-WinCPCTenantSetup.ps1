#Requires -Version 5.1
<#
.SYNOPSIS
    WinCPC Tenant Setup — Core Module
.DESCRIPTION
    Assessment and remediation functions for tenant readiness.
    Provides a WPF dashboard GUI for non-technical users.
.NOTES
    Author: Shannon Fritz
    Version: 0.1.0
    Based on: Andrew Willows' W365Link-Deployment-Readiness checks
              Shannon Fritz's CloudPC-Replace patterns
#>

# ============================================================================
# REGION: Module State
# ============================================================================
$script:ToolVersion = "1.0.0"
$script:GraphConnected = $false
$script:TenantInfo = @{}
$script:CheckResults = [System.Collections.ArrayList]::new()
$script:IgnoredChecks = [System.Collections.Generic.HashSet[string]]::new()

# Policy cache — populated once per assessment run, cleared on Run Assessment
$script:ConfigPolicyCache = $null      # Settings Catalog policies with their settings
$script:DeviceConfigCache = $null      # Device configuration profiles (custom OMA-URI etc)

# Logging callback — set by the GUI function, used by module-level functions
$script:WriteLog = $null
function Write-ModuleLog {
    param([string]$Message, [string]$Tag = "INFO")
    if ($script:WriteLog) { & $script:WriteLog $Message $Tag }
}

# Well-known App IDs for Conditional Access
$script:W365AppId  = "0af06dc6-e4b5-4f28-818e-e78e62d137a5"  # Windows 365
$script:AVDAppId   = "9cdead84-a844-4324-93f2-b2e6bb768d07"  # Azure Virtual Desktop
$script:WCLAppId   = "270efc09-cd0d-444b-a71f-39af4910ec45"  # Windows Cloud Login

# License SKU part name patterns
$script:W365SkuParts = @("CPC_E_","CPC_B_","CPC_F_","WIN365","Windows_365_")  # Windows_365_ covers FedRAMP/Gov SKUs
$script:IntuneSkuParts = @(
    "INTUNE_A","Intune_EDU","INTUNE_SMB","Microsoft_Intune_Suite",
    "SPE_E3","SPE_E5","Microsoft_365_E5","Microsoft_365_E3","SPB",
    "Microsoft_365_Business_Premium","EMSPREMIUM","Microsoft_365_A3",
    "Microsoft_365_A5","SPE_A3","SPE_A5","Microsoft_365_G3",
    "Microsoft_365_G5","SPE_G3","SPE_G5",
    "M365EDU_","M365GOV_"  # EDU (M365EDU_A3/A5_FACULTY/STUDENT) and Gov tenants
)
$script:EntraPremiumSkuParts = @(
    "AAD_PREMIUM","EMSPREMIUM","SPE_E3","SPE_E5","Microsoft_365_E5",
    "Microsoft_365_E3","SPB","Microsoft_365_Business_Premium","EMS",
    "Microsoft_365_A3","Microsoft_365_A5","SPE_A3","SPE_A5",
    "Microsoft_365_G3","Microsoft_365_G5","SPE_G3","SPE_G5",
    "M365EDU_","M365GOV_"  # EDU (M365EDU_A3/A5_FACULTY/STUDENT) and Gov tenants
)

# ============================================================================
# REGION: Graph Helpers
# ============================================================================
function Test-GraphModule {
    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
        return $false
    }
    return $true
}

function Install-GraphModule {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}

function Connect-W365Graph {
    $readScopes = @(
        "DeviceManagementServiceConfig.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "Policy.Read.All",
        "Directory.Read.All",
        "CloudPC.Read.All"
    )
    $writeScopes = @(
        "DeviceManagementServiceConfig.ReadWrite.All",
        "DeviceManagementConfiguration.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "Policy.ReadWrite.DeviceConfiguration",
        "Policy.ReadWrite.MobilityManagement",
        "Policy.ReadWrite.AuthenticationMethod",
        "Directory.ReadWrite.All"
    )
    $allScopes = $readScopes + $writeScopes

    $context = Get-MgContext
    if ($null -eq $context) {
        Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
    } else {
        $missingScopes = $allScopes | Where-Object { $context.Scopes -notcontains $_ }
        if ($missingScopes.Count -gt 0) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Connect-MgGraph -Scopes $allScopes -NoWelcome -ErrorAction Stop
            $context = Get-MgContext
        }
    }

    $script:TenantInfo["Account"]  = $context.Account
    $script:TenantInfo["TenantId"] = $context.TenantId

    # Get tenant display name
    $org = Invoke-GraphSafe -Uri "/organization"
    if (-not $org._error -and $org.value) {
        $script:TenantInfo["TenantName"] = $org.value[0].displayName
    }

    $script:GraphConnected = $true
    return $context
}

function Invoke-GraphSafe {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [string]$ApiVersion = "beta",
        [object]$Body = $null
    )
    try {
        $fullUri = "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))"
        $params = @{
            Method      = $Method
            Uri         = $fullUri
            OutputType  = "PSObject"
            ErrorAction = "Stop"
        }
        if ($Body) {
            $params["Body"]        = ($Body | ConvertTo-Json -Depth 10)
            $params["ContentType"] = "application/json"
        }
        $response = Invoke-MgGraphRequest @params

        # Handle pagination for GET requests with collections
        if ($Method -eq "GET" -and $response.value -and $response.'@odata.nextLink') {
            $allValues = [System.Collections.ArrayList]::new($response.value)
            $nextLink = $response.'@odata.nextLink'
            while ($nextLink) {
                $nextResponse = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
                if ($nextResponse.value) {
                    $allValues.AddRange($nextResponse.value)
                }
                $nextLink = $nextResponse.'@odata.nextLink'
            }
            $response.value = $allValues
            $response.PSObject.Properties.Remove('@odata.nextLink')
        }

        return $response
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if (-not $statusCode -and $_.Exception.PSObject.Properties['StatusCode']) {
            try { $statusCode = [int]$_.Exception.StatusCode } catch {}
        }
        if (-not $statusCode) {
            $msg = $_.Exception.Message
            if     ($msg -match 'NotFound')     { $statusCode = 404 }
            elseif ($msg -match 'Forbidden')    { $statusCode = 403 }
            elseif ($msg -match 'Unauthorized') { $statusCode = 401 }
        }
        return [PSCustomObject]@{ "_error" = $_.Exception.Message; "_statusCode" = $statusCode }
    }
}

# ============================================================================
# REGION: Policy Cache Helpers
# ============================================================================
function Get-CachedConfigPolicies {
    if ($null -ne $script:ConfigPolicyCache) {
        Write-ModuleLog "Using cached Settings Catalog policies ($($script:ConfigPolicyCache.Count) policies)" "INFO"
        return $script:ConfigPolicyCache
    }

    Write-ModuleLog "Fetching Settings Catalog policies from Graph..." "INFO"
    $result = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies?`$filter=platforms eq 'windows10'"
    if ($result._error) {
        $result = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies"
    }
    if ($result._error) { return @{ _error = $result._error } }

    $policies = @(if ($result.value) { $result.value } else { @() })

    Write-ModuleLog "Found $($policies.Count) Settings Catalog policies, fetching settings..." "INFO"
    foreach ($pol in $policies) {
        $settingsResp = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies/$($pol.id)/settings"
        $pol | Add-Member -NotePropertyName '_settings' -NotePropertyValue @() -Force
        if (-not $settingsResp._error -and $settingsResp.value) {
            $pol._settings = @($settingsResp.value)
        }
    }

    $script:ConfigPolicyCache = $policies
    Write-ModuleLog "Cached $($policies.Count) Settings Catalog policies" "OK"
    return $policies
}

function Get-CachedDeviceConfigs {
    if ($null -ne $script:DeviceConfigCache) {
        Write-ModuleLog "Using cached device configurations ($($script:DeviceConfigCache.Count) profiles)" "INFO"
        return $script:DeviceConfigCache
    }

    Write-ModuleLog "Fetching device configurations from Graph..." "INFO"
    $result = Invoke-GraphSafe -Uri "/deviceManagement/deviceConfigurations"
    if ($result._error) { return @{ _error = $result._error } }

    $script:DeviceConfigCache = @(if ($result.value) { $result.value } else { @() })
    return $script:DeviceConfigCache
}

function Clear-PolicyCache {
    $script:ConfigPolicyCache = $null
    $script:DeviceConfigCache = $null
    Write-ModuleLog "Policy cache cleared" "INFO"
}

# ============================================================================
# REGION: Check Result Helper
# ============================================================================
function Add-CheckResult {
    param(
        [string]$Category,
        [string]$CheckName,
        [ValidateSet("Pass","Warning","Fail","Info","Error")]
        [string]$Status,
        [string]$Detail,
        [string]$Remediation = "",
        [string]$LearnMoreUrl = "",
        [string]$PortalUrl = "",
        [string]$Criteria = "",
        [string]$RiskLevel = "",
        [bool]$CanFix = $false,
        [string]$FixAction = ""
    )
    $null = $script:CheckResults.Add([PSCustomObject]@{
        Category     = $Category
        CheckName    = $CheckName
        Status       = $Status
        Detail       = $Detail
        Remediation  = $Remediation
        LearnMoreUrl = $LearnMoreUrl
        PortalUrl    = $PortalUrl
        Criteria     = $Criteria
        RiskLevel    = $RiskLevel
        CanFix       = $CanFix
        FixAction    = $FixAction
    })
}

function Get-ScoreColor {
    param([int]$Score)
    if ($Score -ge 90) { "#107c10" }
    elseif ($Score -ge 60) { "#0078d4" }
    elseif ($Score -ge 30) { "#e87400" }
    else { "#d13438" }
}

function Test-PolicyAssigned {
    param([string]$Uri)
    $assignments = Invoke-GraphSafe -Uri $Uri
    if ($assignments._error) { return $false }
    $list = @(if ($assignments.value) { $assignments.value } else { @() })
    return ($list.Count -gt 0)
}

function Get-OrCreateWCPCFilter {
    # Returns the filter ID, or throws if user cancels
    $filters = Invoke-GraphSafe -Uri "/deviceManagement/assignmentFilters"
    $filterId = $null

    if (-not $filters._error) {
        $filterList = if ($filters.value) { $filters.value } else { @() }
        $linkFilter = $filterList | Where-Object {
            $_.rule -like "*WCPC*" -or $_.displayName -like "*CPC*" -or $_.displayName -like "*Link*"
        } | Select-Object -First 1
        if ($linkFilter) { return $linkFilter.id }
    }

    $msg = "This fix requires a WCPC Intune filter to scope the policy to Windows CPC Devices only.`n`nNo WCPC filter was found. Create one now?"
    $result = Show-FixDialog -Title "Prerequisite: Intune Filter" -Icon "Warning" -Message $msg -Buttons @(
        @{ Label="Create Filter"; Value="create"; Style="Primary" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    if ($result -eq "create") {
        $body = @{
            displayName = "Windows CPC Devices"
            description = "Targets Windows CPC Devices using operatingSystemSKU = WCPC"
            platform    = "windows10AndLater"
            rule        = '(device.operatingSystemSKU -eq "WCPC")'
        }
        $filterResult = Invoke-GraphSafe -Uri "/deviceManagement/assignmentFilters" -Method "POST" -Body $body
        if ($filterResult._error) { throw "Failed to create Intune filter: $($filterResult._error)" }
        Write-ModuleLog "Created Intune filter 'Windows CPC Devices' ($($filterResult.id))" "OK"
        return $filterResult.id
    }

    throw "Cancelled by user."
}

# ============================================================================
# REGION: Assessment Checks
# ============================================================================

# --- CHECK 1: Licensing ---
function Test-W365Licensing {
    $category = "Licensing"
    $skuResponse = Invoke-GraphSafe -Uri "/subscribedSkus"

    if ($skuResponse._error) {
        Add-CheckResult -Category $category -CheckName "Retrieve tenant licenses" `
            -Status "Error" -Detail "Could not query licenses: $($skuResponse._error)" `
            -Criteria "ERROR: Could not query Graph API for license data" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Critical"
        return
    }

    $skus = if ($skuResponse.value) { $skuResponse.value } else { @($skuResponse) | Where-Object { $_.skuPartNumber } }

    # Windows 365
    $w365Skus = $skus | Where-Object {
        $sku = $_.skuPartNumber
        ($script:W365SkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($w365Skus) {
        $skuNames = ($w365Skus | ForEach-Object { "$($_.skuPartNumber) ($($_.consumedUnits)/$($_.prepaidUnits.enabled))" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Windows 365 license" `
            -Status "Pass" -Detail "Found: $skuNames" `
            -Criteria "PASS: W365 license SKU found in tenant
FAIL: No W365 Enterprise, Frontline, or Business license found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Low" `
    } else {
        Add-CheckResult -Category $category -CheckName "Windows 365 license" `
            -Status "Fail" -Detail "No Windows 365 license found in tenant." `
            -Remediation "Purchase and assign a Windows 365 license." `
 `
            -Criteria "PASS: W365 license SKU found in tenant
FAIL: No W365 Enterprise, Frontline, or Business license found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Critical"
    }

    # Intune
    $intuneSkus = $skus | Where-Object {
        $sku = $_.skuPartNumber
        ($script:IntuneSkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($intuneSkus) {
        $skuNames = ($intuneSkus | ForEach-Object { $_.skuPartNumber }) -join ", "
        Add-CheckResult -Category $category -CheckName "Microsoft Intune license" `
            -Status "Pass" -Detail "Intune capability found via: $skuNames" `
            -Criteria "PASS: Intune capability found via license SKU
FAIL: No license providing Intune found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Low" `
    } else {
        Add-CheckResult -Category $category -CheckName "Microsoft Intune license" `
            -Status "Fail" -Detail "No Intune license found. Link requires Intune for device management." `
            -Remediation "Assign a license that includes Intune (standalone, M365 E3/E5, Business Premium)." `
 `
            -Criteria "PASS: Intune capability found via license SKU
FAIL: No license providing Intune found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Critical"
    }

    # Entra ID Premium
    $entraSkus = $skus | Where-Object {
        $sku = $_.skuPartNumber
        ($script:EntraPremiumSkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($entraSkus) {
        $skuNames = ($entraSkus | ForEach-Object { $_.skuPartNumber }) -join ", "
        Add-CheckResult -Category $category -CheckName "Entra ID Premium license" `
            -Status "Pass" -Detail "Entra Premium found via: $skuNames" `
            -Criteria "PASS: Entra ID Premium found via license SKU
FAIL: No Entra Premium license (auto MDM enrollment will silently fail)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Low" `
    } else {
        Add-CheckResult -Category $category -CheckName "Entra ID Premium license" `
            -Status "Fail" -Detail "No Entra ID Premium license found. Without it, auto MDM enrollment silently fails." `
            -Remediation "Assign Entra ID Premium P1/P2 (standalone, M365 E3/E5, EMS, Business Premium)." `
 `
            -Criteria "PASS: Entra ID Premium found via license SKU
FAIL: No Entra Premium license (auto MDM enrollment will silently fail)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -PortalUrl "https://admin.microsoft.com/Adminportal/Home#/licenses" `
            -RiskLevel "Critical"
    }
}

# --- CHECK 2: Entra ID Device Join ---
function Test-W365EntraDeviceJoin {
    $category = "Entra ID Device Join"
    $regPolicy = Invoke-GraphSafe -Uri "/policies/deviceRegistrationPolicy"

    if ($regPolicy._error) {
        Add-CheckResult -Category $category -CheckName "Device registration policy" `
            -Status "Error" -Detail "Could not retrieve policy: $($regPolicy._error)" `
 `
            -Criteria "ERROR: Could not read device registration policy from Graph API" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
            -RiskLevel "Medium"
        return
    }

    $joinSetting = $regPolicy.azureADJoin
    if ($joinSetting) {
        $appliesTo = $joinSetting.appliesTo
        if ([string]::IsNullOrWhiteSpace($appliesTo) -and $joinSetting.allowedToJoin) {
            $odataType = $joinSetting.allowedToJoin.'@odata.type'
            if ($odataType -like '*allDeviceRegistrationMembership*')            { $appliesTo = "all" }
            elseif ($odataType -like '*enumeratedDeviceRegistrationMembership*') { $appliesTo = "selected" }
            elseif ($odataType -like '*noDeviceRegistrationMembership*')         { $appliesTo = "none" }
        }
        if ($appliesTo -eq "0") { $appliesTo = "none" }
        elseif ($appliesTo -eq "1") { $appliesTo = "all" }
        elseif ($appliesTo -eq "2") { $appliesTo = "selected" }

        if ($appliesTo -eq "none" -or $joinSetting.isAllowed -eq $false) {
            Add-CheckResult -Category $category -CheckName "Users may join devices" `
                -Status "Fail" -Detail "Device join is set to NONE — no users can join Windows CPC Devices." `
                -Remediation "Set to All or Selected in Entra → Identity → Devices → Device Settings." `
 `
                -Criteria "PASS: Set to All
WARNING: Set to Selected (verify WCPC Device users are included)
FAIL: Set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
                -RiskLevel "Critical" -CanFix $true -FixAction "fix-entra-join"
        }
        elseif ($appliesTo -eq "all") {
            Add-CheckResult -Category $category -CheckName "Users may join devices" `
                -Status "Pass" -Detail "All users are allowed to join devices to Entra ID." `
                -Criteria "PASS: Set to All
WARNING: Set to Selected (verify WCPC Device users are included)
FAIL: Set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
                -RiskLevel "Low" `
        }
        elseif ($appliesTo -eq "selected") {
            Add-CheckResult -Category $category -CheckName "Users may join devices" `
                -Status "Warning" -Detail "Device join is set to SELECTED. Ensure WCPC Device users are included." `
                -Remediation "Verify target groups in Entra → Identity → Devices → Device Settings." `
 `
                -Criteria "PASS: Set to All
WARNING: Set to Selected (verify WCPC Device users are included)
FAIL: Set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
                -RiskLevel "Medium"
        }
    } else {
        Add-CheckResult -Category $category -CheckName "Users may join devices" `
            -Status "Warning" -Detail "Could not determine device join setting. Verify manually." `
 `
            -Criteria "PASS: Set to All
WARNING: Set to Selected (verify WCPC Device users are included)
FAIL: Set to None" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
            -RiskLevel "Medium"
    }

    # Max devices per user
    $maxDevices = $regPolicy.userDeviceQuota
    if ($null -ne $maxDevices) {
        if ([int]$maxDevices -lt 20) {
            Add-CheckResult -Category $category -CheckName "Max devices per user" `
                -Status "Warning" -Detail "Limit is $maxDevices. May be low for bulk onboarding." `
                -Remediation "Consider increasing in Entra → Identity → Devices → Device Settings." `
 `
                -Criteria "PASS: Limit is 20 or higher
WARNING: Limit below 20 (may be low for bulk onboarding)" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
                -RiskLevel "Medium"
        } else {
            Add-CheckResult -Category $category -CheckName "Max devices per user" `
                -Status "Pass" -Detail "Limit is $maxDevices per user." `
                -Criteria "PASS: Limit is 20 or higher
WARNING: Limit below 20 (may be low for bulk onboarding)" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
                -RiskLevel "Low" `
        }
    }

    # MFA to register or join devices (legacy setting)
    $mfaSetting = $regPolicy.multiFactorAuthConfiguration
    if (-not $mfaSetting -and $regPolicy.azureADJoin) {
        $mfaSetting = $regPolicy.azureADJoin.multiFactorAuthConfiguration
    }

    $mfaCriteria = "PASS: MFA for device join is disabled (No)`nWARNING: MFA for device join is enabled (Yes) — should use CA policy instead"

    if ($mfaSetting -eq "required" -or "$mfaSetting" -eq "1") {
        Add-CheckResult -Category $category -CheckName "MFA to register or join devices" `
            -Status "Warning" `
            -Detail "The legacy setting 'Require MFA to register or join devices' is enabled. Microsoft recommends disabling this and using a Conditional Access policy targeting 'Register or join devices' instead for more granular control." `
            -Remediation "Set to NO in Entra → Identity → Devices → Device Settings, then create a CA policy targeting the user action 'Register or join devices'." `
 `
            -Criteria $mfaCriteria `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
            -RiskLevel "Medium"
    }
    elseif ($mfaSetting -eq "notRequired" -or "$mfaSetting" -eq "0" -or -not $mfaSetting) {
        Add-CheckResult -Category $category -CheckName "MFA to register or join devices" `
            -Status "Pass" -Detail "Legacy MFA for device join is disabled. Conditional Access should be used for MFA requirements." `
            -Criteria $mfaCriteria `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
            -RiskLevel "Low" `
    }
    else {
        Add-CheckResult -Category $category -CheckName "MFA to register or join devices" `
            -Status "Warning" -Detail "MFA setting value is '$mfaSetting'. Verify manually in Entra → Devices → Device Settings." `
            -Criteria $mfaCriteria `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings" `
            -RiskLevel "Medium"
    }
}

# --- CHECK 3: MDM Auto-Enrollment ---
function Test-W365MDMScope {
    $category = "Intune Auto-Enrollment"
    $mdmPolicies = Invoke-GraphSafe -Uri "/policies/mobileDeviceManagementPolicies"

    if ($mdmPolicies._error) {
        Add-CheckResult -Category $category -CheckName "MDM User Scope" `
            -Status "Error" -Detail "Could not query MDM policies: $($mdmPolicies._error)" `
 `
            -Criteria "PASS: MDM scope set to All
WARNING: MDM scope set to Selected
FAIL: MDM scope set to None" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
            -RiskLevel "High"
        return
    }

    $policies = if ($mdmPolicies.value) { $mdmPolicies.value } else { @($mdmPolicies) | Where-Object { $_.id } }
    $intunePolicy = $policies | Where-Object {
        $_.displayName -like "*Intune*" -or
        $_.discoveryUrl -like "*enrollment.manage.microsoft.com*"
    }

    if (-not $intunePolicy) {
        Add-CheckResult -Category $category -CheckName "Microsoft Intune MDM application" `
            -Status "Fail" -Detail "No Intune MDM application found. Devices will NOT auto-enroll." `
            -Remediation "Navigate to Entra → Settings → Mobility → Microsoft Intune and set MDM scope." `
 `
            -Criteria "FAIL: No Intune MDM application found on the Mobility page" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
            -RiskLevel "Critical" -CanFix $true -FixAction "fix-mdm-scope"
        return
    }

    switch ($intunePolicy.appliesTo) {
        "none" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Fail" -Detail "MDM scope is NONE. Devices will join Entra but NOT enroll in Intune." `
                -Remediation "Set MDM scope to All or Some in Entra → Settings → Mobility → Microsoft Intune." `
 `
                -Criteria "PASS: MDM scope set to All
WARNING: MDM scope set to Selected
FAIL: MDM scope set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
                -RiskLevel "Critical" -CanFix $true -FixAction "fix-mdm-scope"
        }
        "all" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Pass" -Detail "MDM scope is ALL. All users will auto-enroll." `
                -Criteria "PASS: MDM scope set to All
WARNING: MDM scope set to Selected
FAIL: MDM scope set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
                -RiskLevel "Low" `
        }
        "selected" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Warning" -Detail "MDM scope is SELECTED. Ensure WCPC Device users are in scope." `
                -Remediation "Verify groups in Entra → Settings → Mobility → Microsoft Intune." `
 `
                -Criteria "PASS: MDM scope set to All
WARNING: MDM scope set to Selected
FAIL: MDM scope set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
                -RiskLevel "Medium"
        }
        default {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Info" -Detail "MDM scope value: '$($intunePolicy.appliesTo)'. Review manually." `
 `
                -Criteria "PASS: MDM scope set to All
WARNING: MDM scope set to Selected
FAIL: MDM scope set to None" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
                -RiskLevel "Medium"
        }
    }

    # Conflicting MDM apps
    $otherMdmApps = $policies | Where-Object {
        ($_.displayName -notlike "*Intune*") -and
        ($_.discoveryUrl -notlike "*enrollment.manage.microsoft.com*") -and
        ($_.appliesTo -ne "none")
    }
    if ($otherMdmApps) {
        $names = ($otherMdmApps | ForEach-Object { $_.displayName }) -join ", "
        Add-CheckResult -Category $category -CheckName "Conflicting MDM applications" `
            -Status "Warning" -Detail "Other active MDM apps found: $names" `
            -Remediation "Ensure only Intune has MDM scope enabled. Set others to None." `
 `
            -Criteria "PASS: No other active MDM applications
WARNING: Other MDM apps with active scope found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
            -RiskLevel "High"
    } else {
        Add-CheckResult -Category $category -CheckName "Conflicting MDM applications" `
            -Status "Pass" -Detail "No conflicting MDM applications found." `
            -Criteria "PASS: No other active MDM applications
WARNING: Other MDM apps with active scope found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility" `
            -RiskLevel "Low" `
    }
}

# --- CHECK 4: Enrollment Restrictions ---
function Test-W365EnrollmentRestrictions {
    $category = "Enrollment Restrictions"
    $enrollConfigs = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations"

    if ($enrollConfigs._error) {
        Add-CheckResult -Category $category -CheckName "Platform restrictions" `
            -Status "Error" -Detail "Could not query enrollment configs: $($enrollConfigs._error)" `
 `
            -Criteria "PASS: Personal Windows enrollment not blocked`nFAIL: A platform restriction blocks personal devices" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/platformRestrictions" `
            -RiskLevel "High"
        return
    }

    $configs = if ($enrollConfigs.value) { $enrollConfigs.value } else { @() }

    # Log all configs for debugging
    foreach ($c in $configs) {
    }

    $personalBlocked = $false
    $platformBlocked = $false
    $blockingPolicies = @()
    $allowingPolicies = @()
    $lowestBlockPriority = 999
    $lowestAllowPriority = 999

    foreach ($config in $configs) {
        $odataType = if ($config.'@odata.type') { $config.'@odata.type' } else { '' }
        if ($odataType -notlike '*platformRestriction*' -and $odataType -notlike '*PlatformRestriction*') { continue }

        $shortType = $odataType.Split('.')[-1]

        $label = if ($config.displayName) { $config.displayName } else { "Policy $($config.id)" }
        $pri = if ($null -ne $config.priority) { [int]$config.priority } else { 999 }
        $isDefault = ($shortType -like '*RestrictionsConfiguration*')

        $winR = $null
        if ($isDefault) {
            $winR = $config.windowsRestriction
            if ($winR) {
            }
        } else {
            if ($config.platformType -eq "windows" -or $config.platformType -eq "windowsMobile") {
                $winR = $config.platformRestriction
                if ($winR) {
                }
            } else {
                continue
            }
        }

        if (-not $winR) { continue }

        $isBlocking = $false
        if ($winR.personalDeviceEnrollmentBlocked -eq $true -or "$($winR.personalDeviceEnrollmentBlocked)" -eq "True") {
            $personalBlocked = $true
            $isBlocking = $true
            $blockingPolicies += "$label — personal devices blocked (Priority: $pri)"
            if ($pri -lt $lowestBlockPriority) { $lowestBlockPriority = $pri }
        }
        if ($winR.platformBlocked -eq $true -or "$($winR.platformBlocked)" -eq "True") {
            $platformBlocked = $true
            $isBlocking = $true
            $blockingPolicies += "$label — Windows platform blocked (Priority: $pri)"
            if ($pri -lt $lowestBlockPriority) { $lowestBlockPriority = $pri }
        }

        if (-not $isBlocking -and -not $isDefault) {
            # This is a per-platform Allow policy for Windows
            $allowingPolicies += "$label (Priority: $pri)"
            if ($pri -lt $lowestAllowPriority) { $lowestAllowPriority = $pri }
        }
    }

    $criteriaText = "PASS: No restrictions blocking Windows enrollment`nWARNING: Block exists but a higher-priority Allow may override it`nFAIL: A restriction blocks Windows enrollment with no override"

    if ($personalBlocked -or $platformBlocked) {
        $policyList = $blockingPolicies -join "; "

        # Check if there's an Allow policy with higher priority (lower number) than the block
        $hasOverride = ($allowingPolicies.Count -gt 0 -and $lowestAllowPriority -lt $lowestBlockPriority)

        if ($hasOverride) {
            $allowList = $allowingPolicies -join "; "
            Add-CheckResult -Category $category -CheckName "Windows personal device enrollment" `
                -Status "Warning" `
                -Detail "Blocking policy found ($policyList) but a higher-priority Allow policy exists ($allowList). Some users may be able to enroll, but review policy assignments to confirm." `
                -Remediation "Review enrollment restriction assignments to ensure Windows CPC Device users are covered by the Allow policy." `
 `
                -Criteria $criteriaText `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
                -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/platformRestrictions" `
                -RiskLevel "Medium"
        } else {
            Add-CheckResult -Category $category -CheckName "Windows personal device enrollment" `
                -Status "Fail" `
                -Detail "Enrollment restricted: $policyList. Windows CPC Devices may be blocked during enrollment." `
                -Remediation "Use corporate identifiers (serial numbers), a WCPC SKU filter, or a DEM account to bypass." `
 `
                -Criteria $criteriaText `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
                -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/platformRestrictions" `
                -RiskLevel "Critical" -CanFix $true -FixAction "fix-enrollment"
        }
    } else {
        Add-CheckResult -Category $category -CheckName "Windows personal device enrollment" `
            -Status "Pass" -Detail "No restriction blocking personal Windows devices. Windows CPC Devices should enroll." `
            -Criteria $criteriaText `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/platformRestrictions" `
            -RiskLevel "Low" `
    }
}

# --- CHECK 5: Cloud PC SSO ---
function Test-W365CloudPCSSO {
    $category = "SSO Configuration"
    $provPolicies = Invoke-GraphSafe -Uri "/deviceManagement/virtualEndpoint/provisioningPolicies"

    if ($provPolicies._error) {
        Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
            -Status "Error" -Detail "Could not query provisioning policies: $($provPolicies._error)" `
 `
            -Criteria "ERROR/WARNING: Could not query provisioning policies or none found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/weightedAppList" `
            -RiskLevel "High"
        return
    }

    $allPolicies = if ($provPolicies.value) { $provPolicies.value } else { @() }
    if ($allPolicies.Count -eq 0) {
        Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
            -Status "Warning" -Detail "No provisioning policies found." `
            -Criteria "ERROR/WARNING: Could not query provisioning policies or none found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/weightedAppList" `
            -RiskLevel "Medium"
        return
    }

    $ssoDisabled = @()
    $ssoEnabled = @()

    foreach ($policy in $allPolicies) {
        $sso = $false
        if ($null -ne $policy.enableSingleSignOn) { $sso = $policy.enableSingleSignOn }
        elseif ($null -ne $policy.windowsSetting -and $null -ne $policy.windowsSetting.enableSingleSignOn) {
            $sso = $policy.windowsSetting.enableSingleSignOn
        }
        elseif ($null -ne $policy.domainJoinConfigurations) {
            foreach ($djc in $policy.domainJoinConfigurations) {
                if ($djc.type -eq "azureADJoin" -and $djc.enableSingleSignOn -eq $true) { $sso = $true }
            }
        }
        if ($policy.PSObject.Properties.Name -contains "singleSignOnStatus") {
            $sso = ($policy.singleSignOnStatus -eq "enabled")
        }
        if ($sso) { $ssoEnabled += $policy.displayName } else { $ssoDisabled += $policy.displayName }
    }

    $total = $ssoEnabled.Count + $ssoDisabled.Count
    if ($ssoDisabled.Count -gt 0) {
        $disabledList = $ssoDisabled -join ", "
        Add-CheckResult -Category $category -CheckName "SSO on provisioning policies ($($ssoEnabled.Count)/$total)" `
            -Status "Fail" `
            -Detail "$($ssoEnabled.Count)/$total policies have SSO enabled. Disabled on: $disabledList. Link CANNOT connect without SSO." `
            -Remediation "Enable SSO on each policy in Intune → Devices → Windows 365 → Provisioning policies." `
 `
            -Criteria "PASS: SSO enabled on all evaluated provisioning policies
FAIL: SSO disabled on one or more policies (Link cannot connect without SSO)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/weightedAppList" `
            -RiskLevel "Critical"
    } else {
        Add-CheckResult -Category $category -CheckName "SSO on provisioning policies ($total/$total)" `
            -Status "Pass" -Detail "All $total provisioning policies have SSO enabled." `
            -Criteria "PASS: SSO enabled on all evaluated provisioning policies
FAIL: SSO disabled on one or more policies (Link cannot connect without SSO)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/weightedAppList" `
            -RiskLevel "Low" `
    }

    # SSO consent suppression check
    $spResponse = Invoke-GraphSafe -Uri "/servicePrincipals?`$filter=appId eq '$($script:WCLAppId)'"
    if (-not $spResponse._error) {
        $spList = if ($spResponse.value) { $spResponse.value } else { @() }
        if ($spList.Count -eq 0) {
            Add-CheckResult -Category $category -CheckName "SSO consent suppression" `
                -Status "Warning" -Detail "'Windows Cloud Login' service principal not found. Consent suppression cannot be configured." `
                -Remediation "Register the enterprise app or run: New-MgServicePrincipal -AppId '$($script:WCLAppId)'" `
 `
                -Criteria "PASS: Consent suppression configured with target device groups
WARNING: Windows Cloud Login service principal not found
FAIL: Not configured or no target groups assigned" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview" `
                -RiskLevel "High"
        } else {
            $spId = $spList[0].id
            $targetGroups = Invoke-GraphSafe -Uri "/servicePrincipals/$spId/remoteDesktopSecurityConfiguration/targetDeviceGroups"
            if ($targetGroups._error) {
                if ($targetGroups._statusCode -eq 404) {
                    Add-CheckResult -Category $category -CheckName "SSO consent suppression" `
                        -Status "Fail" -Detail "Remote Desktop security config not found. SSO consent not suppressed — users will see errors every 30 days." `
                        -Remediation "Configure consent suppression via Entra → Enterprise Apps → Windows Cloud Login." `
 `
                        -Criteria "PASS: Consent suppression configured with target device groups
WARNING: Windows Cloud Login service principal not found
FAIL: Not configured or no target groups assigned" `
                        -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                        -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview" `
                        -RiskLevel "Critical"
                }
            } else {
                $groups = if ($targetGroups.value) { $targetGroups.value } else { @() }
                if ($groups.Count -gt 0) {
                    $groupNames = ($groups | ForEach-Object { $_.displayName }) -join ", "
                    Add-CheckResult -Category $category -CheckName "SSO consent suppression" `
                        -Status "Pass" -Detail "Configured with $($groups.Count) target group(s): $groupNames" `
                        -Criteria "PASS: Consent suppression configured with target device groups
WARNING: Windows Cloud Login service principal not found
FAIL: Not configured or no target groups assigned" `
                        -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                        -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview" `
                        -RiskLevel "Low" `
                } else {
                    Add-CheckResult -Category $category -CheckName "SSO consent suppression" `
                        -Status "Fail" -Detail "Config exists but NO target device groups assigned. Consent suppression incomplete." `
                        -Remediation "Add your Cloud PC device group to the Windows Cloud Login service principal." `
 `
                        -Criteria "PASS: Consent suppression configured with target device groups
WARNING: Windows Cloud Login service principal not found
FAIL: Not configured or no target groups assigned" `
                        -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                        -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview" `
                        -RiskLevel "Critical"
                }
            }
        }
    }
}

# --- CHECK 6: Conditional Access ---
function Test-W365ConditionalAccess {
    $category = "Conditional Access"
    $caPolicies = Invoke-GraphSafe -Uri "/identity/conditionalAccess/policies"

    if ($caPolicies._error) {
        Add-CheckResult -Category $category -CheckName "Conditional Access policies" `
            -Status "Error" -Detail "Could not query CA policies: $($caPolicies._error)" `
 `
            -Criteria "ERROR: Could not query Conditional Access policies from Graph API" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
            -RiskLevel "High"
        return
    }

    $policies = if ($caPolicies.value) { $caPolicies.value } else { @() }
    $enabledPolicies = $policies | Where-Object { $_.state -eq "enabled" -or $_.state -eq "enabledForReportingButNotEnforced" }

    $resourceCriteria = "INFO: Lists CA policies targeting W365, AVD, Windows Cloud Login, or All cloud apps that may affect Windows CPC Device connections"
    $userActionCriteria = "PASS: 'Register or join devices' policy is enabled`nINFO: Policy exists but in Report-only mode`nWARNING: MFA/controls on resources but no 'Register or join devices' policy`nFAIL: Unsupported controls (device compliance, sign-in frequency) on user-action policy"

    # Policies targeting W365 resources OR All cloud apps
    $w365Policies = @()
    $allAppsPolicies = @()
    foreach ($pol in $enabledPolicies) {
        $targetApps = @()
        if ($pol.conditions.applications.includeApplications) { $targetApps = $pol.conditions.applications.includeApplications }

        # Check for "All cloud apps" / "All resources"
        if ($targetApps -contains "All" -or $targetApps -contains "AllApps") {
            $allAppsPolicies += $pol
            $w365Policies += $pol
            continue
        }

        # Check for specific W365-related app IDs
        if ($targetApps -contains $script:W365AppId -or $targetApps -contains $script:AVDAppId -or
            $targetApps -contains $script:WCLAppId) {
            $w365Policies += $pol
        }
    }

    # Policies targeting user action "Register or join devices" ONLY (not "Register security info")
    $registerJoinPolicies = @()
    $registerSecInfoPolicies = @()
    foreach ($pol in $enabledPolicies) {
        $userActions = @()
        if ($pol.conditions.applications.includeUserActions) { $userActions = $pol.conditions.applications.includeUserActions }
        if ($userActions -contains "urn:user:registerdevice") {
            $registerJoinPolicies += $pol
        }
        if ($userActions -contains "urn:user:registersecurityinfo") {
            $registerSecInfoPolicies += $pol
        }
    }

    # Report W365 resource policies
    if ($w365Policies.Count -gt 0) {
        $allAppsCount = $allAppsPolicies.Count
        $policyNames = ($w365Policies | ForEach-Object {
            $apps = @()
            if ($_.conditions.applications.includeApplications -contains "All" -or
                $_.conditions.applications.includeApplications -contains "AllApps") { $apps += "All cloud apps" }
            else {
                if ($_.conditions.applications.includeApplications -contains $script:W365AppId) { $apps += "W365" }
                if ($_.conditions.applications.includeApplications -contains $script:AVDAppId) { $apps += "AVD" }
                if ($_.conditions.applications.includeApplications -contains $script:WCLAppId) { $apps += "WCL" }
            }
            "$($_.displayName) ($($apps -join ',')) [$($_.state)]"
        })
        $detail = "Windows CPC Devices authenticate in two stages: (1) interactive sign-in on the device, and (2) non-interactive SSO connection to the Cloud PC. CA policies on W365 resources apply during stage 2, where users cannot be prompted for MFA. "
        $detail += "Found $($w365Policies.Count) policy(ies) that will apply"
        if ($allAppsCount -gt 0) { $detail += " ($allAppsCount targeting All cloud apps)" }
        if ($policyNames.Count -le 5) {
            $detail += ": $($policyNames -join '; ')"
        } else {
            $first3 = ($policyNames | Select-Object -First 3) -join '; '
            $detail += ": $first3; ... and $($policyNames.Count - 3) more"
        }
        $detail += ". If any of these require MFA, you also need a 'Register or join devices' user-action policy so the user can complete MFA during stage 1."
        Add-CheckResult -Category $category -CheckName "CA policies on W365 resources" `
            -Status "Info" -Detail $detail `
            -Criteria $resourceCriteria `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
            -RiskLevel "Medium"

        # Check if any require MFA or auth strength
        $mfaRequired = $w365Policies | Where-Object {
            ($_.grantControls.builtInControls -contains "mfa") -or
            ($_.grantControls.authenticationStrength) -or
            ($_.sessionControls.signInFrequency)
        }

        if ($mfaRequired -and $registerJoinPolicies.Count -eq 0) {
            $mfaNames = @($mfaRequired | ForEach-Object { $_.displayName })
            $mfaDisplay = if ($mfaNames.Count -le 3) {
                $mfaNames -join ", "
            } else {
                "$( ($mfaNames | Select-Object -First 3) -join ', ') ... and $($mfaNames.Count - 3) more"
            }
            Add-CheckResult -Category $category -CheckName "Missing 'Register or join devices' policy" `
                -Status "Warning" `
                -Detail "$($mfaRequired.Count) policy(ies) require MFA or auth controls when connecting to W365 resources ($mfaDisplay). Because the Cloud PC connection is non-interactive (stage 2), the user cannot be prompted for MFA at that point. Without a matching 'Register or join devices' policy, MFA is completed during stage 1 (device sign-in), which provides the token for stage 2." `
                -Remediation "Create a CA policy targeting the user action 'Register or join devices' with the same Grant controls (e.g. Require MFA) as your resource policies. This ensures the user satisfies MFA during interactive sign-in." `
 `
                -Criteria $userActionCriteria `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
                -RiskLevel "Medium" -CanFix $true -FixAction "fix-ca-useraction"
        }
        elseif ($mfaRequired -and $registerJoinPolicies.Count -gt 0) {
            $enabledUA = @($registerJoinPolicies | Where-Object { $_.state -eq "enabled" })
            $reportOnlyUA = @($registerJoinPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })

            if ($enabledUA.Count -gt 0) {
                $uaNames = ($enabledUA | ForEach-Object { $_.displayName }) -join ", "
                Add-CheckResult -Category $category -CheckName "'Register or join devices' policy" `
                    -Status "Pass" -Detail "Found enabled user-action policy: $uaNames" `
                    -Criteria $userActionCriteria `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                    -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
                    -RiskLevel "Low" `
            }
            elseif ($reportOnlyUA.Count -gt 0) {
                $uaNames = ($reportOnlyUA | ForEach-Object { $_.displayName }) -join ", "
                Add-CheckResult -Category $category -CheckName "'Register or join devices' policy" `
                    -Status "Info" -Detail "Found user-action policy in Report-only mode: $uaNames. Review the settings and enable it when ready." `
                    -Remediation "Open the policy in Entra, verify settings, add break-glass exclusions, then change from Report-only to On." `
 `
                    -Criteria $userActionCriteria `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                    -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
                    -RiskLevel "Medium"
            }
        }
    } else {
        Add-CheckResult -Category $category -CheckName "CA policies on W365 resources" `
            -Status "Info" -Detail "No enabled CA policies targeting Windows 365, Azure Virtual Desktop, Windows Cloud Login, or All cloud apps were found. If you add CA policies to these resources later, you will also need a 'Register or join devices' user-action policy to support the two-stage authentication model on Windows CPC Devices." `
            -Criteria $resourceCriteria `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
            -RiskLevel "Low"
    }

    # Check for unsupported controls/conditions on register/join policies
    if ($registerJoinPolicies.Count -gt 0) {
        foreach ($uaPol in $registerJoinPolicies) {
            $issues = @()

            # Only MFA and auth strength are supported grant controls
            $builtIn = $uaPol.grantControls.builtInControls
            if ($builtIn -contains "compliantDevice") { $issues += "Require compliant device" }
            if ($builtIn -contains "domainJoinedDevice") { $issues += "Require Hybrid Azure AD joined" }
            if ($builtIn -contains "approvedApplication") { $issues += "Require approved client app" }
            if ($builtIn -contains "compliantApplication") { $issues += "Require app protection policy" }
            if ($builtIn -contains "passwordChange") { $issues += "Require password change" }
            if ($uaPol.grantControls.customAuthenticationFactors) { $issues += "Custom controls" }
            if ($uaPol.grantControls.termsOfUse) { $issues += "Terms of use" }

            # Unsupported session controls
            if ($uaPol.sessionControls.signInFrequency.isEnabled -eq $true) { $issues += "Sign-in frequency (session control)" }
            if ($uaPol.sessionControls.persistentBrowser.isEnabled -eq $true) { $issues += "Persistent browser (session control)" }

            # Unsupported conditions
            if ($uaPol.conditions.clientAppTypes -and $uaPol.conditions.clientAppTypes -ne "all") { $issues += "Client apps condition" }
            if ($uaPol.conditions.devices) { $issues += "Filters for devices / Device state condition" }

            if ($issues.Count -gt 0) {
                Add-CheckResult -Category $category -CheckName "Unsupported controls on '$($uaPol.displayName)'" `
                    -Status "Fail" -Detail "Unsupported controls/conditions: $($issues -join ', '). Only 'Require MFA' and 'Require authentication strength' are supported for the 'Register or join devices' user action." `
                    -Remediation "Remove unsupported controls from this policy. Client apps, device filters, and device state conditions are also not supported." `
 `
                    -Criteria $userActionCriteria `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                    -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies" `
                    -RiskLevel "Critical"
            }
        }
    }
}

# --- CHECK 7: Authentication Methods (FIDO2) ---
function Test-W365AuthMethods {
    $category = "Authentication Methods"
    $authMethods = Invoke-GraphSafe -Uri "/policies/authenticationMethodsPolicy"

    if ($authMethods._error) {
        Add-CheckResult -Category $category -CheckName "Authentication methods" `
            -Status "Error" -Detail "Could not query auth methods: $($authMethods._error)" `
 `
            -Criteria "ERROR: Could not query authentication methods policy" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods" `
            -RiskLevel "Medium"
        return
    }

    $configs = $authMethods.authenticationMethodConfigurations
    if (-not $configs) {
        Add-CheckResult -Category $category -CheckName "FIDO2 security key" `
            -Status "Info" -Detail "Could not parse auth method configs. Check manually." `
            -Criteria "PASS: FIDO2 enabled`nINFO: Disabled or not found (optional)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -PortalUrl "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods" `
            -RiskLevel "Medium"
        return
    }

    # Determine FIDO2 state first — downstream checks depend on this
    # FIDO2 result is deferred until after WHfB/custom profile checks
    $fido2Enabled = $false
    $fido2Config = $configs | Where-Object { $_.id -eq "fido2" -or $_.'@odata.type' -like "*fido2*" }
    if ($fido2Config -and $fido2Config.state -eq "enabled") { $fido2Enabled = $true }

    $fido2Criteria = "PASS: FIDO2 enabled`nWARNING: Disabled but WHfB or custom profile depends on it`nINFO: Disabled (optional, nothing depends on it)"
    $fido2Portal = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods"
    $fido2Learn = "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods"

    # CBA warning
    $cbaConfig = $configs | Where-Object { $_.id -eq "x509Certificate" -or $_.'@odata.type' -like "*x509*" }
    if ($cbaConfig -and $cbaConfig.state -eq "enabled") {
        Add-CheckResult -Category $category -CheckName "Certificate-based auth (CBA)" `
            -Status "Warning" -Detail "CBA is enabled but NOT supported for web sign-in on Windows CPC Devices. Users need an alternative sign-in method." `
 `
            -Criteria "WARNING: CBA is enabled but not supported for web sign-in on Windows CPC Devices" `
            -LearnMoreUrl $fido2Learn `
            -PortalUrl $fido2Portal `
            -RiskLevel "Medium"
    }

    # Reserve position for FIDO2 result (will be inserted here after all state is gathered)
    $fido2InsertIndex = $script:CheckResults.Count

    # Windows Hello for Business — Security keys for sign-in
    $whfbConfigs = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations"
    $whfbSecKeyEnabled = $false
    if (-not $whfbConfigs._error) {
        $whfbPolicies = @(if ($whfbConfigs.value) { $whfbConfigs.value } else { @() }) |
            Where-Object { $_.'@odata.type' -like '*WindowsHelloForBusiness*' }
        foreach ($whfb in $whfbPolicies) {
            if ($whfb.securityKeyForSignIn -eq "enabled" -or "$($whfb.securityKeyForSignIn)" -eq "Enabled") {
                $whfbSecKeyEnabled = $true
            }
        }
    }

    $whfbCriteria = "PASS: Enabled and FIDO2 auth method is also enabled`nWARNING: Enabled but FIDO2 auth method is disabled (misconfiguration)`nINFO: Not enabled"
    $whfbPortal = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/windowsHelloForBusiness"
    $whfbLearn = "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods#fido2-security-key"

    if ($whfbSecKeyEnabled -and $fido2Enabled) {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (WHfB)" `
            -Status "Pass" -Detail "Security keys for sign-in is enabled in WHfB and FIDO2 auth method is enabled." `
            -Criteria $whfbCriteria `
            -LearnMoreUrl $whfbLearn `
            -PortalUrl $whfbPortal `
            -RiskLevel "Low" `
    }
    elseif ($whfbSecKeyEnabled -and -not $fido2Enabled) {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (WHfB)" `
            -Status "Warning" -Detail "Security keys for sign-in is enabled in WHfB but the FIDO2 authentication method is disabled. Users won't be able to use security keys until FIDO2 is enabled." `
            -Remediation "Enable FIDO2 in Entra → Protection → Authentication methods, or disable this WHfB setting if security keys are not needed." `
            -Criteria $whfbCriteria `
            -LearnMoreUrl $whfbLearn `
            -PortalUrl $whfbPortal `
            -RiskLevel "Medium"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (WHfB)" `
            -Status "Info" -Detail "Security keys for sign-in is not enabled in WHfB. This setting allows FIDO2 keys on all Windows devices enrolled after enabling." `
            -Remediation "To enable: Intune → Devices → Enroll Devices → Windows Hello for Business → Set 'Use security keys for sign-in' to Enabled." `
            -Criteria $whfbCriteria `
            -LearnMoreUrl $whfbLearn `
            -PortalUrl $whfbPortal `
            -RiskLevel "Low" -CanFix $true -FixAction "fix-whfb-seckey"
    }

    # Custom OMA-URI profile for security key sign-in
    $omaUriFound = $false
    $omaProfileName = ""
    $omaProfileId = ""
    $omaAssigned = $false
    $deviceConfigs = Get-CachedDeviceConfigs

    if (-not ($deviceConfigs -is [PSCustomObject] -and $deviceConfigs._error)) {
        $customProfiles = @($deviceConfigs | Where-Object {
            $_.'@odata.type' -like '*custom*' -or $_.'@odata.type' -like '*oma*' -or
            $_.'@odata.type' -like '*windows10Custom*'
        })

        foreach ($profile in $customProfiles) {
            $fullProfile = Invoke-GraphSafe -Uri "/deviceManagement/deviceConfigurations/$($profile.id)"
            if (-not $fullProfile._error -and $fullProfile.omaSettings) {
                foreach ($oma in $fullProfile.omaSettings) {
                    if ($oma.omaUri -like '*UseSecurityKeyForSignin*') {
                        $omaUriFound = $true
                        $omaProfileName = $profile.displayName
                        $omaProfileId = $profile.id
                    }
                }
            }
            if ($omaUriFound) { break }
        }
    }

    if ($omaUriFound -and $omaProfileId) {
        $omaAssigned = Test-PolicyAssigned "/deviceManagement/deviceConfigurations/$omaProfileId/assignments"
    }

    $omaCriteria = "PASS: Profile found, assigned, and FIDO2 enabled`nWARNING: Profile assigned but FIDO2 disabled (misconfiguration)`nINFO: Not found or not assigned"
    $omaPortal = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"
    $omaLearn = "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods#fido2-security-key"

    if ($omaUriFound -and $omaAssigned -and $fido2Enabled) {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (Custom profile)" `
            -Status "Pass" -Detail "Found custom OMA-URI profile '$omaProfileName', assigned, and FIDO2 is enabled." `
            -Criteria $omaCriteria `
            -LearnMoreUrl $omaLearn `
            -PortalUrl $omaPortal `
            -RiskLevel "Low" `
    }
    elseif ($omaUriFound -and $omaAssigned -and -not $fido2Enabled) {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (Custom profile)" `
            -Status "Warning" -Detail "Found custom OMA-URI profile '$omaProfileName' and it is assigned, but FIDO2 authentication method is disabled. Users won't be able to use security keys." `
            -Remediation "Enable FIDO2 in Entra → Protection → Authentication methods for the security key profile to take effect." `
            -Criteria $omaCriteria `
            -LearnMoreUrl $omaLearn `
            -PortalUrl $omaPortal `
            -RiskLevel "Medium"
    }
    elseif ($omaUriFound -and -not $omaAssigned) {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (Custom profile)" `
            -Status "Info" -Detail "Found custom OMA-URI profile '$omaProfileName' but it is not assigned. Assign it for the policy to take effect." `
            -Remediation "Open the profile in Intune, assign to All Devices with a WCPC filter to target Windows CPC Devices only." `
            -Criteria $omaCriteria `
            -LearnMoreUrl $omaLearn `
            -PortalUrl $omaPortal `
            -RiskLevel "Low"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Security keys for sign-in (Custom profile)" `
            -Status "Info" -Detail "No custom OMA-URI profile found for UseSecurityKeyForSignin. This method allows targeting specific devices using an Intune filter." `
            -Remediation "To create: OMA-URI ./Device/Vendor/MSFT/PassportForWork/SecurityKey/UseSecurityKeyForSignin = Integer 1, assign to All Devices with WCPC filter." `
            -Criteria $omaCriteria `
            -LearnMoreUrl $omaLearn `
            -PortalUrl $omaPortal `
            -RiskLevel "Low" -CanFix $true -FixAction "fix-seckey-profile"
    }

    # Insert FIDO2 result at reserved position so it appears before WHfB/custom profile
    $fido2NeededBy = ($whfbSecKeyEnabled -or ($omaUriFound -and $omaAssigned))
    $fido2Result = $null

    if ($fido2Enabled) {
        $fido2Result = [PSCustomObject]@{
            Category = $category; CheckName = "FIDO2 security key"; Status = "Pass"
            Detail = "FIDO2 sign-in is enabled."
            Remediation = ""; LearnMoreUrl = $fido2Learn; PortalUrl = $fido2Portal
            Criteria = $fido2Criteria; RiskLevel = "Low"; CanFix = $false; FixAction = ""
        }
    }
    elseif ($fido2NeededBy) {
        $fido2Detail = if ($fido2Config) { "FIDO2 is '$($fido2Config.state)'." } else { "FIDO2 not found in auth methods." }
        $dependents = @()
        if ($whfbSecKeyEnabled) { $dependents += "WHfB security key sign-in" }
        if ($omaUriFound -and $omaAssigned) { $dependents += "Custom OMA-URI profile" }
        $fido2Result = [PSCustomObject]@{
            Category = $category; CheckName = "FIDO2 security key"; Status = "Warning"
            Detail = "$fido2Detail FIDO2 must be enabled for security key sign-in to work. Depends on it: $($dependents -join ', ')."
            Remediation = "Enable in Entra → Protection → Authentication methods → FIDO2 security key."
            LearnMoreUrl = $fido2Learn; PortalUrl = $fido2Portal
            Criteria = $fido2Criteria; RiskLevel = "Medium"; CanFix = $true; FixAction = "fix-fido2"
        }
    }
    else {
        $fido2Detail = if ($fido2Config) { "FIDO2 is '$($fido2Config.state)'." } else { "FIDO2 not found in auth methods." }
        $fido2Result = [PSCustomObject]@{
            Category = $category; CheckName = "FIDO2 security key"; Status = "Info"
            Detail = "$fido2Detail Security keys are optional — only web sign-in will be available without FIDO2."
            Remediation = "To enable: Entra → Protection → Authentication methods → FIDO2 security key."
            LearnMoreUrl = $fido2Learn; PortalUrl = $fido2Portal
            Criteria = $fido2Criteria; RiskLevel = "Low"; CanFix = $false; FixAction = ""
        }
    }

    $script:CheckResults.Insert($fido2InsertIndex, $fido2Result)
}

# --- CHECK 8: Auto-Detect Time Zone ---
function Test-W365TimeZone {
    $category = "Device Configuration"
    $tzCriteria = "PASS: Settings catalog policy with 'Let Apps Access Location = Force Allow' found and assigned`nINFO: Policy exists but not assigned`nWARNING: No matching policy found"
    $tzLearn = "https://learn.microsoft.com/en-us/windows-365/link/auto-detect-time-zone"
    $tzPortal = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"

    $policies = Get-CachedConfigPolicies
    if ($policies -is [PSCustomObject] -and $policies._error) {
        Add-CheckResult -Category $category -CheckName "Auto-detect time zone" `
            -Status "Error" -Detail "Could not query configuration policies: $($policies._error)" `
            -Criteria $tzCriteria `
            -LearnMoreUrl $tzLearn `
            -PortalUrl $tzPortal `
            -RiskLevel "Medium"
        return
    }

    $tzPolicyFound = $false
    $tzPolicyName = ""
    $tzPolicyId = ""
    $tzPolicyAssigned = $false

    foreach ($pol in $policies) {
        foreach ($setting in $pol._settings) {
            $defId = $setting.settingInstance.settingDefinitionId
            if ($defId -like '*letappsaccesslocation*') {
                $tzPolicyFound = $true
                $tzPolicyName = $pol.name
                $tzPolicyId = $pol.id
                break
            }
        }
        if ($tzPolicyFound) { break }
    }

    # Check assignments if found
    if ($tzPolicyFound -and $tzPolicyId) {
        $tzPolicyAssigned = Test-PolicyAssigned "/deviceManagement/configurationPolicies/$tzPolicyId/assignments"
    }

    if ($tzPolicyFound -and $tzPolicyAssigned) {
        Add-CheckResult -Category $category -CheckName "Auto-detect time zone" `
            -Status "Pass" -Detail "Found settings catalog policy '$tzPolicyName' with location access configured and assigned." `
            -Criteria $tzCriteria `
            -LearnMoreUrl $tzLearn `
            -PortalUrl $tzPortal `
            -RiskLevel "Low" `
    }
    elseif ($tzPolicyFound -and -not $tzPolicyAssigned) {
        Add-CheckResult -Category $category -CheckName "Auto-detect time zone" `
            -Status "Info" -Detail "Found settings catalog policy '$tzPolicyName' but it is not assigned. Assign it to Windows CPC Devices for the setting to take effect." `
            -Remediation "Open the policy in Intune, assign to All Devices with a WCPC filter to target Windows CPC Devices." `
            -Criteria $tzCriteria `
            -LearnMoreUrl $tzLearn `
            -PortalUrl $tzPortal `
            -RiskLevel "Medium"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Auto-detect time zone" `
            -Status "Warning" -Detail "No settings catalog policy found for auto time zone detection. Without this, Windows CPC Devices may show the wrong time zone." `
            -Remediation "Create a Settings Catalog policy: Privacy → Let Apps Access Location = Force Allow, assign to Windows CPC Devices." `
            -Criteria $tzCriteria `
            -LearnMoreUrl $tzLearn `
            -PortalUrl $tzPortal `
            -RiskLevel "Medium" -CanFix $true -FixAction "fix-timezone"
    }
}

# --- CHECK 9: Screen Timeout ---
function Test-W365ScreenTimeout {
    $category = "Device Configuration"
    $stCriteria = "PASS: Settings catalog policy with screen timeout configured and assigned`nINFO: Policy exists but not assigned`nWARNING: No matching policy found (default is 5 minutes)"
    $stLearn = "https://learn.microsoft.com/en-us/windows-365/link/change-screen-time-out"
    $stPortal = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"

    $policies = Get-CachedConfigPolicies
    if ($policies -is [PSCustomObject] -and $policies._error) {
        Add-CheckResult -Category $category -CheckName "Screen timeout" `
            -Status "Error" -Detail "Could not query configuration policies: $($policies._error)" `
            -Criteria $stCriteria `
            -LearnMoreUrl $stLearn `
            -PortalUrl $stPortal `
            -RiskLevel "Medium"
        return
    }

    $stPolicyFound = $false
    $stPolicyName = ""
    $stPolicyId = ""
    $stPolicyAssigned = $false
    $stTimeoutValue = ""

    foreach ($pol in $policies) {
        foreach ($setting in $pol._settings) {
            $defId = $setting.settingInstance.settingDefinitionId
            if ($defId -like '*displayofftimeoutpluggedin*' -or $defId -like '*turnoffthedisplay*pluggedin*') {
                $stPolicyFound = $true
                $stPolicyName = $pol.name
                $stPolicyId = $pol.id
                if ($setting.settingInstance.choiceSettingValue.children) {
                    foreach ($child in $setting.settingInstance.choiceSettingValue.children) {
                        if ($child.simpleSettingValue.value) {
                            $secs = $child.simpleSettingValue.value
                            $stTimeoutValue = " ($secs seconds / $([math]::Round($secs / 60)) minutes)"
                        }
                    }
                }
                break
            }
        }
        if ($stPolicyFound) { break }
    }

    if ($stPolicyFound -and $stPolicyId) {
        $stPolicyAssigned = Test-PolicyAssigned "/deviceManagement/configurationPolicies/$stPolicyId/assignments"
    }

    if ($stPolicyFound -and $stPolicyAssigned) {
        Add-CheckResult -Category $category -CheckName "Screen timeout" `
            -Status "Pass" -Detail "Found screen timeout policy '$stPolicyName'$stTimeoutValue and it is assigned." `
            -Criteria $stCriteria `
            -LearnMoreUrl $stLearn `
            -PortalUrl $stPortal `
            -RiskLevel "Low" `
    }
    elseif ($stPolicyFound -and -not $stPolicyAssigned) {
        Add-CheckResult -Category $category -CheckName "Screen timeout" `
            -Status "Info" -Detail "Found screen timeout policy '$stPolicyName'$stTimeoutValue but it is not assigned." `
            -Remediation "Open the policy in Intune, assign to All Devices with a WCPC filter to target Windows CPC Devices." `
            -Criteria $stCriteria `
            -LearnMoreUrl $stLearn `
            -PortalUrl $stPortal `
            -RiskLevel "Medium"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Screen timeout" `
            -Status "Warning" -Detail "No screen timeout policy found. Default is 5 minutes. Consider creating a policy if a longer timeout is desired." `
            -Remediation "Create a Settings Catalog policy: Video and Display → Turn off the display (plugged in) = Enabled, set seconds." `
            -Criteria $stCriteria `
            -LearnMoreUrl $stLearn `
            -PortalUrl $stPortal `
            -RiskLevel "Medium" -CanFix $true -FixAction "fix-screen-timeout"
    }
}

# --- CHECK 10: Intune Filters ---
function Test-W365IntuneFilters {
    $category = "Intune Filters"
    $filters = Invoke-GraphSafe -Uri "/deviceManagement/assignmentFilters"

    if ($filters._error) {
        Add-CheckResult -Category $category -CheckName "Intune device filters" `
            -Status "Error" -Detail "Could not query filters: $($filters._error)" `
 `
            -Criteria "ERROR: Could not query Intune assignment filters" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/create-intune-filter" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/assignmentFilter" `
            -RiskLevel "Medium"
        return
    }

    $filterList = if ($filters.value) { $filters.value } else { @() }
    $linkFilters = $filterList | Where-Object {
        $_.rule -like "*WCPC*" -or $_.rule -like "*operatingSystemSKU*" -or
        $_.displayName -like "*CPC*" -or $_.displayName -like "*Link*"
    }


    if ($linkFilters) {
        $filterNames = ($linkFilters | ForEach-Object { "$($_.displayName)" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Windows CPC Device filter" `
            -Status "Pass" -Detail "Found filter(s): $filterNames" `
            -Criteria "PASS: Filter targeting operatingSystemSKU WCPC found`nWARNING: No matching filter found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/create-intune-filter" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/assignmentFilter" `
            -RiskLevel "Low" `
    } else {
        Add-CheckResult -Category $category -CheckName "Windows CPC Device filter" `
            -Status "Warning" -Detail "No Intune filter targeting Windows CPC Devices (WCPC SKU) found. Recommended for policy targeting." `
            -Remediation "Create filter: Intune → Tenant admin → Filters → Windows 10+ → operatingSystemSKU Equals WCPC." `
            -Criteria "PASS: Filter targeting operatingSystemSKU WCPC found`nWARNING: No matching filter found" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/create-intune-filter" `
            -PortalUrl "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/assignmentFilter" `
            -RiskLevel "Medium" -CanFix $true -FixAction "fix-intune-filter"
    }
}


function Show-FixDialog {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Icon = "Question",
        [array]$Buttons  # Array of @{ Label="..."; Value="..."; Style="Primary|Neutral|Danger" }
    )

    $iconGlyph = switch ($Icon) { 'Warning'{"⚠"}; 'Error'{"✖"}; 'Question'{"?"}; default{"ℹ"} }
    $iconColor = switch ($Icon) { 'Warning'{"#7A5700"}; 'Error'{"#C42B1C"}; 'Question'{"#0078D4"}; default{"#0078D4"} }

    $escapedMsg = [System.Security.SecurityElement]::Escape($Message)
    # Convert newlines to XML line breaks for TextBlock with xml:space="preserve"
    $escapedMsg = $escapedMsg -replace "`n", '&#xA;'

    # Build button XAML
    $btnXamlParts = @()
    for ($i = 0; $i -lt $Buttons.Count; $i++) {
        $btn = $Buttons[$i]
        $bg = switch ($btn.Style) { 'Primary'{"#0078D4"}; 'Danger'{"#C42B1C"}; 'Success'{"#107C10"}; default{"#E0E0E0"} }
        $fg = switch ($btn.Style) { 'Neutral'{"#1F1F1F"}; default{"White"} }
        $hoverBg = switch ($btn.Style) { 'Primary'{"#106EBE"}; 'Danger'{"#A02015"}; 'Success'{"#0e6b0e"}; default{"#C8C8C8"} }
        $escapedLabel = [System.Security.SecurityElement]::Escape($btn.Label)
        $margin = if ($i -gt 0) { '8,0,0,0' } else { '0' }
        $btnXamlParts += @"
<Button x:Name="btn$i" Content="$escapedLabel" MinWidth="120" Height="32" Margin="$margin"
        Background="$bg" Foreground="$fg" FontWeight="SemiBold" BorderThickness="0" Cursor="Hand" Padding="12,0">
    <Button.Style><Style TargetType="Button"><Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
                <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="$hoverBg"/></Trigger>
            </ControlTemplate.Triggers>
        </ControlTemplate>
    </Setter.Value></Setter></Style></Button.Style>
</Button>
"@
    }
    $buttonsXaml = $btnXamlParts -join "`n"

    [xml]$dlgXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$Title" SizeToContent="WidthAndHeight"
        MinWidth="400" MaxWidth="560"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="White">
    <Border Padding="24,20">
        <StackPanel>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,16">
                <TextBlock Text="$iconGlyph" FontSize="22" Foreground="$iconColor"
                           VerticalAlignment="Top" Margin="0,0,12,0"/>
                <TextBlock Text="$escapedMsg" TextWrapping="Wrap" MaxWidth="420" xml:space="preserve"
                           VerticalAlignment="Center"/>
            </StackPanel>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                $buttonsXaml
            </StackPanel>
        </StackPanel>
    </Border>
</Window>
"@

    $dlgReader = [System.Xml.XmlNodeReader]::new($dlgXaml)
    $dlg = [System.Windows.Markup.XamlReader]::Load($dlgReader)
    if ($script:Window) { $dlg.Owner = $script:Window }

    $script:_fixDlgResult = $null

    for ($i = 0; $i -lt $Buttons.Count; $i++) {
        $btnCtrl = $dlg.FindName("btn$i")
        $btnCtrl.Tag = $Buttons[$i].Value
        $btnCtrl.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $script:_fixDlgResult = $s.Tag
            [System.Windows.Window]::GetWindow($s).Close()
        })
    }

    $dlg.ShowDialog() | Out-Null
    return $script:_fixDlgResult
}

# ============================================================================
# REGION: Remediation Functions
# ============================================================================
function Invoke-FixEntraJoin {
    $msg = "This fix will allow ALL users in your tenant to join devices to Entra ID.`n`n"
    $msg += "Current setting:`n    Device join is restricted or disabled`n`n"
    $msg += "New setting:`n    All users may join devices`n`n"
    $msg += "For lab/demo tenants this is recommended. In production, you may want to scope to specific groups via the portal."

    $result = Show-FixDialog -Title "Fix: Entra Device Join" -Message $msg -Buttons @(
        @{ Label="Set to All"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            # Read current policy, roundtrip through JSON for mutable object, modify, send back
            $currentPolicy = Invoke-GraphSafe -Uri "/policies/deviceRegistrationPolicy"
            if ($currentPolicy._error) { throw "Could not read current policy: $($currentPolicy._error)" }

            $json = $currentPolicy | ConvertTo-Json -Depth 10
            $policy = $json | ConvertFrom-Json

            # Update azureADJoin — set allowedToJoin to "all" membership type
            if ($policy.azureADJoin) {
                $policy.azureADJoin.allowedToJoin = @{
                    '@odata.type' = '#microsoft.graph.allDeviceRegistrationMembership'
                }
            }

            # Remove read-only / OData properties
            foreach ($p in @('@odata.context','_error','_statusCode')) {
                if ($policy.PSObject.Properties[$p]) { $policy.PSObject.Properties.Remove($p) }
            }

            $apiResult = Invoke-GraphSafe -Uri "/policies/deviceRegistrationPolicy" -Method "PUT" -Body $policy
            if ($apiResult._error) { throw "Failed to update device join setting: $($apiResult._error)" }
            return "Device join set to All users."
        }
        "portal" {
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixMDMScope {
    $msg = "This fix will set the Intune MDM auto-enrollment scope to ALL users.`n`n"
    $msg += "Current setting:`n    MDM auto-enrollment is disabled or scoped`n`n"
    $msg += "New setting:`n    All users auto-enroll in Intune on device join`n`n"
    $msg += "For lab/demo tenants this is recommended. In production, you may want to scope to specific groups via the portal."

    $result = Show-FixDialog -Title "Fix: MDM Auto-Enrollment" -Message $msg -Buttons @(
        @{ Label="Set to All"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $mdmPolicies = Invoke-GraphSafe -Uri "/policies/mobileDeviceManagementPolicies"
            if ($mdmPolicies._error) { throw "Could not query MDM policies: $($mdmPolicies._error)" }

            $policies = if ($mdmPolicies.value) { $mdmPolicies.value } else { @($mdmPolicies) | Where-Object { $_.id } }
            $intunePolicy = $policies | Where-Object {
                $_.displayName -like "*Intune*" -or $_.discoveryUrl -like "*enrollment.manage.microsoft.com*"
            }
            if (-not $intunePolicy) { throw "Intune MDM application not found." }

            $body = @{ appliesTo = "all" }
            $apiResult = Invoke-GraphSafe -Uri "/policies/mobileDeviceManagementPolicies/$($intunePolicy.id)" -Method "PATCH" -Body $body
            if ($apiResult._error) { throw "Failed to update MDM scope: $($apiResult._error)" }
            return "MDM auto-enrollment scope set to All."
        }
        "portal" {
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Mobility"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixSSO {
    throw "SSO must be configured manually on each provisioning policy."
}

function Invoke-FixFIDO2 {
    $msg = "This fix will enable FIDO2 security keys as an authentication method in your tenant.`n`n"
    $msg += "Current setting:`n    FIDO2 security key = Disabled`n`n"
    $msg += "New setting:`n    FIDO2 security key = Enabled for All users`n`n"
    $msg += "NOTE: This enables FIDO2 as an option for ALL users. It does not force anyone to use it — users without physical security keys can still sign in with other methods. For production tenants, consider scoping to specific groups via the portal."

    $result = Show-FixDialog -Title "Fix: FIDO2 Authentication Method" -Message $msg -Buttons @(
        @{ Label="Enable for All"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                '@odata.type' = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
                state = "enabled"
            }
            $apiResult = Invoke-GraphSafe -Uri "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2" `
                -Method "PATCH" -Body $body
            if ($apiResult._error) { throw "Failed to enable FIDO2: $($apiResult._error)" }
            return "FIDO2 security key authentication enabled for all users."
        }
        "portal" {
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixWHfBSecurityKey {
    $msg = "This fix will enable 'Use security keys for sign-in' in the Windows Hello for Business enrollment settings.`n`n"
    $msg += "Current setting:`n    Security keys for sign-in = Disabled`n`n"
    $msg += "New setting:`n    Security keys for sign-in = Enabled`n`n"
    $msg += "NOTE: This applies to ALL Windows devices enrolled after this change. Already-enrolled devices are not affected. This does NOT enable, configure, or require Windows Hello for Business itself."

    $result = Show-FixDialog -Title "Fix: Security Keys for Sign-In (WHfB)" -Message $msg -Buttons @(
        @{ Label="Enable"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            # Find the WHfB enrollment config
            $enrollConfigs = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations"
            if ($enrollConfigs._error) { throw "Could not query enrollment configs: $($enrollConfigs._error)" }

            $whfbPolicy = @(if ($enrollConfigs.value) { $enrollConfigs.value } else { @() }) |
                Where-Object { $_.'@odata.type' -like '*WindowsHelloForBusiness*' } |
                Select-Object -First 1

            if (-not $whfbPolicy) { throw "Windows Hello for Business enrollment configuration not found." }

            # Read-modify-write: roundtrip through JSON for a mutable object
            $json = $whfbPolicy | ConvertTo-Json -Depth 10
            $policy = $json | ConvertFrom-Json
            $policy.securityKeyForSignIn = "enabled"

            # Remove read-only properties
            foreach ($p in @('@odata.context','id','createdDateTime','lastModifiedDateTime','version','roleScopeTagIds')) {
                if ($policy.PSObject.Properties[$p]) { $policy.PSObject.Properties.Remove($p) }
            }

            $apiResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations/$($whfbPolicy.id)" `
                -Method "PATCH" -Body $policy
            if ($apiResult._error) { throw "Failed to update WHfB setting: $($apiResult._error)" }
            return "Security keys for sign-in enabled in WHfB settings."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/windowsHelloForBusiness"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixSecurityKeyProfile {
    $filterId = Get-OrCreateWCPCFilter

    # Create the custom profile
    $omaUri = "./Device/Vendor/MSFT/PassportForWork/SecurityKey/UseSecurityKeyForSignin"
    $msg = "This fix will create a custom Intune configuration profile that enables FIDO2 security key sign-in for Windows CPC Devices.`n`n"
    $msg += "What it creates:`n"
    $msg += "    Name: WCPCD Enable Security Keys at Sign-in`n"
    $msg += "    OMA-URI: .../SecurityKey/UseSecurityKeyForSignin`n"
    $msg += "    Value: 1 (Enabled)`n"
    $msg += "    Assigned to: All Devices`n"
    $msg += "    Filter: Include Windows CPC Devices (WCPC) only`n`n"
    $msg += "NOTE: This only targets Windows CPC Devices via the Intune filter. Other Windows devices are not affected."

    $result = Show-FixDialog -Title "Fix: Security Key Custom Profile" -Message $msg -Buttons @(
        @{ Label="Create Profile"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
                displayName   = 'WCPCD Enable Security Keys at Sign-in'
                description   = 'Enables FIDO Security Keys to be used during Windows Sign In on Windows CPC Devices'
                omaSettings   = @(
                    @{
                        '@odata.type' = '#microsoft.graph.omaSettingInteger'
                        displayName   = 'Turn on FIDO WCPCD Enable Security Keys at Sign-in'
                        description   = 'Enables FIDO2 security key sign-in'
                        omaUri        = $omaUri
                        value         = 1
                    }
                )
            }
            $createResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceConfigurations" -Method "POST" -Body $body
            if ($createResult._error) { throw "Failed to create profile: $($createResult._error)" }

            $profileId = $createResult.id

            # Assign to All Devices with WCPC filter
            $assignBody = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
                            deviceAndAppManagementAssignmentFilterId   = $filterId
                            deviceAndAppManagementAssignmentFilterType = 'include'
                        }
                    }
                )
            }
            $assignResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceConfigurations/$profileId/assign" -Method "POST" -Body $assignBody
            if ($assignResult._error) { throw "Profile created but assignment failed: $($assignResult._error)" }

            return "Created 'WCPCD Enable Security Keys at Sign-in' profile, assigned to All Devices with WCPC filter."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixTimeZone {
    $filterId = Get-OrCreateWCPCFilter

    $msg = "This fix will create a Settings Catalog policy that enables auto time zone detection on Windows CPC Devices.`n`n"
    $msg += "What it creates:`n"
    $msg += "    Name: WCPCD Enable Auto Time Zone Detection`n"
    $msg += "    Setting: Privacy → Let Apps Access Location = Force Allow`n"
    $msg += "    Assigned to: All Devices`n"
    $msg += "    Filter: Include Windows CPC Devices (WCPC) only`n`n"
    $msg += "This ensures Windows CPC Devices automatically detect and use the local time zone."

    $result = Show-FixDialog -Title "Fix: Auto-Detect Time Zone" -Message $msg -Buttons @(
        @{ Label="Create Policy"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                name         = "WCPCD Enable Auto Time Zone Detection"
                description  = "Enables auto time zone detection on Windows CPC Devices by allowing location access"
                platforms    = "windows10"
                technologies = "mdm"
                templateReference = @{
                    templateId = ""
                    templateFamily = "none"
                }
                settings     = @(
                    @{
                        settingInstance = @{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                            settingDefinitionId = 'device_vendor_msft_policy_config_privacy_letappsaccesslocation'
                            choiceSettingValue  = @{
                                value    = 'device_vendor_msft_policy_config_privacy_letappsaccesslocation_1'
                                children = @()
                            }
                        }
                    }
                )
            }
            $createResult = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies" -Method "POST" -Body $body
            if ($createResult._error) { throw "Failed to create policy: $($createResult._error)" }

            $policyId = $createResult.id

            # Assign to All Devices with WCPC filter
            $assignBody = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
                            deviceAndAppManagementAssignmentFilterId   = $filterId
                            deviceAndAppManagementAssignmentFilterType = 'include'
                        }
                    }
                )
            }
            $assignResult = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies/$policyId/assign" -Method "POST" -Body $assignBody
            if ($assignResult._error) { throw "Policy created but assignment failed: $($assignResult._error)" }

            return "Created 'WCPCD Enable Auto Time Zone Detection' policy, assigned to Windows CPC Devices."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixScreenTimeout {
    $filterId = Get-OrCreateWCPCFilter

    $timeoutSeconds = 600
    $timeoutMinutes = 10

    $msg = "This fix will create a Settings Catalog policy that sets the screen timeout for Windows CPC Devices.`n`n"
    $msg += "What it creates:`n"
    $msg += "    Name: WCPCD Set Screen Timeout`n"
    $msg += "    Setting: Turn off the display (plugged in) = Enabled`n"
    $msg += "    Timeout: $timeoutSeconds seconds ($timeoutMinutes minutes)`n"
    $msg += "    Assigned to: All Devices`n"
    $msg += "    Filter: Include Windows CPC Devices (WCPC) only`n`n"
    $msg += "The default is 5 minutes. This sets it to $timeoutMinutes minutes."

    $result = Show-FixDialog -Title "Fix: Screen Timeout" -Message $msg -Buttons @(
        @{ Label="Create Policy"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                name         = "WCPCD Set Screen Timeout"
                description  = "Sets screen timeout to $timeoutMinutes minutes on Windows CPC Devices"
                platforms    = "windows10"
                technologies = "mdm"
                templateReference = @{
                    templateId = ""
                    templateFamily = "none"
                }
                settings     = @(
                    @{
                        settingInstance = @{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                            settingDefinitionId = 'device_vendor_msft_policy_config_power_displayofftimeoutpluggedin'
                            choiceSettingValue  = @{
                                value    = 'device_vendor_msft_policy_config_power_displayofftimeoutpluggedin_1'
                                children = @(
                                    @{
                                        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                                        settingDefinitionId = 'device_vendor_msft_policy_config_power_displayofftimeoutpluggedin_entervideoacpowerdowntimeout'
                                        simpleSettingValue  = @{
                                            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'
                                            value         = $timeoutSeconds
                                        }
                                    }
                                )
                            }
                        }
                    }
                )
            }
            $createResult = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies" -Method "POST" -Body $body
            if ($createResult._error) { throw "Failed to create policy: $($createResult._error)" }

            $policyId = $createResult.id

            $assignBody = @{
                assignments = @(
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget'
                            deviceAndAppManagementAssignmentFilterId   = $filterId
                            deviceAndAppManagementAssignmentFilterType = 'include'
                        }
                    }
                )
            }
            $assignResult = Invoke-GraphSafe -Uri "/deviceManagement/configurationPolicies/$policyId/assign" -Method "POST" -Body $assignBody
            if ($assignResult._error) { throw "Policy created but assignment failed: $($assignResult._error)" }

            return "Created 'WCPCD Set Screen Timeout' policy ($timeoutMinutes min), assigned to Windows CPC Devices."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesWindowsMenu/~/configuration"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixIntuneFilter {
    $filterName = "Windows CPC Devices"
    $filterRule = '(device.operatingSystemSKU -eq "WCPC")'

    $msg = "This fix will create an Intune assignment filter for Windows CPC Devices.`n`n"
    $msg += "Filter name:`n    $filterName`n`n"
    $msg += "Platform:`n    Windows 10 and later`n`n"
    $msg += "Rule:`n    $filterRule`n`n"
    $msg += "This filter can be used to target or exclude Windows CPC Devices in policy assignments."

    $result = Show-FixDialog -Title "Fix: Intune Filter" -Message $msg -Buttons @(
        @{ Label="Create Filter"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Copy Rule"; Value="copy"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                displayName = $filterName
                description = "Targets Windows CPC Devices using operatingSystemSKU = WCPC"
                platform    = "windows10AndLater"
                rule        = $filterRule
            }
            $apiResult = Invoke-GraphSafe -Uri "/deviceManagement/assignmentFilters" -Method "POST" -Body $body
            if ($apiResult._error) { throw "Failed to create Intune filter: $($apiResult._error)" }
            return "Created Intune filter '$filterName'."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/assignmentFilter"
            return "Opened portal."
        }
        "copy" {
            [System.Windows.Clipboard]::SetText($filterRule)
            return "Filter rule copied to clipboard: $filterRule"
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixEnrollment {
    $filterId = Get-OrCreateWCPCFilter

    # Create the Allow enrollment restriction
    $msg = "This fix will create an enrollment restriction that allows Windows CPC Devices to enroll.`n`n"
    $msg += "What it creates:`n"
    $msg += "    Name: Allow Enrollment of Windows CPC Devices`n"
    $msg += "    Type: Windows platform restriction (Allow)`n"
    $msg += "    Assigned to: All Users`n"
    $msg += "    Filter: Include Windows CPC Devices (WCPC)`n`n"
    $msg += "The policy will be created at the highest priority so it takes precedence over any blocking policies."

    $result = Show-FixDialog -Title "Fix: Enrollment Restriction" -Message $msg -Buttons @(
        @{ Label="Create Policy"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            # Create per-platform restriction that allows Windows enrollment
            $body = @{
                '@odata.type'       = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'
                displayName         = 'Allow Enrollment of Windows CPC Devices'
                description         = 'Allows Windows CPC Devices to enroll even when personal devices are blocked'
                platformType        = 'windows'
                platformRestriction = @{
                    platformBlocked                  = $false
                    personalDeviceEnrollmentBlocked   = $false
                }
            }
            $createResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations" -Method "POST" -Body $body
            if ($createResult._error) { throw "Failed to create enrollment restriction: $($createResult._error)" }

            $policyId = $createResult.id

            # Assign to All Users with the WCPC filter (include)
            $assignBody = @{
                enrollmentConfigurationAssignments = @(
                    @{
                        target = @{
                            '@odata.type'                              = '#microsoft.graph.allLicensedUsersAssignmentTarget'
                            deviceAndAppManagementAssignmentFilterId   = $filterId
                            deviceAndAppManagementAssignmentFilterType = 'include'
                        }
                    }
                )
            }
            $assignResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations/$policyId/assign" -Method "POST" -Body $assignBody
            if ($assignResult._error) { throw "Policy created but assignment failed: $($assignResult._error)" }

            # Set priority to 1 (highest after the immovable default at 0)
            $priBody = @{ priority = 1 }
            $priResult = Invoke-GraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations/$policyId/setPriority" -Method "POST" -Body $priBody
            if ($priResult._error) {
                Write-ModuleLog "Warning: Policy created but could not set priority: $($priResult._error)" "WARN"
            }

            return "Created 'Allow Enrollment of Windows CPC Devices' policy at highest priority, assigned to All Users with WCPC filter."
        }
        "portal" {
            Start-Process "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesEnrollmentMenu/~/platformRestrictions"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-FixCAUserAction {
    $msg = "This fix will create a Conditional Access policy for the user action 'Register or join devices'.`n`n"
    $msg += "What it creates:`n"
    $msg += "    Name: MFA for Device Join or Registration`n"
    $msg += "    Assigned to: All Users`n"
    $msg += "    Target: User action 'Register or join devices'`n"
    $msg += "    Grant: Require multifactor authentication`n"
    $msg += "    State: Report-only (NOT enforced)`n`n"
    $msg += "NOTE: This policy requires MFA whenever any Windows device is joined to Entra ID — not just Windows CPC Devices. Review the scope carefully before enabling.`n`n"
    $msg += "IMPORTANT: The policy will be created in Report-only mode. You must review the settings and enable it manually."

    $result = Show-FixDialog -Title "Fix: Register or Join Devices Policy" -Message $msg -Buttons @(
        @{ Label="Create in Report-Only"; Value="apply"; Style="Primary" },
        @{ Label="Open in Portal"; Value="portal"; Style="Neutral" },
        @{ Label="Cancel"; Value="cancel"; Style="Neutral" }
    )

    switch ($result) {
        "apply" {
            $body = @{
                displayName = "MFA for Device Join or Registration"
                state       = "enabledForReportingButNotEnforced"
                conditions  = @{
                    users = @{
                        includeUsers = @("All")
                    }
                    applications = @{
                        includeUserActions = @("urn:user:registerdevice")
                    }
                }
                grantControls = @{
                    operator        = "OR"
                    builtInControls = @("mfa")
                }
            }
            $apiResult = Invoke-GraphSafe -Uri "/identity/conditionalAccess/policies" -Method "POST" -Body $body
            if ($apiResult._error) { throw "Failed to create CA policy: $($apiResult._error)" }

            $confirmResult = Show-FixDialog -Title "Policy Created — Action Required" -Icon "Warning" -Message "The policy 'MFA for Device Join or Registration' has been created in Report-only mode.`n`nIMPORTANT: This policy is NOT enforced yet.`n`nNext steps:`n    1. Open the policy in the Entra portal`n    2. Review the settings and assignments`n    3. Add any exclusions (break-glass accounts)`n    4. Change the state from Report-only to On" -Buttons @(
                @{ Label="Open in Portal"; Value="portal"; Style="Primary" },
                @{ Label="OK"; Value="ok"; Style="Neutral" }
            )

            if ($confirmResult -eq "portal") {
                Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
            }

            return "Created CA policy 'MFA for Device Join or Registration' in Report-only mode."
        }
        "portal" {
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
            return "Opened portal."
        }
        default { throw "Cancelled by user." }
    }
}

function Invoke-Fix {
    param([string]$FixAction)
    switch ($FixAction) {
        "fix-entra-join"        { Invoke-FixEntraJoin }
        "fix-mdm-scope"         { Invoke-FixMDMScope }
        "fix-enrollment"        { Invoke-FixEnrollment }
        "fix-ca-useraction"     { Invoke-FixCAUserAction }
        "fix-sso"               { Invoke-FixSSO }
        "fix-fido2"             { Invoke-FixFIDO2 }
        "fix-whfb-seckey"       { Invoke-FixWHfBSecurityKey }
        "fix-seckey-profile"    { Invoke-FixSecurityKeyProfile }
        "fix-timezone"          { Invoke-FixTimeZone }
        "fix-screen-timeout"    { Invoke-FixScreenTimeout }
        "fix-intune-filter"     { Invoke-FixIntuneFilter }
        default                 { throw "Unknown fix action: $FixAction" }
    }
}

# ============================================================================
# REGION: WPF GUI
# ============================================================================
function Start-WinCPCTenantSetupGUI {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

    # Enable per-monitor DPI awareness for crisp text on all monitors
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DpiHelper {
    [DllImport("shcore.dll")]
    public static extern int SetProcessDpiAwareness(int awareness);
}
"@ -ErrorAction SilentlyContinue
        [DpiHelper]::SetProcessDpiAwareness(2) | Out-Null  # 2 = Per-Monitor DPI Aware
    } catch {}

    # ---- XAML ----
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Tenant Setup for Cloud PC Devices"
        Width="920" Height="720" MinWidth="780" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        Background="#f5f5f5"
        FontFamily="Segoe UI"
        TextOptions.TextFormattingMode="Display"
        TextOptions.TextRenderingMode="ClearType"
        RenderOptions.ClearTypeHint="Enabled"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True">
    <Window.Resources>
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="#0078d4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#106ebe"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#cccccc"/>
                                <Setter Property="Foreground" Value="#888888"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="#e1e1e1"/>
            <Setter Property="Foreground" Value="#1b1b1b"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#c8c8c8"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#f0f0f0"/>
                                <Setter Property="Foreground" Value="#aaaaaa"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="FixButton" TargetType="Button">
            <Setter Property="Background" Value="#107c10"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Margin" Value="4,0,0,0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="3" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#0e6b0e"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#cccccc"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="IgnoreButton" TargetType="Button">
            <Setter Property="Background" Value="#888888"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Margin" Value="4,0,0,0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="3" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#666666"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="PillButton" TargetType="Button">
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Opacity" Value="0.8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="140"/>
        </Grid.RowDefinitions>

        <!-- HEADER -->
        <Border Grid.Row="0" Background="#1b1b1b" Padding="24,16">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <TextBlock Text="Windows 365 Cloud PC Devices" FontSize="20" FontWeight="Bold" Foreground="White"/>
                    <TextBlock Text="Tenant Configuration Tool  v$($script:ToolVersion)" FontSize="13" Foreground="#aaaaaa" Margin="0,2,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" HorizontalAlignment="Right">
                    <TextBlock x:Name="txtConnection" Text="Not connected  " Foreground="#ff6666"
                               VerticalAlignment="Center" FontSize="12" Margin="0,0,12,0"/>
                    <Button x:Name="btnConnect" Content="Connect to Tenant" Style="{StaticResource PrimaryButton}"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- SCORE BAR -->
        <Border Grid.Row="1" Background="White" BorderBrush="#e1e1e1" BorderThickness="0,0,0,1" Padding="24,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,16,0">
                    <TextBlock Text="Readiness:" FontSize="14" FontWeight="SemiBold" VerticalAlignment="Center"/>
                    <TextBlock x:Name="txtScore" Text=" —" FontSize="14" FontWeight="Bold"
                               Foreground="#0078d4" VerticalAlignment="Center" Margin="4,0,0,0"/>
                </StackPanel>
                <StackPanel x:Name="panelPills" Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center"/>
                <Button x:Name="btnAssess" Grid.Column="3" Content="Run Assessment"
                        Style="{StaticResource PrimaryButton}" IsEnabled="False"/>
                <Button x:Name="btnExport" Grid.Column="4" Content="Export Report"
                        Style="{StaticResource SecondaryButton}" IsEnabled="False" Margin="8,0,0,0"/>
            </Grid>
        </Border>

        <!-- CHECK RESULTS LIST -->
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" Padding="24,8">
            <StackPanel x:Name="panelChecks">
                <TextBlock Text="Connect to a tenant and run the assessment to see results."
                           FontSize="13" Foreground="#707070" HorizontalAlignment="Center"
                           Margin="0,40,0,0"/>
            </StackPanel>
        </ScrollViewer>

        <!-- SEPARATOR -->
        <GridSplitter Grid.Row="3" Height="4" HorizontalAlignment="Stretch"
                      Background="#e1e1e1" ResizeDirection="Rows" ShowsPreview="True"/>

        <!-- LOG PANEL -->
        <Border Grid.Row="4" Background="#1e1e1e" Padding="12,8">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Text="Activity Log" FontSize="11" Foreground="#888888"
                           FontWeight="SemiBold" Margin="0,0,0,4"/>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" x:Name="scrollLog">
                    <TextBox x:Name="txtLog" FontFamily="Cascadia Mono,Consolas,Courier New"
                               FontSize="11" Foreground="#cccccc" Background="Transparent"
                               BorderThickness="0" IsReadOnly="True" TextWrapping="Wrap"/>
                </ScrollViewer>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

    # ---- Create Window ----
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $script:Window = $window

    # ---- Get Controls ----
    $btnConnect  = $window.FindName("btnConnect")
    $txtConnection = $window.FindName("txtConnection")
    $btnAssess   = $window.FindName("btnAssess")
    $btnExport   = $window.FindName("btnExport")
    $txtScore    = $window.FindName("txtScore")
    $panelPills  = $window.FindName("panelPills")
    $panelChecks = $window.FindName("panelChecks")
    $txtLog      = $window.FindName("txtLog")
    $scrollLog   = $window.FindName("scrollLog")


    # ---- Log Helper ----
    $script:LogLines = [System.Text.StringBuilder]::new()
    function Write-Log {
        param([string]$Message, [string]$Tag = "INFO")
        $timestamp = Get-Date -Format "HH:mm:ss"
        $line = "[$timestamp] $($Tag.PadRight(6)) $Message"
        $null = $script:LogLines.AppendLine($line)
        $txtLog.Text = $script:LogLines.ToString()
        $scrollLog.ScrollToEnd()
        $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    }

    # Wire up the module-level logging callback
    $script:WriteLog = { param($Message, $Tag) Write-Log $Message $Tag }

    # ---- Filter State ----
    $script:HiddenStatuses = [System.Collections.Generic.HashSet[string]]::new()

    function Update-Pills {
        $panelPills.Children.Clear()
        $pillDefs = @(
            @{ Status="Pass"; Label="Passed"; Bg="#dff6dd"; Fg="#107c10"; BgOff="#f0f0f0"; FgOff="#aaaaaa" },
            @{ Status="Fail"; Label="Failed"; Bg="#fde7e9"; Fg="#d13438"; BgOff="#f0f0f0"; FgOff="#aaaaaa" },
            @{ Status="Warning"; Label="Warnings"; Bg="#fff4ce"; Fg="#e87400"; BgOff="#f0f0f0"; FgOff="#aaaaaa" },
            @{ Status="Info"; Label="Info"; Bg="#deecf9"; Fg="#0078d4"; BgOff="#f0f0f0"; FgOff="#aaaaaa" }
        )

        foreach ($def in $pillDefs) {
            $count = @($script:CheckResults | Where-Object { $_.Status -eq $def.Status }).Count
            if ($count -eq 0) { continue }

            $isHidden = $script:HiddenStatuses.Contains($def.Status)
            $bg = if ($isHidden) { $def.BgOff } else { $def.Bg }
            $fg = if ($isHidden) { $def.FgOff } else { $def.Fg }

            $pill = [System.Windows.Controls.Button]::new()
            $pill.Tag = $def.Status
            $pill.Margin = [System.Windows.Thickness]::new(0,0,6,0)
            $pill.Cursor = [System.Windows.Input.Cursors]::Hand
            $pill.ToolTip = if ($isHidden) { "Show $($def.Label)" } else { "Hide $($def.Label)" }
            $pill.Background = $script:BC.ConvertFrom($bg)
            $pill.BorderThickness = [System.Windows.Thickness]::new(0)
            $pill.Padding = [System.Windows.Thickness]::new(10,4,10,4)
            $pill.Style = $window.FindResource("PillButton")

            $pillPanel = [System.Windows.Controls.StackPanel]::new()
            $pillPanel.Orientation = "Horizontal"

            $pillCount = [System.Windows.Controls.TextBlock]::new()
            $pillCount.Text = "$count"
            $pillCount.FontSize = 16
            $pillCount.FontWeight = "Bold"
            $pillCount.Foreground = $script:BC.ConvertFrom($fg)
            $pillCount.VerticalAlignment = "Center"

            $pillLabel = [System.Windows.Controls.TextBlock]::new()
            $pillLabel.Text = " $($def.Label)"
            $pillLabel.FontSize = 11
            $pillLabel.Foreground = $script:BC.ConvertFrom($fg)
            $pillLabel.VerticalAlignment = "Center"

            $pillPanel.Children.Add($pillCount) | Out-Null
            $pillPanel.Children.Add($pillLabel) | Out-Null
            $pill.Content = $pillPanel

            $pill.Add_Click({
                param($sender, $e)
                $status = $sender.Tag
                if ($script:HiddenStatuses.Contains($status)) {
                    $script:HiddenStatuses.Remove($status) | Out-Null
                } else {
                    $script:HiddenStatuses.Add($status) | Out-Null
                }
                Update-Dashboard
            })

            $panelPills.Children.Add($pill) | Out-Null
        }
    }

    # ---- Build Check Row UI ----
    # Cached brush converter for performance
    $script:BC = [System.Windows.Media.BrushConverter]::new()

    function New-CheckRow {
        param([PSCustomObject]$Check)

        $statusColors = @{
            "Pass"    = @{ Bg = "#dff6dd"; Fg = "#107c10"; Icon = [char]0x2705 }
            "Fail"    = @{ Bg = "#fde7e9"; Fg = "#d13438"; Icon = [char]0x274C }
            "Warning" = @{ Bg = "#fff4ce"; Fg = "#e87400"; Icon = [char]0x26A0 }
            "Info"    = @{ Bg = "#deecf9"; Fg = "#0078d4"; Icon = [char]0x2139 }
            "Error"   = @{ Bg = "#f3e8f9"; Fg = "#881798"; Icon = [char]0x26D4 }
        }

        $colors = $statusColors[$Check.Status]

        # Unique key for this check (used for ignore tracking)
        $checkKey = "$($Check.Category)|$($Check.CheckName)"
        $isIgnored = $script:IgnoredChecks.Contains($checkKey)

        # Override colors if ignored
        if ($isIgnored) {
            $colors = @{ Bg = "#f0f0f0"; Fg = "#999999"; Icon = [char]0x2796 }
        }

        # Outer border for the check row
        $border = [System.Windows.Controls.Border]::new()
        $bgColor = if ($isIgnored) { "#fafafa" } else { "White" }
        $border.Background    = $script:BC.ConvertFrom($bgColor)
        $border.BorderBrush   = $script:BC.ConvertFrom("#e1e1e1")
        $border.BorderThickness = [System.Windows.Thickness]::new(1)
        $border.CornerRadius  = [System.Windows.CornerRadius]::new(4)
        $border.Margin        = [System.Windows.Thickness]::new(0,4,0,0)
        $border.Padding       = [System.Windows.Thickness]::new(12,10,12,10)

        $grid = [System.Windows.Controls.Grid]::new()
        $col1 = [System.Windows.Controls.ColumnDefinition]::new()
        $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $col2 = [System.Windows.Controls.ColumnDefinition]::new()
        $col2.Width = [System.Windows.GridLength]::Auto
        $grid.ColumnDefinitions.Add($col1)
        $grid.ColumnDefinitions.Add($col2)

        # Left: status + name + detail
        $leftPanel = [System.Windows.Controls.StackPanel]::new()

        $headerPanel = [System.Windows.Controls.WrapPanel]::new()
        $headerPanel.VerticalAlignment = "Center"

        # Status badge
        $badge = [System.Windows.Controls.Border]::new()
        $badge.Background    = $script:BC.ConvertFrom($colors.Bg)
        $badge.CornerRadius  = [System.Windows.CornerRadius]::new(3)
        $badge.Padding       = [System.Windows.Thickness]::new(6,2,6,2)
        $badge.Margin        = [System.Windows.Thickness]::new(0,0,8,0)

        $badgeText = [System.Windows.Controls.TextBlock]::new()
        $badgeText.Text       = if ($isIgnored) { "IGNORED" } else { $Check.Status.ToUpper() }
        $badgeText.FontSize   = 10
        $badgeText.FontWeight = "Bold"
        $badgeText.Foreground = $script:BC.ConvertFrom($colors.Fg)
        $badge.Child = $badgeText
        $headerPanel.Children.Add($badge) | Out-Null

        # Category + check name
        $nameBlock = [System.Windows.Controls.TextBlock]::new()
        $nameBlock.FontSize   = 13
        $nameBlock.FontWeight = "SemiBold"
        $nameBlock.Foreground = $script:BC.ConvertFrom("#1b1b1b")
        $nameBlock.Text       = "$($Check.Category) — $($Check.CheckName)"
        $headerPanel.Children.Add($nameBlock) | Out-Null

        # Risk badge (if applicable)
        if ($Check.RiskLevel -and $Check.Status -in @("Fail","Warning")) {
            $riskColors = @{
                "Critical" = @{ Bg = "#d13438"; Fg = "White" }
                "High"     = @{ Bg = "#e87400"; Fg = "White" }
                "Medium"   = @{ Bg = "#fff4ce"; Fg = "#7a6400" }
                "Low"      = @{ Bg = "#f0f0f0"; Fg = "#707070" }
            }
            $rc = $riskColors[$Check.RiskLevel]
            $riskBadge = [System.Windows.Controls.Border]::new()
            $riskBadge.Background   = $script:BC.ConvertFrom($rc.Bg)
            $riskBadge.CornerRadius = [System.Windows.CornerRadius]::new(3)
            $riskBadge.Padding      = [System.Windows.Thickness]::new(6,2,6,2)
            $riskBadge.Margin       = [System.Windows.Thickness]::new(6,0,0,0)
            $riskBadge.VerticalAlignment = "Center"

            $riskText = [System.Windows.Controls.TextBlock]::new()
            $riskText.Text       = "$($Check.RiskLevel) Risk"
            $riskText.FontSize   = 9
            $riskText.FontWeight = "Bold"
            $riskText.Foreground = $script:BC.ConvertFrom($rc.Fg)
            $riskText.VerticalAlignment = "Center"
            $riskBadge.Child = $riskText
            $headerPanel.Children.Add($riskBadge) | Out-Null
        }

        $leftPanel.Children.Add($headerPanel) | Out-Null

        # Detail text
        $detailBlock = [System.Windows.Controls.TextBlock]::new()
        $detailBlock.Text         = $Check.Detail
        $detailBlock.FontSize     = 12
        $detailBlock.Foreground   = $script:BC.ConvertFrom("#505050")
        $detailBlock.TextWrapping = "Wrap"
        $detailBlock.Margin       = [System.Windows.Thickness]::new(0,4,0,0)
        $leftPanel.Children.Add($detailBlock) | Out-Null

        # Remediation text (if present)
        if ($Check.Remediation) {
            $remBlock = [System.Windows.Controls.TextBlock]::new()
            $remBlock.FontSize     = 11
            $remBlock.Foreground   = $script:BC.ConvertFrom("#707070")
            $remBlock.TextWrapping = "Wrap"
            $remBlock.Margin       = [System.Windows.Thickness]::new(0,4,0,0)
            $remBlock.Text = "Remediation: $($Check.Remediation)"
            $leftPanel.Children.Add($remBlock) | Out-Null
        }

        # Links row (Learn More + Open in Portal) with copy buttons
        if ($Check.LearnMoreUrl -or $Check.PortalUrl) {
            $linkPanel = [System.Windows.Controls.WrapPanel]::new()
            $linkPanel.Margin = [System.Windows.Thickness]::new(0,4,0,0)

            if ($Check.LearnMoreUrl) {
                $copyDoc = [System.Windows.Controls.TextBlock]::new()
                $copyDoc.Text = [char]0xE8C8
                $copyDoc.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe MDL2 Assets")
                $copyDoc.FontSize = 12
                $copyDoc.Foreground = $script:BC.ConvertFrom("#0078d4")
                $copyDoc.Cursor = [System.Windows.Input.Cursors]::Hand
                $copyDoc.ToolTip = "Copy link"
                $copyDoc.VerticalAlignment = "Center"
                $copyDoc.Margin = [System.Windows.Thickness]::new(0,0,4,0)
                $copyDoc.Tag = $Check.LearnMoreUrl
                $copyDoc.Add_MouseLeftButtonUp({
                    param($sender, $e)
                    [System.Windows.Clipboard]::SetText($sender.Tag)
                    $sender.Text = [char]0xE73E
                    $sender.Foreground = $script:BC.ConvertFrom("#107c10")
                    Write-Log "Copied: $($sender.Tag)" "INFO"
                    $timer = [System.Windows.Threading.DispatcherTimer]::new()
                    $timer.Interval = [TimeSpan]::FromSeconds(1.5)
                    $timer.Tag = $sender
                    $timer.Add_Tick({
                        param($t, $e)
                        $t.Tag.Text = [char]0xE8C8
                        $t.Tag.Foreground = $script:BC.ConvertFrom("#0078d4")
                        $t.Stop()
                    })
                    $timer.Start()
                })
                $linkPanel.Children.Add($copyDoc) | Out-Null

                $docBlock = [System.Windows.Controls.TextBlock]::new()
                $docBlock.FontSize = 11
                $docBlock.VerticalAlignment = "Center"
                $docLink = [System.Windows.Documents.Hyperlink]::new()
                $docLink.Inlines.Add("Learn More") | Out-Null
                $docLink.NavigateUri = [Uri]::new($Check.LearnMoreUrl)
                $docLink.Foreground = $script:BC.ConvertFrom("#0078d4")
                $docLink.TextDecorations = $null
                $docLink.Add_RequestNavigate({
                    param($sender, $e)
                    Start-Process $e.Uri.AbsoluteUri
                    $e.Handled = $true
                })
                $docBlock.Inlines.Add($docLink) | Out-Null
                $linkPanel.Children.Add($docBlock) | Out-Null
            }

            if ($Check.LearnMoreUrl -and $Check.PortalUrl) {
                $sepBlock = [System.Windows.Controls.TextBlock]::new()
                $sepBlock.Text = "    |    "
                $sepBlock.Foreground = $script:BC.ConvertFrom("#cccccc")
                $sepBlock.FontSize = 11
                $sepBlock.VerticalAlignment = "Center"
                $linkPanel.Children.Add($sepBlock) | Out-Null
            }

            if ($Check.PortalUrl) {
                $copyPortal = [System.Windows.Controls.TextBlock]::new()
                $copyPortal.Text = [char]0xE8C8
                $copyPortal.FontFamily = [System.Windows.Media.FontFamily]::new("Segoe MDL2 Assets")
                $copyPortal.FontSize = 12
                $copyPortal.Foreground = $script:BC.ConvertFrom("#0078d4")
                $copyPortal.Cursor = [System.Windows.Input.Cursors]::Hand
                $copyPortal.ToolTip = "Copy link"
                $copyPortal.VerticalAlignment = "Center"
                $copyPortal.Margin = [System.Windows.Thickness]::new(0,0,4,0)
                $copyPortal.Tag = $Check.PortalUrl
                $copyPortal.Add_MouseLeftButtonUp({
                    param($sender, $e)
                    [System.Windows.Clipboard]::SetText($sender.Tag)
                    $sender.Text = [char]0xE73E
                    $sender.Foreground = $script:BC.ConvertFrom("#107c10")
                    Write-Log "Copied: $($sender.Tag)" "INFO"
                    $timer = [System.Windows.Threading.DispatcherTimer]::new()
                    $timer.Interval = [TimeSpan]::FromSeconds(1.5)
                    $timer.Tag = $sender
                    $timer.Add_Tick({
                        param($t, $e)
                        $t.Tag.Text = [char]0xE8C8
                        $t.Tag.Foreground = $script:BC.ConvertFrom("#0078d4")
                        $t.Stop()
                    })
                    $timer.Start()
                })
                $linkPanel.Children.Add($copyPortal) | Out-Null

                $portalBlock = [System.Windows.Controls.TextBlock]::new()
                $portalBlock.FontSize = 11
                $portalBlock.VerticalAlignment = "Center"
                $portalLink = [System.Windows.Documents.Hyperlink]::new()
                $portalLink.Inlines.Add("Open in Portal →") | Out-Null
                $portalLink.NavigateUri = [Uri]::new($Check.PortalUrl)
                $portalLink.Foreground = $script:BC.ConvertFrom("#0078d4")
                $portalLink.TextDecorations = $null
                $portalLink.Add_RequestNavigate({
                    param($sender, $e)
                    Start-Process $e.Uri.AbsoluteUri
                    $e.Handled = $true
                })
                $portalBlock.Inlines.Add($portalLink) | Out-Null
                $linkPanel.Children.Add($portalBlock) | Out-Null
            }

            # Show Criteria link
            if ($Check.Criteria) {
                if ($Check.LearnMoreUrl -or $Check.PortalUrl) {
                    $sep2 = [System.Windows.Controls.TextBlock]::new()
                    $sep2.Text = "    |    "
                    $sep2.Foreground = $script:BC.ConvertFrom("#cccccc")
                    $sep2.FontSize = 11
                    $sep2.VerticalAlignment = "Center"
                    $linkPanel.Children.Add($sep2) | Out-Null
                }

                $criteriaBtn = [System.Windows.Controls.Button]::new()
                $criteriaBtn.Content = "Show Criteria"
                $criteriaBtn.Tag = "$($Check.CheckName)|||$($Check.Criteria)"
                $criteriaBtn.FontSize = 11
                $criteriaBtn.Foreground = $script:BC.ConvertFrom("#0078d4")
                $criteriaBtn.Background = [System.Windows.Media.Brushes]::Transparent
                $criteriaBtn.BorderThickness = [System.Windows.Thickness]::new(0)
                $criteriaBtn.Cursor = [System.Windows.Input.Cursors]::Hand
                $criteriaBtn.Padding = [System.Windows.Thickness]::new(0)
                $criteriaBtn.VerticalAlignment = "Center"
                $criteriaBtn.Add_Click({
                    param($sender, $e)
                    $parts = $sender.Tag -split '\|\|\|', 2
                    $checkName = $parts[0]
                    $criteria = $parts[1]
                    Show-FixDialog -Title "Criteria: $checkName" -Icon "Info" -Message $criteria -Buttons @(
                        @{ Label="OK"; Value="ok"; Style="Primary" }
                    )
                })
                $linkPanel.Children.Add($criteriaBtn) | Out-Null
            }

            $leftPanel.Children.Add($linkPanel) | Out-Null
        }

        [System.Windows.Controls.Grid]::SetColumn($leftPanel, 0)
        $grid.Children.Add($leftPanel) | Out-Null

        # Right: button panel
        $btnPanel = [System.Windows.Controls.StackPanel]::new()
        $btnPanel.Orientation = "Horizontal"
        $btnPanel.VerticalAlignment = "Center"

        # Ignore/Undo button (for Warning and Fail items)
        if ($Check.Status -in @("Fail","Warning")) {
            $ignoreBtn = [System.Windows.Controls.Button]::new()
            $ignoreBtn.Tag = $checkKey
            $ignoreBtn.VerticalAlignment = "Center"

            if ($isIgnored) {
                $ignoreBtn.Content = "Undo"
                $ignoreBtn.Style = $window.FindResource("IgnoreButton")
            } else {
                $ignoreBtn.Content = "Ignore"
                $ignoreBtn.Style = $window.FindResource("IgnoreButton")
            }

            $ignoreBtn.Add_Click({
                param($sender, $e)
                $key = $sender.Tag
                if ($script:IgnoredChecks.Contains($key)) {
                    $script:IgnoredChecks.Remove($key) | Out-Null
                    Write-Log "Unignored: $key" "INFO"
                } else {
                    $script:IgnoredChecks.Add($key) | Out-Null
                    Write-Log "Ignored: $key" "INFO"
                }
                Update-Dashboard
            })

            $btnPanel.Children.Add($ignoreBtn) | Out-Null
        }

        # Fix button (if applicable and not ignored)
        if ($Check.CanFix -and $Check.Status -in @("Fail","Warning") -and -not $isIgnored) {
            $fixBtn = [System.Windows.Controls.Button]::new()
            $fixBtn.Content = "Fix"
            $fixBtn.Tag     = $Check.FixAction
            $fixBtn.VerticalAlignment = "Center"
            $fixBtn.Style   = $window.FindResource("FixButton")
            $fixBtn.Margin  = [System.Windows.Thickness]::new(6,0,0,0)

            $fixBtn.Add_Click({
                param($sender, $e)
                $action = $sender.Tag
                $sender.IsEnabled = $false
                $sender.Content = "Fixing..."
                try {
                    Write-Log "Starting fix: $action" "ACTION"
                    $msg = Invoke-Fix -FixAction $action
                    Write-Log $msg "OK"
                    $sender.Content = "Done"
                    # Only re-run assessment if an actual change was made (not portal/clipboard)
                    if ($msg -notmatch 'Opened|clipboard|Cancelled') {
                        Write-Log "Re-running assessment..." "INFO"
                        $btnAssess.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
                    } else {
                        $sender.Content = "Fix"
                        $sender.IsEnabled = $true
                    }
                } catch {
                    $err = $_.Exception.Message
                    if ($err -match 'Cancelled') {
                        Write-Log "Fix cancelled by user." "INFO"
                        $sender.Content = "Fix"
                        $sender.IsEnabled = $true
                    } else {
                        Write-Log "Fix failed: $err" "FAIL"
                        $sender.Content = "Failed"
                        $sender.IsEnabled = $true
                    }
                }
            })

            $btnPanel.Children.Add($fixBtn) | Out-Null
        }

        if ($btnPanel.Children.Count -gt 0) {
            [System.Windows.Controls.Grid]::SetColumn($btnPanel, 1)
            $grid.Children.Add($btnPanel) | Out-Null
        }

        $border.Child = $grid
        return $border
    }

    # ---- Render Results ----
    function Update-Dashboard {
        $panelChecks.Children.Clear()

        if ($script:CheckResults.Count -eq 0) {
            $empty = [System.Windows.Controls.TextBlock]::new()
            $empty.Text = "No results yet. Click 'Run Assessment' to check your tenant."
            $empty.FontSize = 13
            $empty.Foreground = $script:BC.ConvertFrom("#707070")
            $empty.HorizontalAlignment = "Center"
            $empty.Margin = [System.Windows.Thickness]::new(0,40,0,0)
            $panelChecks.Children.Add($empty) | Out-Null
            return
        }

        # Update filter pills
        Update-Pills

        # Group by category, filter by hidden statuses
        $categories = $script:CheckResults | Select-Object -ExpandProperty Category -Unique
        foreach ($cat in $categories) {
            $catChecks = @($script:CheckResults | Where-Object { $_.Category -eq $cat })
            $visibleChecks = @($catChecks | Where-Object { -not $script:HiddenStatuses.Contains($_.Status) })

            if ($visibleChecks.Count -eq 0) { continue }

            # Category header
            $catHeader = [System.Windows.Controls.TextBlock]::new()
            $catHeader.Text       = $cat
            $catHeader.FontSize   = 15
            $catHeader.FontWeight = "SemiBold"
            $catHeader.Foreground = $script:BC.ConvertFrom("#1b1b1b")
            $catHeader.Margin     = [System.Windows.Thickness]::new(0,16,0,4)
            $panelChecks.Children.Add($catHeader) | Out-Null

            foreach ($check in $visibleChecks) {
                $row = New-CheckRow -Check $check
                $panelChecks.Children.Add($row) | Out-Null
            }
        }

        # Update score (ignored items don't count)
        $nonIgnored = @($script:CheckResults | Where-Object {
            $key = "$($_.Category)|$($_.CheckName)"
            -not $script:IgnoredChecks.Contains($key)
        })
        $pass = @($nonIgnored | Where-Object { $_.Status -eq "Pass" }).Count
        $actionable = @($nonIgnored | Where-Object { $_.Status -in @("Pass","Fail","Warning") }).Count
        $ignored = $script:IgnoredChecks.Count
        $score = if ($actionable -gt 0) { [math]::Round(($pass / $actionable) * 100) } else { 0 }

        $scoreText = "$score%"
        if ($ignored -gt 0) { $scoreText += " ($ignored ignored)" }
        $txtScore.Text = $scoreText

        $scoreColor = Get-ScoreColor $score
        $txtScore.Foreground = $script:BC.ConvertFrom($scoreColor)

        $btnExport.IsEnabled = $true
    }

    # ---- Event: Connect / Disconnect ----
    $btnConnect.Add_Click({
        # Disconnect flow
        if ($btnConnect.Tag -eq 'connected') {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
            $script:GraphConnected = $false
            $script:TenantInfo = @{}
            $script:CheckResults.Clear()
            $script:IgnoredChecks.Clear()

            $txtConnection.Text = "Not connected  "
            $txtConnection.Foreground = $script:BC.ConvertFrom("#ff6666")
            $btnConnect.Content = "Connect to Tenant"
            $btnConnect.Background = $script:BC.ConvertFrom("#0078d4")
            $btnConnect.Tag = $null
            $btnAssess.IsEnabled = $false
            $btnExport.IsEnabled = $false
            $txtScore.Text = " —"
            $panelChecks.Children.Clear()
            $empty = [System.Windows.Controls.TextBlock]::new()
            $empty.Text = "Connect to a tenant and run the assessment to see results."
            $empty.FontSize = 13
            $empty.Foreground = $script:BC.ConvertFrom("#707070")
            $empty.HorizontalAlignment = "Center"
            $empty.Margin = [System.Windows.Thickness]::new(0,40,0,0)
            $panelChecks.Children.Add($empty) | Out-Null
            Write-Log "Disconnected." "OK"
            return
        }

        # Connect flow
        $btnConnect.IsEnabled = $false
        $btnConnect.Content = "Connecting..."
        try {
            # Check for Graph module
            if (-not (Test-GraphModule)) {
                Write-Log "Microsoft.Graph module not found. Installing..." "WARN"
                $result = [System.Windows.MessageBox]::Show(
                    "Microsoft.Graph PowerShell module is required but not installed.`n`nInstall it now?",
                    "Module Required", "YesNo", "Question")
                if ($result -eq "Yes") {
                    Write-Log "Installing Microsoft.Graph module..." "ACTION"
                    Install-GraphModule
                    Write-Log "Module installed successfully." "OK"
                } else {
                    Write-Log "Module installation cancelled." "WARN"
                    $btnConnect.Content = "Connect to Tenant"
                    $btnConnect.IsEnabled = $true
                    return
                }
            }

            Write-Log "Connecting to Microsoft Graph..." "ACTION"
            $context = Connect-W365Graph
            Write-Log "Connected as: $($context.Account)" "OK"
            Write-Log "Tenant: $($script:TenantInfo['TenantName']) ($($script:TenantInfo['TenantId']))" "OK"

            $txtConnection.Text = "$($context.Account)  "
            $txtConnection.Foreground = $script:BC.ConvertFrom("#66ff66")
            $btnConnect.Content = [char]0x2713 + " Disconnect"
            $btnConnect.Background = $script:BC.ConvertFrom("#107c10")
            $btnConnect.Tag = 'connected'
            $btnConnect.IsEnabled = $true
            $btnAssess.IsEnabled = $true
        }
        catch {
            $err = $_.Exception.Message
            Write-Log "Connection failed: $err" "FAIL"
            $txtConnection.Text = "Connection failed  "
            $btnConnect.Content = "Connect to Tenant"
            $btnConnect.IsEnabled = $true
        }
    })

    # ---- Event: Assess ----
    $btnAssess.Add_Click({
        $btnAssess.IsEnabled = $false
        $btnAssess.Content = "Running..."
        $txtScore.Text = " ..."

        try {
            Write-Log "Starting tenant assessment..." "ACTION"

            $checkNames = @(
                "Licensing", "Entra Device Join", "MDM Auto-Enrollment",
                "Enrollment Restrictions", "Cloud PC SSO", "Conditional Access",
                "Authentication Methods", "Device Configuration", "Screen Timeout", "Intune Filters"
            )

            $script:CheckResults.Clear()
            Clear-PolicyCache

            $checkFunctions = @(
                { Test-W365Licensing },
                { Test-W365EntraDeviceJoin },
                { Test-W365MDMScope },
                { Test-W365EnrollmentRestrictions },
                { Test-W365CloudPCSSO },
                { Test-W365ConditionalAccess },
                { Test-W365AuthMethods },
                { Test-W365TimeZone },
                { Test-W365ScreenTimeout },
                { Test-W365IntuneFilters }
            )

            for ($i = 0; $i -lt $checkFunctions.Count; $i++) {
                Write-Log "[$($i+1)/$($checkFunctions.Count)] Checking $($checkNames[$i])..." "CHECK"
                $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                try {
                    & $checkFunctions[$i]
                } catch {
                    Write-Log "Check failed: $($_.Exception.Message)" "FAIL"
                }
            }

            Update-Dashboard

            $pass = @($script:CheckResults | Where-Object { $_.Status -eq "Pass" }).Count
            $fail = @($script:CheckResults | Where-Object { $_.Status -eq "Fail" }).Count
            $warn = @($script:CheckResults | Where-Object { $_.Status -eq "Warning" }).Count
            Write-Log "Assessment complete: $pass passed, $fail failed, $warn warnings" "OK"

        } catch {
            Write-Log "Assessment error: $($_.Exception.Message)" "FAIL"
        }

        $btnAssess.Content = "Run Assessment"
        $btnAssess.IsEnabled = $true
    })


    # ---- Event: Export ----
    $btnExport.Add_Click({
        try {
            $saveDialog = [Microsoft.Win32.SaveFileDialog]::new()
            $saveDialog.Filter   = "HTML Report|*.html"
            $saveDialog.FileName = "W365Link-ReadinessReport.html"
            $saveDialog.Title    = "Save Readiness Report"

            if ($saveDialog.ShowDialog() -eq $true) {
                Write-Log "Generating HTML report..." "ACTION"
                $html = Export-ReadinessReport
                $html | Out-File -FilePath $saveDialog.FileName -Encoding utf8 -Force
                Write-Log "Report saved to: $($saveDialog.FileName)" "OK"
                Start-Process $saveDialog.FileName
            }
        } catch {
            Write-Log "Export failed: $($_.Exception.Message)" "FAIL"
        }
    })

    # ---- Show Window ----
    Write-Log "WinCPC Tenant Setup tool ready." "INFO"
    Write-Log "Click 'Connect to Tenant' to begin." "INFO"
    $window.ShowDialog() | Out-Null
}

# ============================================================================
# REGION: HTML Report Export
# ============================================================================
function Export-ReadinessReport {
    $totalChecks = $script:CheckResults.Count
    $passCount   = @($script:CheckResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount   = @($script:CheckResults | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount   = @($script:CheckResults | Where-Object { $_.Status -eq "Warning" }).Count
    $infoCount   = @($script:CheckResults | Where-Object { $_.Status -eq "Info" }).Count

    $actionable = $passCount + $failCount + $warnCount
    $score = if ($actionable -gt 0) { [math]::Round(($passCount / $actionable) * 100) } else { 0 }

    $scoreColor = Get-ScoreColor $score

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $tenantId  = $script:TenantInfo["TenantId"]
    $account   = $script:TenantInfo["Account"]
    $tenantName = $script:TenantInfo["TenantName"]

    # Build category rows
    $categories = $script:CheckResults | Select-Object -ExpandProperty Category -Unique
    $bodyHtml = ""

    foreach ($cat in $categories) {
        $catChecks = @($script:CheckResults | Where-Object { $_.Category -eq $cat })
        $catPass = @($catChecks | Where-Object { $_.Status -eq "Pass" }).Count

        $bodyHtml += "<div style='margin:16px 0'>"
        $bodyHtml += "<h3 style='font-size:16px;margin:0 0 8px;color:#1b1b1b'>$cat ($catPass/$($catChecks.Count) passed)</h3>"

        foreach ($check in $catChecks) {
            $statusColors = @{
                "Pass"    = @{ Bg = "#dff6dd"; Fg = "#107c10" }
                "Fail"    = @{ Bg = "#fde7e9"; Fg = "#d13438" }
                "Warning" = @{ Bg = "#fff4ce"; Fg = "#e87400" }
                "Info"    = @{ Bg = "#deecf9"; Fg = "#0078d4" }
                "Error"   = @{ Bg = "#f3e8f9"; Fg = "#881798" }
            }
            $sc = $statusColors[$check.Status]
            $esc = { param($s) [System.Security.SecurityElement]::Escape($s) }

            $bodyHtml += "<div style='background:white;border:1px solid #e1e1e1;border-radius:6px;padding:12px 16px;margin:4px 0'>"
            $bodyHtml += "<span style='display:inline-block;background:$($sc.Bg);color:$($sc.Fg);padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700'>$($check.Status.ToUpper())</span> "
            $bodyHtml += "<strong style='font-size:13px'>$(& $esc $check.CheckName)</strong>"

            if ($check.RiskLevel -and $check.Status -in @("Fail","Warning")) {
                $bodyHtml += " <span style='font-size:10px;padding:2px 6px;border-radius:3px;background:#d13438;color:white;font-weight:700'>$(& $esc $check.RiskLevel)</span>"
            }

            $bodyHtml += "<div style='font-size:12px;color:#505050;margin-top:6px'>$(& $esc $check.Detail)</div>"

            if ($check.Remediation) {
                $bodyHtml += "<div style='font-size:11px;color:#707070;margin-top:4px;padding:8px;background:#f6f6f6;border-radius:4px'>Remediation: $(& $esc $check.Remediation)</div>"
            }
            if ($check.LearnMoreUrl) {
                $bodyHtml += "<a href='$($check.LearnMoreUrl)' target='_blank' style='font-size:11px;color:#0078d4;text-decoration:none;margin-top:4px;display:inline-block'>Learn More</a>"
            }
            if ($check.LearnMoreUrl -and $check.PortalUrl) {
                $bodyHtml += "<span style='font-size:11px;color:#ccc;margin:0 8px'>|</span>"
            }
            if ($check.PortalUrl) {
                $bodyHtml += "<a href='$($check.PortalUrl)' target='_blank' style='font-size:11px;color:#0078d4;text-decoration:none;margin-top:4px;display:inline-block'>Open in Portal &rarr;</a>"
            }
            $bodyHtml += "</div>"
        }
        $bodyHtml += "</div>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinCPC - Tenant Readiness Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; font-size: 14px; color: #1b1b1b; background: #f5f5f5; margin: 0; padding: 0; }
.header { background: linear-gradient(135deg, #1b1b1b 0%, #2d2d2d 100%); color: white; padding: 32px 48px; }
.header h1 { font-size: 24px; margin: 0 0 4px; }
.header .sub { font-size: 13px; opacity: 0.7; }
.header .meta { font-size: 12px; opacity: 0.8; margin-top: 12px; }
.score-bar { background: white; padding: 20px 48px; border-bottom: 1px solid #e1e1e1; display: flex; align-items: center; gap: 24px; }
.score-num { font-size: 36px; font-weight: 700; color: $scoreColor; }
.score-label { font-size: 12px; color: #707070; }
.stats { display: flex; gap: 12px; }
.stat { padding: 8px 16px; border-radius: 6px; text-align: center; border: 1px solid #e1e1e1; }
.stat .n { font-size: 24px; font-weight: 700; }
.stat .l { font-size: 10px; color: #707070; text-transform: uppercase; }
.content { max-width: 900px; margin: 0 auto; padding: 16px 48px 48px; }
.footer { text-align: center; padding: 24px; font-size: 11px; color: #707070; border-top: 1px solid #e1e1e1; }
</style>
</head>
<body>
<div class="header">
    <h1>WinCPC — Tenant Readiness Report</h1>
    <div class="sub">Automated assessment for Windows CPC Device deployment</div>
    <div class="meta">$timestamp &bull; Tenant: $tenantName ($tenantId) &bull; Run by: $account</div>
</div>
<div class="score-bar">
    <div><div class="score-num">$score%</div><div class="score-label">READINESS</div></div>
    <div class="stats">
        <div class="stat"><div class="n" style="color:#107c10">$passCount</div><div class="l">Passed</div></div>
        <div class="stat"><div class="n" style="color:#d13438">$failCount</div><div class="l">Failed</div></div>
        <div class="stat"><div class="n" style="color:#e87400">$warnCount</div><div class="l">Warnings</div></div>
        <div class="stat"><div class="n" style="color:#0078d4">$infoCount</div><div class="l">Info</div></div>
    </div>
</div>
<div class="content">$bodyHtml</div>
<div class="footer">
    Generated by WinCPC Tenant Setup Tool &bull;
    <a href="https://learn.microsoft.com/en-us/windows-365/link/" style="color:#0078d4">Windows CPC Device Documentation</a>
</div>
</body>
</html>
"@

    return $html
}

# Launch the GUI
Start-WinCPCTenantSetupGUI
