#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Provisions a new Active Directory user account with validation, secure password
    handling, audit logging, and rollback on partial failure.

.DESCRIPTION
    Automates new-hire account creation: validates that the target OU and security
    groups exist before making any changes, checks for duplicate usernames/UPNs,
    creates the AD user with a securely-supplied temporary password, assigns
    department-based group membership, logs the action to an audit file, and rolls
    back the created account if group assignment fails partway through.

    Supports -WhatIf and -Confirm (via SupportsShouldProcess) so admins can preview
    exactly what would happen before committing any change.

.PARAMETER FirstName
    New user's first name.

.PARAMETER LastName
    New user's last name.

.PARAMETER Department
    Department name — used to look up group membership in $GroupMapPath.

.PARAMETER OU
    Distinguished name of the target Organizational Unit, e.g. "OU=Billing,DC=contoso,DC=local"

.PARAMETER InitialPassword
    Temporary password as a SecureString. Never pass or store this as plain text —
    prompt for it with Read-Host -AsSecureString (see example below).

.PARAMETER Domain
    UPN domain suffix, e.g. "contoso.local". Defaults to the domain of the machine
    running the script if not supplied.

.PARAMETER GroupMapPath
    Path to a JSON file mapping department names to arrays of group names, e.g.
    { "Billing": ["Billing-Staff", "VPN-Users"] }
    Keeping this external avoids hard-coding group names into the script itself.

.PARAMETER LogPath
    Path to the audit log CSV. By default, the log is stored in the repository
    root as AD-Provisioning-AuditLog.csv. Every run appends who ran it, when, 
    what account was created, and which groups were assigned (or attempted).

.EXAMPLE
    $Password = Read-Host "Enter temporary password" -AsSecureString

    .\scripts\New-ADUserProvisioning.ps1 `
        -FirstName "Jane" `
        -LastName "Doe" `
        -Department "Billing" `
        -OU "OU=Billing,DC=contoso,DC=local" `
        -InitialPassword $Password `
        -WhatIf

    Preview what the script would do without making any changes. Remove -WhatIf
    to actually run it.

.NOTES
    Requirements:
    - The ActiveDirectory PowerShell module (RSAT: Active Directory module).
      This does NOT need to run on a domain controller — any domain-joined
      machine with RSAT installed and network access to a DC works.
    - An account with delegated permission to create user objects and modify
      group membership in the target OU (does not require Domain Admin).
    - A group-map JSON file describing department -> group name mappings for
      your environment (see -GroupMapPath).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$FirstName,

    [Parameter(Mandatory = $true)]
    [string]$LastName,

    [Parameter(Mandatory = $true)]
    [string]$Department,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Get-ADOrganizationalUnit -Identity $_ -ErrorAction SilentlyContinue)) {
            throw "OU '$_' does not exist or is not reachable."
        }
        $true
    })]
    [string]$OU,

    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$InitialPassword,

    [Parameter(Mandatory = $false)]
    [string]$Domain = (Get-ADDomain).DNSRoot,

    [Parameter(Mandatory = $false)]
    [string]$GroupMapPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "group-map.json"),

    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "AD-Provisioning-AuditLog.csv")
)

Import-Module ActiveDirectory -ErrorAction Stop

function Write-AuditLog {
    param(
        [string]$Action,
        [string]$Username,
        [string]$Detail,
        [string]$Result
    )

    try {
        $entry = [PSCustomObject]@{
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            RunBy      = "$env:USERDOMAIN\$env:USERNAME"
            Action     = $Action
            Username   = $Username
            Detail     = $Detail
            Result     = $Result
        }

        $entry | Export-Csv `
            -LiteralPath $LogPath `
            -Append `
            -NoTypeInformation `
            -Encoding UTF8 `
            -ErrorAction Stop
    }
    catch {
        Write-Warning "Audit logging failed: $($_.Exception.Message)"
    }
}

# --- Load group map (avoids hard-coding department/group names in the script) ---
if (-not (Test-Path -LiteralPath $GroupMapPath -PathType Leaf)) {
    Write-Error "Group map file not found at '$GroupMapPath'."
    return
}

try {
    $groupMap = Get-Content `
        -LiteralPath $GroupMapPath `
        -Raw `
        -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "Unable to read group map '$GroupMapPath': $($_.Exception.Message)"
    return
}

# --- Load the department's configured security groups ---
if (-not $groupMap.$Department) {
    Write-Error "No group mapping found for department '$Department' in '$GroupMapPath'."
    return
}

$targetGroups = @($groupMap.$Department)

if ($targetGroups.Count -eq 0) {
    Write-Error "Department '$Department' does not have any security groups configured."
    return
}

# --- Validate all target groups exist before touching anything ---
foreach ($group in $targetGroups) {
    if (-not (Get-ADGroup -Identity $group -ErrorAction SilentlyContinue)) {
        Write-Error "Security group '$group' does not exist. Aborting before any changes were made."
        return
    }
}

# --- Generate a safe, unique username and UPN ---
$cleanFirstName = $FirstName.ToLowerInvariant() -replace '[^a-z0-9]', ''
$cleanLastName = $LastName.ToLowerInvariant() -replace '[^a-z0-9]', ''

if ([string]::IsNullOrWhiteSpace($cleanFirstName) -or
    [string]::IsNullOrWhiteSpace($cleanLastName)) {
    Write-Error "FirstName and LastName must contain characters that can be used in a username."
    return
}

$baseUsername = "$cleanFirstName.$cleanLastName"
$counter = 1

do {
    $suffix = if ($counter -eq 1) { "" } else { $counter.ToString() }
    $maximumBaseLength = 20 - $suffix.Length

    $trimmedBase = $baseUsername.Substring(
        0,
        [Math]::Min($baseUsername.Length, $maximumBaseLength)
    )

    $username = "$trimmedBase$suffix"
    $upn = "$username@$Domain"

    $escapedUsername = $username.Replace("'", "''")
    $escapedUpn = $upn.Replace("'", "''")

    $existingUser = Get-ADUser `
        -Filter "SamAccountName -eq '$escapedUsername' -or UserPrincipalName -eq '$escapedUpn'" `
        -ErrorAction Stop

    $counter++

    if ($counter -gt 9999) {
        Write-Error "Unable to generate a unique username for $FirstName $LastName."
        return
    }
}
while ($existingUser)

$displayName = "$FirstName $LastName"
$createdUser = $null

# --- Create the account ---
if ($PSCmdlet.ShouldProcess($username, "Create AD user account")) {
    try {
        $createdUser = New-ADUser `
            -Name $displayName `
            -GivenName $FirstName `
            -Surname $LastName `
            -SamAccountName $username `
            -UserPrincipalName $upn `
            -Path $OU `
            -AccountPassword $InitialPassword `
            -ChangePasswordAtLogon $true `
            -Enabled $true `
            -Department $Department `
            -PassThru `
            -ErrorAction Stop

        Write-Host "Created user account: $username" -ForegroundColor Green
        Write-AuditLog -Action "CreateUser" -Username $username -Detail "OU=$OU; Department=$Department" -Result "Success"
    }
    catch {
        Write-Error "Failed to create user '$username': $_"
        Write-AuditLog -Action "CreateUser" -Username $username -Detail $_.Exception.Message -Result "Failed"
        return
    }

    # --- Assign group membership, with rollback if it fails partway through ---
    $assignedGroups = @()
    try {
       foreach ($group in $targetGroups) {
    if ($PSCmdlet.ShouldProcess($username, "Add to security group '$group'")) {
        Add-ADGroupMember `
            -Identity $group `
            -Members $createdUser `
            -ErrorAction Stop

        $assignedGroups += $group

        Write-Host "Added $username to group: $group" -ForegroundColor Green

        Write-AuditLog `
            -Action "AddToGroup" `
            -Username $username `
            -Detail $group `
            -Result "Success"
         }
    }
}
    catch {
        Write-Error "Group assignment failed on '$group': $_"
        Write-AuditLog -Action "AddToGroup" -Username $username -Detail "$group : $($_.Exception.Message)" -Result "Failed"

        Write-Warning "Rolling back: removing partially-provisioned account '$username' (assigned groups: $($assignedGroups -join ', '))."
        try {
            Remove-ADUser -Identity $createdUser -Confirm:$false -ErrorAction Stop
            Write-AuditLog -Action "Rollback" -Username $username -Detail "Removed after group assignment failure" -Result "Success"
        }
        catch {
            Write-Error "ROLLBACK FAILED — account '$username' was created but group assignment failed and cleanup did not succeed. Manual review required."
            Write-AuditLog -Action "Rollback" -Username $username -Detail $_.Exception.Message -Result "Failed - manual review required"
        }
        return
    }

Write-Host "`nProvisioning complete for $username. User must change password at next logon." -ForegroundColor Yellow
Write-Host "Audit log: $LogPath"
}
elseif ($WhatIfPreference) {
    foreach ($group in $targetGroups) {
        $null = $PSCmdlet.ShouldProcess(
            $username,
            "Add to security group '$group'"
        )
    }
}
