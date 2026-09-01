# AD Automation Toolkit

PowerShell scripts that automate common Active Directory user lifecycle tasks — the kind of repetitive, error-prone work that eats up hours in any IT admin's week and is a common source of onboarding/offboarding mistakes when done manually.

## Why this exists
In a typical office IT environment, user provisioning, password resets, and offboarding are handled manually across multiple systems — which is slow and creates security gaps (e.g. an offboarded employee whose AD account and group memberships aren't fully removed). These scripts standardize that process and build in the safety checks a manual process tends to skip.

## Scripts

| Script | What it does |
|---|---|
| `New-ADUserProvisioning.ps1` | Creates a new AD user account with pre-flight validation, secure password handling, audit logging, and automatic rollback if group assignment fails |
| *(more coming daily)* | Password reset, offboarding/account disable, bulk CSV import |

### `New-ADUserProvisioning.ps1` features
- **`-WhatIf` / `-Confirm` support** — preview exactly what the script would do before any change is made
- **Pre-flight validation** — confirms the target OU and every security group exist *before* creating anything
- **Duplicate detection** — checks for existing usernames and UPNs, auto-resolves collisions (e.g. `jane.doe` → `jane.doe2`)
- **Secure password handling** — the temporary password is passed as a `SecureString` and never written to disk or logged in plain text
- **Forced password change** — every new account requires a password change at first logon
- **Audit logging** — every action (account created, group assigned, failures, rollbacks) is appended to a CSV log with timestamp and the admin who ran it
- **No hard-coded environment values** — domain, OU, and department→group mappings are all passed in or read from an external config file, not baked into the script
- **Rollback on partial failure** — if the account is created but a group assignment fails, the script automatically removes the account rather than leaving a half-configured user behind

## Requirements
- **Does not need to run on a domain controller.** Any domain-joined machine with the RSAT Active Directory PowerShell module installed and network access to a DC will work.
- PowerShell 5.1+ with the `ActiveDirectory` module (RSAT)
- An account with delegated permission to create user objects and manage group membership in the target OU (Domain Admin is not required)
- A `group-map.json` file in the same directory (or pointed to via `-GroupMapPath`) describing department → group mappings for your environment — see `group-map.json` in this repo for the format

## Usage
Preview first with `-WhatIf`, then run for real:
```powershell
$Password = Read-Host "Enter temporary password" -AsSecureString

.\New-ADUserProvisioning.ps1 `
    -FirstName "Jane" `
    -LastName "Doe" `
    -Department "Billing" `
    -OU "OU=Billing,DC=contoso,DC=local" `
    -InitialPassword $Password `
    -WhatIf
```
Remove `-WhatIf` once the preview looks correct.

## Notes
All examples use placeholder values (`contoso.local`) — replace with your own environment's domain, OU structure, and group names in `group-map.json` before running in production.
