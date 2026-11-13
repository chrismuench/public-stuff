## ================================================================== ##
## GMSA Setup for SQL Servers
##
## EASIEST - just run the file with no arguments and pick from the menu:
##     .\Adding_GMSA_to_AD_and_SQL_Server.ps1
##
## FASTER (for scripting/automation) - run directly with parameters:
##
##   On the DOMAIN CONTROLLER:
##     .\Adding_GMSA_to_AD_and_SQL_Server.ps1 -New -GroupName Svc_GMSA_SQL `
##         -GroupPath "OU=Groups,DC=contoso,DC=com" -GmsaName svc_GmsaSqlDS `
##         -DnsHostName svc_GmsaSqlDS.contoso.com -GmsaOU "OU=Managed Service Accounts,DC=contoso,DC=com"
##     (any value you leave out will be prompted for interactively)
##
##   On each SQL SERVER:
##     .\Adding_GMSA_to_AD_and_SQL_Server.ps1 -Install -GmsaName svc_GmsaSqlDS
##
##   Add -WhatIf to preview changes without making them, or -Confirm to be
##   prompted before each change.
##
## ADVANCED - dot-source instead if you want to call the functions
## individually, script multiple gMSAs in a loop, etc:
##     . .\Adding_GMSA_to_AD_and_SQL_Server.ps1
##     New-GmsaForSql
##     Install-GmsaOnServer
## ================================================================== ##

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch]$New,
    [switch]$Install,
    [string]$GroupName,
    [string]$GroupPath,
    [string]$GmsaName,
    [string]$DnsHostName,
    [string]$GmsaOU,
    [int]$ManagedPasswordIntervalInDays = 30,
    [switch]$SkipDcCheck
)

function Write-StatusHost {
    <#
    .SYNOPSIS
        Write-Host with a foreground color, used for all status/progress output.
    #>
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [ConsoleColor]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Returns $true if the current PowerShell session is running elevated
        (Run as Administrator).
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDomainController {
    <#
    .SYNOPSIS
        Returns $true if the current machine is a domain controller.
    #>
    return (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -in @(4,5)
}

function New-GmsaForSql {
    <#
    .SYNOPSIS
        Run on a DOMAIN CONTROLLER. Creates the AD group used to control
        which servers can retrieve a gMSA's password, then creates the
        gMSA itself and links it to that group.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$GroupName,
        [string]$GroupPath,
        [string]$GmsaName,
        [string]$DnsHostName,
        [string]$GmsaOU,
        [int]$ManagedPasswordIntervalInDays = 30
    )

    if (-not (Test-IsAdministrator)) {
        Write-StatusHost "This must be run from an elevated PowerShell session (Run as Administrator)." -Color Red
        Write-StatusHost "Right-click PowerShell -> Run as Administrator, then re-run New-GmsaForSql." -Color Yellow
        return
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-StatusHost "`n=== Step 1: KDS Root Key ===" -Color Cyan
    $kds = Get-KdsRootKey
    if (-not $kds) {
        Write-StatusHost "No KDS root key found. This is required before any gMSA can be created." -Color Yellow
        $create = Read-Host "Create one now? Note: needs up to 10 hours to replicate unless you force it. (y/n)"
        if ($create -eq 'y') {
            $force = Read-Host "Force it to be effective immediately? Only do this in a single-DC lab/test environment (y/n)"
            if ($force -eq 'y') {
                if ($PSCmdlet.ShouldProcess("KDS Root Key", "Create (effective immediately)")) {
                    Add-KdsRootKey -EffectiveImmediately
                }
            } else {
                if ($PSCmdlet.ShouldProcess("KDS Root Key", "Create")) {
                    Add-KdsRootKey
                    Write-StatusHost "Root key created. Wait for AD replication (up to 10 hours) before creating the gMSA." -Color Yellow
                }
            }
        } else {
            Write-StatusHost "Cannot continue without a KDS root key. Ask a Domain Admin to run Add-KdsRootKey." -Color Red
            return
        }
    } else {
        Write-StatusHost "KDS root key already exists." -Color Green
    }

    Write-StatusHost "`n=== Step 2: AD Group (controls which servers can use the gMSA) ===" -Color Cyan
    if (-not $GroupName) {
        $hasGroup = Read-Host "Do you already have an AD group set up for this? (y/n)"
        if ($hasGroup -eq 'y') {
            $GroupName = Read-Host "Existing group name"
            $found = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
            while (-not $found) {
                Write-StatusHost "Could not find a group named '$GroupName' in AD." -Color Red
                $retry = Read-Host "Try a different existing group name? (y/n)"
                if ($retry -eq 'y') {
                    $GroupName = Read-Host "Existing group name"
                    $found = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
                } else {
                    Write-StatusHost "OK, we'll create a new group instead." -Color Yellow
                    $GroupName = $null
                    break
                }
            }
        }
        if (-not $GroupName) {
            $GroupName = Read-Host "Group name (e.g. Svc_GMSA_SQL)"
        }
    }

    $existingGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($existingGroup) {
        Write-StatusHost "Group '$GroupName' already exists - reusing it." -Color Yellow
    } else {
        if (-not $GroupPath) {
            $GroupPath = Read-Host "OU path for the group (e.g. OU=Service Account Groups,OU=Groups,DC=contoso,DC=com)"
        }
        try {
            if ($PSCmdlet.ShouldProcess($GroupName, "Create AD group in $GroupPath")) {
                New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupCategory Security `
                    -GroupScope Global -DisplayName $GroupName -Path $GroupPath `
                    -Description "Members of this group are allowed to retrieve this gMSA's password" -ErrorAction Stop
                Write-StatusHost "Group '$GroupName' created." -Color Green
            }
        } catch {
            Write-StatusHost "Failed to create group: $($_.Exception.Message)" -Color Red
            Write-StatusHost "Common cause: the OU path doesn't exist. Double-check '$GroupPath' in ADUC." -Color Yellow
            return
        }
    }

    Write-StatusHost "`nAdd each SQL server's COMPUTER object (not user) to '$GroupName' now." -Color Cyan
    $addNow = Read-Host "Add a computer to the group now? (y/n)"
    while ($addNow -eq 'y') {
        $computerName = Read-Host "Computer (server) name"
        try {
            if ($PSCmdlet.ShouldProcess($computerName, "Add to group '$GroupName'")) {
                Add-ADGroupMember -Identity $GroupName -Members "$computerName`$" -ErrorAction Stop
                Write-StatusHost "Added $computerName." -Color Green
            }
        } catch {
            Write-StatusHost "Could not add '$computerName': $($_.Exception.Message)" -Color Red
        }
        $addNow = Read-Host "Add another computer? (y/n)"
    }

    Write-StatusHost "`n=== Step 3: Create the gMSA ===" -Color Cyan
    if (-not $GmsaName) { $GmsaName = Read-Host "gMSA name (e.g. svc_GmsaSqlDS)" }
    if ($GmsaName.Length -gt 15) {
        Write-StatusHost "'$GmsaName' is longer than 15 characters - the SamAccountName will be truncated by AD. Consider a shorter name." -Color Yellow
    }
    if (-not $DnsHostName) {
        $domainSuffix = $null
        try {
            $domainSuffix = (Get-ADDomain -ErrorAction Stop).DNSRoot
        } catch {
            $domainSuffix = $env:USERDNSDOMAIN
        }
        if ($domainSuffix) {
            $suggestedDns = "$GmsaName.$domainSuffix"
            $DnsHostName = Read-Host "DNS host name for the gMSA [$suggestedDns]"
            if (-not $DnsHostName) { $DnsHostName = $suggestedDns }
        } else {
            $DnsHostName = Read-Host "DNS host name for the gMSA (e.g. $GmsaName.contoso.com)"
        }
    }
    if (-not $GmsaOU) {
        $GmsaOU = Read-Host "OU path for the gMSA (e.g. OU=Managed Service Accounts,OU=Service Accounts,DC=contoso,DC=com)"
    }

    $existingGmsa = Get-ADServiceAccount -Filter "Name -eq '$GmsaName'" -ErrorAction SilentlyContinue
    if ($existingGmsa) {
        Write-StatusHost "A gMSA named '$GmsaName' already exists. Aborting to avoid overwriting it." -Color Red
        return
    }

    try {
        if ($PSCmdlet.ShouldProcess($GmsaName, "Create gMSA in $GmsaOU")) {
            New-ADServiceAccount -Name $GmsaName -Path $GmsaOU -DNSHostName $DnsHostName `
                -PrincipalsAllowedToRetrieveManagedPassword $GroupName -TrustedForDelegation $true `
                -ManagedPasswordIntervalInDays $ManagedPasswordIntervalInDays -ErrorAction Stop
            Write-StatusHost "gMSA '$GmsaName' created." -Color Green
        }
    } catch {
        Write-StatusHost "Failed to create gMSA: $($_.Exception.Message)" -Color Red
        return
    }

    ## Explicitly set strong Kerberos encryption types (AES). Without this, the account
    ## can default to/allow weaker types (e.g. RC4), which will fail installation with
    ## "The provided context did not match the target" on servers/domains with RC4 disabled.
    try {
        if ($PSCmdlet.ShouldProcess($GmsaName, "Set Kerberos encryption types to AES128,AES256")) {
            Set-ADServiceAccount -Identity $GmsaName -KerberosEncryptionType AES128,AES256 -ErrorAction Stop
            Write-StatusHost "Kerberos encryption set to AES128/AES256." -Color Green
        }
    } catch {
        Write-StatusHost "Could not set Kerberos encryption types: $($_.Exception.Message)" -Color Yellow
        Write-StatusHost "You may need to run this manually before installing on a server: Set-ADServiceAccount -Identity $GmsaName -KerberosEncryptionType AES128,AES256" -Color Yellow
    }

    Write-StatusHost "`n=== Summary ===" -Color Cyan
    Get-ADServiceAccount -Identity $GmsaName -Properties DNSHostName,KerberosEncryptionType,ManagedPasswordIntervalInDays,Name,PrincipalsAllowedToRetrieveManagedPassword,SamAccountName,ServicePrincipalNames |
        Format-List DNSHostName,KerberosEncryptionType,ManagedPasswordIntervalInDays,Name,PrincipalsAllowedToRetrieveManagedPassword,SamAccountName,ServicePrincipalNames

    Write-StatusHost "Next: on each SQL server that's a member of '$GroupName', run this script there with -Install -GmsaName $GmsaName." -Color Cyan
}

function Install-GmsaOnServer {
    <#
    .SYNOPSIS
        Run on a SQL SERVER. Installs a gMSA locally so it can be used as a
        service account, checking common failure points along the way.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [string]$GmsaName,
        [switch]$SkipDcCheck
    )

    if (-not (Test-IsAdministrator)) {
        Write-StatusHost "This must be run from an elevated PowerShell session (Run as Administrator)." -Color Red
        Write-StatusHost "Right-click PowerShell -> Run as Administrator, then re-run Install-GmsaOnServer." -Color Yellow
        return
    }

    if ((Test-IsDomainController) -and -not $SkipDcCheck) {
        Write-StatusHost "This machine is a Domain Controller. There is no reason to install a gMSA (Install-ADServiceAccount) on a DC - this is only for member servers (e.g. your SQL servers)." -Color Red
        Write-StatusHost "Run this script with -New here instead if you're trying to create/configure the gMSA." -Color Yellow
        Write-StatusHost "If you really need to proceed anyway, re-run with -SkipDcCheck." -Color Yellow
        return
    }

    ## RSAT tools are needed to talk to AD from this server.
    $feature = Get-WindowsFeature RSAT-AD-PowerShell -ErrorAction SilentlyContinue
    if ($feature -and -not $feature.Installed) {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install RSAT-AD-PowerShell feature")) {
            Write-StatusHost "Installing RSAT-AD-PowerShell..." -Color Cyan
            Install-WindowsFeature RSAT-AD-PowerShell | Out-Null
        }
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    if (-not $GmsaName) { $GmsaName = Read-Host "gMSA name to install (e.g. svc_GmsaSqlDS)" }

    $gmsa = Get-ADServiceAccount -Identity $GmsaName -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
    if (-not $gmsa) {
        Write-StatusHost "Could not find a gMSA named '$GmsaName' in AD. Check the spelling, or that this server can reach the domain." -Color Red
        return
    }

    ## Check this server is actually allowed to retrieve the password before attempting install,
    ## so we can give a clearer message than the raw AD error.
    $thisComputer = "$($env:COMPUTERNAME)`$"
    $allowed = $gmsa.PrincipalsAllowedToRetrieveManagedPassword
    $isAllowed = $false
    foreach ($principal in $allowed) {
        try {
            if ($principal -match '^CN=') {
                $obj = Get-ADObject -Identity $principal -ErrorAction Stop
                if ($obj.ObjectClass -eq 'group') {
                    if (Get-ADGroupMember -Identity $obj -Recursive -ErrorAction Stop | Where-Object { $_.SamAccountName -eq $thisComputer }) {
                        $isAllowed = $true
                    }
                } elseif ($obj.Name -eq $env:COMPUTERNAME) {
                    $isAllowed = $true
                }
            }
        } catch {
            ## Non-fatal - fall through to the real install attempt either way.
        }
    }

    if (-not $isAllowed) {
        Write-StatusHost "This server ($env:COMPUTERNAME) does not appear to be authorized to retrieve '$GmsaName''s password yet." -Color Red
        Write-StatusHost "This is usually because the computer was just added to the allowed group and its Kerberos ticket hasn't refreshed. Reboot this server, then re-run this script." -Color Yellow
        return
    }

    Write-StatusHost "Installing gMSA '$GmsaName' on this server..." -Color Cyan
    try {
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install gMSA '$GmsaName'")) {
            Install-ADServiceAccount -Identity $GmsaName -ErrorAction Stop
        } else {
            return
        }
    } catch {
        $msg = $_.Exception.Message
        Write-StatusHost "Install failed: $msg" -Color Red
        if ($msg -match 'provided context did not match the target') {
            Write-StatusHost "This is almost always a Kerberos encryption type mismatch (the gMSA allows RC4 but this server/domain has RC4 disabled)." -Color Yellow
            Write-StatusHost "Fix on the DC: Set-ADServiceAccount -Identity $GmsaName -KerberosEncryptionType AES128,AES256" -Color Yellow
        } elseif ($msg -match 'Access is denied|Access Denied') {
            Write-StatusHost "This server likely isn't in PrincipalsAllowedToRetrieveManagedPassword yet, or group membership hasn't replicated. Verify and reboot this server if it was just added." -Color Yellow
        }
        return
    }

    Write-StatusHost "Testing gMSA..." -Color Cyan
    $result = Test-ADServiceAccount -Identity $GmsaName
    if ($result) {
        Write-StatusHost "Success - '$GmsaName' is installed and working on this server." -Color Green
    } else {
        Write-StatusHost "Test-ADServiceAccount returned False. If this server was just added to the allowed group, reboot it and re-run this script with -Install -GmsaName $GmsaName." -Color Yellow
    }
}

function Show-GmsaMenu {
    <#
    .SYNOPSIS
        Interactive menu shown when the script is run with no action
        specified. Lets someone pick what to do without knowing the
        parameter names up front.
    #>
    do {
        Write-StatusHost "`n=== GMSA Setup for SQL Servers ===" -Color Cyan
        Write-Host "  1) Set up a gMSA  (run this on the Domain Controller)"
        Write-Host "  2) Install a gMSA on this server  (run this on a SQL Server)"
        Write-Host "  3) Exit"
        $choice = Read-Host "`nChoose an option (1-3)"
        switch ($choice) {
            '1' { New-GmsaForSql }
            '2' { Install-GmsaOnServer }
            '3' { return }
            default { Write-StatusHost "'$choice' isn't a valid option - enter 1, 2, or 3." -Color Red }
        }
    } while ($choice -ne '3')
}

## ================================================================== ##
## Entry point - only runs when the file is executed directly
## (.\script.ps1 ...), NOT when it's dot-sourced (. .\script.ps1).
## Dot-sourcing just loads the functions above without running anything.
## ================================================================== ##
$wasDotSourced = ($MyInvocation.InvocationName -eq '.')

if (-not $wasDotSourced) {
    if ($New -and $Install) {
        Write-StatusHost "Specify only one of -New or -Install, not both." -Color Red
    } elseif ($New) {
        $params = @{}
        if ($PSBoundParameters.ContainsKey('GroupName')) { $params.GroupName = $GroupName }
        if ($PSBoundParameters.ContainsKey('GroupPath')) { $params.GroupPath = $GroupPath }
        if ($PSBoundParameters.ContainsKey('GmsaName')) { $params.GmsaName = $GmsaName }
        if ($PSBoundParameters.ContainsKey('DnsHostName')) { $params.DnsHostName = $DnsHostName }
        if ($PSBoundParameters.ContainsKey('GmsaOU')) { $params.GmsaOU = $GmsaOU }
        if ($PSBoundParameters.ContainsKey('ManagedPasswordIntervalInDays')) { $params.ManagedPasswordIntervalInDays = $ManagedPasswordIntervalInDays }
        New-GmsaForSql @params
    } elseif ($Install) {
        $params = @{}
        if ($PSBoundParameters.ContainsKey('GmsaName')) { $params.GmsaName = $GmsaName }
        if ($SkipDcCheck) { $params.SkipDcCheck = $true }
        Install-GmsaOnServer @params
    } else {
        ## No parameters given at all - drop into the interactive menu
        ## rather than just printing usage and doing nothing.
        Show-GmsaMenu
    }
}