# ============================================================================
# CCDC Complete Security Automation - Optimized Final Edition
# Run from Domain Controller with Domain Admin privileges
# ============================================================================

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Production-ready CCDC security automation with unified configuration
    
.DESCRIPTION
    - Single configuration file for all user types and privileges
    - ExcludedUsers section protects critical accounts from being disabled
    - Automated group membership enforcement (including RDP and WinRM)
    - Domain/Enterprise Admins automatically get RDP and WinRM access
    - Strong password generation with CCDC-compliant special characters
    - Comprehensive terminal-only logging (no disk writes)
    - Remote server management via WinRM
    - Complete group auditing and cleanup
    - Optimized for speed and reliability
    
.PARAMETER ConfigFile
    Path to consolidated user configuration file (default: .\users_config.txt)
    
.PARAMETER PasswordLength
    Length of generated passwords (default: 16, min: 12, max: 32)
    
.PARAMETER SkipGroupAudit
    Skip group auditing and cleanup
    
.PARAMETER SkipPasswordReset
    Skip password reset operations
    
.PARAMETER SkipRemoteServers
    Skip remote server processing
    
.PARAMETER DryRun
    Show what would be changed without making actual changes
    
.NOTES
    Special characters allowed: )('.,@|=:;/-!
    All logging is terminal-only for operational security
    Version: 2.0 - Optimized Edition
#>

param(
    [string]$ConfigFile = ".\users_config.txt",
    [int]$PasswordLength = 16,
    [switch]$SkipGroupAudit,
    [switch]$SkipPasswordReset,
    [switch]$SkipRemoteServers,
    [switch]$DryRun
)

# ============================================================================
# Global Configuration
# ============================================================================
$script:ExecutionLog = @()
$script:PasswordResets = @()
$script:GroupChanges = @()
$script:AccountChanges = @()
$script:Errors = @()
$script:Warnings = @()
$script:StartTime = Get-Date
$script:DomainController = $env:COMPUTERNAME
$script:Statistics = @{
    GroupsProcessed = 0
    MembersRemoved = 0
    MembersAdded = 0
    PasswordsReset = 0
    AccountsDisabled = 0
    ServersProcessed = 0
}

# Validate password length
if ($PasswordLength -lt 12 -or $PasswordLength -gt 32) {
    Write-Host "[ERROR] Password length must be between 12 and 32 characters" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL', 'PASSWORD', 'CHANGE', 'AUDIT', 'DRYRUN')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory=$false)]
        [switch]$NoTimestamp
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    
    # Store in execution log
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date
        Level = $Level
        Message = $Message
    }
    $script:ExecutionLog += $logEntry
    
    # Console output with color coding
    if (-not $NoTimestamp) {
        Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    }
    
    switch ($Level) {
        'INFO'     { Write-Host "[INFO]     " -NoNewline -ForegroundColor Cyan; Write-Host $Message }
        'SUCCESS'  { Write-Host "[SUCCESS]  " -NoNewline -ForegroundColor Green; Write-Host $Message }
        'WARNING'  { 
            Write-Host "[WARNING]  " -NoNewline -ForegroundColor Yellow
            Write-Host $Message
            $script:Warnings += $logEntry
        }
        'ERROR'    { 
            Write-Host "[ERROR]    " -NoNewline -ForegroundColor Red
            Write-Host $Message
            $script:Errors += $logEntry
        }
        'CRITICAL' { 
            Write-Host "[CRITICAL] " -NoNewline -ForegroundColor White -BackgroundColor Red
            Write-Host $Message
            $script:Errors += $logEntry
        }
        'PASSWORD' { 
            Write-Host "[PASSWORD] " -NoNewline -ForegroundColor Black -BackgroundColor Green
            Write-Host $Message -ForegroundColor White
        }
        'CHANGE'   { 
            Write-Host "[CHANGE]   " -NoNewline -ForegroundColor Magenta
            Write-Host $Message
        }
        'AUDIT'    { 
            Write-Host "[AUDIT]    " -NoNewline -ForegroundColor Blue
            Write-Host $Message
        }
        'DRYRUN'   {
            Write-Host "[DRY RUN]  " -NoNewline -ForegroundColor Yellow -BackgroundColor DarkBlue
            Write-Host $Message
        }
    }
}

function Write-SectionHeader {
    param([string]$Title)
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

function Write-SubSection {
    param([string]$Title)
    
    Write-Host "`n  $Title" -ForegroundColor Yellow
    Write-Host ("  " + ("-" * 76)) -ForegroundColor DarkGray
}

function Write-Progress-Inline {
    param([string]$Activity, [int]$Current, [int]$Total)
    
    $percent = [math]::Round(($Current / $Total) * 100)
    Write-Host "    Progress: $Current/$Total ($percent%)" -ForegroundColor Gray
}

# ============================================================================
# Configuration File Parser (Optimized)
# ============================================================================

function Parse-ConfigFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Configuration file not found: $FilePath" -Level CRITICAL
        return $null
    }
    
    $config = @{
        RegularUsers = [System.Collections.Generic.HashSet[string]]::new()
        Administrators = [System.Collections.Generic.HashSet[string]]::new()
        DomainAdmins = [System.Collections.Generic.HashSet[string]]::new()
        EnterpriseAdmins = [System.Collections.Generic.HashSet[string]]::new()
        RemoteDesktopUsers = [System.Collections.Generic.HashSet[string]]::new()
        RemoteManagementUsers = [System.Collections.Generic.HashSet[string]]::new()
        ExcludedUsers = [System.Collections.Generic.HashSet[string]]::new()
    }
    
    try {
        $content = Get-Content $FilePath -ErrorAction Stop
        $currentSection = $null
        $lineNumber = 0
        
        foreach ($line in $content) {
            $lineNumber++
            $line = $line.Trim()
            
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
                continue
            }
            
            # Check for section header
            if ($line -match '^\[(.+)\]$') {
                $sectionName = $matches[1]
                
                if ($config.ContainsKey($sectionName)) {
                    $currentSection = $sectionName
                    Write-Log "Parsing section: [$currentSection]" -Level INFO
                } else {
                    Write-Log "Unknown section [$sectionName] on line $lineNumber - skipping" -Level WARNING
                    $currentSection = $null
                }
                continue
            }
            
            # Add user to current section
            if ($currentSection) {
                $username = $line.ToLower()
                
                # Validate username (basic validation)
                if ($username -match '^[a-z0-9_\-\.]+$') {
                    $null = $config[$currentSection].Add($username)
                } else {
                    Write-Log "Invalid username '$username' on line $lineNumber - skipping" -Level WARNING
                }
            }
        }
        
        # Convert HashSets to arrays for easier handling
        $result = @{}
        foreach ($key in $config.Keys) {
            $result[$key] = @($config[$key])
        }
        
        Write-Log "Configuration parsed successfully" -Level SUCCESS
        foreach ($section in $result.Keys) {
            $count = $result[$section].Count
            Write-Log "  $section - $count users" -Level INFO
        }
        
        return $result
        
    } catch {
        Write-Log "Failed to parse configuration file: $_" -Level CRITICAL
        return $null
    }
}

# ============================================================================
# Password Generation Functions (Optimized)
# ============================================================================

function Generate-CCDCPassword {
    param([int]$Length = 16)
    
    # CCDC-compliant character sets
    $upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowerCase = "abcdefghijklmnopqrstuvwxyz"
    $numbers = "0123456789"
    $specialChars = ")(';.,@|=:/-!"
    
    # Pre-allocate array for better performance
    $password = New-Object char[] $Length
    $charSets = @($upperCase, $lowerCase, $numbers, $specialChars)
    
    # Ensure at least 2 of each type for strong complexity
    $password[0] = $upperCase[(Get-Random -Maximum $upperCase.Length)]
    $password[1] = $upperCase[(Get-Random -Maximum $upperCase.Length)]
    $password[2] = $lowerCase[(Get-Random -Maximum $lowerCase.Length)]
    $password[3] = $lowerCase[(Get-Random -Maximum $lowerCase.Length)]
    $password[4] = $numbers[(Get-Random -Maximum $numbers.Length)]
    $password[5] = $numbers[(Get-Random -Maximum $numbers.Length)]
    $password[6] = $specialChars[(Get-Random -Maximum $specialChars.Length)]
    $password[7] = $specialChars[(Get-Random -Maximum $specialChars.Length)]
    
    # Fill remaining with random mix
    $allChars = $upperCase + $lowerCase + $numbers + $specialChars
    for ($i = 8; $i -lt $Length; $i++) {
        $password[$i] = $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Fisher-Yates shuffle for randomization
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = Get-Random -Maximum ($i + 1)
        $temp = $password[$i]
        $password[$i] = $password[$j]
        $password[$j] = $temp
    }
    
    return -join $password
}

function Test-PasswordComplexity {
    param([string]$Password)
    
    return ($Password -cmatch '[A-Z]') -and
           ($Password -cmatch '[a-z]') -and
           ($Password -match '[0-9]') -and
           ($Password -match '[)(''.,@|=:;/\-!]') -and
           ($Password -notmatch '[^A-Za-z0-9)(''.,@|=:;/\-!]')
}

# ============================================================================
# Remote Management Functions (Optimized)
# ============================================================================

function Test-WinRMConnection {
    param([string]$ComputerName)
    
    try {
        $null = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-RemoteGroupOperation {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [string]$Operation,  # 'Get', 'Add', 'Remove'
        [string]$MemberName = $null
    )
    
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($group, $op, $member)
            
            switch ($op) {
                'Get' {
                    try {
                        return Get-LocalGroupMember -Group $group -ErrorAction Stop | 
                               Select-Object Name, ObjectClass, SID
                    } catch {
                        # Fallback to net localgroup
                        $output = net localgroup $group 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $membersList = @()
                            $inMembers = $false
                            foreach ($line in $output) {
                                $line = $line.Trim()
                                if ($line -match '^-+$') { $inMembers = $true; continue }
                                if ($inMembers -and $line -and $line -notmatch '^The command completed') {
                                    $membersList += [PSCustomObject]@{
                                        Name = $line
                                        ObjectClass = "Unknown"
                                        SID = $null
                                    }
                                }
                            }
                            return $membersList
                        }
                        return @()
                    }
                }
                'Add' {
                    Add-LocalGroupMember -Group $group -Member $member -ErrorAction Stop
                    return $true
                }
                'Remove' {
                    Remove-LocalGroupMember -Group $group -Member $member -ErrorAction Stop
                    return $true
                }
            }
        } -ArgumentList $GroupName, $Operation, $MemberName -ErrorAction Stop
        
        return $result
    } catch {
        return $null
    }
}

# ============================================================================
# Banner
# ============================================================================
Clear-Host
Write-Host "`n"
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  CCDC SECURITY AUTOMATION - OPTIMIZED FINAL EDITION" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  Domain Controller: " -NoNewline -ForegroundColor Gray
Write-Host $script:DomainController -ForegroundColor White
Write-Host "  Execution Time: " -NoNewline -ForegroundColor Gray
Write-Host ($script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
Write-Host "  Configuration File: " -NoNewline -ForegroundColor Gray
Write-Host $ConfigFile -ForegroundColor White
Write-Host "  Password Length: " -NoNewline -ForegroundColor Gray
Write-Host "$PasswordLength characters" -ForegroundColor White
Write-Host "  Special Chars: " -NoNewline -ForegroundColor Gray
Write-Host ")('.,@|=:;/-!" -ForegroundColor Green
if ($DryRun) {
    Write-Host "  MODE: " -NoNewline -ForegroundColor Gray
    Write-Host "DRY RUN (No changes will be made)" -ForegroundColor Yellow -BackgroundColor DarkBlue
}
Write-Host ("=" * 80) -ForegroundColor Cyan

# ============================================================================
# Load Configuration
# ============================================================================
Write-SectionHeader "CONFIGURATION LOADING"

$userConfig = Parse-ConfigFile -FilePath $ConfigFile
if ($null -eq $userConfig) {
    Write-Log "Failed to load configuration file. Exiting." -Level CRITICAL
    exit 1
}

# Combine all authorized users (unique list)
$allAuthorizedUsers = @()
foreach ($section in $userConfig.Keys) {
    $allAuthorizedUsers += $userConfig[$section]
}
$allAuthorizedUsers = $allAuthorizedUsers | Select-Object -Unique | Where-Object { $_ }

Write-Log "Total unique authorized users: $($allAuthorizedUsers.Count)" -Level INFO

# Display configuration summary
Write-SubSection "User Configuration Summary"
$configSummary = @(
    @{Section="Regular Users"; Count=$userConfig.RegularUsers.Count; Users=$userConfig.RegularUsers},
    @{Section="Administrators"; Count=$userConfig.Administrators.Count; Users=$userConfig.Administrators},
    @{Section="Domain Admins"; Count=$userConfig.DomainAdmins.Count; Users=$userConfig.DomainAdmins},
    @{Section="Enterprise Admins"; Count=$userConfig.EnterpriseAdmins.Count; Users=$userConfig.EnterpriseAdmins},
    @{Section="Remote Desktop Users"; Count=$userConfig.RemoteDesktopUsers.Count; Users=$userConfig.RemoteDesktopUsers},
    @{Section="Remote Management Users"; Count=$userConfig.RemoteManagementUsers.Count; Users=$userConfig.RemoteManagementUsers},
    @{Section="EXCLUDED USERS (never disabled)"; Count=$userConfig.ExcludedUsers.Count; Users=$userConfig.ExcludedUsers; Color="Cyan"}
)

foreach ($item in $configSummary) {
    if ($item.Color) {
        Write-Host "    $($item.Section): " -NoNewline -ForegroundColor $item.Color
        Write-Host $item.Count -ForegroundColor White
    } else {
        Write-Host "    $($item.Section): " -NoNewline
        Write-Host $item.Count -ForegroundColor White
    }
    if ($item.Count -gt 0) {
        Write-Host "      " -NoNewline
        if ($item.Color) {
            Write-Host ($item.Users -join ", ") -ForegroundColor $item.Color
        } else {
            Write-Host ($item.Users -join ", ") -ForegroundColor Gray
        }
    }
}

# ============================================================================
# Discover Domain Infrastructure
# ============================================================================
Write-SectionHeader "DOMAIN INFRASTRUCTURE DISCOVERY"

try {
    $allComputers = Get-ADComputer -Filter * -Properties OperatingSystem, DNSHostName | 
                    Where-Object { $_.Name -ne $script:DomainController }
    Write-Log "Discovered $($allComputers.Count) domain computers (excluding DC)" -Level SUCCESS
} catch {
    Write-Log "Failed to query domain computers: $_" -Level CRITICAL
    exit 1
}

# Test WinRM connectivity for Windows machines
$windowsComputers = @()
if (-not $SkipRemoteServers) {
    Write-SubSection "Testing WinRM Connectivity"
    
    $connectionTests = 0
    $connectionSuccess = 0
    $total = ($allComputers | Where-Object { $_.OperatingSystem -like "*Windows*" }).Count
    $current = 0
    
    foreach ($computer in $allComputers) {
        $computerName = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
        $os = $computer.OperatingSystem
        
        if ($os -like "*Windows*") {
            $current++
            $connectionTests++
            Write-Host "    [$current/$total] Testing $computerName..." -NoNewline -ForegroundColor Gray
            
            if (Test-WinRMConnection -ComputerName $computerName) {
                $windowsComputers += $computerName
                $connectionSuccess++
                Write-Host " OK" -ForegroundColor Green
            } else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Log "WinRM not accessible on $computerName" -Level WARNING
            }
        }
    }
    
    Write-Log "WinRM connectivity: $connectionSuccess/$connectionTests Windows computers accessible" -Level INFO
} else {
    Write-Log "Remote server processing skipped" -Level INFO
}

# ============================================================================
# PHASE 1: Domain Group Enforcement
# ============================================================================
if (-not $SkipGroupAudit) {
    Write-SectionHeader "PHASE 1: DOMAIN GROUP MEMBERSHIP ENFORCEMENT"
    
    # CRITICAL: Domain Admins and Enterprise Admins should automatically get RDP and WinRM access
    # Combine users from config with automatic privileges for Domain/Enterprise Admins
    $rdpUsers = @($userConfig.RemoteDesktopUsers) + @($userConfig.DomainAdmins) + @($userConfig.EnterpriseAdmins) | Select-Object -Unique
    $winrmUsers = @($userConfig.RemoteManagementUsers) + @($userConfig.DomainAdmins) + @($userConfig.EnterpriseAdmins) | Select-Object -Unique
    
    # Define group configurations
    $groupConfigurations = @(
        @{
            Name = "Domain Admins"
            AuthorizedUsers = $userConfig.DomainAdmins
            DefaultMembers = @("Administrator")
            Critical = $true
        },
        @{
            Name = "Enterprise Admins"
            AuthorizedUsers = $userConfig.EnterpriseAdmins
            DefaultMembers = @("Administrator")
            Critical = $true
        },
        @{
            Name = "Schema Admins"
            AuthorizedUsers = @()
            DefaultMembers = @("Administrator")
            Critical = $true
        },
        @{
            Name = "Administrators"
            AuthorizedUsers = $userConfig.Administrators
            DefaultMembers = @("Administrator", "Domain Admins", "Enterprise Admins")
            Critical = $true
        },
        @{
            Name = "Account Operators"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $true
        },
        @{
            Name = "Backup Operators"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $true
        },
        @{
            Name = "Server Operators"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $true
        },
        @{
            Name = "Print Operators"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $true
        },
        @{
            Name = "DnsAdmins"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $true
        },
        @{
            Name = "Group Policy Creator Owners"
            AuthorizedUsers = @()
            DefaultMembers = @("Administrator")
            Critical = $true
        },
        @{
            Name = "Remote Desktop Users"
            AuthorizedUsers = $rdpUsers  # Includes Domain/Enterprise Admins automatically
            DefaultMembers = @()
            Critical = $false
        },
        @{
            Name = "Remote Management Users"
            AuthorizedUsers = $winrmUsers  # Includes Domain/Enterprise Admins automatically
            DefaultMembers = @()
            Critical = $false
        },
        @{
            Name = "Hyper-V Administrators"
            AuthorizedUsers = @()
            DefaultMembers = @()
            Critical = $false
        }
    )
    
    $groupsProcessed = 0
    $totalGroups = $groupConfigurations.Count
    
    foreach ($groupConfig in $groupConfigurations) {
        $groupName = $groupConfig.Name
        $authorizedUsers = $groupConfig.AuthorizedUsers
        $defaultMembers = $groupConfig.DefaultMembers
        
        $groupsProcessed++
        Write-SubSection "Group: $groupName [$groupsProcessed/$totalGroups]"
        
        try {
            $currentMembers = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
            $script:Statistics.GroupsProcessed++
            
            Write-Log "Auditing group: $groupName ($($currentMembers.Count) members)" -Level AUDIT
            
            # Process current members
            foreach ($member in $currentMembers) {
                $memberName = $member.SamAccountName
                $memberNameLower = $memberName.ToLower()
                
                # Skip if member is excluded - don't touch their group memberships
                if ($userConfig.ExcludedUsers -contains $memberNameLower) {
                    Write-Host "      [-] " -NoNewline -ForegroundColor Cyan
                    Write-Host $memberName -NoNewline
                    Write-Host " (excluded - untouched)" -ForegroundColor Cyan
                    continue
                }
                
                # Check if member is authorized
                $isAuthorized = ($defaultMembers -contains $memberName) -or 
                               ($authorizedUsers -contains $memberNameLower)
                
                if ($isAuthorized) {
                    Write-Host "      [+] " -NoNewline -ForegroundColor Green
                    Write-Host $memberName -NoNewline
                    Write-Host " (authorized)" -ForegroundColor DarkGray
                } else {
                    Write-Host "      [x] " -NoNewline -ForegroundColor Red
                    Write-Host $memberName -NoNewline
                    
                    if ($DryRun) {
                        Write-Host " `[WOULD REMOVE`]" -ForegroundColor Yellow
                        Write-Log "Would remove unauthorized member '$memberName' from '$groupName'" -Level DRYRUN
                    } else {
                        try {
                            Remove-ADGroupMember -Identity $groupName -Member $memberName -Confirm:$false -ErrorAction Stop
                            Write-Host " `[REMOVED`]" -ForegroundColor Yellow
                            Write-Log "Removed unauthorized member '$memberName' from '$groupName'" -Level CHANGE
                            
                            $script:GroupChanges += [PSCustomObject]@{
                                Type = "Domain Group"
                                Group = $groupName
                                Member = $memberName
                                Action = "Removed"
                                Reason = "Unauthorized"
                            }
                            $script:Statistics.MembersRemoved++
                        } catch {
                            Write-Host " `[FAILED`]" -ForegroundColor Red
                            Write-Log "Failed to remove '$memberName' from '${groupName}': $_" -Level ERROR
                        }
                    }
                }
            }
            
            # Add missing authorized members
            $currentMemberNames = $currentMembers | ForEach-Object { $_.SamAccountName.ToLower() }
            
            foreach ($authorizedUser in $authorizedUsers) {
                # Skip if user is excluded - don't touch their group memberships
                if ($userConfig.ExcludedUsers -contains $authorizedUser) {
                    continue
                }
                
                if ($currentMemberNames -notcontains $authorizedUser) {
                    try {
                        $user = Get-ADUser -Identity $authorizedUser -ErrorAction Stop
                        
                        if ($DryRun) {
                            Write-Host "      + " -NoNewline -ForegroundColor Cyan
                            Write-Host "$authorizedUser " -NoNewline
                            Write-Host "`[WOULD ADD`]" -ForegroundColor Yellow
                            Write-Log "Would add authorized member '$authorizedUser' to '$groupName'" -Level DRYRUN
                        } else {
                            try {
                                Add-ADGroupMember -Identity $groupName -Members $authorizedUser -ErrorAction Stop
                                Write-Host "      + " -NoNewline -ForegroundColor Cyan
                                Write-Host "$authorizedUser " -NoNewline
                                Write-Host "`[ADDED`]" -ForegroundColor Green
                                Write-Log "Added authorized member '$authorizedUser' to '$groupName'" -Level CHANGE
                                
                                $script:GroupChanges += [PSCustomObject]@{
                                    Type = "Domain Group"
                                    Group = $groupName
                                    Member = $authorizedUser
                                    Action = "Added"
                                    Reason = "Authorized but missing"
                                }
                                $script:Statistics.MembersAdded++
                            } catch {
                                Write-Log "Failed to add '$authorizedUser' to '${groupName}': $_" -Level ERROR
                            }
                        }
                    } catch {
                        Write-Log "Authorized user '$authorizedUser' not found in AD for group '$groupName'" -Level WARNING
                    }
                }
            }
            
        } catch {
            Write-Log "Group '$groupName' does not exist or cannot be accessed" -Level WARNING
        }
    }
    
    Write-SubSection "Group Enforcement Summary"
    Write-Host "      Groups Processed: " -NoNewline; Write-Host $script:Statistics.GroupsProcessed -ForegroundColor White
    Write-Host "      Members Removed: " -NoNewline; Write-Host $script:Statistics.MembersRemoved -ForegroundColor Yellow
    Write-Host "      Members Added: " -NoNewline; Write-Host $script:Statistics.MembersAdded -ForegroundColor Green
    
    if ($rdpUsers.Count -gt 0) {
        Write-Host "`n      Note: Domain/Enterprise Admins automatically granted RDP access" -ForegroundColor Cyan
        Write-Host "      RDP Access Users: " -NoNewline; Write-Host ($rdpUsers -join ", ") -ForegroundColor White
    }
    
    if ($winrmUsers.Count -gt 0) {
        Write-Host "`n      Note: Domain/Enterprise Admins automatically granted WinRM access" -ForegroundColor Cyan
        Write-Host "      WinRM Access Users: " -NoNewline; Write-Host ($winrmUsers -join ", ") -ForegroundColor White
    }
    
    # Special handling for Guest account
    Write-SubSection "Built-in Account Management"
    
    try {
        $guestAccount = Get-ADUser -Identity "Guest" -Properties Enabled -ErrorAction Stop
        if ($guestAccount.Enabled) {
            if ($DryRun) {
                Write-Log "Would disable Guest account" -Level DRYRUN
            } else {
                Disable-ADAccount -Identity "Guest" -ErrorAction Stop
                Write-Log "Disabled Guest account" -Level CHANGE
                $script:AccountChanges += [PSCustomObject]@{
                    Type = "Domain Account"
                    Account = "Guest"
                    Action = "Disabled"
                }
            }
        } else {
            Write-Log "Guest account already disabled" -Level INFO
        }
    } catch {
        Write-Log "Guest account not found or already disabled" -Level INFO
    }
}

# ============================================================================
# PHASE 2: Domain User Password Management
# ============================================================================
if (-not $SkipPasswordReset) {
    Write-SectionHeader "PHASE 2: DOMAIN USER PASSWORD MANAGEMENT"
    
    try {
        $domainUsers = Get-ADUser -Filter * -Properties SamAccountName, Enabled, PasswordLastSet
        Write-Log "Processing $($domainUsers.Count) domain user accounts" -Level INFO
    } catch {
        Write-Log "Failed to query domain users: $_" -Level CRITICAL
        exit 1
    }
    
    $accountsSkipped = 0
    $total = ($domainUsers | Where-Object { $_.SamAccountName -notlike "*$" }).Count
    $current = 0
    
    Write-SubSection "Password Resets and Account Status"
    
    foreach ($user in $domainUsers) {
        $username = $user.SamAccountName
        $usernameLower = $username.ToLower()
        
        # Skip computer accounts
        if ($username -like "*$") {
            $accountsSkipped++
            continue
        }
        
        $current++
        if ($current % 10 -eq 0) {
            Write-Progress-Inline -Activity "Processing users" -Current $current -Total $total
        }
        
        # Check if user is excluded (CRITICAL - COMPLETELY hands-off!)
        $isExcluded = $userConfig.ExcludedUsers -contains $usernameLower
        
        if ($isExcluded) {
            # EXCLUDED USER - DO NOT TOUCH! Left completely alone for scoring/judges
            Write-Host "    [-] EXCLUDED: " -NoNewline -ForegroundColor Cyan
            Write-Host "Domain\$username " -NoNewline -ForegroundColor White
            Write-Host "(completely untouched - no password reset, no group changes)" -ForegroundColor Cyan
            Write-Log "Excluded user skipped: Domain\$username - left completely untouched" -Level INFO
            $accountsSkipped++
            continue  # Skip to next user - don't process this one at all
        }
        
        if ($allAuthorizedUsers -contains $usernameLower) {
            # Authorized user - reset password
            $newPassword = Generate-CCDCPassword -Length $PasswordLength
            
            # Validate password complexity (should always pass with optimized generator)
            if (-not (Test-PasswordComplexity -Password $newPassword)) {
                Write-Log "Password complexity check failed for $username - this should not happen!" -Level ERROR
                continue
            }
            
            if ($DryRun) {
                Write-Host "`n    " -NoNewline
                Write-Host "[+] WOULD RESET: " -NoNewline -ForegroundColor Yellow
                Write-Host "Domain\$username" -ForegroundColor White
                Write-Log "Would reset password: Domain\$username" -Level DRYRUN
            } else {
                try {
                    $securePassword = ConvertTo-SecureString -AsPlainText $newPassword -Force
                    Set-ADAccountPassword -Identity $user -NewPassword $securePassword -Reset -ErrorAction Stop
                    Set-ADUser -Identity $user -ChangePasswordAtLogon $false -Enabled $true -ErrorAction Stop
                    
                    Write-Host "`n    " -NoNewline
                    Write-Host "[+] RESET: " -NoNewline -ForegroundColor Green
                    Write-Host "Domain\$username" -ForegroundColor White
                    Write-Host "      Password: " -NoNewline -ForegroundColor Green
                    Write-Host $newPassword -ForegroundColor Black -BackgroundColor Green
                    
                    Write-Log "Password reset: Domain\$username" -Level CHANGE
                    
                    $script:PasswordResets += [PSCustomObject]@{
                        Type = "Domain User"
                        Account = $username
                        Password = $newPassword
                        Timestamp = Get-Date
                    }
                    $script:Statistics.PasswordsReset++
                } catch {
                    Write-Log "Failed to reset password for Domain\${username}: $_" -Level ERROR
                }
            }
        } else {
            # Unauthorized user - disable
            if ($user.Enabled) {
                if ($DryRun) {
                    Write-Host "    [x] WOULD DISABLE: " -NoNewline -ForegroundColor Yellow
                    Write-Host "Domain\$username (unauthorized)" -ForegroundColor Gray
                    Write-Log "Would disable unauthorized user: Domain\$username" -Level DRYRUN
                } else {
                    try {
                        Set-ADUser -Identity $user -Enabled $false -ErrorAction Stop
                        Write-Host "    [x] DISABLED: " -NoNewline -ForegroundColor Yellow
                        Write-Host "Domain\$username (unauthorized)" -ForegroundColor Gray
                        Write-Log "Disabled unauthorized user: Domain\$username" -Level CHANGE
                        
                        $script:AccountChanges += [PSCustomObject]@{
                            Type = "Domain Account"
                            Account = $username
                            Action = "Disabled"
                        }
                        $script:Statistics.AccountsDisabled++
                    } catch {
                        Write-Log "Failed to disable Domain\${username}: $_" -Level ERROR
                    }
                }
            } else {
                $accountsSkipped++
            }
        }
    }
    
    Write-SubSection "Domain User Summary"
    Write-Host "      Passwords Reset: " -NoNewline; Write-Host $script:Statistics.PasswordsReset -ForegroundColor Green
    Write-Host "      Accounts Disabled: " -NoNewline; Write-Host $script:Statistics.AccountsDisabled -ForegroundColor Yellow
    Write-Host "      Accounts Skipped: " -NoNewline; Write-Host $accountsSkipped -ForegroundColor Gray
}

# ============================================================================
# PHASE 3: Remote Server Local Group Enforcement
# ============================================================================
if (-not $SkipGroupAudit -and -not $SkipRemoteServers -and $windowsComputers.Count -gt 0) {
    Write-SectionHeader "PHASE 3: REMOTE SERVER LOCAL GROUP ENFORCEMENT"
    
    # CRITICAL: Domain/Enterprise Admins automatically get RDP and WinRM on all servers
    $localGroupConfigs = @(
        @{
            Name = "Administrators"
            AuthorizedUsers = $userConfig.Administrators
            DefaultMembers = @("Administrator", "Domain Admins", "Enterprise Admins")
        },
        @{
            Name = "Backup Operators"
            AuthorizedUsers = @()
            DefaultMembers = @()
        },
        @{
            Name = "Remote Desktop Users"
            AuthorizedUsers = $rdpUsers  # Includes Domain/Enterprise Admins automatically
            DefaultMembers = @("Domain Admins", "Enterprise Admins")
        },
        @{
            Name = "Remote Management Users"
            AuthorizedUsers = $winrmUsers  # Includes Domain/Enterprise Admins automatically
            DefaultMembers = @("Domain Admins", "Enterprise Admins")
        }
    )
    
    $totalServers = $windowsComputers.Count
    $currentServer = 0
    
    foreach ($computerName in $windowsComputers) {
        $currentServer++
        $script:Statistics.ServersProcessed++
        
        Write-SubSection "Server: $computerName [$currentServer/$totalServers]"
        
        foreach ($groupConfig in $localGroupConfigs) {
            $groupName = $groupConfig.Name
            $authorizedUsers = $groupConfig.AuthorizedUsers
            $defaultMembers = $groupConfig.DefaultMembers
            
            Write-Host "      Group: $groupName" -ForegroundColor Cyan
            
            $members = Invoke-RemoteGroupOperation -ComputerName $computerName -GroupName $groupName -Operation 'Get'
            
            if ($null -eq $members) {
                Write-Host "        (unable to query)" -ForegroundColor Red
                continue
            }
            
            if ($members.Count -eq 0) {
                Write-Host "        (empty)" -ForegroundColor DarkGray
                
                # Add authorized users to empty group
                foreach ($authorizedUser in $authorizedUsers) {
                    $domainUser = "$env:USERDOMAIN\$authorizedUser"
                    
                    if ($DryRun) {
                        Write-Host "        + " -NoNewline -ForegroundColor Cyan
                        Write-Host "$domainUser " -NoNewline
                        Write-Host "`[WOULD ADD`]" -ForegroundColor Yellow
                    } else {
                        $result = Invoke-RemoteGroupOperation -ComputerName $computerName -GroupName $groupName -Operation 'Add' -MemberName $domainUser
                        if ($result) {
                            Write-Host "        + " -NoNewline -ForegroundColor Cyan
                            Write-Host "$domainUser " -NoNewline
                            Write-Host "`[ADDED`]" -ForegroundColor Green
                            Write-Log "Added '$domainUser' to '$groupName' on $computerName" -Level CHANGE
                            
                            $script:GroupChanges += [PSCustomObject]@{
                                Type = "Local Group"
                                Computer = $computerName
                                Group = $groupName
                                Member = $domainUser
                                Action = "Added"
                            }
                            $script:Statistics.MembersAdded++
                        }
                    }
                }
                continue
            }
            
            foreach ($member in $members) {
                $memberName = $member.Name
                $shortName = $memberName -replace ".*\\", ""
                $shortNameLower = $shortName.ToLower()
                
                # Skip if member is excluded - don't touch their group memberships
                if ($userConfig.ExcludedUsers -contains $shortNameLower) {
                    Write-Host "        [-] " -NoNewline -ForegroundColor Cyan
                    Write-Host $memberName -NoNewline
                    Write-Host " (excluded - untouched)" -ForegroundColor Cyan
                    continue
                }
                
                # Check if authorized
                $isDefault = $false
                foreach ($defaultMember in $defaultMembers) {
                    if ($memberName -like "*\$defaultMember" -or $memberName -eq $defaultMember) {
                        $isDefault = $true
                        break
                    }
                }
                
                $isAuthorized = $isDefault -or ($authorizedUsers -contains $shortNameLower)
                
                if ($isAuthorized) {
                    Write-Host "        [+] " -NoNewline -ForegroundColor Green
                    Write-Host $memberName -ForegroundColor White
                } else {
                    Write-Host "        [x] " -NoNewline -ForegroundColor Red
                    Write-Host $memberName -NoNewline
                    
                    if ($DryRun) {
                        Write-Host " `[WOULD REMOVE`]" -ForegroundColor Yellow
                    } else {
                        $result = Invoke-RemoteGroupOperation -ComputerName $computerName -GroupName $groupName -Operation 'Remove' -MemberName $memberName
                        if ($result) {
                            Write-Host " `[REMOVED`]" -ForegroundColor Yellow
                            Write-Log "Removed '$memberName' from '$groupName' on $computerName" -Level CHANGE
                            
                            $script:GroupChanges += [PSCustomObject]@{
                                Type = "Local Group"
                                Computer = $computerName
                                Group = $groupName
                                Member = $memberName
                                Action = "Removed"
                            }
                            $script:Statistics.MembersRemoved++
                        } else {
                            Write-Host " `[FAILED`]" -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Add missing authorized members
            $currentMemberNames = $members | ForEach-Object { 
                ($_.Name -replace ".*\\", "").ToLower() 
            }
            
            foreach ($authorizedUser in $authorizedUsers) {
                # Skip if user is excluded - don't touch their group memberships
                if ($userConfig.ExcludedUsers -contains $authorizedUser) {
                    continue
                }
                
                if ($currentMemberNames -notcontains $authorizedUser) {
                    $domainUser = "$env:USERDOMAIN\$authorizedUser"
                    
                    if ($DryRun) {
                        Write-Host "        + " -NoNewline -ForegroundColor Cyan
                        Write-Host "$domainUser " -NoNewline
                        Write-Host "`[WOULD ADD`]" -ForegroundColor Yellow
                    } else {
                        $result = Invoke-RemoteGroupOperation -ComputerName $computerName -GroupName $groupName -Operation 'Add' -MemberName $domainUser
                        if ($result) {
                            Write-Host "        + " -NoNewline -ForegroundColor Cyan
                            Write-Host "$domainUser " -NoNewline
                            Write-Host "`[ADDED`]" -ForegroundColor Green
                            Write-Log "Added '$domainUser' to '$groupName' on $computerName" -Level CHANGE
                            
                            $script:GroupChanges += [PSCustomObject]@{
                                Type = "Local Group"
                                Computer = $computerName
                                Group = $groupName
                                Member = $domainUser
                                Action = "Added"
                            }
                            $script:Statistics.MembersAdded++
                        }
                    }
                }
            }
        }
    }
}

# ============================================================================
# PHASE 4: Remote Server Local User Management
# ============================================================================
if (-not $SkipPasswordReset -and -not $SkipRemoteServers -and $windowsComputers.Count -gt 0) {
    Write-SectionHeader "PHASE 4: REMOTE SERVER LOCAL USER MANAGEMENT"
    
    foreach ($computerName in $windowsComputers) {
        Write-SubSection "Server: $computerName"
        
        try {
            $localUsers = Invoke-Command -ComputerName $computerName -ScriptBlock {
                Get-LocalUser | Select-Object Name, Enabled, SID, Description
            } -ErrorAction Stop
            
            Write-Log "Processing $($localUsers.Count) local users on $computerName" -Level INFO
            
            foreach ($localUser in $localUsers) {
                $username = $localUser.Name
                $usernameLower = $username.ToLower()
                
                # System accounts - ensure disabled
                if ($usernameLower -in @('guest', 'defaultaccount', 'wdagutilityaccount')) {
                    if ($localUser.Enabled) {
                        if ($DryRun) {
                            Write-Host "      [x] WOULD DISABLE: " -NoNewline -ForegroundColor Yellow
                            Write-Host "$username (system account)" -ForegroundColor Gray
                        } else {
                            try {
                                Invoke-Command -ComputerName $computerName -ScriptBlock {
                                    param($user)
                                    Disable-LocalUser -Name $user -ErrorAction Stop
                                } -ArgumentList $username -ErrorAction Stop
                                
                                Write-Host "      [x] DISABLED: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$username (system account)" -ForegroundColor Gray
                                Write-Log "Disabled system account '$username' on $computerName" -Level CHANGE
                            } catch {
                                Write-Log "Failed to disable system account '$username' on ${computerName}: $_" -Level WARNING
                            }
                        }
                    }
                    continue
                }
                
                # Check if user is excluded (CRITICAL - COMPLETELY hands-off!)
                $isExcluded = $userConfig.ExcludedUsers -contains $usernameLower
                
                if ($isExcluded) {
                    # EXCLUDED USER - DO NOT TOUCH! Left completely alone for scoring/judges
                    Write-Host "      [-] EXCLUDED: " -NoNewline -ForegroundColor Cyan
                    Write-Host "$computerName\$username " -NoNewline -ForegroundColor White
                    Write-Host "(completely untouched)" -ForegroundColor Cyan
                    Write-Log "Excluded user skipped: $computerName\$username - left completely untouched" -Level INFO
                    continue  # Skip to next user - don't process this one at all
                }
                
                if ($allAuthorizedUsers -contains $usernameLower) {
                    # Authorized user - reset password
                    $newPassword = Generate-CCDCPassword -Length $PasswordLength
                    
                    if ($DryRun) {
                        Write-Host "`n      " -NoNewline
                        Write-Host "[+] WOULD RESET: " -NoNewline -ForegroundColor Yellow
                        Write-Host "$computerName\$username" -ForegroundColor White
                    } else {
                        try {
                            Invoke-Command -ComputerName $computerName -ScriptBlock {
                                param($user, $pass)
                                $securePass = ConvertTo-SecureString -AsPlainText $pass -Force
                                Set-LocalUser -Name $user -Password $securePass -ErrorAction Stop
                                Enable-LocalUser -Name $user -ErrorAction Stop
                            } -ArgumentList $username, $newPassword -ErrorAction Stop
                            
                            Write-Host "`n      " -NoNewline
                            Write-Host "[+] RESET: " -NoNewline -ForegroundColor Green
                            Write-Host "$computerName\$username" -ForegroundColor White
                            Write-Host "        Password: " -NoNewline -ForegroundColor Green
                            Write-Host $newPassword -ForegroundColor Black -BackgroundColor Green
                            
                            Write-Log "Password reset: $computerName\$username" -Level CHANGE
                            
                            $script:PasswordResets += [PSCustomObject]@{
                                Type = "Local User"
                                Computer = $computerName
                                Account = $username
                                Password = $newPassword
                                Timestamp = Get-Date
                            }
                        } catch {
                            Write-Log "Failed to reset password for $computerName\${username}: $_" -Level ERROR
                        }
                    }
                } else {
                    # Unauthorized user - disable
                    if ($localUser.Enabled) {
                        if ($DryRun) {
                            Write-Host "      [x] WOULD DISABLE: " -NoNewline -ForegroundColor Yellow
                            Write-Host "$computerName\$username (unauthorized)" -ForegroundColor Gray
                        } else {
                            try {
                                Invoke-Command -ComputerName $computerName -ScriptBlock {
                                    param($user)
                                    Disable-LocalUser -Name $user -ErrorAction Stop
                                } -ArgumentList $username -ErrorAction Stop
                                
                                Write-Host "      [x] DISABLED: " -NoNewline -ForegroundColor Yellow
                                Write-Host "$computerName\$username (unauthorized)" -ForegroundColor Gray
                                Write-Log "Disabled unauthorized user: $computerName\$username" -Level CHANGE
                                
                                $script:AccountChanges += [PSCustomObject]@{
                                    Type = "Local Account"
                                    Computer = $computerName
                                    Account = $username
                                    Action = "Disabled"
                                }
                            } catch {
                                Write-Log "Failed to disable $computerName\${username}: $_" -Level ERROR
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log "Failed to process local users on ${computerName}: $_" -Level ERROR
        }
    }
}

# ============================================================================
# FINAL SUMMARY AND CHANGE LOG
# ============================================================================
$endTime = Get-Date
$duration = $endTime - $script:StartTime

Write-SectionHeader "EXECUTION COMPLETE - SUMMARY REPORT"

Write-SubSection "Execution Statistics"
Write-Host "      Start Time: " -NoNewline; Write-Host ($script:StartTime.ToString("HH:mm:ss")) -ForegroundColor White
Write-Host "      End Time: " -NoNewline; Write-Host ($endTime.ToString("HH:mm:ss")) -ForegroundColor White
Write-Host "      Duration: " -NoNewline; Write-Host ("{0:mm}m {0:ss}s" -f $duration) -ForegroundColor White
Write-Host "      Total Log Entries: " -NoNewline; Write-Host $script:ExecutionLog.Count -ForegroundColor White
if ($DryRun) {
    Write-Host "`n      MODE: DRY RUN - No actual changes were made" -ForegroundColor Yellow -BackgroundColor DarkBlue
}

Write-SubSection "Change Summary"
Write-Host "      Groups Processed: " -NoNewline; Write-Host $script:Statistics.GroupsProcessed -ForegroundColor Cyan
Write-Host "      Group Members Removed: " -NoNewline; Write-Host $script:Statistics.MembersRemoved -ForegroundColor Yellow
Write-Host "      Group Members Added: " -NoNewline; Write-Host $script:Statistics.MembersAdded -ForegroundColor Green
Write-Host "      Password Resets: " -NoNewline; Write-Host $script:Statistics.PasswordsReset -ForegroundColor Green
Write-Host "      Accounts Disabled: " -NoNewline; Write-Host $script:Statistics.AccountsDisabled -ForegroundColor Yellow
Write-Host "      Servers Processed: " -NoNewline; Write-Host $script:Statistics.ServersProcessed -ForegroundColor Cyan
Write-Host "      Warnings: " -NoNewline; Write-Host $script:Warnings.Count -ForegroundColor Yellow
Write-Host "      Errors: " -NoNewline; Write-Host $script:Errors.Count -ForegroundColor Red

if ($script:PasswordResets.Count -gt 0 -and -not $DryRun) {
    Write-SubSection "Password Reset Log"
    Write-Host "`n      ALL PASSWORDS - RECORD THESE NOW!" -ForegroundColor White -BackgroundColor Red
    Write-Host "      " + ("=" * 72) -ForegroundColor Red
    
    foreach ($reset in $script:PasswordResets) {
        if ($reset.Type -eq "Domain User") {
            Write-Host "      Domain\$($reset.Account): " -NoNewline -ForegroundColor Cyan
        } else {
            Write-Host "      $($reset.Computer)\$($reset.Account): " -NoNewline -ForegroundColor Cyan
        }
        Write-Host $reset.Password -ForegroundColor Black -BackgroundColor Green
    }
    
    Write-Host "      " + ("=" * 72) -ForegroundColor Red
}

if ($script:GroupChanges.Count -gt 0) {
    Write-SubSection "Group Membership Changes"
    $script:GroupChanges | Format-Table -Property Type, Group, Member, Action, @{
        Label = "Computer/Domain"
        Expression = { if ($_.Computer) { $_.Computer } else { "Domain" } }
    } -AutoSize
}

if ($script:AccountChanges.Count -gt 0) {
    Write-SubSection "Account Status Changes"
    $script:AccountChanges | Format-Table -Property Type, Account, Action, @{
        Label = "Computer/Domain"
        Expression = { if ($_.Computer) { $_.Computer } else { "Domain" } }
    } -AutoSize
}

if ($script:Errors.Count -gt 0) {
    Write-SubSection "Errors Encountered"
    foreach ($err in $script:Errors) {
        Write-Host "      [$($err.Timestamp.ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor Red
        Write-Host $err.Message -ForegroundColor Red
    }
}

if ($script:Warnings.Count -gt 0 -and $script:Warnings.Count -le 10) {
    Write-SubSection "Warnings"
    foreach ($warning in $script:Warnings) {
        Write-Host "      [$($warning.Timestamp.ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor Yellow
        Write-Host $warning.Message -ForegroundColor Yellow
    }
} elseif ($script:Warnings.Count -gt 10) {
    Write-SubSection "Warnings"
    Write-Host "      $($script:Warnings.Count) warnings logged (showing first 10):" -ForegroundColor Yellow
    foreach ($warning in $script:Warnings | Select-Object -First 10) {
        Write-Host "      [$($warning.Timestamp.ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor Yellow
        Write-Host $warning.Message -ForegroundColor Yellow
    }
}

# ============================================================================
# Security Recommendations
# ============================================================================
Write-SectionHeader "POST-EXECUTION SECURITY CHECKLIST"

Write-Host "`n  CRITICAL NOTES:" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "     *  Domain Admins automatically get RDP and WinRM access" -ForegroundColor White
Write-Host "     *  Enterprise Admins automatically get RDP and WinRM access" -ForegroundColor White
Write-Host "     *  This ensures high-privilege accounts can manage all servers" -ForegroundColor White
if ($userConfig.ExcludedUsers.Count -gt 0) {
    Write-Host "     *  EXCLUDED USERS protected from disable: $($userConfig.ExcludedUsers -join ', ')" -ForegroundColor Cyan
}

Write-Host "`n  IMMEDIATE ACTIONS:" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "    [ ] Screenshot or record all passwords above" -ForegroundColor White
Write-Host "    [ ] Distribute passwords to team securely" -ForegroundColor White
Write-Host "    [ ] Verify all scoring services are operational" -ForegroundColor White
Write-Host "    [ ] Test RDP access for authorized users" -ForegroundColor White
Write-Host "    [ ] Test WinRM access for automation accounts" -ForegroundColor White
Write-Host "    [ ] Clear PowerShell command history" -ForegroundColor White

Write-Host "`n  ONGOING MONITORING:" -ForegroundColor Yellow
Write-Host "    [ ] Monitor for re-enabled accounts" -ForegroundColor White
Write-Host "    [ ] Watch for unauthorized group membership changes" -ForegroundColor White
Write-Host "    [ ] Check for new user account creation" -ForegroundColor White
Write-Host "    [ ] Monitor RDP connections (Event ID 4624, Logon Type 10)" -ForegroundColor White
Write-Host "    [ ] Monitor WinRM usage (Event ID 4688)" -ForegroundColor White
Write-Host "    [ ] Review Security event logs (Event IDs: 4728, 4729, 4732, 4733)" -ForegroundColor White

Write-Host "`n  CLEANUP COMMANDS:" -ForegroundColor Cyan
Write-Host "    Clear-History" -ForegroundColor Gray
Write-Host "    Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue" -ForegroundColor Gray

Write-Host "`n" -NoNewline
Write-Host ("=" * 80) -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  DRY RUN completed - No changes were made" -ForegroundColor Yellow
    Write-Host "  Remove -DryRun parameter to execute actual changes" -ForegroundColor Yellow
} else {
    Write-Host "  Script execution completed successfully" -ForegroundColor Green
    Write-Host "  All logging was terminal-only - no files created on disk" -ForegroundColor Green
}
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""
