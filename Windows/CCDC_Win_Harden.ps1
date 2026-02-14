# ============================================================================
# CCDC ULTIMATE Windows Hardening Script - All-in-One Edition
# Run from Domain Controller with Domain Admin privileges
# ============================================================================

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Ultimate CCDC Windows hardening with comprehensive security automation
    
.DESCRIPTION
    Complete hardening solution combining:
    - Automatic role detection (MSSQL, IIS, DC, RDP, etc.)
    - Service persistence (auto-restart critical services)
    - IIS-specific comprehensive hardening
    - Firewall configuration (role-based)
    - Service hardening
    - Registry hardening (20+ settings)
    - Security policy enforcement
    - Windows Defender configuration
    - PII file scanning
    - System enumeration and auditing
    - Optional process/service monitoring
    - Scheduled task auditing
    - Network baseline comparison
    - Terminal-only logging (no disk writes on DC)
    
.PARAMETER TargetServers
    Comma-separated list of specific servers to harden
    
.PARAMETER SkipFirewall
    Skip firewall configuration
    
.PARAMETER SkipServices
    Skip service hardening
    
.PARAMETER SkipRegistry
    Skip registry hardening
    
.PARAMETER SkipPersistence
    Skip service persistence scheduled task creation
    
.PARAMETER SkipPIIScan
    Skip PII file scanning
    
.PARAMETER SkipEnumeration
    Skip system enumeration
    
.PARAMETER EnableProcessMonitor
    Enable real-time process monitoring (blocks execution)
    
.PARAMETER EnableServiceMonitor
    Enable real-time service monitoring (blocks execution)
    
.PARAMETER DryRun
    Preview what would be changed without making changes
    
.NOTES
    Run from Domain Controller as Domain Admin
    Combines best practices from multiple CCDC sources
    Service persistence protects against Red Team disruption
#>

param(
    [string[]]$TargetServers = $null,
    [switch]$SkipFirewall,
    [switch]$SkipServices,
    [switch]$SkipRegistry,
    [switch]$SkipPersistence,
    [switch]$SkipPIIScan,
    [switch]$SkipEnumeration,
    [switch]$EnableProcessMonitor,
    [switch]$EnableServiceMonitor,
    [switch]$DryRun
)

# ============================================================================
# Global Configuration
# ============================================================================
$script:StartTime = Get-Date
$script:ExecutionLog = @()
$script:PersistenceActions = @()
$script:PIIFiles = @()
$script:Errors = @()
$script:Warnings = @()
$script:Statistics = @{
    ServersProcessed = 0
    RolesDetected = 0
    FirewallRulesAdded = 0
    ServicesHardened = 0
    RegistryKeysSet = 0
    SecurityPoliciesApplied = 0
    PersistenceTasksCreated = 0
    IISServersHardened = 0
    SQLServersAudited = 0
    BackdoorUsersDetected = 0
    LOLBinsBlocked = 0
    PIIFilesFound = 0
    ScheduledTasksAudited = 0
}

# Role detection signatures with service persistence mapping
$script:RoleSignatures = @{
    DomainController = @{
        Services = @('NTDS', 'DNS', 'Netlogon', 'W32Time', 'DFSR', 'Dfs', 'IsmServ', 'ADWS', 'kdc')
        MandatoryService = 'NTDS'  # Must be running to confirm this role
        Ports = @(53, 88, 123, 135, 139, 389, 445, 464, 636, 3268, 3269, '49152-65535')
        Description = "Active Directory Domain Controller"
        CriticalServices = @('NTDS', 'DNS', 'Netlogon', 'W32Time', 'kdc', 'DFSR', 'Dfs', 'ADWS', 'LanmanWorkstation', 'LanmanServer')
    }
    MSSQL = @{
        Services = @('MSSQLSERVER', 'SQLSERVERAGENT', 'SQLBrowser')
        Ports = @(1433, 1434)
        Description = "Microsoft SQL Server"
        CriticalServices = @('MSSQLSERVER')
    }
    IIS = @{
        Services = @('W3SVC', 'WAS')
        Ports = @(80, 443, 8080)
        Description = "Internet Information Services (Web Server)"
        CriticalServices = @('W3SVC', 'WAS')
    }
    RDP = @{
        Services = @('TermService', 'SessionEnv')
        Ports = @(3389)
        Description = "Remote Desktop Services"
        CriticalServices = @('TermService')
    }
    FileServer = @{
        Services = @('LanmanServer')
        Ports = @(445)
        Description = "File and Print Server"
        CriticalServices = @('LanmanServer')
    }
    DNS = @{
        Services = @('DNS')
        Ports = @(53)
        Description = "DNS Server"
        CriticalServices = @('DNS')
    }
    DHCP = @{
        Services = @('DHCPServer')
        Ports = @(67, 68)
        Description = "DHCP Server"
        CriticalServices = @('DHCPServer')
    }
    WinRM = @{
        Services = @('WinRM')
        Ports = @(5985, 5986)
        Description = "Windows Remote Management"
        CriticalServices = @('WinRM')
    }
    'Hyper-V' = @{
        Services = @('vmms', 'vmcompute')
        Ports = @(2179)
        Description = "Hyper-V Virtualization"
        CriticalServices = @('vmms')
    }
    SSH = @{
        Services = @('sshd', 'OpenSSHd')
        Ports = @(22)
        Description = "SSH Server"
        CriticalServices = @('sshd', 'OpenSSHd')
    }
    FTP = @{
        Services = @('FTPSVC', 'msftpsvc')
        Ports = @(21)
        Description = "FTP Server"
        CriticalServices = @('FTPSVC')
    }
    MySQL = @{
        Services = @('MySQL', 'MySQL80')
        Ports = @(3306)
        Description = "MySQL Database Server"
        CriticalServices = @('MySQL', 'MySQL80')
    }
}

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL', 'CHANGE', 'DRYRUN', 'ROLE', 'PERSIST', 'PII', 'AUDIT')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date
        Level = $Level
        Message = $Message
    }
    $script:ExecutionLog += $logEntry
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    
    switch ($Level) {
        'INFO'     { Write-Host "[INFO]     " -NoNewline -ForegroundColor Cyan }
        'SUCCESS'  { Write-Host "[SUCCESS]  " -NoNewline -ForegroundColor Green }
        'WARNING'  { 
            Write-Host "[WARNING]  " -NoNewline -ForegroundColor Yellow
            $script:Warnings += $logEntry
        }
        'ERROR'    { 
            Write-Host "[ERROR]    " -NoNewline -ForegroundColor Red
            $script:Errors += $logEntry
        }
        'CRITICAL' { 
            Write-Host "[CRITICAL] " -NoNewline -ForegroundColor White -BackgroundColor Red
            $script:Errors += $logEntry
        }
        'CHANGE'   { Write-Host "[CHANGE]   " -NoNewline -ForegroundColor Magenta }
        'DRYRUN'   { Write-Host "[DRY RUN]  " -NoNewline -ForegroundColor Yellow -BackgroundColor DarkBlue }
        'ROLE'     { Write-Host "[ROLE]     " -NoNewline -ForegroundColor Blue }
        'PERSIST'  { Write-Host "[PERSIST]  " -NoNewline -ForegroundColor Green -BackgroundColor DarkGreen }
        'PII'      { Write-Host "[PII]      " -NoNewline -ForegroundColor Red -BackgroundColor Yellow }
        'AUDIT'    { Write-Host "[AUDIT]    " -NoNewline -ForegroundColor Cyan }
    }
    
    Write-Host $Message
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

# ============================================================================
# Role Detection Functions
# ============================================================================

function Detect-ServerRoles {
    param(
        [string]$ComputerName
    )
    
    $detectedRoles = @()
    
    try {
        $services = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name
        } -ErrorAction Stop
        
        $serviceNames = $services.Name
        
        foreach ($role in $script:RoleSignatures.Keys) {
            $signature = $script:RoleSignatures[$role]
            $matchedServices = 0
            
            foreach ($requiredService in $signature.Services) {
                if ($serviceNames -contains $requiredService) {
                    $matchedServices++
                }
            }
            
            if ($matchedServices -gt 0) {
                # If role has a MandatoryService, it MUST be running to confirm the role
                # This prevents false positives (e.g. Win11 with LanmanServer != DC)
                if ($signature.MandatoryService) {
                    if ($serviceNames -notcontains $signature.MandatoryService) {
                        continue  # Skip this role - mandatory service not found
                    }
                }
                
                $detectedRoles += [PSCustomObject]@{
                    Role = $role
                    Description = $signature.Description
                    MatchedServices = $matchedServices
                    RequiredPorts = $signature.Ports
                    Services = $signature.Services
                    CriticalServices = $signature.CriticalServices
                }
                
                $script:Statistics.RolesDetected++
            }
        }
        
        return $detectedRoles
        
    } catch {
        Write-Log "Failed to detect roles on ${ComputerName}: $_" -Level ERROR
        return @()
    }
}

# ============================================================================
# Service Persistence Functions
# ============================================================================

function Create-ServicePersistence {
    param(
        [string]$ComputerName,
        [array]$Roles
    )
    
    Write-SubSection "Creating Service Persistence on $ComputerName"
    
    $criticalServices = @()
    foreach ($role in $Roles) {
        $criticalServices += $role.CriticalServices
    }
    $criticalServices = $criticalServices | Select-Object -Unique
    
    if ($criticalServices.Count -eq 0) {
        Write-Log "No critical services detected for persistence" -Level INFO
        return
    }
    
    Write-Log "Creating persistence for $($criticalServices.Count) critical services" -Level INFO
    
    try {
        $scriptBlock = {
            param($servicesStr, $dryRun)
            
            # Split pipe-delimited string back into array
            $services = $servicesStr -split '\|'
            
            $results = @{
                TasksCreated = 0
                TasksFailed = 0
                ServiceMonitorCreated = $false
            }
            
            $watchdogScript = @'
# CCDC Service Persistence Watchdog
$services = @(
{0}
)

foreach ($svc in $services) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            # Check if stopped
            if ($service.Status -ne 'Running') {
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                $eventMessage = "CCDC Watchdog restarted service: $svc"
                Write-EventLog -LogName Application -Source "CCDC-Watchdog" -EventId 1001 -EntryType Information -Message $eventMessage -ErrorAction SilentlyContinue
            }
            # Check startup type
            if ($service.StartType -ne 'Automatic') {
                Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
            }
        }
    } catch {
        # Silent fail - don't alert Red Team
    }
}
'@
            
            $serviceList = ($services | ForEach-Object { "    '$_'" }) -join ",`r`n"
            $watchdogScript = $watchdogScript.Replace('{0}', $serviceList)
            
            $watchdogPath = "C:\Windows\System32\CCDC-ServiceWatchdog.ps1"
            
            if (-not $dryRun) {
                try {
                    if (-not [System.Diagnostics.EventLog]::SourceExists("CCDC-Watchdog")) {
                        New-EventLog -LogName Application -Source "CCDC-Watchdog" -ErrorAction SilentlyContinue
                    }
                } catch {}
                
                $watchdogScript | Out-File -FilePath $watchdogPath -Encoding ASCII -Force
                
                $taskName = "CCDC-ServicePersistence"
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
                    -Argument "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File `"$watchdogPath`""
                
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 9999)
                
                $settings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -RunOnlyIfNetworkAvailable:$false `
                    -DontStopOnIdleEnd `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 1)
                
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                Register-ScheduledTask -TaskName $taskName `
                    -Action $action `
                    -Trigger $trigger `
                    -Settings $settings `
                    -Principal $principal `
                    -Description "CCDC service persistence - monitors and restarts critical services" `
                    -ErrorAction Stop
                
                $results.TasksCreated++
                $results.ServiceMonitorCreated = $true
                
                foreach ($svc in $services) {
                    try {
                        sc.exe failure $svc reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
                        $results.TasksCreated++
                    } catch {}
                }
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would create persistence for services: $($criticalServices -join ', ')" -Level DRYRUN
        } else {
            $servicesStr = $criticalServices -join '|'
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $servicesStr, $false -ErrorAction Stop
            
            if ($result.ServiceMonitorCreated) {
                Write-Log "Service persistence watchdog created (runs every 2 minutes)" -Level PERSIST
                Write-Log "Monitoring services: $($criticalServices -join ', ')" -Level PERSIST
                Write-Log "Scheduled task created: $($result.TasksCreated)" -Level SUCCESS
                
                $script:Statistics.PersistenceTasksCreated += $result.TasksCreated
                
                $script:PersistenceActions += [PSCustomObject]@{
                    Server = $ComputerName
                    Services = $criticalServices -join ', '
                    TasksCreated = $result.TasksCreated
                    Timestamp = Get-Date
                }
            }
        }
        
    } catch {
        Write-Log "Failed to create service persistence on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Firewall Configuration Functions
# ============================================================================

function Configure-RoleBasedFirewall {
    param(
        [string]$ComputerName,
        [array]$Roles
    )
    
    Write-SubSection "Configuring Firewall for $ComputerName"
    
    try {
        $requiredPorts = @()
        foreach ($role in $Roles) {
            $requiredPorts += $role.RequiredPorts
        }
        $requiredPorts = $requiredPorts | Select-Object -Unique | Sort-Object
        
        # Convert all ports to strings for WinRM serialization safety
        # (Invoke-Command deserializes [int] as Deserialized.System.Int32 which fails -is [int])
        [string[]]$portStrings = $requiredPorts | ForEach-Object { [string]$_ }
        
        Write-Log "Required ports for detected roles: $($portStrings -join ', ')" -Level INFO
        
        $scriptBlock = {
            param($portsStr, $dryRun)
            
            # Split pipe-delimited string back into array
            $ports = $portsStr -split '\|'
            
            $results = @{
                FirewallEnabled = $false
                RulesAdded = 0
                RulesRemoved = 0
            }
            
            # Ports that need UDP rules in addition to TCP
            $udpPorts = @(53, 67, 68, 88, 123, 389, 464, 500, 4500)
            
            try {
                if (-not $dryRun) {
                    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
                    $results.FirewallEnabled = $true
                }
                
                $existingRules = Get-NetFirewallRule -DisplayName "CCDC-*" -ErrorAction SilentlyContinue
                if ($existingRules -and -not $dryRun) {
                    Remove-NetFirewallRule -DisplayName "CCDC-*" -ErrorAction SilentlyContinue
                    $results.RulesRemoved = $existingRules.Count
                }
                
                # Always allow ICMP (scoring systems often ping)
                if (-not $dryRun) {
                    New-NetFirewallRule -DisplayName "CCDC-Allow-ICMPv4" -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                }
                $results.RulesAdded++
                
                # Always allow WinRM for remote management (script depends on this)
                foreach ($wmPort in @('5985', '5986')) {
                    if ($ports -notcontains $wmPort) {
                        if (-not $dryRun) {
                            New-NetFirewallRule -DisplayName "CCDC-Allow-TCP-$wmPort" -Direction Inbound -Protocol TCP -LocalPort ([int]$wmPort) -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                        }
                        $results.RulesAdded++
                    }
                }
                
                foreach ($port in $ports) {
                    $portStr = [string]$port
                    if ($portStr -match '^\d+$') {
                        $portNum = [int]$portStr
                        if (-not $dryRun) {
                            New-NetFirewallRule -DisplayName "CCDC-Allow-TCP-$portStr" -Direction Inbound -Protocol TCP -LocalPort $portNum -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                            # Add UDP rule if this port typically needs it
                            if ($portNum -in $udpPorts) {
                                New-NetFirewallRule -DisplayName "CCDC-Allow-UDP-$portStr" -Direction Inbound -Protocol UDP -LocalPort $portNum -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                                $results.RulesAdded++
                            }
                        }
                        $results.RulesAdded++
                    } elseif ($portStr -match '^(\d+)-(\d+)$') {
                        if (-not $dryRun) {
                            New-NetFirewallRule -DisplayName "CCDC-Allow-TCP-$portStr" -Direction Inbound -Protocol TCP -LocalPort $portStr -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                        }
                        $results.RulesAdded++
                    }
                }
            } catch {
                $results.Error = $_.Exception.Message
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would configure firewall with ports: $($portStrings -join ', ')" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList ($portStrings -join '|'), $false -ErrorAction Stop
            
            if ($result.Error) {
                Write-Log "Firewall configuration failed: $($result.Error)" -Level ERROR
            } else {
                Write-Log "Firewall rules added: $($result.RulesAdded), removed: $($result.RulesRemoved)" -Level SUCCESS
                $script:Statistics.FirewallRulesAdded += $result.RulesAdded
            }
        }
        
    } catch {
        Write-Log "Failed to configure firewall on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Service Hardening Functions
# ============================================================================

function Harden-Services {
    param(
        [string]$ComputerName,
        [array]$Roles
    )
    
    Write-SubSection "Hardening Services on $ComputerName"
    
    $servicesToDisable = @(
        'RemoteRegistry', 'XblAuthManager', 'XblGameSave', 'XboxGipSvc', 'XboxNetApiSvc',
        'Browser', 'bthserv', 'MapsBroker', 'lfsvc', 'SharedAccess', 'TrkWks',
        'WMPNetworkSvc', 'RetailDemo', 'Fax', 'WerSvc', 'DiagTrack', 'dmwappushservice'
    )
    
    # SAFETY: Services that must NEVER be disabled regardless of role detection
    # These are infrastructure-critical and breaking them can take down the domain
    # Also protects dependencies for ServiceGuardian (Winmgmt, Schedule)
    $neverDisable = @(
        'NTDS', 'DNS', 'Netlogon', 'W32Time', 'DFSR', 'Dfs', 'ADWS', 'kdc', 'IsmServ',
        'LanmanWorkstation', 'LanmanServer', 'TermService', 'WinRM', 'WinDefend',
        'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'LSM', 'SamSs', 'EventLog',
        'gpsvc', 'CryptSvc', 'Dhcp', 'Dnscache', 'nlasvc', 'BFE', 'mpssvc',
        'MSSQLSERVER', 'W3SVC', 'WAS', 'DHCPServer', 'vmms',
        'Winmgmt', 'Schedule'
    )
    
    $requiredServices = @()
    foreach ($role in $Roles) {
        $requiredServices += $role.Services
    }
    # Merge role-detected services with never-disable list
    $requiredServices = ($requiredServices + $neverDisable) | Select-Object -Unique
    
    $hasFileServer = $Roles | Where-Object { $_.Role -eq 'FileServer' }
    if (-not $hasFileServer) {
        $servicesToDisable += 'Spooler'
    }
    
    try {
        $scriptBlock = {
            param($disableStr, $requiredStr, $dryRun)
            
            # Split pipe-delimited strings back into arrays (avoids WinRM serialization issues)
            $servicesToDisable = $disableStr -split '\|'
            $requiredServices = if ($requiredStr) { $requiredStr -split '\|' } else { @() }
            
            $results = @{ Disabled = 0; Skipped = 0; Failed = 0 }
            
            foreach ($serviceName in $servicesToDisable) {
                try {
                    if ($requiredServices -contains $serviceName) {
                        $results.Skipped++
                        continue
                    }
                    
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($service -and ($service.Status -eq 'Running' -or $service.StartType -ne 'Disabled')) {
                        if (-not $dryRun) {
                            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                        }
                        $results.Disabled++
                    }
                } catch {
                    $results.Failed++
                }
            }
            
            return $results
        }
        
        if ($DryRun) {
            $toDisable = $servicesToDisable | Where-Object { $requiredServices -notcontains $_ }
            Write-Log "Would disable $($toDisable.Count) unnecessary services" -Level DRYRUN
        } else {
            # Join arrays as strings to avoid WinRM serialization issues
            $disableStr = $servicesToDisable -join '|'
            $requiredStr = $requiredServices -join '|'
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $disableStr, $requiredStr, $false -ErrorAction Stop
            Write-Log "Services disabled: $($result.Disabled), skipped: $($result.Skipped), failed: $($result.Failed)" -Level SUCCESS
            $script:Statistics.ServicesHardened += $result.Disabled
        }
        
    } catch {
        Write-Log "Failed to harden services on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Registry Hardening Functions
# ============================================================================

function Harden-Registry {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Applying Registry Hardening on $ComputerName"
    
    $registrySettings = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Value = 2; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Value = 255; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'NoDataExecutionPrevention'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Value = 5; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name = 'LDAPClientIntegrity'; Value = 2; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name = 'NodeType'; Value = 2; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableRealtimeMonitoring'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAutoUpdate'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RestrictNullSessAccess'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'UseMachineId'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'EnableSecuritySignature'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Type = 'DWord' },
        # PowerShell transcript and module logging
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableInvocationHeader'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Value = 1; Type = 'DWord' },
        # Reduce cached credentials (limits offline credential attacks)
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'CachedLogonsCount'; Value = '2'; Type = 'String' },
        # RDP NLA enforcement (requires authentication before session)
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'UserAuthentication'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = 'SecurityLayer'; Value = 2; Type = 'DWord' },
        # RDP idle session timeout (15 min disconnect, 30 min logoff - prevents abandoned sessions)
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MaxIdleTime'; Value = 900000; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MaxDisconnectionTime'; Value = 1800000; Type = 'DWord' },
        # Disable RDP drive/clipboard redirection (Red Team uses for file transfer)
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; Value = 1; Type = 'DWord' },
        # Log full command line in process creation events (Event ID 4688)
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Type = 'DWord' }
    )
    
    try {
        # Convert settings to JSON for reliable WinRM transport
        # (Hashtable arrays lose type information through PowerShell remoting serialization)
        $settingsJson = $registrySettings | ConvertTo-Json -Depth 3 -Compress
        
        $scriptBlock = {
            param($jsonSettings, $dryRun)
            
            $settings = $jsonSettings | ConvertFrom-Json
            $results = @{ Applied = 0; Skipped = 0; Failed = 0 }
            
            foreach ($setting in $settings) {
                try {
                    if (-not (Test-Path $setting.Path) -and -not $dryRun) {
                        New-Item -Path $setting.Path -Force | Out-Null
                    }
                    
                    $currentValue = $null
                    try {
                        $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue).$($setting.Name)
                    } catch {}
                    
                    if ($currentValue -eq $setting.Value) {
                        $results.Skipped++
                    } else {
                        if (-not $dryRun) {
                            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
                        }
                        $results.Applied++
                    }
                } catch {
                    $results.Failed++
                }
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would apply $($registrySettings.Count) registry settings" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $settingsJson, $false -ErrorAction Stop
            Write-Log "Registry keys applied: $($result.Applied), skipped: $($result.Skipped), failed: $($result.Failed)" -Level SUCCESS
            $script:Statistics.RegistryKeysSet += $result.Applied
        }
        
    } catch {
        Write-Log "Failed to harden registry on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Security Policy Functions
# ============================================================================

function Apply-SecurityPolicies {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Applying Security Policies on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{ Applied = 0; Failed = 0 }
            
            try {
                if (-not $dryRun) {
                    net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:5 2>&1 | Out-Null
                }
                $results.Applied++
                
                $auditCategories = @(
                    "Credential Validation", "Logon", "Audit Policy Change",
                    "Special Logon", "Security Group Management", "User Account Management"
                )
                
                foreach ($category in $auditCategories) {
                    if (-not $dryRun) {
                        auditpol.exe /set /subcategory:"$category" /success:enable /failure:enable 2>&1 | Out-Null
                    }
                    $results.Applied++
                }
                
                if (-not $dryRun) {
                    net user Guest /active:no 2>&1 | Out-Null
                }
                $results.Applied++
            } catch {
                $results.Failed++
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would apply security policies" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            Write-Log "Security policies applied: $($result.Applied)" -Level SUCCESS
            $script:Statistics.SecurityPoliciesApplied += $result.Applied
        }
        
    } catch {
        Write-Log "Failed to apply security policies on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# RDP/WinRM Logon Rights Functions
# ============================================================================

function Grant-RemoteLogonRights {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Granting Remote Logon Rights on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{ Applied = 0; Failed = 0; Details = '' }
            
            try {
                $tempDir = "$env:TEMP\ccdc-secedit"
                if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force | Out-Null }
                
                $exportFile = "$tempDir\secpol-export.inf"
                $importFile = "$tempDir\secpol-import.inf"
                $seceditDb  = "$tempDir\secedit.sdb"
                
                # Export current local security policy
                secedit.exe /export /cfg $exportFile /quiet 2>&1 | Out-Null
                
                if (-not (Test-Path $exportFile)) {
                    $results.Failed++
                    $results.Details = 'secedit export failed'
                    return $results
                }
                
                $content = Get-Content $exportFile -Raw
                
                # Well-known SIDs for logon rights
                # *S-1-5-32-544 = BUILTIN\Administrators
                # *S-1-5-32-555 = BUILTIN\Remote Desktop Users
                # *S-1-5-32-580 = BUILTIN\Remote Management Users
                
                $modified = $false
                
                # --- SeRemoteInteractiveLogonRight (Allow log on through Remote Desktop Services) ---
                $rdpSids = @('*S-1-5-32-544', '*S-1-5-32-555')
                
                if ($content -match '(?m)^SeRemoteInteractiveLogonRight\s*=\s*(.*)$') {
                    $currentLine = $matches[0]
                    $currentValue = $matches[1]
                    $missingSids = @()
                    foreach ($sid in $rdpSids) {
                        if ($currentValue -notlike "*$sid*") {
                            $missingSids += $sid
                        }
                    }
                    if ($missingSids.Count -gt 0) {
                        $newValue = ($currentValue.TrimEnd() + ',' + ($missingSids -join ','))
                        $content = $content.Replace($currentLine, "SeRemoteInteractiveLogonRight = $newValue")
                        $modified = $true
                        $results.Applied++
                    }
                } else {
                    # Line doesn't exist at all - add it under [Privilege Rights]
                    $rdpLine = "SeRemoteInteractiveLogonRight = " + ($rdpSids -join ',')
                    if ($content -match '(?m)^\[Privilege Rights\]') {
                        $content = $content -replace '(?m)^(\[Privilege Rights\])', "`$1`r`n$rdpLine"
                        $modified = $true
                        $results.Applied++
                    }
                }
                
                # --- SeDenyRemoteInteractiveLogonRight (ensure RDP Users are NOT in deny list) ---
                if ($content -match '(?m)^SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$') {
                    $currentLine = $matches[0]
                    $currentValue = $matches[1]
                    # Remove Remote Desktop Users SID if present in deny list
                    if ($currentValue -like '*S-1-5-32-555*') {
                        $newValue = ($currentValue -replace '\*S-1-5-32-555,?', '').TrimEnd(',').TrimEnd()
                        $content = $content.Replace($currentLine, "SeDenyRemoteInteractiveLogonRight = $newValue")
                        $modified = $true
                        $results.Applied++
                    }
                }
                
                # --- SeNetworkLogonRight (Access this computer from the network - needed for WinRM) ---
                $networkSids = @('*S-1-5-32-544', '*S-1-5-32-580')
                
                if ($content -match '(?m)^SeNetworkLogonRight\s*=\s*(.*)$') {
                    $currentLine = $matches[0]
                    $currentValue = $matches[1]
                    $missingSids = @()
                    foreach ($sid in $networkSids) {
                        if ($currentValue -notlike "*$sid*") {
                            $missingSids += $sid
                        }
                    }
                    if ($missingSids.Count -gt 0) {
                        $newValue = ($currentValue.TrimEnd() + ',' + ($missingSids -join ','))
                        $content = $content.Replace($currentLine, "SeNetworkLogonRight = $newValue")
                        $modified = $true
                        $results.Applied++
                    }
                }
                
                if ($modified -and -not $dryRun) {
                    $content | Out-File -FilePath $importFile -Encoding Unicode -Force
                    
                    # Remove stale db if exists
                    Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
                    
                    $importResult = secedit.exe /configure /db $seceditDb /cfg $importFile /quiet 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $results.Details = 'Policy imported successfully'
                    } else {
                        $results.Failed++
                        $results.Details = "secedit import failed: $importResult"
                    }
                } elseif (-not $modified) {
                    $results.Details = 'All logon rights already correct'
                }
                
                # Cleanup temp files
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                
            } catch {
                $results.Failed++
                $results.Details = $_.Exception.Message
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would grant Remote Desktop and WinRM logon rights" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            
            if ($result.Failed -gt 0) {
                Write-Log "Remote logon rights failed: $($result.Details)" -Level ERROR
            } else {
                Write-Log "Remote logon rights configured ($($result.Applied) changes): $($result.Details)" -Level SUCCESS
            }
        }
        
    } catch {
        Write-Log "Failed to grant remote logon rights on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Windows Defender Functions
# ============================================================================

function Enable-WindowsDefender {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Configuring Windows Defender on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{ Enabled = $false; Updated = $false; Error = $null }
            
            try {
                $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($defenderService) {
                    if (-not $dryRun) {
                        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
                        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
                        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                        Update-MpSignature -ErrorAction SilentlyContinue
                        $results.Updated = $true
                    }
                    $results.Enabled = $true
                }
            } catch {
                $results.Error = $_.Exception.Message
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would enable Windows Defender and update signatures" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            
            if ($result.Enabled) {
                Write-Log "Windows Defender enabled and updated" -Level SUCCESS
            } else {
                Write-Log "Windows Defender not available" -Level INFO
            }
        }
        
    } catch {
        Write-Log "Failed to configure Windows Defender on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# IIS Comprehensive Hardening Functions
# ============================================================================

function Harden-IIS {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Comprehensive IIS Hardening on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{
                AppPoolsHardened = 0
                DirectoryBrowsingDisabled = 0
                AnonymousAuthDisabled = 0
                CustomErrorsDeleted = 0
                Error = $null
            }
            
            try {
                Import-Module WebAdministration -ErrorAction Stop
                
                if (-not $dryRun) {
                    # Set application pool privileges to minimum
                    foreach ($item in Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue) {
                        try {
                            $tempPath = "IIS:\AppPools\$($item.Name)"
                            Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
                            $results.AppPoolsHardened++
                        } catch {}
                    }
                    
                    # Disable directory browsing on all sites
                    foreach ($item in Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue) {
                        try {
                            $tempPath = "IIS:\Sites\$($item.Name)"
                            Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value $false
                            $results.DirectoryBrowsingDisabled++
                        } catch {}
                    }
                    
                    # Disable Anonymous Authentication
                    try {
                        Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Allow -PSPath IIS:/
                        foreach ($item in Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue) {
                            $tempPath = "IIS:\Sites\$($item.Name)"
                            Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath $tempPath -Name enabled -Value $false
                            $results.AnonymousAuthDisabled++
                        }
                        Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Deny -PSPath IIS:/
                    } catch {}
                    
                    # Delete Custom Error Pages
                    try {
                        $sysDrive = $Env:SystemDrive
                        $tempPath = (Get-WebConfiguration "//httperrors/error" -ErrorAction SilentlyContinue).prefixLanguageFilePath | Select-Object -First 1
                        if ($tempPath) {
                            $tempPath = $tempPath.Substring($tempPath.IndexOf('\')+1)
                            $fullPath = Join-Path $sysDrive $tempPath
                            $deleted = Get-ChildItem -Path $fullPath -Include *.* -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { 
                                $_.Delete()
                                $results.CustomErrorsDeleted++
                            }
                        }
                    } catch {}
                }
            } catch {
                $results.Error = $_.Exception.Message
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would harden IIS (app pools, directory browsing, auth, errors)" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            
            Write-Log "IIS hardening complete: AppPools=$($result.AppPoolsHardened), DirBrowse=$($result.DirectoryBrowsingDisabled), AnonAuth=$($result.AnonymousAuthDisabled)" -Level SUCCESS
            $script:Statistics.IISServersHardened++
        }
        
    } catch {
        Write-Log "Failed to harden IIS on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Event Log Hardening Functions
# ============================================================================

function Harden-EventLogs {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Configuring Event Log Sizes on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{ Configured = 0; Failed = 0 }
            
            # Use wevtutil.exe instead of .NET SaveChanges() which fails through WinRM
            $logConfigs = @(
                @{ Name = 'Security'; MaxSize = 268435456 },      # 256 MB
                @{ Name = 'System'; MaxSize = 134217728 },        # 128 MB
                @{ Name = 'Application'; MaxSize = 134217728 },   # 128 MB
                @{ Name = 'Windows PowerShell'; MaxSize = 134217728 }  # 128 MB
            )
            
            foreach ($logConfig in $logConfigs) {
                try {
                    if (-not $dryRun) {
                        $maxSizeKB = $logConfig.MaxSize / 1024
                        wevtutil.exe sl $logConfig.Name /ms:$($logConfig.MaxSize) 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            $results.Configured++
                        } else {
                            $results.Failed++
                        }
                    } else {
                        $results.Configured++
                    }
                } catch {
                    $results.Failed++
                }
            }
            
            # Enable PowerShell operational log (often disabled by default)
            try {
                if (-not $dryRun) {
                    wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /e:true /ms:134217728 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        $results.Configured++
                    } else {
                        $results.Failed++
                    }
                }
            } catch {
                $results.Failed++
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would increase event log sizes (Security=256MB, System/App/PS=128MB)" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            Write-Log "Event logs configured: $($result.Configured), failed: $($result.Failed)" -Level SUCCESS
        }
        
    } catch {
        Write-Log "Failed to configure event logs on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# PowerShell v2 Disable Functions
# ============================================================================

function Disable-PowerShellV2 {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Disabling PowerShell v2 on $ComputerName"
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            $results = @{ Disabled = $false; AlreadyDisabled = $false; Error = $null }
            
            try {
                # Check if PSv2 feature is installed
                $feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
                
                if ($null -eq $feature) {
                    # Try server feature check
                    $feature = Get-WindowsFeature -Name PowerShell-V2 -ErrorAction SilentlyContinue
                    if ($feature -and $feature.Installed) {
                        if (-not $dryRun) {
                            Remove-WindowsFeature -Name PowerShell-V2 -ErrorAction Stop | Out-Null
                            $results.Disabled = $true
                        }
                    } else {
                        $results.AlreadyDisabled = $true
                    }
                } else {
                    if ($feature.State -eq 'Enabled') {
                        if (-not $dryRun) {
                            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
                            $results.Disabled = $true
                        }
                    } else {
                        $results.AlreadyDisabled = $true
                    }
                }
            } catch {
                $results.Error = $_.Exception.Message
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would disable PowerShell v2 engine" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            
            if ($result.Disabled) {
                Write-Log "PowerShell v2 disabled (Red Team can no longer bypass logging via downgrade)" -Level SUCCESS
            } elseif ($result.AlreadyDisabled) {
                Write-Log "PowerShell v2 already disabled" -Level INFO
            } elseif ($result.Error) {
                Write-Log "Could not disable PowerShell v2: $($result.Error)" -Level WARNING
            }
        }
        
    } catch {
        Write-Log "Failed to disable PowerShell v2 on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# SQL Server Audit Functions (Report-Only - Do NOT change, may break scoring)
# ============================================================================

function Audit-SQLServer {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "SQL Server Security Audit on $ComputerName (READ-ONLY)"
    
    try {
        $scriptBlock = {
            $results = @{
                SAEnabled = $null
                XpCmdShellEnabled = $null
                CLREnabled = $null
                RemoteAccessEnabled = $null
                AdHocQueriesEnabled = $null
                SQLVersion = $null
                SQLPort = $null
                Error = $null
            }
            
            try {
                # Try to load SQL module or use direct connection
                $sqlInstance = "localhost"
                
                # Get SQL version
                try {
                    $version = Invoke-Sqlcmd -Query "SELECT @@VERSION AS Version" -ServerInstance $sqlInstance -ErrorAction Stop
                    $results.SQLVersion = ($version.Version -split "`n")[0]
                } catch {
                    # Fallback: try with sqlcmd.exe
                    $versionOut = sqlcmd -S $sqlInstance -Q "SELECT @@VERSION" -h -1 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $results.SQLVersion = ($versionOut | Where-Object { $_ -match 'Microsoft' }) -join ' '
                    } else {
                        $results.Error = "Cannot connect to SQL Server"
                        return $results
                    }
                }
                
                # Check dangerous configurations
                $checks = @(
                    @{ Name = 'XpCmdShellEnabled'; Query = "SELECT CONVERT(INT, value_in_use) AS val FROM sys.configurations WHERE name = 'xp_cmdshell'" },
                    @{ Name = 'CLREnabled'; Query = "SELECT CONVERT(INT, value_in_use) AS val FROM sys.configurations WHERE name = 'clr enabled'" },
                    @{ Name = 'RemoteAccessEnabled'; Query = "SELECT CONVERT(INT, value_in_use) AS val FROM sys.configurations WHERE name = 'remote access'" },
                    @{ Name = 'AdHocQueriesEnabled'; Query = "SELECT CONVERT(INT, value_in_use) AS val FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'" }
                )
                
                foreach ($check in $checks) {
                    try {
                        $queryResult = Invoke-Sqlcmd -Query $check.Query -ServerInstance $sqlInstance -ErrorAction Stop
                        $results[$check.Name] = [bool]$queryResult.val
                    } catch {
                        try {
                            $out = sqlcmd -S $sqlInstance -Q $check.Query -h -1 -W 2>&1
                            if ($LASTEXITCODE -eq 0 -and $out) {
                                $val = ($out | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
                                if ($null -ne $val) {
                                    $results[$check.Name] = [bool][int]$val
                                }
                            }
                        } catch {}
                    }
                }
                
                # Check SA account status
                try {
                    $saCheck = Invoke-Sqlcmd -Query "SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'" -ServerInstance $sqlInstance -ErrorAction Stop
                    $results.SAEnabled = -not [bool]$saCheck.is_disabled
                } catch {
                    try {
                        $out = sqlcmd -S $sqlInstance -Q "SELECT is_disabled FROM sys.server_principals WHERE name = 'sa'" -h -1 -W 2>&1
                        if ($LASTEXITCODE -eq 0 -and $out) {
                            $val = ($out | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
                            if ($null -ne $val) {
                                $results.SAEnabled = -not [bool][int]$val
                            }
                        }
                    } catch {}
                }
                
                # Check listening port
                try {
                    $sqlPort = Get-NetTCPConnection -OwningProcess (Get-Process -Name sqlservr -ErrorAction SilentlyContinue).Id -State Listen -ErrorAction SilentlyContinue |
                        Where-Object { $_.LocalPort -ne 0 } |
                        Select-Object -First 1 -ExpandProperty LocalPort
                    $results.SQLPort = $sqlPort
                } catch {}
                
            } catch {
                $results.Error = $_.Exception.Message
            }
            
            return $results
        }
        
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
        
        if ($result.Error) {
            Write-Log "SQL audit failed: $($result.Error)" -Level WARNING
            return
        }
        
        $script:Statistics.SQLServersAudited++
        
        if ($result.SQLVersion) {
            Write-Log "SQL Version: $($result.SQLVersion)" -Level AUDIT
        }
        if ($result.SQLPort) {
            Write-Log "SQL Listening Port: $($result.SQLPort)" -Level AUDIT
        }
        
        # Report findings with severity
        $issues = @()
        
        if ($result.SAEnabled -eq $true) {
            Write-Log "WARNING: 'sa' account is ENABLED - consider disabling if scoring allows" -Level WARNING
            $issues += "sa enabled"
        } elseif ($result.SAEnabled -eq $false) {
            Write-Log "sa account is disabled" -Level SUCCESS
        }
        
        if ($result.XpCmdShellEnabled -eq $true) {
            Write-Log "CRITICAL: xp_cmdshell is ENABLED - Red Team can execute OS commands!" -Level WARNING
            $issues += "xp_cmdshell"
        } elseif ($result.XpCmdShellEnabled -eq $false) {
            Write-Log "xp_cmdshell is disabled" -Level SUCCESS
        }
        
        if ($result.CLREnabled -eq $true) {
            Write-Log "WARNING: CLR is ENABLED - can be used for code execution" -Level WARNING
            $issues += "CLR enabled"
        }
        
        if ($result.AdHocQueriesEnabled -eq $true) {
            Write-Log "WARNING: Ad Hoc Distributed Queries ENABLED" -Level WARNING
            $issues += "Ad Hoc Queries"
        }
        
        if ($issues.Count -eq 0) {
            Write-Log "SQL Server audit clean - no critical issues found" -Level SUCCESS
        } else {
            Write-Log "SQL ISSUES FOUND: $($issues -join ', ') - Review manually before changing (may break scoring!)" -Level WARNING
        }
        
    } catch {
        Write-Log "Failed to audit SQL Server on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# PII Scanning Functions
# ============================================================================

function Scan-PIIFiles {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Scanning for PII Files on $ComputerName"
    
    # Improved patterns with word boundaries (fewer false positives)
    $piiPatterns = @(
        '\b\d{3}[-| |.]\d{2}[-| |.]\d{4}\b',           # SSN
        '\b\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}\b',       # Phone
        '\b\d+\s+[\w\s]+\s+(?:road|street|avenue|boulevard|court)\b'  # Street address
    )
    
    # Filter by extension FIRST (UCI approach) - massively faster than scanning every file
    $fileExtensions = '\.docx|\.doc|\.odt|\.xlsx|\.xls|\.ods|\.pptx|\.ppt|\.pdf|\.mdb|\.accdb|\.sqlite3?|\.eml|\.msg|\.txt|\.csv|\.html?|\.xml|\.json'
    
    try {
        $scriptBlock = {
            param($patternsStr, $extensions)
            
            # Split patterns back from transport string (using ||| to avoid conflicts with regex pipe)
            $patterns = $patternsStr -split '\|\|\|'
            
            $found = @()
            $paths = @("C:\Users\*\Downloads", "C:\Users\*\Documents", "C:\Users\*\Desktop", "C:\inetpub")
            
            foreach ($path in $paths) {
                # Extension filter runs before content scan - skips binaries, images, etc.
                Get-ChildItem -Recurse -Force -Path $path -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -match $extensions -and $_.Name -ne 'desktop.ini' } |
                    ForEach-Object {
                        try {
                            foreach ($pattern in $patterns) {
                                $piiMatch = Select-String -Path $_.FullName -Pattern $pattern -ErrorAction SilentlyContinue
                                if ($piiMatch) {
                                    $found += $_.FullName
                                    break  # One match per file is enough
                                }
                            }
                        } catch {}
                    }
            }
            
            return $found | Select-Object -Unique
        }
        
        $patternsStr = $piiPatterns -join '|||'
        $piiFiles = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $patternsStr, $fileExtensions -ErrorAction Stop
        
        if ($piiFiles.Count -gt 0) {
            Write-Log "Found $($piiFiles.Count) potential PII files" -Level PII
            $script:Statistics.PIIFilesFound += $piiFiles.Count
            $script:PIIFiles += [PSCustomObject]@{
                Server = $ComputerName
                Files = $piiFiles
                Count = $piiFiles.Count
            }
        } else {
            Write-Log "No PII files found" -Level SUCCESS
        }
        
    } catch {
        Write-Log "Failed to scan PII on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# LOLBins Outbound Blocking Functions (from CyberHansel/UCI approach)
# ============================================================================

function Block-LOLBins {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Blocking LOLBins Outbound Connections on $ComputerName"
    
    # These are Living-Off-The-Land binaries Red Team uses to download payloads
    # Blocking OUTBOUND only - cannot break inbound scoring services
    $lolbins = @(
        'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
        'cscript.exe', 'wscript.exe', 'hh.exe', 'msiexec.exe',
        'notepad.exe', 'calc.exe', 'pcalua.exe', 'print.exe',
        'esentutl.exe', 'expand.exe', 'extrac32.exe', 'findstr.exe',
        'replace.exe', 'makecab.exe', 'nltest.exe'
    )
    
    try {
        $scriptBlock = {
            param($dryRun)
            
            # Define inside scriptblock to avoid WinRM array serialization issues
            $binaries = @(
                'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
                'cscript.exe', 'wscript.exe', 'hh.exe', 'msiexec.exe',
                'notepad.exe', 'calc.exe', 'pcalua.exe', 'print.exe',
                'esentutl.exe', 'expand.exe', 'extrac32.exe', 'findstr.exe',
                'replace.exe', 'makecab.exe', 'nltest.exe'
            )
            
            $results = @{ RulesAdded = 0; Failed = 0 }
            
            foreach ($binary in $binaries) {
                $ruleName = "CCDC-Block-LOLBin-$($binary -replace '\.exe$','')"
                $programPath = "$env:SystemRoot\System32\$binary"
                
                # Skip if binary does not exist on this system
                if (-not (Test-Path $programPath)) { continue }
                
                if (-not $dryRun) {
                    try {
                        # Remove existing rule if present (idempotent)
                        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                        
                        # Block outbound TCP only
                        New-NetFirewallRule -DisplayName $ruleName `
                            -Direction Outbound `
                            -Protocol TCP `
                            -Program $programPath `
                            -Action Block `
                            -Profile Any `
                            -Description "CCDC: Block $binary from making outbound connections" `
                            -ErrorAction SilentlyContinue | Out-Null
                        $results.RulesAdded++
                    } catch {
                        $results.Failed++
                    }
                } else {
                    $results.RulesAdded++
                }
            }
            
            return $results
        }
        
        if ($DryRun) {
            Write-Log "Would block outbound connections for $($lolbins.Count) LOLBins" -Level DRYRUN
        } else {
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $false -ErrorAction Stop
            Write-Log "LOLBin outbound rules added: $($result.RulesAdded), failed: $($result.Failed)" -Level SUCCESS
            $script:Statistics.FirewallRulesAdded += $result.RulesAdded
        }
        
    } catch {
        Write-Log "Failed to block LOLBins on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Backdoor User Detection Functions (from UCI CCDC statistical analysis)
# ============================================================================

function Audit-BackdoorUsers {
    Write-SubSection "Auditing for Backdoor AD Users (Statistical Analysis)"
    
    # UCI approach: legitimate users typically have consistent Description,
    # Company, and Department fields. Red Team backdoor accounts are outliers.
    # This is READ-ONLY audit - does not disable or modify any accounts.
    
    try {
        $users = Get-ADUser -Filter * -Properties SamAccountName, Description, Company, Department, WhenCreated, Enabled -ErrorAction Stop
        
        # Exclude well-known built-in accounts - they always flag as outliers
        $builtinAccounts = @('administrator', 'guest', 'krbtgt', 'defaultaccount', 'wdagutilityaccount')
        $users = $users | Where-Object { 
            $_.SamAccountName -notlike '*$' -and 
            $builtinAccounts -notcontains $_.SamAccountName.ToLower() 
        }
        
        if ($users.Count -lt 5) {
            Write-Log "Too few users ($($users.Count)) for statistical analysis" -Level INFO
            return
        }
        
        $suspiciousUsers = @()
        
        # Analyze Description field lengths
        $descLengths = $users | ForEach-Object { if ($null -eq $_.Description) { 0 } else { $_.Description.Length } }
        $descAvg = ($descLengths | Measure-Object -Average).Average
        $descSd = [Math]::Sqrt(($descLengths | ForEach-Object { ($_ - $descAvg) * ($_ - $descAvg) } | Measure-Object -Average).Average)
        
        # Analyze Company field lengths
        $compLengths = $users | ForEach-Object { if ($null -eq $_.Company) { 0 } else { $_.Company.Length } }
        $compAvg = ($compLengths | Measure-Object -Average).Average
        $compSd = [Math]::Sqrt(($compLengths | ForEach-Object { ($_ - $compAvg) * ($_ - $compAvg) } | Measure-Object -Average).Average)
        
        # Analyze Department field lengths
        $deptLengths = $users | ForEach-Object { if ($null -eq $_.Department) { 0 } else { $_.Department.Length } }
        $deptAvg = ($deptLengths | Measure-Object -Average).Average
        $deptSd = [Math]::Sqrt(($deptLengths | ForEach-Object { ($_ - $deptAvg) * ($_ - $deptAvg) } | Measure-Object -Average).Average)
        
        foreach ($user in $users) {
            $flags = @()
            
            # Check Description outlier (2+ standard deviations)
            $descLen = if ($null -eq $user.Description) { 0 } else { $user.Description.Length }
            if ($descSd -gt 0 -and [Math]::Abs($descLen - $descAvg) / $descSd -ge 2) {
                $flags += "Description"
            }
            
            # Check Company outlier
            $compLen = if ($null -eq $user.Company) { 0 } else { $user.Company.Length }
            if ($compSd -gt 0 -and [Math]::Abs($compLen - $compAvg) / $compSd -ge 2) {
                $flags += "Company"
            }
            
            # Check Department outlier
            $deptLen = if ($null -eq $user.Department) { 0 } else { $user.Department.Length }
            if ($deptSd -gt 0 -and [Math]::Abs($deptLen - $deptAvg) / $deptSd -ge 2) {
                $flags += "Department"
            }
            
            # Also flag recently created accounts (last 48 hours)
            if ($user.WhenCreated -gt (Get-Date).AddHours(-48)) {
                $flags += "RecentlyCreated"
            }
            
            if ($flags.Count -ge 2) {
                $suspiciousUsers += [PSCustomObject]@{
                    Username = $user.SamAccountName
                    Enabled = $user.Enabled
                    Flags = $flags -join ', '
                    Created = $user.WhenCreated
                }
            }
        }
        
        $script:Statistics.BackdoorUsersDetected = $suspiciousUsers.Count
        
        if ($suspiciousUsers.Count -gt 0) {
            Write-Log "ALERT: $($suspiciousUsers.Count) suspicious accounts detected (2+ outlier flags)" -Level WARNING
            foreach ($sus in $suspiciousUsers) {
                Write-Host "      [!] " -NoNewline -ForegroundColor Red
                Write-Host "$($sus.Username)" -NoNewline -ForegroundColor White
                Write-Host " (Enabled=$($sus.Enabled)) Flags: $($sus.Flags)" -ForegroundColor Yellow
            }
            Write-Log "ACTION: Manually review these accounts - they may be Red Team backdoors" -Level WARNING
        } else {
            Write-Log "No suspicious outlier accounts detected" -Level SUCCESS
        }
        
    } catch {
        Write-Log "Failed to audit backdoor users: $_" -Level ERROR
    }
}

# ============================================================================
# System Enumeration Functions
# ============================================================================

function Perform-SystemEnumeration {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "System Enumeration for $ComputerName"
    
    try {
        $scriptBlock = {
            $results = @{}
            
            # OS Info
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            $results.OS = @{
                Name = $osInfo.CSName
                Caption = $osInfo.Caption
                Version = $osInfo.Version
                Build = $osInfo.BuildNumber
            }
            
            # Firewall Status
            $fwProfiles = @{}
            $lines = (netsh advfirewall show allprofiles state) -split "`r`n"
            $profiles = @("Domain Profile", "Private Profile", "Public Profile")
            foreach ($profile in $profiles) {
                $profileLine = $lines | Where-Object { $_ -match "$profile Settings:" }
                if ($profileLine) {
                    $profileIndex = $lines.IndexOf($profileLine)
                    for ($i = 1; $i -le 3; $i++) {
                        if ($profileIndex + $i -lt $lines.Count) {
                            $stateLine = $lines[$profileIndex + $i]
                            if ($stateLine -match "State\s+(\w+)") {
                                $fwProfiles[$profile] = $matches[1]
                                break
                            }
                        }
                    }
                }
            }
            $results.Firewall = $fwProfiles
            
            # Defender Status
            try {
                $defStatus = Get-MpComputerStatus
                $results.Defender = @{
                    Antivirus = $defStatus.AntivirusEnabled
                    RealTime = $defStatus.RealTimeProtectionEnabled
                    Antispyware = $defStatus.AntispywareEnabled
                }
            } catch {
                $results.Defender = "Not Available"
            }
            
            # Network Adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, MacAddress
            $results.NetworkAdapters = $adapters
            
            # Active Ports
            $activePorts = Get-NetTCPConnection | 
                Where-Object { $_.State -eq 'Listen' } | 
                Select-Object LocalPort -Unique | 
                Sort-Object LocalPort
            $results.ActivePorts = $activePorts.LocalPort
            
            return $results
        }
        
        $enumResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
        
        Write-Log "OS: $($enumResults.OS.Caption) Build $($enumResults.OS.Build)" -Level AUDIT
        Write-Log "Firewall: Domain=$($enumResults.Firewall['Domain Profile']), Private=$($enumResults.Firewall['Private Profile']), Public=$($enumResults.Firewall['Public Profile'])" -Level AUDIT
        
        if ($enumResults.Defender -ne "Not Available") {
            Write-Log "Defender: AV=$($enumResults.Defender.Antivirus), RT=$($enumResults.Defender.RealTime)" -Level AUDIT
        }
        
        Write-Log "Active listening ports: $($enumResults.ActivePorts -join ', ')" -Level AUDIT
        
    } catch {
        Write-Log "Failed to enumerate ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Scheduled Task Auditing Functions
# ============================================================================

function Audit-ScheduledTasks {
    param(
        [string]$ComputerName
    )
    
    Write-SubSection "Auditing Scheduled Tasks on $ComputerName"
    
    try {
        $scriptBlock = {
            $tasks = Get-ScheduledTask | 
                Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
                Select-Object TaskName, TaskPath, State
            return $tasks
        }
        
        $tasks = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop
        
        if ($tasks.Count -gt 0) {
            Write-Log "Found $($tasks.Count) non-Microsoft scheduled tasks" -Level AUDIT
            $script:Statistics.ScheduledTasksAudited += $tasks.Count
            
            foreach ($task in $tasks) {
                Write-Host "      Task: $($task.TaskName) [$($task.TaskPath)] - $($task.State)" -ForegroundColor Gray
            }
        } else {
            Write-Log "No custom scheduled tasks found" -Level AUDIT
        }
        
    } catch {
        Write-Log "Failed to audit scheduled tasks on ${ComputerName}: $_" -Level ERROR
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Clear-Host
Write-Host "`n"
Write-SectionHeader "CCDC ULTIMATE WINDOWS HARDENING - ALL-IN-ONE EDITION"
Write-Host "  Start Time: " -NoNewline -ForegroundColor Gray
Write-Host ($script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
if ($DryRun) {
    Write-Host "  MODE: " -NoNewline -ForegroundColor Gray
    Write-Host "DRY RUN (No changes will be made)" -ForegroundColor Yellow -BackgroundColor DarkBlue
}

# ============================================================================
# Discover Target Servers
# ============================================================================
Write-SectionHeader "SERVER DISCOVERY"

$targetComputers = @()

if ($TargetServers) {
    Write-Log "Using provided target servers: $($TargetServers -join ', ')" -Level INFO
    $targetComputers = $TargetServers
} else {
    try {
        Write-Log "Discovering Windows computers in domain..." -Level INFO
        $allComputers = @(Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} -Properties OperatingSystem, DNSHostName)
        Write-Log "Found $($allComputers.Count) Windows computers in domain" -Level SUCCESS
        
        Write-SubSection "Testing WinRM Connectivity"
        
        foreach ($computer in $allComputers) {
            $computerName = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
            Write-Host "    Testing $computerName..." -NoNewline -ForegroundColor Gray
            
            try {
                $null = Test-WSMan -ComputerName $computerName -ErrorAction Stop
                $targetComputers += $computerName
                Write-Host " OK" -ForegroundColor Green
            } catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Log "WinRM not accessible on $computerName" -Level WARNING
            }
        }
        
        Write-Log "WinRM accessible on $($targetComputers.Count) computers" -Level SUCCESS
        
    } catch {
        Write-Log "Failed to discover domain computers: $_" -Level CRITICAL
        exit 1
    }
}

if ($targetComputers.Count -eq 0) {
    Write-Log "No accessible servers found. Exiting." -Level CRITICAL
    exit 1
}

# ============================================================================
# Process Each Server
# ============================================================================
Write-SectionHeader "COMPREHENSIVE SERVER HARDENING"

foreach ($serverName in $targetComputers) {
    $script:Statistics.ServersProcessed++
    
    Write-SubSection "Processing Server: $serverName [$($script:Statistics.ServersProcessed)/$($targetComputers.Count)]"
    
    # Detect roles
    Write-Log "Detecting installed roles..." -Level INFO
    $detectedRoles = Detect-ServerRoles -ComputerName $serverName
    
    if ($detectedRoles.Count -gt 0) {
        Write-Log "Detected roles on ${serverName}:" -Level ROLE
        foreach ($role in $detectedRoles) {
            Write-Host "      * " -NoNewline -ForegroundColor Blue
            Write-Host "$($role.Role)" -NoNewline -ForegroundColor White
            Write-Host " - $($role.Description)" -ForegroundColor Gray
        }
    } else {
        Write-Log "No specific roles detected (generic Windows server)" -Level INFO
    }
    
    # System Enumeration
    if (-not $SkipEnumeration) {
        Perform-SystemEnumeration -ComputerName $serverName
        Audit-ScheduledTasks -ComputerName $serverName
    }
    
    # Apply hardening
    if (-not $SkipFirewall) {
        Configure-RoleBasedFirewall -ComputerName $serverName -Roles $detectedRoles
    }
    
    if (-not $SkipServices) {
        Harden-Services -ComputerName $serverName -Roles $detectedRoles
    }
    
    if (-not $SkipRegistry) {
        Harden-Registry -ComputerName $serverName
    }
    
    Apply-SecurityPolicies -ComputerName $serverName
    Grant-RemoteLogonRights -ComputerName $serverName
    Enable-WindowsDefender -ComputerName $serverName
    
    # Event log hardening (safe - purely additive)
    Harden-EventLogs -ComputerName $serverName
    
    # Disable PowerShell v2 (prevents logging bypass)
    Disable-PowerShellV2 -ComputerName $serverName
    
    # Block LOLBins outbound connections (outbound-only, cannot break inbound scoring)
    if (-not $SkipFirewall) {
        Block-LOLBins -ComputerName $serverName
    }
    
    # IIS-specific hardening
    $hasIIS = $detectedRoles | Where-Object { $_.Role -eq 'IIS' }
    if ($hasIIS) {
        Harden-IIS -ComputerName $serverName
    }
    
    # SQL Server audit (read-only - reports issues but changes nothing)
    $hasMSSQL = $detectedRoles | Where-Object { $_.Role -eq 'MSSQL' }
    $hasMySQL = $detectedRoles | Where-Object { $_.Role -eq 'MySQL' }
    if ($hasMSSQL) {
        Audit-SQLServer -ComputerName $serverName
    }
    if ($hasMySQL) {
        Write-Log "MySQL detected - manual hardening recommended (check root password, remote access, test databases)" -Level WARNING
    }
    
    # PII Scanning
    if (-not $SkipPIIScan) {
        Scan-PIIFiles -ComputerName $serverName
    }
    
    # Service Persistence (runs last)
    if (-not $SkipPersistence) {
        Create-ServicePersistence -ComputerName $serverName -Roles $detectedRoles
    }
    
    Write-Log "Completed hardening for $serverName" -Level SUCCESS
}

# ============================================================================
# Domain-Wide Backdoor User Detection (runs once after server hardening)
# ============================================================================
if (-not $SkipEnumeration) {
    Audit-BackdoorUsers
}

# ============================================================================
# Summary Report
# ============================================================================
$endTime = Get-Date
$duration = $endTime - $script:StartTime

Write-SectionHeader "EXECUTION SUMMARY"

Write-SubSection "Execution Statistics"
Write-Host "      Start Time: " -NoNewline; Write-Host ($script:StartTime.ToString("HH:mm:ss")) -ForegroundColor White
Write-Host "      End Time: " -NoNewline; Write-Host ($endTime.ToString("HH:mm:ss")) -ForegroundColor White
Write-Host "      Duration: " -NoNewline; Write-Host ("{0:mm}m {0:ss}s" -f $duration) -ForegroundColor White

Write-SubSection "Hardening Statistics"
Write-Host "      Servers Processed: " -NoNewline; Write-Host $script:Statistics.ServersProcessed -ForegroundColor Cyan
Write-Host "      Roles Detected: " -NoNewline; Write-Host $script:Statistics.RolesDetected -ForegroundColor Blue
Write-Host "      Firewall Rules Added: " -NoNewline; Write-Host $script:Statistics.FirewallRulesAdded -ForegroundColor Green
Write-Host "      Services Hardened: " -NoNewline; Write-Host $script:Statistics.ServicesHardened -ForegroundColor Green
Write-Host "      Registry Keys Set: " -NoNewline; Write-Host $script:Statistics.RegistryKeysSet -ForegroundColor Green
Write-Host "      Security Policies Applied: " -NoNewline; Write-Host $script:Statistics.SecurityPoliciesApplied -ForegroundColor Green
Write-Host "      Persistence Tasks Created: " -NoNewline; Write-Host $script:Statistics.PersistenceTasksCreated -ForegroundColor Green
Write-Host "      IIS Servers Hardened: " -NoNewline; Write-Host $script:Statistics.IISServersHardened -ForegroundColor Green
Write-Host "      SQL Servers Audited: " -NoNewline; Write-Host $script:Statistics.SQLServersAudited -ForegroundColor Cyan
Write-Host "      Backdoor Users Detected: " -NoNewline; Write-Host $script:Statistics.BackdoorUsersDetected -ForegroundColor $(if ($script:Statistics.BackdoorUsersDetected -gt 0) { 'Red' } else { 'Green' })
Write-Host "      PII Files Found: " -NoNewline; Write-Host $script:Statistics.PIIFilesFound -ForegroundColor $(if ($script:Statistics.PIIFilesFound -gt 0) { 'Red' } else { 'Green' })
Write-Host "      Scheduled Tasks Audited: " -NoNewline; Write-Host $script:Statistics.ScheduledTasksAudited -ForegroundColor Cyan
Write-Host "      Warnings: " -NoNewline; Write-Host $script:Warnings.Count -ForegroundColor Yellow
Write-Host "      Errors: " -NoNewline; Write-Host $script:Errors.Count -ForegroundColor Red

if ($script:PersistenceActions.Count -gt 0) {
    Write-SubSection "Service Persistence Summary"
    $script:PersistenceActions | Format-Table -Property Server, Services, TasksCreated -AutoSize
}

if ($script:PIIFiles.Count -gt 0) {
    Write-SubSection "PII Files Detected (CRITICAL!)"
    foreach ($item in $script:PIIFiles) {
        Write-Host "  Server: $($item.Server) - $($item.Count) files" -ForegroundColor Red
        $item.Files | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    }
}

if ($script:Errors.Count -gt 0) {
    Write-SubSection "Errors Encountered"
    foreach ($err in $script:Errors | Select-Object -First 10) {
        Write-Host "      [$($err.Timestamp.ToString('HH:mm:ss'))] " -NoNewline -ForegroundColor Red
        Write-Host $err.Message -ForegroundColor Red
    }
}

Write-SectionHeader "POST-HARDENING ACTIONS"

Write-Host "`n  IMMEDIATE:" -ForegroundColor Red -BackgroundColor Yellow
Write-Host "    [ ] Verify all scoring services functional" -ForegroundColor White
Write-Host "    [ ] Test connectivity to hardened servers" -ForegroundColor White
Write-Host "    [ ] Test RDP access (NLA now enforced)" -ForegroundColor White
Write-Host "    [ ] Review PII files and secure/delete" -ForegroundColor White
Write-Host "    [ ] Verify service persistence running" -ForegroundColor White

if ($script:Statistics.BackdoorUsersDetected -gt 0) {
    Write-Host "`n  BACKDOOR USERS (MANUAL - review audit output above):" -ForegroundColor Red
    Write-Host "    [ ] Review flagged accounts - compare against your users_config.txt" -ForegroundColor White
    Write-Host "    [ ] If account is NOT in your config AND NOT a scoring account:" -ForegroundColor White
    Write-Host "        Disable-ADAccount -Identity '<username>'" -ForegroundColor Gray
    Write-Host "    [ ] Check if flagged accounts have unusual group memberships" -ForegroundColor White
}

if ($script:Statistics.SQLServersAudited -gt 0) {
    Write-Host "`n  SQL SERVER (MANUAL - review audit output above):" -ForegroundColor Yellow
    Write-Host "    [ ] If xp_cmdshell is enabled and scoring doesn't use it:" -ForegroundColor White
    Write-Host "        EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;" -ForegroundColor Gray
    Write-Host "    [ ] If 'sa' account is enabled and scoring doesn't use it:" -ForegroundColor White
    Write-Host "        ALTER LOGIN sa DISABLE;" -ForegroundColor Gray
    Write-Host "    [ ] Change sa password if it must stay enabled:" -ForegroundColor White
    Write-Host "        ALTER LOGIN sa WITH PASSWORD = 'NewStr0ngP@ss!';" -ForegroundColor Gray
}

Write-Host "`n  PERSISTENCE VERIFICATION:" -ForegroundColor Cyan
Write-Host "    Get-ScheduledTask -TaskName 'CCDC-ServicePersistence'" -ForegroundColor Gray
Write-Host "    Get-Content C:\Windows\System32\CCDC-ServiceWatchdog.ps1" -ForegroundColor Gray
Write-Host "    Get-EventLog -LogName Application -Source 'CCDC-Watchdog' -Newest 10" -ForegroundColor Gray

Write-Host "`n  MONITORING COMMANDS:" -ForegroundColor Cyan
Write-Host "    # Check for Red Team PowerShell activity:" -ForegroundColor Gray
Write-Host "    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20" -ForegroundColor Gray
Write-Host "    # Check for new processes:" -ForegroundColor Gray
Write-Host "    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 20" -ForegroundColor Gray

Write-Host "`n" -NoNewline
Write-Host ("=" * 80) -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  DRY RUN completed - No changes were made" -ForegroundColor Yellow
} else {
    Write-Host "  Ultimate hardening completed successfully" -ForegroundColor Green
    Write-Host "  Service persistence enabled, PII scanned, systems enumerated" -ForegroundColor Green
}
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Optional Monitoring (Blocks Execution)
# ============================================================================

if ($EnableProcessMonitor) {
    Write-SectionHeader "PROCESS MONITORING ENABLED"
    Write-Log "Starting real-time process monitoring (Ctrl+C to exit)..." -Level WARNING
    
    $script:allowedProcesses = @{}
    Get-Process | ForEach-Object { $script:allowedProcesses[$_.Name] = $true }
    
    $action = {
        $processName = $event.SourceEventArgs.NewEvent.ProcessName
        $processId = $event.SourceEventArgs.NewEvent.ProcessId
        
        if (-not $script:allowedProcesses.ContainsKey($processName)) {
            $wshell = New-Object -ComObject WScript.Shell
            $response = $wshell.Popup("ALARM! NEW PROCESS: $processName (PID: $processId)`n`nAllow?", 15, "Security Alert", 0x34)
            
            if ($response -eq 6) {
                $script:allowedProcesses[$processName] = $true
                Write-Log "Allowed process: $processName" -Level SUCCESS
            } else {
                Write-Log "Terminating process: $processName (PID: $processId)" -Level CHANGE
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action $action -SourceIdentifier "ProcessMonitor" | Out-Null
    
    try {
        while ($true) { Start-Sleep -Seconds 1 }
    } finally {
        Unregister-Event -SourceIdentifier "ProcessMonitor"
    }
}

if ($EnableServiceMonitor) {
    Write-SectionHeader "SERVICE MONITORING ENABLED"
    Write-Log "Starting real-time service monitoring (Ctrl+C to exit)..." -Level WARNING
    
    $baselineServices = Get-Service | Where-Object { $_.Status -eq "Running" }
    
    while ($true) {
        $currentServices = Get-Service | Where-Object { $_.Status -eq "Running" }
        $diffs = Compare-Object -ReferenceObject $baselineServices -DifferenceObject $currentServices -Property Name
        
        if ($diffs) {
            foreach ($diff in $diffs) {
                if ($diff.SideIndicator -eq '=>') {
                    $newService = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $diff.Name } | Select-Object Name, DisplayName, PathName
                    Write-Host "`n!!! NEW SERVICE STARTED !!!" -ForegroundColor Red -BackgroundColor Yellow
                    Write-Host "  Name: $($newService.Name)" -ForegroundColor White
                    Write-Host "  Display: $($newService.DisplayName)" -ForegroundColor White
                    Write-Host "  Path: $($newService.PathName)" -ForegroundColor Yellow
                    
                    $response = Read-Host "`nTerminate this service? (y/n)"
                    if ($response -match "^[Yy]$") {
                        Stop-Service -Name $diff.Name -Force
                        Write-Log "Terminated service: $($newService.Name)" -Level CHANGE
                    }
                }
            }
            $baselineServices = $currentServices
        }
        
        Start-Sleep -Seconds 1
    }
}
