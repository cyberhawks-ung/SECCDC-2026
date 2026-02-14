<#
.SYNOPSIS
    ServiceGuardian - Blue Team Service Protection Script
.DESCRIPTION
    Monitors a Windows service and auto-restarts it when it goes down.
    For non-system services, also creates backups and can restore.
.PARAMETER ServiceName
    The name of the service to protect (e.g., "nginx", "Apache2.4", "TermService")
.PARAMETER Install
    Installs the scheduled task for auto-monitoring
.PARAMETER Uninstall
    Removes the scheduled task
.PARAMETER CheckInterval
    Interval in seconds between service checks (default: 15)
.PARAMETER BackupOnly
    Only create a backup without installing monitoring
.EXAMPLE
    .\ServiceGuardian.ps1 -ServiceName "TermService" -Install
    .\ServiceGuardian.ps1 -ServiceName "nginx" -Install -CheckInterval 10
    .\ServiceGuardian.ps1 -ServiceName "TermService" -Uninstall
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,
    
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$BackupOnly,
    
    [int]$CheckInterval = 15
)

# Configuration
$BackupRoot = "C:\ServiceGuardian\Backups"
$LogPath = "C:\ServiceGuardian\Logs"
$ConfigPath = "C:\ServiceGuardian\Config"
$TaskNamePrefix = "ServiceGuardian"

# Ensure running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Initialize directories
function Initialize-Directories {
    $dirs = @($BackupRoot, $LogPath, $ConfigPath)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "[+] Created directory: $dir" -ForegroundColor Green
        }
    }
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $LogPath "$ServiceName-$(Get-Date -Format 'yyyy-MM-dd').log"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor Cyan }
    }
}

# Get service details
function Get-ServiceDetails {
    param([string]$Name)
    
    try {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($null -eq $service) {
            $service = Get-WmiObject -Class Win32_Service -Filter "DisplayName='$Name'" -ErrorAction Stop
        }
        return $service
    }
    catch {
        Write-Log "Failed to get service details for '$Name': $_" -Level "ERROR"
        return $null
    }
}

# Check if service is a Windows built-in (svchost-based)
function Test-IsSystemService {
    param([string]$Name)
    
    $service = Get-ServiceDetails -Name $Name
    if ($null -eq $service) { return $false }
    
    # Check if it runs from svchost.exe (Windows shared service host)
    if ($service.PathName -like "*svchost.exe*") {
        return $true
    }
    
    # Check if executable is in System32 or Windows folder
    $pathLower = $service.PathName.ToLower()
    if ($pathLower -like "*\windows\system32\*" -or $pathLower -like "*\windows\syswow64\*") {
        return $true
    }
    
    return $false
}

# Create backup of service (for non-system services)
function New-ServiceBackup {
    param([string]$Name)
    
    Write-Log "Creating backup for service: $Name"
    
    $service = Get-ServiceDetails -Name $Name
    if ($null -eq $service) {
        Write-Log "Service '$Name' not found!" -Level "ERROR"
        return $false
    }
    
    # Check if this is a system service
    if (Test-IsSystemService -Name $Name) {
        Write-Log "Service '$Name' is a Windows built-in service (svchost-based)" -Level "WARNING"
        Write-Log "Skipping file backup - will save service configuration only" -Level "INFO"
        
        # Just save the service configuration
        $backupDir = Join-Path $BackupRoot "$Name-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        
        $configData = @{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartMode = $service.StartMode
            ServiceAccount = $service.StartName
            Description = $service.Description
            IsSystemService = $true
            BackupDate = (Get-Date).ToString("o")
        }
        
        $configFile = Join-Path $backupDir "service-config.json"
        $configData | ConvertTo-Json | Out-File -FilePath $configFile -Encoding UTF8
        
        # Export registry settings for the service
        $regPath = "HKLM\SYSTEM\CurrentControlSet\Services\$Name"
        $regBackupFile = Join-Path $backupDir "service-registry.reg"
        reg export $regPath $regBackupFile /y 2>$null
        
        $backupDir | Out-File -FilePath (Join-Path $ConfigPath "$Name-LatestBackup.txt") -Force
        
        Write-Log "Configuration backup created at: $backupDir" -Level "SUCCESS"
        return $true
    }
    
    # For non-system services, backup the executable directory
    $servicePath = $service.PathName
    if ($servicePath -match '^"([^"]+)"') {
        $exePath = $matches[1]
    }
    elseif ($servicePath -match '^([^\s]+)') {
        $exePath = $matches[1]
    }
    else {
        $exePath = $servicePath
    }
    
    if (-not (Test-Path $exePath)) {
        Write-Log "Service executable not found at: $exePath" -Level "ERROR"
        return $false
    }
    
    $serviceDir = Split-Path -Parent $exePath
    $backupDir = Join-Path $BackupRoot "$Name-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    try {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        
        Write-Log "Backing up directory: $serviceDir"
        Copy-Item -Path "$serviceDir\*" -Destination $backupDir -Recurse -Force -ErrorAction SilentlyContinue
        
        $configData = @{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartMode = $service.StartMode
            ServiceAccount = $service.StartName
            Description = $service.Description
            OriginalDirectory = $serviceDir
            IsSystemService = $false
            BackupDate = (Get-Date).ToString("o")
        }
        
        $configFile = Join-Path $backupDir "service-config.json"
        $configData | ConvertTo-Json | Out-File -FilePath $configFile -Encoding UTF8
        
        $backupDir | Out-File -FilePath (Join-Path $ConfigPath "$Name-LatestBackup.txt") -Force
        
        Write-Log "Backup created successfully at: $backupDir" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Backup failed: $_" -Level "ERROR"
        return $false
    }
}

# Restore service from backup (non-system services only)
function Restore-ServiceFromBackup {
    param([string]$Name)
    
    Write-Log "Attempting to restore service '$Name' from backup" -Level "WARNING"
    
    $latestBackupFile = Join-Path $ConfigPath "$Name-LatestBackup.txt"
    if (-not (Test-Path $latestBackupFile)) {
        Write-Log "No backup found for service '$Name'" -Level "ERROR"
        return $false
    }
    
    $backupDir = (Get-Content $latestBackupFile -Raw).Trim()
    
    if (-not (Test-Path $backupDir)) {
        Write-Log "Backup directory not found: $backupDir" -Level "ERROR"
        return $false
    }
    
    $configFile = Join-Path $backupDir "service-config.json"
    if (-not (Test-Path $configFile)) {
        Write-Log "Backup config not found: $configFile" -Level "ERROR"
        return $false
    }
    
    try {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        
        # Can't restore files for system services
        if ($config.IsSystemService) {
            Write-Log "Cannot restore files for system service - attempting registry restore" -Level "WARNING"
            $regBackupFile = Join-Path $backupDir "service-registry.reg"
            if (Test-Path $regBackupFile) {
                reg import $regBackupFile 2>$null
                Write-Log "Registry settings restored" -Level "SUCCESS"
            }
            return $true
        }
        
        $originalDir = $config.OriginalDirectory
        
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Write-Log "Restoring files to: $originalDir"
        Get-ChildItem -Path $backupDir -Exclude "service-config.json" | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $originalDir -Recurse -Force
        }
        
        Write-Log "Service files restored successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Restore failed: $_" -Level "ERROR"
        return $false
    }
}

# Check and restart service
function Test-AndRestartService {
    param([string]$Name)
    
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $service = Get-Service -DisplayName $Name -ErrorAction SilentlyContinue
    }
    
    if ($null -eq $service) {
        Write-Log "Service '$Name' not found on system!" -Level "ERROR"
        return
    }
    
    if ($service.Status -eq 'Running') {
        Write-Log "Service '$Name' is running normally"
        return
    }
    
    Write-Log "Service '$Name' is DOWN (Status: $($service.Status)). Restarting..." -Level "WARNING"
    
    # First, make sure the service is set to start
    Set-Service -Name $service.Name -StartupType Automatic -ErrorAction SilentlyContinue
    
    $restartAttempts = 0
    $maxAttempts = 3
    
    while ($restartAttempts -lt $maxAttempts) {
        $restartAttempts++
        Write-Log "Restart attempt $restartAttempts of $maxAttempts"
        
        try {
            Start-Service -Name $service.Name -ErrorAction Stop
            Start-Sleep -Seconds 3
            
            $service.Refresh()
            if ($service.Status -eq 'Running') {
                Write-Log "Service '$Name' restarted successfully!" -Level "SUCCESS"
                return
            }
        }
        catch {
            Write-Log "Start attempt failed: $_" -Level "WARNING"
        }
        
        # If failed, try stopping any hung process first
        if ($restartAttempts -eq 2) {
            Write-Log "Attempting force kill of any hung processes..." -Level "WARNING"
            $svcDetail = Get-ServiceDetails -Name $Name
            if ($svcDetail -and $svcDetail.ProcessId -and $svcDetail.ProcessId -ne 0) {
                Stop-Process -Id $svcDetail.ProcessId -Force -ErrorAction SilentlyContinue
            }
            
            # For non-system services, try restore
            if (-not (Test-IsSystemService -Name $Name)) {
                Restore-ServiceFromBackup -Name $Name
            }
        }
        
        Start-Sleep -Seconds 2
    }
    
    Write-Log "CRITICAL: Failed to restart service '$Name' after $maxAttempts attempts!" -Level "ERROR"
}

# Install scheduled task for monitoring
function Install-ServiceMonitor {
    param(
        [string]$Name,
        [int]$Interval
    )
    
    $taskName = "$TaskNamePrefix-$Name"
    
    Uninstall-ServiceMonitor -Name $Name
    
    # Create the monitoring script
    $monitorScript = @"
# ServiceGuardian Monitor for $Name
`$ErrorActionPreference = 'Continue'
`$LogPath = "C:\ServiceGuardian\Logs"

function Write-Log {
    param([string]`$Message, [string]`$Level = "INFO")
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logFile = Join-Path `$LogPath "$Name-`$(Get-Date -Format 'yyyy-MM-dd').log"
    `$logEntry = "[`$timestamp] [`$Level] `$Message"
    Add-Content -Path `$logFile -Value `$logEntry -ErrorAction SilentlyContinue
}

Write-Log "ServiceGuardian monitor started for $Name"

while (`$true) {
    try {
        `$service = Get-Service -Name '$Name' -ErrorAction SilentlyContinue
        
        if (`$service) {
            if (`$service.Status -ne 'Running') {
                Write-Log "Service DOWN (Status: `$(`$service.Status)) - Restarting..." -Level "WARNING"
                
                # Ensure startup type is automatic
                Set-Service -Name '$Name' -StartupType Automatic -ErrorAction SilentlyContinue
                
                # Try to start
                try {
                    Start-Service -Name '$Name' -ErrorAction Stop
                    Start-Sleep -Seconds 3
                    `$service.Refresh()
                    
                    if (`$service.Status -eq 'Running') {
                        Write-Log "Service RESTORED successfully!" -Level "SUCCESS"
                    } else {
                        Write-Log "Service still not running after start command" -Level "ERROR"
                    }
                }
                catch {
                    Write-Log "Restart failed: `$_" -Level "ERROR"
                    
                    # Wait and retry
                    Start-Sleep -Seconds 5
                    Start-Service -Name '$Name' -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Log "Service not found!" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Monitor error: `$_" -Level "ERROR"
    }
    
    Start-Sleep -Seconds $Interval
}
"@

    $monitorScriptPath = Join-Path $ConfigPath "$Name-Monitor.ps1"
    $monitorScript | Out-File -FilePath $monitorScriptPath -Encoding UTF8 -Force
    
    # Create scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Log "Scheduled task '$taskName' created" -Level "SUCCESS"
        
        # Start monitoring immediately
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScriptPath`"" -WindowStyle Hidden
        Write-Log "Monitor process started" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to create scheduled task: $_" -Level "ERROR"
        
        # Fallback
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScriptPath`"" -WindowStyle Hidden
        Write-Log "Fallback: Background monitor started" -Level "WARNING"
    }
}

# Uninstall scheduled task
function Uninstall-ServiceMonitor {
    param([string]$Name)
    
    $taskName = "$TaskNamePrefix-$Name"
    
    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Log "Scheduled task '$taskName' removed" -Level "SUCCESS"
        }
        
        # Stop any running monitor processes
        Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*$Name-Monitor.ps1*"
        } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # Alternative method to kill monitor
        Get-WmiObject Win32_Process -Filter "CommandLine LIKE '%$Name-Monitor.ps1%'" -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Error during uninstall: $_" -Level "WARNING"
    }
}

# Main execution
Initialize-Directories

if ($BackupOnly) {
    Write-Host "`n=== ServiceGuardian - Backup Mode ===" -ForegroundColor Cyan
    New-ServiceBackup -Name $ServiceName
}
elseif ($Uninstall) {
    Write-Host "`n=== ServiceGuardian - Uninstalling ===" -ForegroundColor Yellow
    Uninstall-ServiceMonitor -Name $ServiceName
    Write-Host "Monitor for '$ServiceName' has been removed." -ForegroundColor Green
}
elseif ($Install) {
    Write-Host "`n=== ServiceGuardian - Installing ===" -ForegroundColor Cyan
    Write-Host "Service: $ServiceName" -ForegroundColor White
    Write-Host "Check Interval: $CheckInterval seconds" -ForegroundColor White
    Write-Host ""
    
    $svc = Get-ServiceDetails -Name $ServiceName
    if ($null -eq $svc) {
        Write-Error "Service '$ServiceName' not found. Please verify the service name."
        exit 1
    }
    
    Write-Host "Found service: $($svc.DisplayName)" -ForegroundColor Green
    Write-Host "Path: $($svc.PathName)" -ForegroundColor Gray
    
    if (Test-IsSystemService -Name $ServiceName) {
        Write-Host "Type: Windows Built-in Service (svchost)" -ForegroundColor Yellow
        Write-Host "Note: File backup not applicable - config/registry backup only" -ForegroundColor Yellow
    } else {
        Write-Host "Type: Standalone Service" -ForegroundColor Green
    }
    Write-Host ""
    
    # Create backup
    Write-Host "Creating backup..." -ForegroundColor Cyan
    New-ServiceBackup -Name $ServiceName
    Write-Host ""
    
    # Install monitor
    Write-Host "Installing service monitor..." -ForegroundColor Cyan
    Install-ServiceMonitor -Name $ServiceName -Interval $CheckInterval
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Service '$ServiceName' is now protected!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Logs: $LogPath\$ServiceName-*.log" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To test: Stop-Service -Name '$ServiceName' -Force" -ForegroundColor Yellow
    Write-Host "To remove: .\ServiceGuardian.ps1 -ServiceName '$ServiceName' -Uninstall" -ForegroundColor Yellow
}
else {
    Write-Host "`n=== ServiceGuardian - Single Check ===" -ForegroundColor Cyan
    Test-AndRestartService -Name $ServiceName
}
