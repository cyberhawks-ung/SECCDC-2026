#!/bin/bash
#
# ServiceGuardian for Linux - Blue Team Service Protection
# Monitors services and auto-restarts them when they go down
# Uses cron for scheduling and systemd for service management
#
# Usage:
#   ./ServiceGuardian.sh install <service_name> [check_interval_seconds]
#   ./ServiceGuardian.sh uninstall <service_name>
#   ./ServiceGuardian.sh backup <service_name>
#   ./ServiceGuardian.sh check <service_name>
#   ./ServiceGuardian.sh status
#

# Configuration
GUARDIAN_DIR="/opt/serviceguardian"
BACKUP_DIR="$GUARDIAN_DIR/backups"
LOG_DIR="$GUARDIAN_DIR/logs"
CONFIG_DIR="$GUARDIAN_DIR/config"
MONITOR_SCRIPT="$GUARDIAN_DIR/monitor.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging
log() {
    local level="$1"
    local service="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local logfile="$LOG_DIR/${service}-$(date '+%Y-%m-%d').log"
    
    echo "[$timestamp] [$level] $message" >> "$logfile"
    
    case "$level" in
        "ERROR")   echo -e "${RED}[$timestamp] [$level] $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[$timestamp] [$level] $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[$timestamp] [$level] $message${NC}" ;;
        *)         echo -e "${CYAN}[$timestamp] [$level] $message${NC}" ;;
    esac
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

# Initialize directories
init_dirs() {
    mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$CONFIG_DIR"
    chmod 700 "$GUARDIAN_DIR"
}

# Check if service exists
service_exists() {
    local service="$1"
    systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${service}.service" || \
    systemctl list-units --type=service --all 2>/dev/null | grep -q "${service}.service"
}

# Get service binary path
get_service_path() {
    local service="$1"
    local exec_path=""
    
    # Try to get ExecStart from systemd
    exec_path=$(systemctl show "$service" -p ExecStart 2>/dev/null | sed 's/ExecStart=//' | awk '{print $1}' | sed 's/.*path=//;s/;.*//')
    
    if [ -z "$exec_path" ] || [ ! -f "$exec_path" ]; then
        # Try from service file directly
        local service_file=$(systemctl show "$service" -p FragmentPath 2>/dev/null | cut -d= -f2)
        if [ -f "$service_file" ]; then
            exec_path=$(grep -oP '(?<=ExecStart=)[^\s]+' "$service_file" 2>/dev/null | head -1)
        fi
    fi
    
    echo "$exec_path"
}

# Backup service
backup_service() {
    local service="$1"
    
    log "INFO" "$service" "Creating backup for service: $service"
    
    if ! service_exists "$service"; then
        log "ERROR" "$service" "Service '$service' not found!"
        return 1
    fi
    
    local backup_name="${service}-$(date '+%Y%m%d-%H%M%S')"
    local backup_path="$BACKUP_DIR/$backup_name"
    mkdir -p "$backup_path"
    
    # Get service info
    local exec_path=$(get_service_path "$service")
    local service_file=$(systemctl show "$service" -p FragmentPath 2>/dev/null | cut -d= -f2)
    
    # Save service configuration
    cat > "$backup_path/service-config.json" << EOF
{
    "service_name": "$service",
    "exec_path": "$exec_path",
    "service_file": "$service_file",
    "backup_date": "$(date -Iseconds)",
    "enabled": "$(systemctl is-enabled "$service" 2>/dev/null || echo 'unknown')",
    "status": "$(systemctl is-active "$service" 2>/dev/null || echo 'unknown')"
}
EOF
    
    # Backup service unit file
    if [ -f "$service_file" ]; then
        cp "$service_file" "$backup_path/"
        log "INFO" "$service" "Backed up service file: $service_file"
    fi
    
    # Backup binary and its directory (if not in /usr/bin or /usr/sbin)
    if [ -n "$exec_path" ] && [ -f "$exec_path" ]; then
        local exec_dir=$(dirname "$exec_path")
        
        # Don't backup system directories
        if [[ "$exec_dir" != "/usr/bin" && "$exec_dir" != "/usr/sbin" && "$exec_dir" != "/bin" && "$exec_dir" != "/sbin" ]]; then
            log "INFO" "$service" "Backing up directory: $exec_dir"
            cp -r "$exec_dir" "$backup_path/service_files" 2>/dev/null || true
        else
            # Just backup the binary
            mkdir -p "$backup_path/service_files"
            cp "$exec_path" "$backup_path/service_files/" 2>/dev/null || true
            log "INFO" "$service" "Backed up binary: $exec_path"
        fi
    fi
    
    # Backup common config locations
    local config_locations=(
        "/etc/$service"
        "/etc/${service}.conf"
        "/etc/${service}.d"
        "/etc/default/$service"
    )
    
    mkdir -p "$backup_path/configs"
    for cfg in "${config_locations[@]}"; do
        if [ -e "$cfg" ]; then
            cp -r "$cfg" "$backup_path/configs/" 2>/dev/null || true
            log "INFO" "$service" "Backed up config: $cfg"
        fi
    done
    
    # Save latest backup reference
    echo "$backup_path" > "$CONFIG_DIR/${service}-latest-backup.txt"
    
    log "SUCCESS" "$service" "Backup created at: $backup_path"
    return 0
}

# Restore service from backup
restore_service() {
    local service="$1"
    
    local latest_file="$CONFIG_DIR/${service}-latest-backup.txt"
    if [ ! -f "$latest_file" ]; then
        log "ERROR" "$service" "No backup found for service '$service'"
        return 1
    fi
    
    local backup_path=$(cat "$latest_file")
    if [ ! -d "$backup_path" ]; then
        log "ERROR" "$service" "Backup directory not found: $backup_path"
        return 1
    fi
    
    log "WARNING" "$service" "Attempting restore from: $backup_path"
    
    # Stop service first
    systemctl stop "$service" 2>/dev/null || true
    sleep 2
    
    # Read config
    local config_file="$backup_path/service-config.json"
    if [ -f "$config_file" ]; then
        local exec_path=$(grep -oP '(?<="exec_path": ")[^"]+' "$config_file")
        local exec_dir=$(dirname "$exec_path")
        
        # Restore service files
        if [ -d "$backup_path/service_files" ] && [[ "$exec_dir" != "/usr/bin" && "$exec_dir" != "/usr/sbin" ]]; then
            log "INFO" "$service" "Restoring service files to: $exec_dir"
            cp -r "$backup_path/service_files/"* "$exec_dir/" 2>/dev/null || true
        fi
    fi
    
    # Restore configs
    if [ -d "$backup_path/configs" ]; then
        for cfg in "$backup_path/configs"/*; do
            if [ -e "$cfg" ]; then
                local cfg_name=$(basename "$cfg")
                log "INFO" "$service" "Restoring config: $cfg_name"
                cp -r "$cfg" "/etc/" 2>/dev/null || true
            fi
        done
    fi
    
    log "SUCCESS" "$service" "Restore completed"
    return 0
}

# Check and restart service
check_service() {
    local service="$1"
    
    if ! service_exists "$service"; then
        log "ERROR" "$service" "Service '$service' not found!"
        return 1
    fi
    
    if systemctl is-active --quiet "$service"; then
        log "INFO" "$service" "Service is running normally"
        return 0
    fi
    
    log "WARNING" "$service" "Service is DOWN - Attempting restart..."
    
    # Ensure service is enabled
    systemctl enable "$service" 2>/dev/null || true
    
    local attempts=0
    local max_attempts=3
    
    while [ $attempts -lt $max_attempts ]; do
        attempts=$((attempts + 1))
        log "INFO" "$service" "Restart attempt $attempts of $max_attempts"
        
        systemctl start "$service" 2>/dev/null
        sleep 3
        
        if systemctl is-active --quiet "$service"; then
            log "SUCCESS" "$service" "Service restarted successfully!"
            return 0
        fi
        
        # On second failure, try restore
        if [ $attempts -eq 2 ]; then
            log "WARNING" "$service" "Multiple failures - attempting restore..."
            restore_service "$service"
        fi
        
        sleep 2
    done
    
    log "ERROR" "$service" "CRITICAL: Failed to restart after $max_attempts attempts!"
    return 1
}

# Create the monitor script
create_monitor_script() {
    cat > "$MONITOR_SCRIPT" << 'MONITOR_EOF'
#!/bin/bash
# ServiceGuardian Monitor Script
# Called by cron to check services

GUARDIAN_DIR="/opt/serviceguardian"
LOG_DIR="$GUARDIAN_DIR/logs"
CONFIG_DIR="$GUARDIAN_DIR/config"

log() {
    local level="$1"
    local service="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local logfile="$LOG_DIR/${service}-$(date '+%Y-%m-%d').log"
    echo "[$timestamp] [$level] $message" >> "$logfile"
}

# Get list of protected services
for config_file in "$CONFIG_DIR"/*.conf; do
    [ -f "$config_file" ] || continue
    
    service=$(basename "$config_file" .conf)
    
    if ! systemctl is-active --quiet "$service"; then
        log "WARNING" "$service" "Service DOWN - Restarting..."
        
        # Enable and start
        systemctl enable "$service" 2>/dev/null || true
        systemctl start "$service" 2>/dev/null
        
        sleep 3
        
        if systemctl is-active --quiet "$service"; then
            log "SUCCESS" "$service" "Service RESTORED!"
        else
            log "ERROR" "$service" "Failed to restart - trying again..."
            
            # Force kill and restart
            systemctl kill "$service" 2>/dev/null || true
            sleep 2
            systemctl start "$service" 2>/dev/null
            
            sleep 3
            if systemctl is-active --quiet "$service"; then
                log "SUCCESS" "$service" "Service RESTORED on second attempt!"
            else
                log "ERROR" "$service" "CRITICAL: Service won't start!"
            fi
        fi
    fi
done
MONITOR_EOF

    chmod +x "$MONITOR_SCRIPT"
}

# Install protection for a service
install_protection() {
    local service="$1"
    local interval="${2:-15}"
    
    echo -e "\n${CYAN}=== ServiceGuardian - Installing ===${NC}"
    echo -e "Service: $service"
    echo -e "Check Interval: $interval seconds"
    echo ""
    
    if ! service_exists "$service"; then
        echo -e "${RED}Error: Service '$service' not found!${NC}"
        exit 1
    fi
    
    # Show service info
    local exec_path=$(get_service_path "$service")
    echo -e "${GREEN}Found service: $service${NC}"
    echo -e "Path: $exec_path"
    echo ""
    
    # Create backup
    echo -e "${CYAN}Creating backup...${NC}"
    backup_service "$service"
    echo ""
    
    # Create config file to mark this service as protected
    echo "protected=true" > "$CONFIG_DIR/${service}.conf"
    echo "interval=$interval" >> "$CONFIG_DIR/${service}.conf"
    echo "installed=$(date -Iseconds)" >> "$CONFIG_DIR/${service}.conf"
    
    # Create monitor script
    create_monitor_script
    
    # Set up cron job
    echo -e "${CYAN}Installing cron job...${NC}"
    
    # Remove any existing cron entry
    crontab -l 2>/dev/null | grep -v "serviceguardian/monitor.sh" | crontab - 2>/dev/null || true
    
    # Add new cron entry (runs every minute, script handles interval internally)
    (crontab -l 2>/dev/null; echo "* * * * * $MONITOR_SCRIPT >/dev/null 2>&1") | crontab -
    
    # For faster checks, also set up a systemd timer or use a loop service
    if [ "$interval" -lt 60 ]; then
        create_systemd_timer "$interval"
    fi
    
    log "SUCCESS" "$service" "Protection installed"
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN} Service '$service' is now protected!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Logs: $LOG_DIR/${service}-*.log"
    echo ""
    echo -e "${YELLOW}To test: systemctl stop $service${NC}"
    echo -e "${YELLOW}To remove: $0 uninstall $service${NC}"
}

# Create systemd timer for sub-minute checks
create_systemd_timer() {
    local interval="$1"
    
    # Create service unit
    cat > /etc/systemd/system/serviceguardian.service << EOF
[Unit]
Description=ServiceGuardian Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=$MONITOR_SCRIPT
EOF

    # Create timer unit
    cat > /etc/systemd/system/serviceguardian.timer << EOF
[Unit]
Description=ServiceGuardian Monitor Timer

[Timer]
OnBootSec=30
OnUnitActiveSec=${interval}s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable serviceguardian.timer
    systemctl start serviceguardian.timer
    
    log "INFO" "system" "Systemd timer installed (${interval}s interval)"
}

# Uninstall protection
uninstall_protection() {
    local service="$1"
    
    echo -e "\n${YELLOW}=== ServiceGuardian - Uninstalling ===${NC}"
    
    # Remove config
    rm -f "$CONFIG_DIR/${service}.conf"
    
    log "SUCCESS" "$service" "Protection removed"
    
    # Check if any services still protected
    local remaining=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
    
    if [ "$remaining" -eq 0 ]; then
        # Remove cron job
        crontab -l 2>/dev/null | grep -v "serviceguardian/monitor.sh" | crontab - 2>/dev/null || true
        
        # Remove systemd timer
        systemctl stop serviceguardian.timer 2>/dev/null || true
        systemctl disable serviceguardian.timer 2>/dev/null || true
        rm -f /etc/systemd/system/serviceguardian.service
        rm -f /etc/systemd/system/serviceguardian.timer
        systemctl daemon-reload
        
        echo -e "${YELLOW}All protections removed, cron and timer disabled${NC}"
    fi
    
    echo -e "${GREEN}Protection removed for '$service'${NC}"
}

# Show status
show_status() {
    echo -e "\n${CYAN}=== ServiceGuardian Status ===${NC}\n"
    
    echo -e "${CYAN}Protected Services:${NC}"
    local found=0
    for config_file in "$CONFIG_DIR"/*.conf; do
        [ -f "$config_file" ] || continue
        found=1
        
        local service=$(basename "$config_file" .conf)
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
        
        case "$status" in
            "active")  echo -e "  ${GREEN}●${NC} $service - ${GREEN}running${NC}" ;;
            *)         echo -e "  ${RED}●${NC} $service - ${RED}$status${NC}" ;;
        esac
    done
    
    if [ $found -eq 0 ]; then
        echo -e "  ${YELLOW}No services protected${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}Cron Status:${NC}"
    if crontab -l 2>/dev/null | grep -q "serviceguardian"; then
        echo -e "  ${GREEN}●${NC} Cron job active"
    else
        echo -e "  ${RED}●${NC} No cron job"
    fi
    
    echo ""
    echo -e "${CYAN}Timer Status:${NC}"
    if systemctl is-active --quiet serviceguardian.timer 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} Systemd timer active"
    else
        echo -e "  ${YELLOW}●${NC} Systemd timer not active"
    fi
    
    echo ""
    echo -e "${CYAN}Recent Logs:${NC}"
    if ls "$LOG_DIR"/*.log 1>/dev/null 2>&1; then
        tail -5 "$LOG_DIR"/*.log 2>/dev/null | head -20
    else
        echo "  No logs yet"
    fi
}

# Main
check_root
init_dirs

case "$1" in
    install)
        [ -z "$2" ] && { echo "Usage: $0 install <service_name> [interval_seconds]"; exit 1; }
        install_protection "$2" "${3:-15}"
        ;;
    uninstall)
        [ -z "$2" ] && { echo "Usage: $0 uninstall <service_name>"; exit 1; }
        uninstall_protection "$2"
        ;;
    backup)
        [ -z "$2" ] && { echo "Usage: $0 backup <service_name>"; exit 1; }
        backup_service "$2"
        ;;
    check)
        [ -z "$2" ] && { echo "Usage: $0 check <service_name>"; exit 1; }
        check_service "$2"
        ;;
    status)
        show_status
        ;;
    *)
        echo "ServiceGuardian for Linux - Blue Team Service Protection"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  install <service> [interval]  - Install protection (default: 15s checks)"
        echo "  uninstall <service>           - Remove protection"
        echo "  backup <service>              - Create backup only"
        echo "  check <service>               - Single check/restart"
        echo "  status                        - Show all protected services"
        echo ""
        echo "Examples:"
        echo "  $0 install sshd 10"
        echo "  $0 install nginx"
        echo "  $0 install named 15"
        echo "  $0 uninstall nginx"
        echo "  $0 status"
        ;;
esac
