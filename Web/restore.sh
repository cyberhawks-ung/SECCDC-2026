#!/bin/bash
#==============================================================================
# CCDC Web Admin - Restore Script
# Quickly restore from backups when red team strikes
#
# Usage: ./restore.sh [command] [-w /path/to/webroot] [-w /another/path]
#==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------
LOCAL_BACKUP_DIR="/opt/ccdc_backups"

# Remote backup location (for pulling backups from your Kali box)
REMOTE_USER="kali"
REMOTE_HOST="YOUR_KALI_IP"
REMOTE_PORT="22"
REMOTE_BACKUP_DIR="/home/kali/Desktop/CCDC/backups"

# Custom web roots (added via -w flag)
CUSTOM_WEBROOTS=()

# Default web root paths to restore
DEFAULT_WEB_PATHS=(
    "/var/www"
    "/usr/share/nginx"
    "/usr/share/wordpress"
    "/usr/share/phpmyadmin"
    "/srv/www"
)

#------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  full          - Interactive full restore"
    echo "  emergency     - Fast restore (no prompts, latest backup)"
    echo "  web           - Restore web content only"
    echo "  config        - Restore configs only"
    echo "  file <path>   - Restore a specific file"
    echo "  dir <path>    - Restore a specific directory"
    echo "  list          - List available backups"
    echo "  pull          - Pull backups from remote Kali box"
    echo ""
    echo "Options:"
    echo "  -w, --webroot PATH   Add custom web root path (can be used multiple times)"
    echo ""
    echo "Examples:"
    echo "  $0 emergency -w /usr/share/myapp"
    echo "  $0 full -w /usr/share/webapp -w /opt/website"
    echo "  $0 web --webroot /usr/share/nginx/custom"
    exit 1
}

# Build list of web paths to restore
get_web_paths() {
    local paths=("${DEFAULT_WEB_PATHS[@]}")
    for custom_path in "${CUSTOM_WEBROOTS[@]}"; do
        paths+=("$custom_path")
    done
    echo "${paths[@]}"
}

print_banner() {
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CCDC WEB ADMIN - RESTORE SCRIPT                    ║"
    echo "║           Quick recovery from red team attacks               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

list_backups() {
    echo -e "${CYAN}=== Available Local Backups ===${NC}"
    echo ""
    
    if [[ -d "$LOCAL_BACKUP_DIR" ]]; then
        ls -lht "${LOCAL_BACKUP_DIR}"/*.tar.gz 2>/dev/null | head -20 || echo "No backups found"
    else
        echo "Backup directory not found: $LOCAL_BACKUP_DIR"
    fi
    
    echo ""
    echo -e "${CYAN}=== Extracted Backup Directories ===${NC}"
    ls -d "${LOCAL_BACKUP_DIR}"/20* 2>/dev/null | head -10 || echo "None"
}

select_backup() {
    list_backups
    echo ""
    
    # Get latest backup by default
    LATEST=$(ls -t "${LOCAL_BACKUP_DIR}"/backup_*.tar.gz 2>/dev/null | head -1)
    
    if [[ -z "$LATEST" ]]; then
        log_error "No backups found!"
        exit 1
    fi
    
    echo -e "${YELLOW}Latest backup: $(basename $LATEST)${NC}"
    read -p "Use latest? (Y/n) or enter backup filename: " choice
    
    if [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]; then
        SELECTED_BACKUP="$LATEST"
    elif [[ -f "${LOCAL_BACKUP_DIR}/${choice}" ]]; then
        SELECTED_BACKUP="${LOCAL_BACKUP_DIR}/${choice}"
    elif [[ -f "$choice" ]]; then
        SELECTED_BACKUP="$choice"
    else
        log_error "Backup not found: $choice"
        exit 1
    fi
    
    log_info "Selected: $SELECTED_BACKUP"
}

extract_backup() {
    local backup_file="$1"
    local extract_dir="${LOCAL_BACKUP_DIR}/restore_tmp"
    
    log_info "Extracting backup..."
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    
    tar -xzf "$backup_file" -C "$extract_dir"
    
    # Find the timestamp directory
    BACKUP_CONTENT=$(ls -d "${extract_dir}"/20* 2>/dev/null | head -1)
    
    if [[ -z "$BACKUP_CONTENT" ]]; then
        # Maybe it's a quick backup
        BACKUP_CONTENT=$(ls -d "${extract_dir}"/quick_* 2>/dev/null | head -1)
    fi
    
    if [[ -z "$BACKUP_CONTENT" ]]; then
        log_error "Could not find backup content"
        exit 1
    fi
    
    log_success "Extracted to: $BACKUP_CONTENT"
}

restore_web_content() {
    log_info "Restoring web content..."
    
    local web_backup="${BACKUP_CONTENT}/web"
    local all_paths=($(get_web_paths))
    
    # Show custom paths if any
    if [[ ${#CUSTOM_WEBROOTS[@]} -gt 0 ]]; then
        log_info "Custom web roots specified:"
        for p in "${CUSTOM_WEBROOTS[@]}"; do
            echo "  - $p"
        done
    fi
    
    if [[ ! -d "$web_backup" ]]; then
        # Quick backup format - look for paths directly in backup
        log_info "Detected quick backup format..."
        
        for web_path in "${all_paths[@]}"; do
            # Try to find the path in the backup
            local backup_path="${BACKUP_CONTENT}${web_path}"
            if [[ -d "$backup_path" ]]; then
                log_info "  Restoring $web_path..."
                if [[ -d "$web_path" ]]; then
                    cp -a "$web_path" "${web_path}.compromised.$(date +%s)" 2>/dev/null || true
                fi
                mkdir -p "$web_path"
                cp -a "$backup_path"/* "$web_path/" 2>/dev/null || true
                log_success "  Restored $web_path"
            fi
        done
        return
    fi
    
    # Full backup format - restore maintaining directory structure
    for web_path in "${all_paths[@]}"; do
        local backup_path="${web_backup}${web_path}"
        if [[ -d "$backup_path" ]]; then
            log_info "  Restoring $web_path..."
            # Backup current state first
            if [[ -d "$web_path" ]]; then
                cp -a "$web_path" "${web_path}.compromised.$(date +%s)" 2>/dev/null || true
            fi
            mkdir -p "$web_path"
            cp -a "$backup_path"/* "$web_path/" 2>/dev/null || true
            log_success "  Restored $web_path"
        fi
    done
}

restore_configs() {
    log_info "Restoring configuration files..."
    
    local config_backup="${BACKUP_CONTENT}/config"
    
    if [[ ! -d "$config_backup" ]]; then
        log_warn "No config backup found"
        return
    fi
    
    # Nginx
    if [[ -d "${config_backup}/etc/nginx" ]]; then
        log_info "  Restoring nginx config..."
        cp -a /etc/nginx "/etc/nginx.compromised.$(date +%s)" 2>/dev/null || true
        cp -a "${config_backup}/etc/nginx"/* /etc/nginx/ 2>/dev/null || true
        log_success "  Restored nginx config"
    fi
    
    # Apache (Debian/Ubuntu)
    if [[ -d "${config_backup}/etc/apache2" ]]; then
        log_info "  Restoring apache2 config..."
        cp -a /etc/apache2 "/etc/apache2.compromised.$(date +%s)" 2>/dev/null || true
        cp -a "${config_backup}/etc/apache2"/* /etc/apache2/ 2>/dev/null || true
        log_success "  Restored apache2 config"
    fi
    
    # Apache (RHEL/CentOS)
    if [[ -d "${config_backup}/etc/httpd" ]]; then
        log_info "  Restoring httpd config..."
        cp -a /etc/httpd "/etc/httpd.compromised.$(date +%s)" 2>/dev/null || true
        cp -a "${config_backup}/etc/httpd"/* /etc/httpd/ 2>/dev/null || true
        log_success "  Restored httpd config"
    fi
    
    # PHP
    if [[ -d "${config_backup}/etc/php" ]]; then
        log_info "  Restoring PHP config..."
        cp -a "${config_backup}/etc/php"/* /etc/php/ 2>/dev/null || true
        log_success "  Restored PHP config"
    fi
    
    # MySQL
    if [[ -d "${config_backup}/etc/mysql" ]]; then
        log_info "  Restoring MySQL config..."
        cp -a "${config_backup}/etc/mysql"/* /etc/mysql/ 2>/dev/null || true
        log_success "  Restored MySQL config"
    fi
}

restore_database() {
    local db_backup="${BACKUP_CONTENT}/databases"
    
    if [[ ! -d "$db_backup" ]]; then
        log_warn "No database backup found"
        return
    fi
    
    log_info "Database backups available:"
    ls -la "$db_backup"/*.sql 2>/dev/null || echo "No SQL files found"
    
    echo ""
    read -p "Restore all databases? (y/N): " restore_db
    
    if [[ "$restore_db" =~ ^[Yy]$ ]]; then
        if [[ -f "${db_backup}/all_databases.sql" ]]; then
            log_info "Restoring all MySQL databases..."
            mysql < "${db_backup}/all_databases.sql" 2>/dev/null && \
                log_success "Databases restored" || \
                log_error "Database restore failed - may need credentials"
        fi
    fi
}

restart_services() {
    log_info "Restarting web services..."
    
    # Nginx
    if systemctl is-active nginx &>/dev/null || systemctl is-enabled nginx &>/dev/null; then
        log_info "  Restarting nginx..."
        systemctl restart nginx && log_success "  nginx restarted" || log_warn "  nginx restart failed"
    fi
    
    # Apache
    if systemctl is-active apache2 &>/dev/null || systemctl is-enabled apache2 &>/dev/null; then
        log_info "  Restarting apache2..."
        systemctl restart apache2 && log_success "  apache2 restarted" || log_warn "  apache2 restart failed"
    fi
    
    if systemctl is-active httpd &>/dev/null || systemctl is-enabled httpd &>/dev/null; then
        log_info "  Restarting httpd..."
        systemctl restart httpd && log_success "  httpd restarted" || log_warn "  httpd restart failed"
    fi
    
    # PHP-FPM
    for phpfpm in php-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm; do
        if systemctl is-active "$phpfpm" &>/dev/null; then
            log_info "  Restarting $phpfpm..."
            systemctl restart "$phpfpm" || true
        fi
    done
    
    # MySQL
    if systemctl is-active mysql &>/dev/null || systemctl is-active mariadb &>/dev/null; then
        log_info "  Restarting MySQL/MariaDB..."
        systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null || true
    fi
}

restore_single_file() {
    local target_file="$1"
    
    if [[ -z "$target_file" ]]; then
        echo "Usage: $0 file /path/to/file"
        exit 1
    fi
    
    select_backup
    extract_backup "$SELECTED_BACKUP"
    
    # Search for the file in backup
    local found_file=$(find "$BACKUP_CONTENT" -path "*${target_file}" -type f 2>/dev/null | head -1)
    
    if [[ -n "$found_file" ]]; then
        log_info "Found: $found_file"
        log_info "Restoring to: $target_file"
        
        # Backup current file
        if [[ -f "$target_file" ]]; then
            cp "$target_file" "${target_file}.compromised.$(date +%s)"
        fi
        
        # Restore
        cp -a "$found_file" "$target_file"
        log_success "Restored: $target_file"
    else
        log_error "File not found in backup: $target_file"
    fi
}

restore_directory() {
    local target_dir="$1"
    
    if [[ -z "$target_dir" ]]; then
        echo "Usage: $0 dir /path/to/directory"
        exit 1
    fi
    
    select_backup
    extract_backup "$SELECTED_BACKUP"
    
    # Search for the directory in backup
    local found_dir=$(find "$BACKUP_CONTENT" -path "*${target_dir}" -type d 2>/dev/null | head -1)
    
    if [[ -n "$found_dir" ]]; then
        log_info "Found: $found_dir"
        log_info "Restoring to: $target_dir"
        
        # Backup current directory
        if [[ -d "$target_dir" ]]; then
            cp -a "$target_dir" "${target_dir}.compromised.$(date +%s)"
        fi
        
        # Restore
        mkdir -p "$target_dir"
        cp -a "$found_dir"/* "$target_dir/"
        log_success "Restored: $target_dir"
    else
        log_error "Directory not found in backup: $target_dir"
    fi
}

pull_from_remote() {
    if [[ "$REMOTE_HOST" == "YOUR_KALI_IP" ]]; then
        log_error "Remote host not configured!"
        log_warn "Edit REMOTE_HOST in this script"
        exit 1
    fi
    
    log_info "Pulling backups from remote host..."
    
    mkdir -p "$LOCAL_BACKUP_DIR"
    
    scp -P "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BACKUP_DIR}/*.tar.gz" \
        "$LOCAL_BACKUP_DIR/" && \
        log_success "Backups pulled from remote" || \
        log_error "Failed to pull from remote"
}

full_restore() {
    select_backup
    extract_backup "$SELECTED_BACKUP"
    
    echo ""
    echo -e "${YELLOW}This will restore:${NC}"
    echo "  - Web content (/var/www, etc.)"
    echo "  - Configuration files (nginx, apache, php, mysql)"
    echo "  - Optionally: databases"
    echo ""
    read -p "Continue with full restore? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Restore cancelled"
        exit 0
    fi
    
    restore_web_content
    restore_configs
    restore_database
    restart_services
    
    echo ""
    log_success "Full restore complete!"
}

emergency_restore() {
    # Fastest possible restore - no prompts
    log_warn "EMERGENCY RESTORE - No prompts, using latest backup"
    
    LATEST=$(ls -t "${LOCAL_BACKUP_DIR}"/backup_*.tar.gz 2>/dev/null | head -1)
    
    if [[ -z "$LATEST" ]]; then
        # Try quick backups
        LATEST=$(ls -t "${LOCAL_BACKUP_DIR}"/quick_*.tar.gz 2>/dev/null | head -1)
    fi
    
    if [[ -z "$LATEST" ]]; then
        log_error "No backups found!"
        exit 1
    fi
    
    log_info "Using: $LATEST"
    extract_backup "$LATEST"
    restore_web_content
    restore_configs
    restart_services
    
    log_success "Emergency restore complete!"
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

# Parse command line arguments
COMMAND=""
FILE_ARG=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -w|--webroot)
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                CUSTOM_WEBROOTS+=("$2")
                shift 2
            else
                echo "Error: -w requires a path argument"
                exit 1
            fi
            ;;
        -h|--help)
            show_usage
            ;;
        full|emergency|web|config|list|pull)
            COMMAND="$1"
            shift
            ;;
        file|dir)
            COMMAND="$1"
            shift
            if [[ -n "$1" && ! "$1" =~ ^- ]]; then
                FILE_ARG="$1"
                shift
            fi
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

print_banner

if [[ $EUID -ne 0 ]]; then
    log_warn "Not running as root - some restores may fail"
    log_warn "Run with: sudo $0"
fi

# Show custom webroots if specified
if [[ ${#CUSTOM_WEBROOTS[@]} -gt 0 ]]; then
    log_info "Custom web roots configured:"
    for p in "${CUSTOM_WEBROOTS[@]}"; do
        echo "  - $p"
    done
    echo ""
fi

case "${COMMAND:-}" in
    "")
        show_usage
        ;;
    full)
        full_restore
        ;;
    emergency)
        emergency_restore
        ;;
    web)
        select_backup
        extract_backup "$SELECTED_BACKUP"
        restore_web_content
        restart_services
        ;;
    config)
        select_backup
        extract_backup "$SELECTED_BACKUP"
        restore_configs
        restart_services
        ;;
    file)
        restore_single_file "$FILE_ARG"
        ;;
    dir)
        restore_directory "$FILE_ARG"
        ;;
    list)
        list_backups
        ;;
    pull)
        pull_from_remote
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        exit 1
        ;;
esac
