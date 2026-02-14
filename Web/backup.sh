#!/bin/bash
#==============================================================================
# CCDC Web Admin - Backup Script
# Creates local + remote backups of critical web files
# Run this IMMEDIATELY when you get access to the environment
#
# Usage: ./backup.sh [full|quick|remote-only] [-w /path/to/webroot] [-w /another/path]
#==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#------------------------------------------------------------------------------
# CONFIGURATION - EDIT THESE
#------------------------------------------------------------------------------
# Remote backup destination (your Kali box)
REMOTE_USER="kali"
REMOTE_HOST="YOUR_KALI_IP"
REMOTE_PORT="22"
REMOTE_BACKUP_DIR="/home/kali/Desktop/CCDC/backups"

# Local backup directory on the server
LOCAL_BACKUP_DIR="/opt/ccdc_backups"

# Timestamp for this backup
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Custom web roots (added via -w flag)
CUSTOM_WEBROOTS=()

#------------------------------------------------------------------------------
# WEB PATHS TO BACKUP - Add/remove as needed for your environment
#------------------------------------------------------------------------------
DEFAULT_WEB_PATHS=(
    "/var/www"
    "/var/www/html"
    "/var/www/wordpress"
    "/usr/share/nginx/html"
    "/usr/share/nginx"
    "/usr/share/wordpress"
    "/usr/share/phpmyadmin"
    "/srv/www"
    "/home/*/public_html"
)

# Will be populated with defaults + custom paths
WEB_PATHS=()

# Config files to backup
CONFIG_PATHS=(
    "/etc/nginx"
    "/etc/apache2"
    "/etc/httpd"
    "/etc/php"
    "/etc/php.ini"
    "/etc/php-fpm.d"
    "/etc/mysql"
    "/etc/my.cnf"
    "/etc/my.cnf.d"
    "/etc/ssl/certs"
    "/etc/ssl/private"
    "/etc/letsencrypt"
)

# WordPress specific paths
WP_PATHS=(
    "/var/www/*/wp-config.php"
    "/var/www/html/wp-config.php"
    "/var/www/wordpress/wp-config.php"
)

# Database configs
DB_PATHS=(
    "/var/lib/mysql"
)

#------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CCDC WEB ADMIN - BACKUP SCRIPT                     ║"
    echo "║           Run this FIRST when you get access!                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  full        - Complete backup (default)"
    echo "  quick       - Fast backup of web roots only"
    echo "  remote-only - Transfer latest backup to remote"
    echo ""
    echo "Options:"
    echo "  -w, --webroot PATH   Add custom web root path (can be used multiple times)"
    echo ""
    echo "Examples:"
    echo "  $0 full -w /usr/share/myapp"
    echo "  $0 quick -w /usr/share/webapp -w /opt/website"
    echo "  $0 full --webroot /usr/share/nginx/custom"
    exit 1
}

init_web_paths() {
    # Start with default paths
    WEB_PATHS=("${DEFAULT_WEB_PATHS[@]}")
    
    # Add custom web roots
    for custom_path in "${CUSTOM_WEBROOTS[@]}"; do
        WEB_PATHS+=("$custom_path")
        log_info "Added custom web root: $custom_path"
    done
}

create_backup_dirs() {
    log_info "Creating backup directories..."
    mkdir -p "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/web"
    mkdir -p "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/config"
    mkdir -p "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/databases"
    mkdir -p "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/crontabs"
    mkdir -p "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users"
}

backup_web_content() {
    log_info "Backing up web content..."
    
    for path in "${WEB_PATHS[@]}"; do
        # Handle glob patterns
        for expanded_path in $path; do
            if [[ -e "$expanded_path" ]]; then
                log_info "  Backing up: $expanded_path"
                # Create directory structure and copy
                dest_dir="${LOCAL_BACKUP_DIR}/${TIMESTAMP}/web$(dirname $expanded_path)"
                mkdir -p "$dest_dir"
                cp -a "$expanded_path" "$dest_dir/" 2>/dev/null || log_warn "  Could not backup $expanded_path"
            fi
        done
    done
}

backup_configs() {
    log_info "Backing up configuration files..."
    
    for path in "${CONFIG_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            log_info "  Backing up: $path"
            dest_dir="${LOCAL_BACKUP_DIR}/${TIMESTAMP}/config$(dirname $path)"
            mkdir -p "$dest_dir"
            cp -a "$path" "$dest_dir/" 2>/dev/null || log_warn "  Could not backup $path"
        fi
    done
    
    # Backup WordPress configs specifically
    for pattern in "${WP_PATHS[@]}"; do
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                log_info "  Backing up WP config: $file"
                dest_dir="${LOCAL_BACKUP_DIR}/${TIMESTAMP}/config$(dirname $file)"
                mkdir -p "$dest_dir"
                cp -a "$file" "$dest_dir/" 2>/dev/null || true
            fi
        done
    done
}

backup_databases() {
    log_info "Backing up databases..."
    
    # Try MySQL/MariaDB
    if command -v mysql &> /dev/null; then
        log_info "  Dumping MySQL/MariaDB databases..."
        
        # Try without password first (for root with socket auth)
        if mysql -e "SELECT 1" &>/dev/null; then
            databases=$(mysql -N -e "SHOW DATABASES" 2>/dev/null | grep -Ev "^(information_schema|performance_schema|sys)$")
            for db in $databases; do
                log_info "    Dumping database: $db"
                mysqldump --single-transaction --routines --triggers "$db" > "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/databases/${db}.sql" 2>/dev/null || log_warn "    Could not dump $db"
            done
            # Also dump all databases in one file
            mysqldump --single-transaction --routines --triggers --all-databases > "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/databases/all_databases.sql" 2>/dev/null || true
        else
            log_warn "  Cannot access MySQL - may need credentials"
            log_warn "  Try: mysqldump -u root -p --all-databases > backup.sql"
        fi
    fi
    
    # Try PostgreSQL
    if command -v psql &> /dev/null; then
        log_info "  Dumping PostgreSQL databases..."
        if sudo -u postgres pg_dumpall > "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/databases/postgres_all.sql" 2>/dev/null; then
            log_success "  PostgreSQL backup complete"
        else
            log_warn "  Could not backup PostgreSQL"
        fi
    fi
}

backup_crontabs() {
    log_info "Backing up crontabs..."
    
    # System crontabs
    for file in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
        if [[ -f "$file" ]]; then
            dest_dir="${LOCAL_BACKUP_DIR}/${TIMESTAMP}/crontabs$(dirname $file)"
            mkdir -p "$dest_dir"
            cp -a "$file" "$dest_dir/" 2>/dev/null || true
        fi
    done
}

backup_users() {
    log_info "Backing up user information..."
    
    cp /etc/passwd "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users/" 2>/dev/null || true
    cp /etc/shadow "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users/" 2>/dev/null || true
    cp /etc/group "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users/" 2>/dev/null || true
    cp /etc/sudoers "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users/" 2>/dev/null || true
    cp -r /etc/sudoers.d "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/users/" 2>/dev/null || true
}

backup_service_status() {
    log_info "Recording service status..."
    
    {
        echo "=== Service Status at $TIMESTAMP ==="
        echo ""
        echo "=== Systemd Services ==="
        systemctl list-units --type=service --state=running 2>/dev/null || true
        echo ""
        echo "=== Listening Ports ==="
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
        echo ""
        echo "=== Running Processes ==="
        ps auxf 2>/dev/null || true
        echo ""
        echo "=== Installed Packages (web-related) ==="
        dpkg -l | grep -iE "(apache|nginx|php|mysql|maria|wordpress|httpd)" 2>/dev/null || \
        rpm -qa | grep -iE "(apache|nginx|php|mysql|maria|wordpress|httpd)" 2>/dev/null || true
    } > "${LOCAL_BACKUP_DIR}/${TIMESTAMP}/service_status.txt"
}

create_tarball() {
    log_info "Creating compressed backup archive..."
    
    cd "${LOCAL_BACKUP_DIR}"
    tar -czf "backup_${TIMESTAMP}.tar.gz" "${TIMESTAMP}/"
    
    log_success "Local backup created: ${LOCAL_BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz"
}

transfer_to_remote() {
    if [[ "$REMOTE_HOST" == "YOUR_KALI_IP" ]]; then
        log_warn "Remote host not configured - skipping remote backup"
        log_warn "Edit REMOTE_HOST in this script to enable remote backups"
        return
    fi
    
    log_info "Transferring backup to remote host..."
    
    # Create remote directory
    ssh -p "$REMOTE_PORT" "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p ${REMOTE_BACKUP_DIR}" 2>/dev/null || {
        log_error "Could not connect to remote host"
        log_warn "Ensure SSH key is set up or run: ssh-copy-id -p $REMOTE_PORT ${REMOTE_USER}@${REMOTE_HOST}"
        return
    }
    
    # Transfer the backup
    scp -P "$REMOTE_PORT" "${LOCAL_BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz" \
        "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_BACKUP_DIR}/" && \
        log_success "Remote backup complete: ${REMOTE_HOST}:${REMOTE_BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz"
}

quick_backup() {
    # Quick backup of just the most critical files
    log_info "Running QUICK backup (critical files only)..."
    
    QUICK_DIR="${LOCAL_BACKUP_DIR}/quick_${TIMESTAMP}"
    mkdir -p "$QUICK_DIR"
    
    # Backup all web roots (default + custom)
    for path in "${WEB_PATHS[@]}"; do
        for expanded_path in $path; do
            if [[ -e "$expanded_path" ]]; then
                log_info "  Quick backup: $expanded_path"
                dest_dir="$QUICK_DIR$(dirname $expanded_path)"
                mkdir -p "$dest_dir"
                cp -a "$expanded_path" "$dest_dir/" 2>/dev/null || true
            fi
        done
    done
    
    # Also grab configs
    cp -a /etc/nginx "$QUICK_DIR/" 2>/dev/null || true
    cp -a /etc/apache2 "$QUICK_DIR/" 2>/dev/null || true
    cp -a /etc/httpd "$QUICK_DIR/" 2>/dev/null || true
    
    tar -czf "${LOCAL_BACKUP_DIR}/quick_${TIMESTAMP}.tar.gz" -C "${LOCAL_BACKUP_DIR}" "quick_${TIMESTAMP}/"
    rm -rf "$QUICK_DIR"
    
    log_success "Quick backup: ${LOCAL_BACKUP_DIR}/quick_${TIMESTAMP}.tar.gz"
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

# Parse command line arguments
COMMAND="full"
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
        full|quick|remote-only)
            COMMAND="$1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

print_banner

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_warn "Not running as root - some backups may fail"
    log_warn "Run with: sudo $0"
fi

# Initialize web paths with defaults + custom
init_web_paths

# Execute command
case "$COMMAND" in
    quick)
        quick_backup
        ;;
    full)
        create_backup_dirs
        backup_web_content
        backup_configs
        backup_databases
        backup_crontabs
        backup_users
        backup_service_status
        create_tarball
        transfer_to_remote
        ;;
    remote-only)
        # Just transfer existing backups
        LATEST=$(ls -t ${LOCAL_BACKUP_DIR}/backup_*.tar.gz 2>/dev/null | head -1)
        if [[ -n "$LATEST" ]]; then
            TIMESTAMP=$(basename "$LATEST" | sed 's/backup_//' | sed 's/.tar.gz//')
            transfer_to_remote
        else
            log_error "No existing backups found"
        fi
        ;;
esac

echo ""
log_success "Backup complete!"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Edit REMOTE_HOST in this script to enable remote backups"
echo "  2. Set up SSH keys: ssh-copy-id user@your-kali-box"
echo "  3. Run restore.sh to restore from backups"
