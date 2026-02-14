#!/bin/bash
#==============================================================================
# CCDC Web Admin - Master Control Script
# One script to rule them all
#
# Usage: ./ccdc.sh [-w /path/to/webroot] [-w /another/path]
#==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Custom web roots (passed to all scripts)
CUSTOM_WEBROOTS=()
WEBROOT_ARGS=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -w|--webroot)
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                CUSTOM_WEBROOTS+=("$2")
                WEBROOT_ARGS="$WEBROOT_ARGS -w $2"
                shift 2
            else
                echo "Error: -w requires a path argument"
                exit 1
            fi
            ;;
        -h|--help)
            echo "Usage: $0 [-w /path/to/webroot] [-w /another/path]"
            echo ""
            echo "Options:"
            echo "  -w, --webroot PATH   Add custom web root path (can be used multiple times)"
            echo ""
            echo "Examples:"
            echo "  $0 -w /usr/share/myapp"
            echo "  $0 -w /usr/share/webapp -w /opt/website"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     ██████╗ ██████╗ ██████╗  ██████╗    ██╗    ██╗███████╗██████╗║"
    echo "║    ██╔════╝██╔════╝██╔══██╗██╔════╝    ██║    ██║██╔════╝██╔══██╗"
    echo "║    ██║     ██║     ██║  ██║██║         ██║ █╗ ██║█████╗  ██████╔╝"
    echo "║    ██║     ██║     ██║  ██║██║         ██║███╗██║██╔══╝  ██╔══██╗"
    echo "║    ╚██████╗╚██████╗██████╔╝╚██████╗    ╚███╔███╔╝███████╗██████╔╝"
    echo "║     ╚═════╝ ╚═════╝╚═════╝  ╚═════╝     ╚══╝╚══╝ ╚══════╝╚═════╝ ║"
    echo "║                                                                  ║"
    echo "║              WEB ADMIN TOOLKIT - COMPETITION READY               ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Show custom webroots if configured
    if [[ ${#CUSTOM_WEBROOTS[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Custom Web Roots:${NC}"
        for p in "${CUSTOM_WEBROOTS[@]}"; do
            echo -e "  ${GREEN}→${NC} $p"
        done
        echo ""
    fi
}

print_menu() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FIRST MINUTES ACTIONS:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}1)${NC} BACKUP NOW     - Immediate full backup (DO THIS FIRST!)"
    echo -e "  ${GREEN}2)${NC} QUICK LOCKDOWN - Fast essential security hardening"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  BACKUP & RESTORE:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}3)${NC} Full Backup    - Complete backup with remote transfer"
    echo -e "  ${GREEN}4)${NC} Quick Backup   - Fast backup of web roots only"
    echo -e "  ${GREEN}5)${NC} EMERGENCY RESTORE - Fastest restore (no prompts)"
    echo -e "  ${GREEN}6)${NC} Restore Menu   - Interactive restore options"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  MONITORING:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}7)${NC} Security Scan  - Full security scan"
    echo -e "  ${GREEN}8)${NC} Live Monitor   - Real-time log monitoring with alerts"
    echo -e "  ${GREEN}9)${NC} Watch Mode     - Continuous monitoring dashboard"
    echo -e "  ${GREEN}10)${NC} Service Status - Check web services"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  HARDENING:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}11)${NC} Full Hardening - Run all security hardening"
    echo -e "  ${GREEN}12)${NC} WordPress      - Harden WordPress installations"
    echo -e "  ${GREEN}13)${NC} Nginx          - Harden Nginx"
    echo -e "  ${GREEN}14)${NC} Apache         - Harden Apache"
    echo -e "  ${GREEN}15)${NC} PHP            - Harden PHP"
    echo -e "  ${GREEN}16)${NC} MySQL          - Harden MySQL/MariaDB"
    echo -e "  ${GREEN}17)${NC} System         - Harden OS settings"
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  UTILITIES:${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}18)${NC} Find Webshells - Scan for suspicious PHP files"
    echo -e "  ${GREEN}19)${NC} Check Crons    - Look for persistence mechanisms"
    echo -e "  ${GREEN}20)${NC} Kill Shells    - Find and kill reverse shell processes"
    echo -e "  ${GREEN}21)${NC} Change Passwords - Change web app admin passwords"
    echo -e "  ${GREEN}22)${NC} Suspicious IPs   - Identify suspicious IPs (NO BLOCKING)"
    echo ""
    echo -e "  ${RED}q)${NC}  Quit"
    echo ""
}

find_webshells() {
    echo -e "${CYAN}=== Scanning for Webshells ===${NC}"
    echo ""
    
    WEBSHELL_PATTERNS='(eval\s*\(\s*base64_decode|eval\s*\(\s*\$_|assert\s*\(\s*\$_|passthru|shell_exec|system\s*\(\s*\$_|exec\s*\(\s*\$_|c99|r57|b374k|WSO|FilesMan)'
    
    # Default paths plus custom webroots
    SEARCH_PATHS=("/var/www" "/usr/share/nginx" "/usr/share/wordpress" "/srv/www")
    for p in "${CUSTOM_WEBROOTS[@]}"; do
        SEARCH_PATHS+=("$p")
    done
    
    echo "Scanning directories:"
    for p in "${SEARCH_PATHS[@]}"; do
        [[ -d "$p" ]] && echo "  - $p"
    done
    echo ""
    
    echo "Checking for webshell patterns..."
    for dir in "${SEARCH_PATHS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -name "*.php" -exec grep -l -E "$WEBSHELL_PATTERNS" {} \; 2>/dev/null | while read file; do
                echo -e "${RED}[SUSPECT]${NC} $file"
            done
        fi
    done
    
    echo ""
    echo "Checking for recently modified PHP files (last 2 hours)..."
    for dir in "${SEARCH_PATHS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -name "*.php" -mmin -120 2>/dev/null | while read file; do
                echo -e "${YELLOW}[RECENT]${NC} $file ($(stat -c '%y' "$file" 2>/dev/null))"
            done
        fi
    done
    
    echo ""
    echo "Checking for hidden PHP files..."
    for dir in "${SEARCH_PATHS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -name ".*php*" 2>/dev/null | while read file; do
                echo -e "${RED}[HIDDEN]${NC} $file"
            done
        fi
    done
    
    echo ""
    echo "Checking for PHP in uploads directories..."
    for dir in "${SEARCH_PATHS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" \( -path "*/uploads/*.php" -o -path "*/upload/*.php" \) 2>/dev/null | while read file; do
                echo -e "${RED}[UPLOAD PHP]${NC} $file"
            done
        fi
    done
}

kill_shells() {
    echo -e "${CYAN}=== Finding Suspicious Processes ===${NC}"
    echo ""
    
    # Find potential reverse shells
    echo "Looking for reverse shell indicators..."
    ps aux | grep -E "(nc\s+-e|ncat|/dev/tcp|bash -i|python.*pty|perl.*socket|ruby.*socket|php.*fsockopen)" | grep -v grep | while read line; do
        echo -e "${RED}[SUSPECT]${NC} $line"
    done
    
    echo ""
    echo "Looking for suspicious network connections..."
    ss -tnp 2>/dev/null | grep -E ":(4444|5555|6666|1234|31337|9999)" | while read line; do
        echo -e "${RED}[SUSPECT PORT]${NC} $line"
    done
    
    echo ""
    echo "Processes listening on unusual ports..."
    ss -tlnp 2>/dev/null | grep -v -E ":(22|80|443|3306|8080|8443|21|25|53)\s" | while read line; do
        echo -e "${YELLOW}[CHECK]${NC} $line"
    done
    
    echo ""
    read -p "Kill suspicious processes? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # Kill common reverse shell patterns
        pkill -9 -f "nc -e" 2>/dev/null
        pkill -9 -f "nc -c" 2>/dev/null
        pkill -9 -f "bash -i" 2>/dev/null
        pkill -9 -f "/dev/tcp" 2>/dev/null
        echo -e "${GREEN}Killed suspicious processes${NC}"
    fi
}

change_passwords() {
    echo -e "${CYAN}=== Password Change Utility ===${NC}"
    echo ""
    echo "What would you like to change?"
    echo "  1) WordPress admin password"
    echo "  2) MySQL root password"
    echo "  3) System user password"
    echo ""
    read -p "Choice: " choice
    
    case "$choice" in
        1)
            echo ""
            echo "WordPress installations found:"
            find /var/www -name "wp-config.php" 2>/dev/null | while read f; do
                echo "  $(dirname $f)"
            done
            echo ""
            read -p "Enter WordPress path (e.g., /var/www/html): " wp_path
            read -p "Enter new admin password: " new_pass
            
            if [[ -f "$wp_path/wp-config.php" ]]; then
                cd "$wp_path"
                if command -v wp &>/dev/null; then
                    wp user update admin --user_pass="$new_pass" --allow-root 2>/dev/null && \
                        echo -e "${GREEN}Password changed via WP-CLI${NC}" || \
                        echo -e "${YELLOW}WP-CLI failed - try manual method${NC}"
                else
                    # Direct database update
                    DB_NAME=$(grep "DB_NAME" wp-config.php | cut -d "'" -f 4)
                    HASH=$(php -r "echo password_hash('$new_pass', PASSWORD_DEFAULT);")
                    mysql "$DB_NAME" -e "UPDATE wp_users SET user_pass='$HASH' WHERE user_login='admin';" 2>/dev/null && \
                        echo -e "${GREEN}Password changed via MySQL${NC}" || \
                        echo -e "${RED}Failed - check MySQL access${NC}"
                fi
            else
                echo -e "${RED}WordPress not found at $wp_path${NC}"
            fi
            ;;
        2)
            read -sp "Enter new MySQL root password: " mysql_pass
            echo ""
            mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysql_pass';" 2>/dev/null && \
                echo -e "${GREEN}MySQL root password changed${NC}" || \
                echo -e "${RED}Failed - may need current password${NC}"
            ;;
        3)
            read -p "Enter username: " username
            passwd "$username"
            ;;
    esac
}

first_minutes() {
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    FIRST 5 MINUTES CHECKLIST                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}Execute these steps IN ORDER:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} BACKUP EVERYTHING"
    echo "    sudo ./backup.sh full"
    echo ""
    echo -e "${GREEN}[2]${NC} QUICK SECURITY LOCKDOWN"
    echo "    sudo ./harden.sh quick"
    echo ""
    echo -e "${GREEN}[3]${NC} CHECK SERVICE STATUS"
    echo "    sudo ./monitor.sh status"
    echo ""
    echo -e "${GREEN}[4]${NC} SCAN FOR EXISTING COMPROMISES"
    echo "    sudo ./monitor.sh scan"
    echo ""
    echo -e "${GREEN}[5]${NC} START MONITORING"
    echo "    sudo ./monitor.sh watch  (in separate terminal)"
    echo ""
    echo -e "${YELLOW}Then proceed with full hardening as time allows.${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    print_banner
    print_menu
    
    read -p "Select option: " choice
    
    case "$choice" in
        1)
            echo "Running immediate backup..."
            sudo bash "$SCRIPT_DIR/backup.sh" full $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        2)
            echo "Running quick lockdown..."
            sudo bash "$SCRIPT_DIR/harden.sh" quick $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        3)
            sudo bash "$SCRIPT_DIR/backup.sh" full $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        4)
            sudo bash "$SCRIPT_DIR/backup.sh" quick $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        5)
            echo -e "${RED}EMERGENCY RESTORE - Using latest backup${NC}"
            sudo bash "$SCRIPT_DIR/restore.sh" emergency $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        6)
            sudo bash "$SCRIPT_DIR/restore.sh" $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        7)
            sudo bash "$SCRIPT_DIR/monitor.sh" scan $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        8)
            sudo bash "$SCRIPT_DIR/monitor.sh" live $WEBROOT_ARGS
            ;;
        9)
            sudo bash "$SCRIPT_DIR/monitor.sh" watch $WEBROOT_ARGS
            ;;
        10)
            sudo bash "$SCRIPT_DIR/monitor.sh" status $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        11)
            sudo bash "$SCRIPT_DIR/harden.sh" all $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        12)
            sudo bash "$SCRIPT_DIR/harden.sh" wordpress $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        13)
            sudo bash "$SCRIPT_DIR/harden.sh" nginx $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        14)
            sudo bash "$SCRIPT_DIR/harden.sh" apache $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        15)
            sudo bash "$SCRIPT_DIR/harden.sh" php $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        16)
            sudo bash "$SCRIPT_DIR/harden.sh" mysql $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        17)
            sudo bash "$SCRIPT_DIR/harden.sh" system $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        18)
            find_webshells
            read -p "Press Enter to continue..."
            ;;
        19)
            sudo bash "$SCRIPT_DIR/monitor.sh" cron $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        20)
            kill_shells
            read -p "Press Enter to continue..."
            ;;
        21)
            change_passwords
            read -p "Press Enter to continue..."
            ;;
        22)
            sudo bash "$SCRIPT_DIR/harden.sh" ips $WEBROOT_ARGS
            read -p "Press Enter to continue..."
            ;;
        q|Q)
            echo "Good luck in competition!"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
done
