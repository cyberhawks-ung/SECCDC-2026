#!/bin/bash
#==============================================================================
# CCDC Web Admin - Log Monitor & Alert Script
# Real-time monitoring for suspicious activity
#
# Usage: ./monitor.sh [command] [-w /path/to/webroot] [-w /another/path]
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

#------------------------------------------------------------------------------
# CONFIGURATION
#------------------------------------------------------------------------------

# Custom web roots (added via -w flag)
CUSTOM_WEBROOTS=()

# Default web directories to monitor
DEFAULT_WEB_DIRS=(
    "/var/www"
    "/usr/share/nginx/html"
    "/usr/share/nginx"
    "/usr/share/wordpress"
    "/usr/share/phpmyadmin"
    "/srv/www"
)

# Will be populated with defaults + custom paths
WEB_DIRS=()

# Log files to monitor
APACHE_LOGS=(
    "/var/log/apache2/access.log"
    "/var/log/apache2/error.log"
    "/var/log/httpd/access_log"
    "/var/log/httpd/error_log"
)

NGINX_LOGS=(
    "/var/log/nginx/access.log"
    "/var/log/nginx/error.log"
)

AUTH_LOGS=(
    "/var/log/auth.log"
    "/var/log/secure"
)

SYSLOG_FILES=(
    "/var/log/syslog"
    "/var/log/messages"
)

MYSQL_LOGS=(
    "/var/log/mysql/error.log"
    "/var/log/mariadb/mariadb.log"
)

# Alert output file
ALERT_LOG="/tmp/ccdc_alerts.log"

# Interval for periodic checks (seconds)
CHECK_INTERVAL=30

show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  scan    - Run full security scan (default)"
    echo "  live    - Live tail web logs with attack highlighting"
    echo "  watch   - Continuous monitoring dashboard"
    echo "  auth    - Check authentication logs only"
    echo "  files   - Check for suspicious file changes"
    echo "  procs   - Check for suspicious processes"
    echo "  network - Check network connections"
    echo "  cron    - Check crontabs for persistence"
    echo "  status  - Check web service status"
    echo ""
    echo "Options:"
    echo "  -w, --webroot PATH   Add custom web root path (can be used multiple times)"
    echo ""
    echo "Examples:"
    echo "  $0 scan -w /usr/share/myapp"
    echo "  $0 files -w /usr/share/webapp -w /opt/website"
    echo "  $0 watch --webroot /usr/share/nginx/custom"
    exit 1
}

init_web_dirs() {
    # Start with default paths
    WEB_DIRS=("${DEFAULT_WEB_DIRS[@]}")
    
    # Add custom web roots
    for custom_path in "${CUSTOM_WEBROOTS[@]}"; do
        WEB_DIRS+=("$custom_path")
    done
}

#------------------------------------------------------------------------------
# ATTACK PATTERNS
#------------------------------------------------------------------------------

# SQL Injection patterns
SQL_INJECTION_PATTERNS=(
    "UNION.*SELECT"
    "SELECT.*FROM"
    "INSERT.*INTO"
    "DELETE.*FROM"
    "DROP.*TABLE"
    "OR.*1.*=.*1"
    "OR.*'.*'.*=.*'"
    "SLEEP\("
    "BENCHMARK\("
    "LOAD_FILE\("
    "INTO.*OUTFILE"
    "INTO.*DUMPFILE"
    "information_schema"
    "0x[0-9a-fA-F]+"
)

# XSS patterns
XSS_PATTERNS=(
    "<script"
    "javascript:"
    "onerror.*="
    "onload.*="
    "onclick.*="
    "onmouseover.*="
    "onfocus.*="
    "document\.cookie"
    "document\.write"
    "eval\("
    "alert\("
)

# Path traversal
TRAVERSAL_PATTERNS=(
    "\.\./\.\."
    "\.\.%2f"
    "%2e%2e"
    "/etc/passwd"
    "/etc/shadow"
    "/proc/self"
    "\.htaccess"
    "\.htpasswd"
    "wp-config\.php"
)

# Command injection
CMD_INJECTION_PATTERNS=(
    ";\s*cat\s"
    ";\s*ls\s"
    ";\s*id\s*;"
    ";\s*whoami"
    ";\s*wget\s"
    ";\s*curl\s"
    "\|\s*cat\s"
    "\|\s*nc\s"
    "\|\s*bash"
    "\|\s*sh\s"
    "\`.*\`"
    "\$\(.*\)"
    "/bin/bash"
    "/bin/sh"
    "nc\s+-e"
    "bash\s+-i"
)

# Webshell indicators
WEBSHELL_PATTERNS=(
    "c99"
    "r57"
    "b374k"
    "weevely"
    "WSO"
    "FilesMan"
    "cmd\.php"
    "shell\.php"
    "passthru"
    "system\("
    "shell_exec"
    "exec\("
    "popen\("
    "proc_open"
    "eval\(base64_decode"
    "assert\("
    "preg_replace.*\/e"
)

# WordPress specific attacks
WP_ATTACK_PATTERNS=(
    "wp-admin/admin-ajax\.php.*action="
    "wp-content/plugins.*\.php\?"
    "xmlrpc\.php"
    "wp-login\.php.*POST"
    "timthumb\.php"
    "wp-config\.php"
    "revslider"
    "uploadify"
)

# Scanner/Tool signatures
SCANNER_PATTERNS=(
    "sqlmap"
    "nikto"
    "nmap"
    "masscan"
    "dirb"
    "gobuster"
    "wfuzz"
    "burp"
    "acunetix"
    "nessus"
    "w3af"
    "ZAP"
    "havij"
    "commix"
)

# Suspicious user agents
SUSPICIOUS_UA=(
    "curl/"
    "wget/"
    "python-requests"
    "libwww-perl"
    "Go-http-client"
    "masscan"
    "zgrab"
    "Nuclei"
)

#------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------

log_alert() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        CRITICAL)
            echo -e "${RED}${BOLD}[CRITICAL]${NC} ${timestamp} - $message"
            ;;
        HIGH)
            echo -e "${RED}[HIGH]${NC} ${timestamp} - $message"
            ;;
        MEDIUM)
            echo -e "${YELLOW}[MEDIUM]${NC} ${timestamp} - $message"
            ;;
        LOW)
            echo -e "${BLUE}[LOW]${NC} ${timestamp} - $message"
            ;;
        INFO)
            echo -e "${CYAN}[INFO]${NC} ${timestamp} - $message"
            ;;
    esac
    
    echo "[${level}] ${timestamp} - ${message}" >> "$ALERT_LOG"
}

check_pattern() {
    local log_file="$1"
    local pattern="$2"
    local alert_level="$3"
    local description="$4"
    
    if [[ -f "$log_file" ]]; then
        matches=$(grep -iE "$pattern" "$log_file" 2>/dev/null | tail -5)
        if [[ -n "$matches" ]]; then
            log_alert "$alert_level" "$description in $log_file"
            echo "$matches" | while read -r line; do
                echo -e "  ${MAGENTA}→${NC} $line"
            done
        fi
    fi
}

check_all_patterns() {
    local log_file="$1"
    
    # SQL Injection
    for pattern in "${SQL_INJECTION_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "HIGH" "SQL Injection attempt"
    done
    
    # XSS
    for pattern in "${XSS_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "MEDIUM" "XSS attempt"
    done
    
    # Path Traversal
    for pattern in "${TRAVERSAL_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "HIGH" "Path traversal attempt"
    done
    
    # Command Injection
    for pattern in "${CMD_INJECTION_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "CRITICAL" "Command injection attempt"
    done
    
    # Webshells
    for pattern in "${WEBSHELL_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "CRITICAL" "Webshell indicator"
    done
    
    # WordPress attacks
    for pattern in "${WP_ATTACK_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "MEDIUM" "WordPress attack"
    done
    
    # Scanners
    for pattern in "${SCANNER_PATTERNS[@]}"; do
        check_pattern "$log_file" "$pattern" "MEDIUM" "Scanner detected"
    done
}

monitor_auth_logs() {
    log_alert "INFO" "Checking authentication logs..."
    
    for log in "${AUTH_LOGS[@]}"; do
        if [[ -f "$log" ]]; then
            # Failed SSH logins
            failed_ssh=$(grep -c "Failed password" "$log" 2>/dev/null || echo 0)
            if [[ $failed_ssh -gt 10 ]]; then
                log_alert "HIGH" "SSH brute force detected: $failed_ssh failed attempts in $log"
                grep "Failed password" "$log" | tail -5 | while read -r line; do
                    echo -e "  ${MAGENTA}→${NC} $line"
                done
            fi
            
            # Successful root logins
            root_logins=$(grep "session opened for user root" "$log" 2>/dev/null | tail -5)
            if [[ -n "$root_logins" ]]; then
                log_alert "MEDIUM" "Root login sessions in $log"
                echo "$root_logins" | while read -r line; do
                    echo -e "  ${MAGENTA}→${NC} $line"
                done
            fi
            
            # sudo failures
            sudo_fail=$(grep "sudo.*authentication failure" "$log" 2>/dev/null | tail -5)
            if [[ -n "$sudo_fail" ]]; then
                log_alert "MEDIUM" "Sudo authentication failures in $log"
                echo "$sudo_fail" | while read -r line; do
                    echo -e "  ${MAGENTA}→${NC} $line"
                done
            fi
            
            # New users added
            new_users=$(grep "new user" "$log" 2>/dev/null | tail -5)
            if [[ -n "$new_users" ]]; then
                log_alert "HIGH" "New users created - verify legitimacy!"
                echo "$new_users" | while read -r line; do
                    echo -e "  ${MAGENTA}→${NC} $line"
                done
            fi
        fi
    done
}

monitor_file_changes() {
    log_alert "INFO" "Checking for suspicious file changes..."
    
    # Show monitored directories
    if [[ ${#CUSTOM_WEBROOTS[@]} -gt 0 ]]; then
        log_alert "INFO" "Custom web roots being monitored:"
        for p in "${CUSTOM_WEBROOTS[@]}"; do
            echo -e "  ${CYAN}→${NC} $p"
        done
    fi
    
    # Check for recently modified PHP files in web directories
    for dir in "${WEB_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            recent_php=$(find "$dir" -name "*.php" -mmin -30 2>/dev/null)
            if [[ -n "$recent_php" ]]; then
                log_alert "HIGH" "Recently modified PHP files in $dir (last 30 min):"
                echo "$recent_php" | while read -r file; do
                    echo -e "  ${MAGENTA}→${NC} $file ($(stat -c '%y' "$file" 2>/dev/null || stat -f '%Sm' "$file" 2>/dev/null))"
                done
            fi
            
            # Check for suspicious file names
            suspicious=$(find "$dir" \( -name "*.php.txt" -o -name "*.php.*" -o -name ".*\.php" -o -name "shell*" -o -name "cmd*" -o -name "c99*" -o -name "r57*" \) 2>/dev/null)
            if [[ -n "$suspicious" ]]; then
                log_alert "CRITICAL" "Suspicious files found in $dir:"
                echo "$suspicious" | while read -r file; do
                    echo -e "  ${MAGENTA}→${NC} $file"
                done
            fi
            
            # Check for world-writable files
            world_writable=$(find "$dir" -type f -perm -o+w 2>/dev/null | head -10)
            if [[ -n "$world_writable" ]]; then
                log_alert "MEDIUM" "World-writable files in $dir:"
                echo "$world_writable" | while read -r file; do
                    echo -e "  ${MAGENTA}→${NC} $file"
                done
            fi
        fi
    done
}

monitor_processes() {
    log_alert "INFO" "Checking for suspicious processes..."
    
    # Check for reverse shells
    netcat_procs=$(ps aux | grep -E "(nc\s+-e|ncat\s+-e|netcat)" | grep -v grep)
    if [[ -n "$netcat_procs" ]]; then
        log_alert "CRITICAL" "Possible reverse shell process:"
        echo "$netcat_procs" | while read -r line; do
            echo -e "  ${MAGENTA}→${NC} $line"
        done
    fi
    
    # Check for crypto miners
    miners=$(ps aux | grep -iE "(xmrig|minerd|cpuminer|cryptonight)" | grep -v grep)
    if [[ -n "$miners" ]]; then
        log_alert "CRITICAL" "Possible crypto miner detected:"
        echo "$miners" | while read -r line; do
            echo -e "  ${MAGENTA}→${NC} $line"
        done
    fi
    
    # Check for suspicious bash/sh processes
    suspicious_shells=$(ps aux | grep -E "bash\s+-i|/dev/tcp|sh\s+-i" | grep -v grep)
    if [[ -n "$suspicious_shells" ]]; then
        log_alert "CRITICAL" "Suspicious shell process:"
        echo "$suspicious_shells" | while read -r line; do
            echo -e "  ${MAGENTA}→${NC} $line"
        done
    fi
    
    # High CPU processes
    high_cpu=$(ps aux --sort=-%cpu | head -6 | tail -5)
    echo -e "\n${CYAN}Top CPU consumers:${NC}"
    echo "$high_cpu"
}

monitor_network() {
    log_alert "INFO" "Checking network connections (IDENTIFY ONLY - no blocking per competition rules)"
    
    # Outbound connections on suspicious ports
    suspicious_ports=$(ss -tn state established 2>/dev/null | grep -E ":(4444|5555|6666|1234|31337|12345)" || true)
    if [[ -n "$suspicious_ports" ]]; then
        log_alert "CRITICAL" "Connections on suspicious ports (REPORT TO TEAM LEAD):"
        echo "$suspicious_ports" | while read -r line; do
            echo -e "  ${MAGENTA}→${NC} $line"
        done
    fi
    
    # Many connections from same IP (potential DDoS or brute force)
    echo -e "\n${CYAN}Top connection sources (high counts may indicate attack):${NC}"
    ss -tn 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -15
    
    # Highlight IPs with many connections
    echo -e "\n${YELLOW}IPs with 10+ connections (possible brute force/scanner):${NC}"
    ss -tn 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | awk '$1 >= 10 {print "  [SUSPICIOUS] " $1 " connections from " $2}'
    
    echo -e "\n${YELLOW}REMINDER: Do NOT block IPs - report suspicious activity to team lead${NC}"
}

monitor_crontabs() {
    log_alert "INFO" "Checking crontabs for persistence..."
    
    # System crontabs
    for cron in /etc/crontab /etc/cron.d/*; do
        if [[ -f "$cron" ]]; then
            suspicious=$(grep -E "(wget|curl|bash|nc|python|perl|\.sh)" "$cron" 2>/dev/null | grep -v "^#")
            if [[ -n "$suspicious" ]]; then
                log_alert "HIGH" "Suspicious cron entry in $cron:"
                echo "$suspicious" | while read -r line; do
                    echo -e "  ${MAGENTA}→${NC} $line"
                done
            fi
        fi
    done
    
    # User crontabs
    for user_cron in /var/spool/cron/* /var/spool/cron/crontabs/*; do
        if [[ -f "$user_cron" ]]; then
            log_alert "MEDIUM" "User crontab found: $user_cron"
            cat "$user_cron" 2>/dev/null | grep -v "^#" | while read -r line; do
                [[ -n "$line" ]] && echo -e "  ${MAGENTA}→${NC} $line"
            done
        fi
    done
}

check_web_status() {
    log_alert "INFO" "Checking web service status..."
    
    # Nginx
    if systemctl is-active nginx &>/dev/null; then
        echo -e "${GREEN}[OK]${NC} nginx is running"
    else
        log_alert "CRITICAL" "nginx is NOT running!"
    fi
    
    # Apache
    if systemctl is-active apache2 &>/dev/null || systemctl is-active httpd &>/dev/null; then
        echo -e "${GREEN}[OK]${NC} Apache is running"
    else
        if systemctl is-enabled apache2 &>/dev/null || systemctl is-enabled httpd &>/dev/null; then
            log_alert "CRITICAL" "Apache is NOT running but should be!"
        fi
    fi
    
    # MySQL
    if systemctl is-active mysql &>/dev/null || systemctl is-active mariadb &>/dev/null; then
        echo -e "${GREEN}[OK]${NC} MySQL/MariaDB is running"
    else
        if systemctl is-enabled mysql &>/dev/null || systemctl is-enabled mariadb &>/dev/null; then
            log_alert "CRITICAL" "MySQL/MariaDB is NOT running but should be!"
        fi
    fi
    
    # PHP-FPM
    for phpfpm in php-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm; do
        if systemctl is-active "$phpfpm" &>/dev/null; then
            echo -e "${GREEN}[OK]${NC} $phpfpm is running"
        fi
    done
}

live_tail() {
    local log_files=()
    
    # Collect existing log files
    for log in "${APACHE_LOGS[@]}" "${NGINX_LOGS[@]}"; do
        [[ -f "$log" ]] && log_files+=("$log")
    done
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        log_alert "INFO" "No web logs found to tail"
        return
    fi
    
    echo -e "${CYAN}Live monitoring: ${log_files[*]}${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    # Create pattern string
    local patterns=""
    for p in "${SQL_INJECTION_PATTERNS[@]}" "${CMD_INJECTION_PATTERNS[@]}" "${WEBSHELL_PATTERNS[@]}"; do
        patterns="${patterns}|${p}"
    done
    patterns="${patterns:1}"  # Remove leading |
    
    tail -f "${log_files[@]}" 2>/dev/null | while read -r line; do
        # Highlight suspicious patterns
        if echo "$line" | grep -qiE "$patterns"; then
            echo -e "${RED}[ALERT]${NC} $line"
            echo "[LIVE ALERT] $(date '+%Y-%m-%d %H:%M:%S') - $line" >> "$ALERT_LOG"
        else
            echo "$line"
        fi
    done
}

run_full_scan() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CCDC WEB ADMIN - SECURITY SCAN                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Starting full security scan at $(date)"
    echo ""
    
    check_web_status
    echo ""
    
    monitor_auth_logs
    echo ""
    
    monitor_file_changes
    echo ""
    
    monitor_processes
    echo ""
    
    monitor_network
    echo ""
    
    monitor_crontabs
    echo ""
    
    # Check web logs for attacks
    log_alert "INFO" "Scanning web logs for attack patterns..."
    for log in "${APACHE_LOGS[@]}" "${NGINX_LOGS[@]}"; do
        if [[ -f "$log" ]]; then
            log_alert "INFO" "Scanning $log..."
            check_all_patterns "$log"
        fi
    done
    
    echo ""
    echo -e "${GREEN}Scan complete. Alerts logged to: $ALERT_LOG${NC}"
}

continuous_monitor() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CCDC WEB ADMIN - CONTINUOUS MONITOR                ║"
    echo "║           Press Ctrl+C to stop                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    while true; do
        clear
        echo -e "${CYAN}=== CCDC Monitor - $(date) ===${NC}"
        echo ""
        
        check_web_status
        echo ""
        
        echo -e "${CYAN}=== Recent Alerts ===${NC}"
        tail -20 "$ALERT_LOG" 2>/dev/null || echo "No alerts yet"
        echo ""
        
        echo -e "${CYAN}=== Top Connections ===${NC}"
        ss -tn 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5
        echo ""
        
        # Quick log check
        for log in "${APACHE_LOGS[@]}" "${NGINX_LOGS[@]}"; do
            if [[ -f "$log" ]]; then
                # Check last 100 lines for attack patterns
                recent=$(tail -100 "$log" 2>/dev/null)
                for pattern in "UNION.*SELECT" "../.." "cmd=" "shell" "<script"; do
                    if echo "$recent" | grep -qiE "$pattern"; then
                        log_alert "HIGH" "Attack pattern '$pattern' seen in $log"
                    fi
                done
            fi
        done
        
        echo ""
        echo -e "${YELLOW}Refreshing in $CHECK_INTERVAL seconds... (Ctrl+C to stop)${NC}"
        sleep "$CHECK_INTERVAL"
    done
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

# Parse command line arguments
COMMAND="scan"

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
        scan|live|watch|auth|files|procs|network|cron|status)
            COMMAND="$1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Initialize web directories with defaults + custom
init_web_dirs

# Show custom webroots if specified
if [[ ${#CUSTOM_WEBROOTS[@]} -gt 0 ]]; then
    echo -e "${CYAN}[INFO]${NC} Custom web roots configured:"
    for p in "${CUSTOM_WEBROOTS[@]}"; do
        echo "  - $p"
    done
    echo ""
fi

case "$COMMAND" in
    scan)
        run_full_scan
        ;;
    live)
        live_tail
        ;;
    watch)
        continuous_monitor
        ;;
    auth)
        monitor_auth_logs
        ;;
    files)
        monitor_file_changes
        ;;
    procs)
        monitor_processes
        ;;
    network)
        monitor_network
        ;;
    cron)
        monitor_crontabs
        ;;
    status)
        check_web_status
        ;;
esac
