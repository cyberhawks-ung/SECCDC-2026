#!/bin/bash
#==============================================================================
# CCDC Web Admin - Security Hardening Script
# Auto-hardens WordPress, Nginx, Apache, PHP, and system
#
# Usage: ./harden.sh [component] [-w /path/to/webroot] [-w /another/path]
#==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Custom web roots (added via -w flag)
CUSTOM_WEBROOTS=()

# Default paths to search for WordPress
DEFAULT_WP_SEARCH_PATHS=(
    "/var/www"
    "/srv/www"
    "/home"
    "/usr/share"
)

#------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CCDC WEB ADMIN - SECURITY HARDENING                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_usage() {
    echo "Usage: $0 [component] [options]"
    echo ""
    echo "Components:"
    echo "  all       - Run all hardening"
    echo "  quick     - Quick lockdown (essential security)"
    echo "  wordpress - WordPress hardening"
    echo "  nginx     - Nginx hardening"
    echo "  apache    - Apache hardening"
    echo "  php       - PHP hardening"
    echo "  mysql     - MySQL/MariaDB hardening"
    echo "  system    - System hardening"
    echo "  ips       - Identify suspicious IPs (no blocking)"
    echo ""
    echo "Options:"
    echo "  -w, --webroot PATH   Add custom web root path to search (can be used multiple times)"
    echo ""
    echo "Examples:"
    echo "  $0 wordpress -w /usr/share/myapp"
    echo "  $0 all -w /usr/share/webapp -w /opt/website"
    echo "  $0 quick --webroot /usr/share/nginx/custom"
    exit 1
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.bak.$(date +%s)"
        log_info "Backed up: $file"
    fi
}

# Get all paths to search for web content
get_search_paths() {
    local paths=("${DEFAULT_WP_SEARCH_PATHS[@]}")
    for custom_path in "${CUSTOM_WEBROOTS[@]}"; do
        paths+=("$custom_path")
    done
    echo "${paths[@]}"
}

#==============================================================================
# WORDPRESS HARDENING
#==============================================================================

harden_wordpress() {
    log_info "=== WordPress Hardening ==="
    
    # Get search paths (defaults + custom)
    local search_paths=($(get_search_paths))
    
    # Show search paths
    log_info "Searching for WordPress in:"
    for p in "${search_paths[@]}"; do
        echo "  - $p"
    done
    
    # Find WordPress installations in all paths
    WP_INSTALLS=""
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            found=$(find "$search_path" -name "wp-config.php" 2>/dev/null || true)
            WP_INSTALLS="$WP_INSTALLS $found"
        fi
    done
    WP_INSTALLS=$(echo "$WP_INSTALLS" | tr ' ' '\n' | grep -v '^$' | sort -u)
    
    if [[ -z "$WP_INSTALLS" ]]; then
        log_warn "No WordPress installations found"
        return
    fi
    
    for wp_config in $WP_INSTALLS; do
        WP_DIR=$(dirname "$wp_config")
        log_info "Hardening WordPress at: $WP_DIR"
        
        # 1. Protect wp-config.php
        backup_file "$wp_config"
        chmod 400 "$wp_config"
        log_success "  wp-config.php permissions set to 400"
        
        # 2. Add security constants if not present
        if ! grep -q "DISALLOW_FILE_EDIT" "$wp_config"; then
            sed -i "/That's all, stop editing!/i\\
// CCDC Security Hardening\\
define('DISALLOW_FILE_EDIT', true);\\
define('DISALLOW_FILE_MODS', true);\\
define('FORCE_SSL_ADMIN', true);\\
define('WP_AUTO_UPDATE_CORE', false);\\
" "$wp_config" 2>/dev/null || log_warn "  Could not add security constants"
            log_success "  Added security constants"
        fi
        
        # 3. Disable XML-RPC (common attack vector)
        HTACCESS="$WP_DIR/.htaccess"
        if [[ -f "$HTACCESS" ]]; then
            backup_file "$HTACCESS"
            if ! grep -q "xmlrpc.php" "$HTACCESS"; then
                cat >> "$HTACCESS" << 'EOF'

# CCDC Security - Block XML-RPC
<Files xmlrpc.php>
    Order Deny,Allow
    Deny from all
</Files>

# Block wp-config.php access
<Files wp-config.php>
    Order Allow,Deny
    Deny from all
</Files>

# Block .htaccess access
<Files .htaccess>
    Order Allow,Deny
    Deny from all
</Files>

# Disable directory browsing
Options -Indexes

# Block common exploits
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
    RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
    RewriteRule .* - [F,L]
</IfModule>
EOF
                log_success "  Added .htaccess security rules"
            fi
        fi
        
        # 4. Fix file permissions
        log_info "  Setting secure file permissions..."
        find "$WP_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true
        find "$WP_DIR" -type f -exec chmod 644 {} \; 2>/dev/null || true
        chmod 400 "$wp_config"
        
        # 5. Secure wp-content/uploads
        UPLOADS_DIR="$WP_DIR/wp-content/uploads"
        if [[ -d "$UPLOADS_DIR" ]]; then
            # Prevent PHP execution in uploads
            cat > "$UPLOADS_DIR/.htaccess" << 'EOF'
# CCDC Security - Prevent PHP execution
<FilesMatch "\.php$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Alternative for newer Apache
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
EOF
            log_success "  Blocked PHP execution in uploads"
        fi
        
        # 6. Remove readme.html and license.txt (version disclosure)
        rm -f "$WP_DIR/readme.html" "$WP_DIR/license.txt" 2>/dev/null
        log_success "  Removed version disclosure files"
        
        # 7. Protect wp-includes
        WP_INCLUDES="$WP_DIR/wp-includes"
        if [[ -d "$WP_INCLUDES" ]] && [[ ! -f "$WP_INCLUDES/.htaccess" ]]; then
            cat > "$WP_INCLUDES/.htaccess" << 'EOF'
# CCDC Security - Protect wp-includes
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^wp-admin/includes/ - [F,L]
    RewriteRule !^wp-includes/ - [S=3]
    RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
    RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
    RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>
EOF
            log_success "  Protected wp-includes"
        fi
        
        # 8. Set correct ownership
        WEB_USER=$(ps aux | grep -E "(apache|nginx|httpd|www-data)" | grep -v grep | head -1 | awk '{print $1}')
        if [[ -n "$WEB_USER" ]]; then
            chown -R "$WEB_USER:$WEB_USER" "$WP_DIR" 2>/dev/null || true
            log_success "  Set ownership to $WEB_USER"
        fi
    done
}

#==============================================================================
# NGINX HARDENING
#==============================================================================

harden_nginx() {
    log_info "=== Nginx Hardening ==="
    
    NGINX_CONF="/etc/nginx/nginx.conf"
    
    if [[ ! -f "$NGINX_CONF" ]]; then
        log_warn "Nginx not found at $NGINX_CONF"
        return
    fi
    
    backup_file "$NGINX_CONF"
    
    # Create security snippet
    SECURITY_SNIPPET="/etc/nginx/snippets/security.conf"
    mkdir -p /etc/nginx/snippets
    
    cat > "$SECURITY_SNIPPET" << 'EOF'
# CCDC Security Hardening for Nginx

# Hide nginx version
server_tokens off;

# Prevent clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS Protection
add_header X-XSS-Protection "1; mode=block" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Content Security Policy (adjust as needed)
# add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;

# Block common attack patterns
location ~* "(eval\(|base64_encode|localhost|loopback|127\.0\.0\.1)" {
    return 444;
}

# Block SQL injection attempts
location ~* "(union.*select|select.*from|insert.*into|drop.*table)" {
    return 444;
}

# Block common exploit file requests
location ~* "\.(bak|config|sql|fla|ini|log|sh|inc|swp|dist|git|svn)$" {
    return 404;
}

# Deny access to hidden files
location ~ /\. {
    deny all;
    return 404;
}

# Block PHP in uploads (WordPress)
location ~* /uploads/.*\.php$ {
    return 403;
}

# Block wp-config.php access
location ~* wp-config\.php {
    deny all;
}

# Block xmlrpc.php
location = /xmlrpc.php {
    deny all;
}

# Limit request methods
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 444;
}

# Rate limiting zone (define in http block)
# limit_req zone=general burst=10 nodelay;
EOF
    
    log_success "Created security snippet: $SECURITY_SNIPPET"
    
    # Add security settings to main nginx.conf if not present
    if ! grep -q "server_tokens off" "$NGINX_CONF"; then
        # Add to http block
        sed -i '/http {/a\    # CCDC Security\n    server_tokens off;\n    client_max_body_size 10M;\n    client_body_buffer_size 1k;\n    client_header_buffer_size 1k;\n    large_client_header_buffers 2 1k;' "$NGINX_CONF" 2>/dev/null || true
        log_success "Added security settings to nginx.conf"
    fi
    
    # Create rate limiting config
    if ! grep -q "limit_req_zone" "$NGINX_CONF"; then
        sed -i '/http {/a\    # Rate limiting\n    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;\n    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;' "$NGINX_CONF" 2>/dev/null || true
        log_success "Added rate limiting zones"
    fi
    
    # Test nginx config
    if nginx -t 2>/dev/null; then
        log_success "Nginx configuration is valid"
        log_info "Reload nginx with: systemctl reload nginx"
    else
        log_error "Nginx configuration test failed!"
        log_warn "Check $NGINX_CONF for errors"
    fi
    
    echo ""
    log_info "To use security snippet in server blocks, add:"
    echo "    include snippets/security.conf;"
}

#==============================================================================
# APACHE HARDENING
#==============================================================================

harden_apache() {
    log_info "=== Apache Hardening ==="
    
    # Detect Apache config location
    if [[ -d "/etc/apache2" ]]; then
        APACHE_DIR="/etc/apache2"
        APACHE_CONF="$APACHE_DIR/apache2.conf"
        SECURITY_CONF="$APACHE_DIR/conf-available/security.conf"
    elif [[ -d "/etc/httpd" ]]; then
        APACHE_DIR="/etc/httpd"
        APACHE_CONF="$APACHE_DIR/conf/httpd.conf"
        SECURITY_CONF="$APACHE_DIR/conf.d/security.conf"
    else
        log_warn "Apache not found"
        return
    fi
    
    backup_file "$APACHE_CONF"
    
    # Create/update security config
    cat > "$SECURITY_CONF" << 'EOF'
# CCDC Security Hardening for Apache

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable TRACE method
TraceEnable Off

# Disable directory listing
<Directory />
    Options -Indexes
    AllowOverride None
    Require all denied
</Directory>

# Set secure headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Remove server header info
    Header unset X-Powered-By
    Header always unset X-Powered-By
</IfModule>

# Disable dangerous file types
<FilesMatch "\.(bak|config|sql|ini|log|sh|inc|swp|dist)$">
    Require all denied
</FilesMatch>

# Block access to hidden files
<DirectoryMatch "/\.">
    Require all denied
</DirectoryMatch>

# Block access to .htaccess and .htpasswd
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Limit request methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Limit request body size (10MB)
LimitRequestBody 10485760

# Timeout settings
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# Disable server-status and server-info
<Location /server-status>
    Require all denied
</Location>

<Location /server-info>
    Require all denied
</Location>
EOF
    
    log_success "Created security config: $SECURITY_CONF"
    
    # Enable required modules and configs (Debian/Ubuntu)
    if [[ -f "/etc/apache2/apache2.conf" ]]; then
        a2enmod headers 2>/dev/null || true
        a2enmod rewrite 2>/dev/null || true
        a2enconf security 2>/dev/null || true
        log_success "Enabled Apache security modules"
    fi
    
    # Disable unnecessary modules
    if command -v a2dismod &>/dev/null; then
        a2dismod status 2>/dev/null || true
        a2dismod autoindex 2>/dev/null || true
        log_success "Disabled unnecessary modules"
    fi
    
    # Test Apache config
    if apache2ctl -t 2>/dev/null || httpd -t 2>/dev/null; then
        log_success "Apache configuration is valid"
        log_info "Reload Apache with: systemctl reload apache2 (or httpd)"
    else
        log_error "Apache configuration test failed!"
    fi
}

#==============================================================================
# PHP HARDENING
#==============================================================================

harden_php() {
    log_info "=== PHP Hardening ==="
    
    # Find PHP ini files
    PHP_INIS=$(find /etc -name "php.ini" 2>/dev/null || true)
    
    if [[ -z "$PHP_INIS" ]]; then
        log_warn "No PHP configuration found"
        return
    fi
    
    for PHP_INI in $PHP_INIS; do
        log_info "Hardening: $PHP_INI"
        backup_file "$PHP_INI"
        
        # Secure PHP settings
        cat >> "$PHP_INI" << 'EOF'

; ==== CCDC Security Hardening ====

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,eval,create_function,assert,pcntl_exec

; Hide PHP version
expose_php = Off

; Disable remote file operations
allow_url_fopen = Off
allow_url_include = Off

; Limit file uploads
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 2

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.use_only_cookies = 1
session.cookie_samesite = Strict

; Error handling (production)
display_errors = Off
display_startup_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; Resource limits
max_execution_time = 30
max_input_time = 60
memory_limit = 128M
post_max_size = 8M

; Disable remote code inclusion
register_globals = Off

; Open basedir restriction (adjust path as needed)
; open_basedir = /var/www:/tmp
EOF
        
        log_success "Applied PHP hardening to $PHP_INI"
    done
    
    log_info "Restart PHP-FPM to apply changes"
}

#==============================================================================
# MYSQL HARDENING
#==============================================================================

harden_mysql() {
    log_info "=== MySQL/MariaDB Hardening ==="
    
    # Find MySQL config
    if [[ -d "/etc/mysql" ]]; then
        MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
        MYSQL_SEC_CONF="/etc/mysql/conf.d/security.cnf"
    elif [[ -f "/etc/my.cnf" ]]; then
        MYSQL_SEC_CONF="/etc/my.cnf.d/security.cnf"
        mkdir -p /etc/my.cnf.d
    else
        log_warn "MySQL configuration not found"
        return
    fi
    
    # Create security config
    cat > "$MYSQL_SEC_CONF" << 'EOF'
# CCDC Security Hardening for MySQL/MariaDB

[mysqld]
# Bind to localhost only (if not needed remotely)
# bind-address = 127.0.0.1

# Disable symbolic links
symbolic-links = 0

# Disable LOAD DATA LOCAL
local-infile = 0

# Disable showing databases to non-privileged users
skip-show-database

# Log slow queries for analysis
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Enable binary logging for recovery
# log_bin = /var/log/mysql/mysql-bin.log

# Connection limits
max_connections = 100
max_connect_errors = 10

# Query cache (if supported)
# query_cache_type = 1
# query_cache_size = 16M

[client]
# Secure client connections
# ssl-mode = REQUIRED
EOF
    
    log_success "Created MySQL security config: $MYSQL_SEC_CONF"
    
    # Run mysql_secure_installation equivalent checks
    if command -v mysql &>/dev/null; then
        log_info "Checking MySQL security..."
        
        # Check for anonymous users
        anon=$(mysql -N -e "SELECT user FROM mysql.user WHERE user='';" 2>/dev/null || echo "error")
        if [[ "$anon" != "error" && -n "$anon" ]]; then
            log_warn "Anonymous MySQL users exist! Run: mysql_secure_installation"
        else
            log_success "No anonymous users found"
        fi
        
        # Check for remote root
        remote_root=$(mysql -N -e "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || echo "error")
        if [[ "$remote_root" != "error" && -n "$remote_root" ]]; then
            log_warn "Remote root login allowed from: $remote_root"
        fi
        
        # Check for test database
        test_db=$(mysql -N -e "SHOW DATABASES LIKE 'test';" 2>/dev/null || echo "")
        if [[ -n "$test_db" ]]; then
            log_warn "Test database exists - consider removing"
        fi
    else
        log_info "MySQL client not available for checking"
    fi
    
    log_info "Restart MySQL to apply changes"
}

#==============================================================================
# SYSTEM HARDENING
#==============================================================================

harden_system() {
    log_info "=== System Hardening ==="
    
    # 1. Set secure file permissions
    log_info "Securing sensitive files..."
    chmod 600 /etc/shadow 2>/dev/null && log_success "  /etc/shadow: 600" || true
    chmod 644 /etc/passwd 2>/dev/null && log_success "  /etc/passwd: 644" || true
    chmod 600 /etc/gshadow 2>/dev/null && log_success "  /etc/gshadow: 600" || true
    chmod 644 /etc/group 2>/dev/null && log_success "  /etc/group: 644" || true
    
    # 2. Secure SSH (if present)
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        log_info "Hardening SSH..."
        backup_file "/etc/ssh/sshd_config"
        
        # Apply secure SSH settings
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config 2>/dev/null
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config 2>/dev/null
        
        log_success "SSH hardened (restart sshd to apply)"
        log_warn "Root login disabled - ensure you have another admin account!"
    fi
    
    # 3. Disable unnecessary services
    log_info "Checking for unnecessary services..."
    for service in telnet rsh rlogin rexec tftp; do
        if systemctl is-active "$service" &>/dev/null; then
            log_warn "Insecure service running: $service"
            log_info "  Disable with: systemctl disable --now $service"
        fi
    done
    
    # 4. Set umask
    if ! grep -q "umask 027" /etc/profile 2>/dev/null; then
        echo "umask 027" >> /etc/profile
        log_success "Set secure umask (027)"
    fi
    
    # 5. Kernel hardening via sysctl
    log_info "Applying kernel hardening..."
    cat > /etc/sysctl.d/99-ccdc-security.conf << 'EOF'
# CCDC Kernel Security Hardening

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log Martian packets
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1

# Protect against time-wait assassination
net.ipv4.tcp_rfc1337 = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-ccdc-security.conf 2>/dev/null && \
        log_success "Applied kernel hardening" || \
        log_warn "Could not apply some kernel settings"
    
    # 6. Check for SUID/SGID files
    log_info "Checking SUID/SGID files..."
    suspicious_suid=$(find /usr -perm /6000 -type f 2>/dev/null | xargs -I{} sh -c 'file {} | grep -q "shell script" && echo {}')
    if [[ -n "$suspicious_suid" ]]; then
        log_warn "Suspicious SUID/SGID scripts found:"
        echo "$suspicious_suid"
    fi
}

#==============================================================================
# SUSPICIOUS IP IDENTIFICATION (NO BLOCKING - COMPETITION RULES)
#==============================================================================

identify_suspicious_ips() {
    log_info "=== Suspicious IP Identification ==="
    log_info "NOTE: This only IDENTIFIES suspicious IPs - no blocking per competition rules"
    echo ""
    
    # Top connection sources
    log_info "Top connection sources (by connection count):"
    echo "--------------------------------------------------------------------------------"
    ss -tn 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -15
    echo ""
    
    # IPs with many connections (potential attackers)
    log_info "IPs with 10+ connections (possible brute force/DDoS):"
    echo "--------------------------------------------------------------------------------"
    ss -tn 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | awk '$1 >= 10 {print "  [HIGH] " $1 " connections from " $2}'
    echo ""
    
    # Failed SSH attempts
    if [[ -f /var/log/auth.log ]]; then
        log_info "Top IPs with failed SSH attempts:"
        echo "--------------------------------------------------------------------------------"
        grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -rn | head -10 | while read count ip; do
            echo "  [ALERT] $count failed attempts from $ip"
        done
    fi
    echo ""
    
    # Connections on suspicious ports
    log_info "Connections on suspicious ports (4444, 5555, 6666, 1234, 31337):"
    echo "--------------------------------------------------------------------------------"
    ss -tn 2>/dev/null | grep -E ":(4444|5555|6666|1234|31337)" | while read line; do
        echo "  [CRITICAL] $line"
    done
    echo ""
    
    # Web log attackers (if logs exist)
    for log in /var/log/apache2/access.log /var/log/nginx/access.log; do
        if [[ -f "$log" ]]; then
            log_info "Top IPs in $log (last 1000 requests):"
            echo "--------------------------------------------------------------------------------"
            tail -1000 "$log" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
            echo ""
        fi
    done
    
    log_warn "REMINDER: Do NOT block IPs - only report suspicious activity to your team lead"
}

#==============================================================================
# QUICK LOCKDOWN
#==============================================================================

quick_lockdown() {
    log_info "=== QUICK LOCKDOWN MODE ==="
    log_warn "This applies essential security measures quickly"
    
    # Get all search paths
    local search_paths=($(get_search_paths))
    
    # 1. Fix critical file permissions - search all paths
    log_info "Securing wp-config.php files..."
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            find "$search_path" -name "wp-config.php" -exec chmod 400 {} \; 2>/dev/null || true
        fi
    done
    chmod 400 /etc/shadow 2>/dev/null || true
    
    # 2. Disable dangerous PHP functions
    log_info "Disabling dangerous PHP functions..."
    for ini in $(find /etc -name "php.ini" 2>/dev/null); do
        if ! grep -q "CCDC Security" "$ini"; then
            echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,eval" >> "$ini"
        fi
    done
    
    # 3. Block XML-RPC for WordPress - search all paths
    log_info "Blocking XML-RPC..."
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            find "$search_path" -name ".htaccess" 2>/dev/null | while read htaccess; do
                if ! grep -q "xmlrpc" "$htaccess" 2>/dev/null; then
                    echo -e "\n<Files xmlrpc.php>\nDeny from all\n</Files>" >> "$htaccess"
                fi
            done
        fi
    done
    
    # 4. Hide server versions
    log_info "Hiding server versions..."
    if [[ -f "/etc/nginx/nginx.conf" ]]; then
        if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
            sed -i '/http {/a\    server_tokens off;' /etc/nginx/nginx.conf 2>/dev/null || true
        fi
    fi
    
    # 5. Apply sysctl hardening
    log_info "Applying kernel hardening..."
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.all.rp_filter=1 2>/dev/null || true
    
    log_success "Quick lockdown complete!"
    log_info "Run './harden.sh all' for comprehensive hardening"
}

#==============================================================================
# MAIN
#==============================================================================

# Parse command line arguments
COMMAND=""

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
        all|quick|wordpress|nginx|apache|php|mysql|system|ips)
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

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
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
    all)
        harden_wordpress
        echo ""
        harden_nginx
        echo ""
        harden_apache
        echo ""
        harden_php
        echo ""
        harden_mysql
        echo ""
        harden_system
        echo ""
        log_success "All hardening complete!"
        log_info "Restart services to apply all changes:"
        echo "  systemctl restart nginx apache2 httpd php-fpm mysql mariadb 2>/dev/null"
        ;;
    quick)
        quick_lockdown
        ;;
    wordpress)
        harden_wordpress
        ;;
    nginx)
        harden_nginx
        ;;
    apache)
        harden_apache
        ;;
    php)
        harden_php
        ;;
    mysql)
        harden_mysql
        ;;
    system)
        harden_system
        ;;
    ips)
        identify_suspicious_ips
        ;;
    *)
        log_error "Unknown component: $COMMAND"
        exit 1
        ;;
esac
