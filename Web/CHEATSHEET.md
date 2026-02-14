# CCDC Web Admin Cheatsheet

## FIRST 5 MINUTES (IN ORDER!)

```bash
cd /path/to/scripts
sudo ./backup.sh full          # 1. BACKUP EVERYTHING FIRST!
sudo ./harden.sh quick         # 2. Quick security lockdown
sudo ./monitor.sh status       # 3. Check services are running
sudo ./monitor.sh scan         # 4. Look for existing compromises
sudo ./monitor.sh watch        # 5. Start monitoring (new terminal)
```

Or use the interactive menu:
```bash
sudo ./ccdc.sh
```

## CUSTOM WEB ROOT (-w flag)

All scripts support the `-w` flag to add custom web root locations:

```bash
# If web content is in /usr/share instead of /var/www:
sudo ./backup.sh full -w /usr/share/mywebapp -w /usr/share/wordpress
sudo ./restore.sh emergency -w /usr/share/mywebapp
sudo ./monitor.sh scan -w /usr/share/mywebapp
sudo ./harden.sh all -w /usr/share/mywebapp

# Interactive menu with custom paths:
sudo ./ccdc.sh -w /usr/share/mywebapp -w /opt/webapp
```

You can use `-w` multiple times to add multiple custom paths.

---

## QUICK COMMANDS

### Backup
```bash
sudo ./backup.sh full          # Full backup (local + remote)
sudo ./backup.sh quick         # Quick backup (web roots only)
sudo ./backup.sh remote-only   # Push latest backup to Kali box
```

### Restore
```bash
sudo ./restore.sh emergency    # FASTEST - no prompts, latest backup
sudo ./restore.sh full         # Interactive full restore
sudo ./restore.sh file /var/www/html/index.php  # Restore single file
sudo ./restore.sh dir /etc/nginx                 # Restore directory
sudo ./restore.sh pull         # Pull backups from remote Kali box
```

### Monitoring
```bash
sudo ./monitor.sh scan         # Full security scan
sudo ./monitor.sh live         # Live tail logs with attack highlighting
sudo ./monitor.sh watch        # Continuous dashboard
sudo ./monitor.sh status       # Check service status
sudo ./monitor.sh files        # Check for modified files
sudo ./monitor.sh procs        # Check suspicious processes
sudo ./monitor.sh cron         # Check crontabs
```

### Hardening
```bash
sudo ./harden.sh quick         # Essential security (fast)
sudo ./harden.sh all           # Full hardening
sudo ./harden.sh wordpress     # WordPress only
sudo ./harden.sh nginx         # Nginx only
sudo ./harden.sh apache        # Apache only
sudo ./harden.sh php           # PHP only
sudo ./harden.sh mysql         # MySQL only
sudo ./harden.sh system        # System hardening
```

---

## MANUAL COMMANDS

### Service Management
```bash
# Restart services after changes
sudo systemctl restart nginx
sudo systemctl restart apache2   # Debian/Ubuntu
sudo systemctl restart httpd     # RHEL/CentOS
sudo systemctl restart php-fpm
sudo systemctl restart php8.1-fpm
sudo systemctl restart mysql
sudo systemctl restart mariadb

# Check status
sudo systemctl status nginx apache2 mysql php-fpm
```

### WordPress CLI
```bash
# Change admin password
wp user update admin --user_pass="NewPassword123!" --allow-root

# List users
wp user list --allow-root

# Install plugin
wp plugin install wordfence --activate --allow-root

# Deactivate all plugins
wp plugin deactivate --all --allow-root
```

### Database
```bash
# Dump all databases
mysqldump --all-databases > backup.sql

# Dump specific database
mysqldump wordpress > wordpress.sql

# Restore database
mysql wordpress < wordpress.sql

# Change MySQL root password
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';"

# List MySQL users
mysql -e "SELECT user,host FROM mysql.user;"
```

### Finding Bad Stuff
```bash
# Recently modified PHP files
find /var/www -name "*.php" -mmin -60

# Files with dangerous functions
grep -r "eval\|base64_decode\|shell_exec\|system\|passthru" /var/www --include="*.php"

# Hidden files
find /var/www -name ".*"

# World-writable files
find /var/www -perm -o+w -type f

# SUID files
find / -perm -4000 2>/dev/null

# Check crontabs
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/*
```

### Network
```bash
# Current connections
ss -tnp
netstat -tlnp

# Who's connecting (identify top sources)
ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Identify suspicious IPs (DO NOT BLOCK - competition rules)
sudo ./harden.sh ips

# Find IPs with many connections
ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
```

### Logs
```bash
# Apache
tail -f /var/log/apache2/access.log
tail -f /var/log/apache2/error.log

# Nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Auth
tail -f /var/log/auth.log

# Combined live view
tail -f /var/log/nginx/*.log /var/log/apache2/*.log
```

---

## ATTACK PATTERNS TO WATCH FOR

### SQL Injection
```
UNION SELECT
' OR 1=1
'; DROP TABLE
SLEEP(
BENCHMARK(
```

### Command Injection
```
; cat /etc/passwd
| nc -e
$(whoami)
`id`
```

### Path Traversal
```
../../../etc/passwd
%2e%2e%2f
```

### Webshells
```
c99, r57, b374k
eval(base64_decode
passthru($_GET
shell_exec($_POST
```

---

## EMERGENCY PROCEDURES

### Red Team Deleted Critical Files
```bash
sudo ./restore.sh emergency
# or for specific file:
sudo ./restore.sh file /var/www/html/wp-config.php
```

### Web Service Won't Start
```bash
# Check config syntax
nginx -t
apache2ctl -t
httpd -t

# Check logs
journalctl -u nginx -n 50
journalctl -u apache2 -n 50

# Restore config
sudo ./restore.sh dir /etc/nginx
sudo systemctl restart nginx
```

### Possible Active Compromise
```bash
# Kill suspicious processes
sudo ./ccdc.sh  # Option 20

# Check what's running
ps auxf
ss -tnp

# Identify suspicious IPs (DO NOT BLOCK - report to team lead)
sudo ./harden.sh ips
sudo ./monitor.sh network
```

### Database Down
```bash
# Check status
sudo systemctl status mysql

# Check disk space
df -h

# Restore from backup
sudo ./restore.sh full  # Choose database restore option
```

---

## COMPETITION TIPS

1. **BACKUP FIRST** - Before touching anything, backup!
2. **Document changes** - Note what you change and when
3. **Monitor constantly** - Keep `./monitor.sh watch` running
4. **Check file changes** - Run `./monitor.sh files` regularly
5. **Don't break scoring** - Test changes carefully
6. **Coordinate with team** - Communicate before major changes
7. **Keep services UP** - Availability matters for scoring

---

## CONFIGURATION LOCATIONS

| Service | Debian/Ubuntu | RHEL/CentOS |
|---------|---------------|-------------|
| Nginx | /etc/nginx/nginx.conf | /etc/nginx/nginx.conf |
| Apache | /etc/apache2/ | /etc/httpd/ |
| PHP | /etc/php/X.X/ | /etc/php.ini |
| MySQL | /etc/mysql/ | /etc/my.cnf |
| Web Root | /var/www/html | /var/www/html |

---

## SSH KEY SETUP (for remote backups)

On the competition server:
```bash
# Generate key if needed
ssh-keygen -t rsa -b 4096

# Copy to your Kali box
ssh-copy-id kali@YOUR_KALI_IP

# Test connection
ssh kali@YOUR_KALI_IP
```

Then edit backup.sh:
```bash
REMOTE_USER="kali"
REMOTE_HOST="YOUR_KALI_IP"
REMOTE_PORT="22"
```
