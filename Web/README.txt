================================================================================
                    CCDC WEB ADMIN TOOLKIT - QUICK REFERENCE
================================================================================

FIRST 5 MINUTES - DO THESE IN ORDER:
================================================================================
1. sudo ./backup.sh full -w /path/to/webroot      # BACKUP EVERYTHING FIRST!
2. sudo ./harden.sh quick -w /path/to/webroot     # Quick security lockdown
3. sudo ./monitor.sh status                        # Verify services running
4. sudo ./monitor.sh scan -w /path/to/webroot     # Check for compromises
5. sudo ./monitor.sh watch -w /path/to/webroot    # Start monitoring (new terminal)

OR just run the interactive menu:
   sudo ./ccdc.sh -w /path/to/webroot


================================================================================
                              SCRIPT REFERENCE
================================================================================

-w FLAG (USE ON ALL SCRIPTS):
--------------------------------------------------------------------------------
Add custom web root paths. Use multiple times for multiple paths.
Example: -w /usr/share/webapp -w /var/www/html -w /opt/mysite


================================================================================
BACKUP.SH - Backup web files, configs, databases
================================================================================

sudo ./backup.sh full -w /path/to/webroot
    What: Complete backup - web files, configs, databases, crontabs, users
    Time: 30 seconds to 5 minutes
    Output: /opt/ccdc_backups/backup_TIMESTAMP.tar.gz

sudo ./backup.sh quick -w /path/to/webroot
    What: Fast backup - just web roots and configs
    Time: 5-30 seconds
    Output: /opt/ccdc_backups/quick_TIMESTAMP.tar.gz

sudo ./backup.sh remote-only
    What: Push latest backup to your Kali box via SSH
    Setup: Edit REMOTE_HOST in backup.sh first


================================================================================
RESTORE.SH - Recover from backups when red team attacks
================================================================================

sudo ./restore.sh emergency -w /path/to/webroot
    What: FASTEST restore - no prompts, uses latest backup
    Time: 5-20 seconds
    Use when: Red team just deleted something, need it back NOW

sudo ./restore.sh full -w /path/to/webroot
    What: Interactive restore - choose what to restore
    Time: 1-5 minutes
    Use when: You have time to be selective

sudo ./restore.sh file /var/www/html/index.php
    What: Restore a single file
    Time: 5 seconds
    Use when: Just one file was modified/deleted

sudo ./restore.sh dir /etc/nginx
    What: Restore entire directory
    Time: 5-30 seconds
    Use when: Config directory was trashed

sudo ./restore.sh list
    What: Show available backups
    Time: Instant

sudo ./restore.sh pull
    What: Pull backups from your remote Kali box
    Setup: Edit REMOTE_HOST in restore.sh first


================================================================================
MONITOR.SH - Detect attacks and suspicious activity
================================================================================

sudo ./monitor.sh scan -w /path/to/webroot
    What: One-time full security scan
    Time: 3-10 seconds
    Checks: Services, auth logs, file changes, processes, network, crons
    Mode: Runs once and exits

sudo ./monitor.sh watch -w /path/to/webroot
    What: Continuous dashboard - refreshes every 30 seconds
    Time: Runs forever until Ctrl+C
    Shows: Service status, alerts, connections
    Mode: FOREGROUND - keep terminal open

sudo ./monitor.sh live -w /path/to/webroot
    What: Real-time log tailing with attack highlighting
    Time: Runs forever until Ctrl+C
    Shows: Web logs with attacks highlighted in red
    Mode: FOREGROUND - keep terminal open

sudo ./monitor.sh status
    What: Quick check if web services are running
    Time: 1-2 seconds

sudo ./monitor.sh files -w /path/to/webroot
    What: Check for recently modified/suspicious files
    Time: 2-5 seconds

sudo ./monitor.sh procs
    What: Check for suspicious processes (reverse shells, miners)
    Time: 1-2 seconds

sudo ./monitor.sh cron
    What: Check crontabs for persistence mechanisms
    Time: 1-2 seconds

sudo ./monitor.sh network
    What: Check network connections for suspicious activity
    Time: 1-2 seconds

sudo ./monitor.sh auth
    What: Check auth logs for brute force, new users
    Time: 2-5 seconds


================================================================================
HARDEN.SH - Security hardening
================================================================================

sudo ./harden.sh quick -w /path/to/webroot
    What: Essential security - fast lockdown
    Time: 5-15 seconds
    Does: Secures wp-config, disables dangerous PHP functions, blocks xmlrpc

sudo ./harden.sh all -w /path/to/webroot
    What: Complete hardening - all components
    Time: 30-60 seconds
    Does: Everything below

sudo ./harden.sh wordpress -w /path/to/webroot
    What: WordPress specific hardening
    Does: Protects wp-config, disables file editor, blocks xmlrpc, 
          secures uploads, fixes permissions

sudo ./harden.sh nginx
    What: Nginx hardening
    Does: Hides version, adds security headers, rate limiting,
          blocks attack patterns

sudo ./harden.sh apache
    What: Apache hardening  
    Does: Hides version, adds security headers, disables dangerous
          methods, blocks sensitive files

sudo ./harden.sh php
    What: PHP hardening
    Does: Disables dangerous functions (exec, shell_exec, system, eval),
          hides version, secures sessions

sudo ./harden.sh mysql
    What: MySQL/MariaDB hardening
    Does: Disables local-infile, connection limits, logging

sudo ./harden.sh system
    What: OS hardening
    Does: SSH hardening, kernel protections, file permissions

sudo ./harden.sh ips
    What: Identify suspicious IPs (NO BLOCKING per competition rules)
    Does: Shows top connection sources, failed SSH attempts, suspicious ports
    Note: Report findings to team lead - do not block IPs


================================================================================
CCDC.SH - Interactive menu (easiest to use)
================================================================================

sudo ./ccdc.sh -w /path/to/webroot
    What: Interactive menu for all functions
    Use: Select options by number
    Tip: Custom web roots are passed to all sub-scripts automatically


================================================================================
                           COMMON SCENARIOS
================================================================================

RED TEAM DELETED FILES:
    sudo ./restore.sh emergency -w /path/to/webroot

WEB SERVICE WON'T START:
    sudo ./restore.sh dir /etc/nginx
    sudo systemctl restart nginx

POSSIBLE ACTIVE ATTACK:
    sudo ./monitor.sh scan -w /path/to/webroot
    sudo ./monitor.sh procs

CHECKING FOR WEBSHELLS:
    sudo ./monitor.sh files -w /path/to/webroot

CONTINUOUS MONITORING (separate terminal):
    sudo ./monitor.sh watch -w /path/to/webroot


================================================================================
                              SETUP NOTES
================================================================================

REMOTE BACKUPS:
Edit backup.sh and restore.sh, change these lines:
    REMOTE_HOST="YOUR_KALI_IP"
    REMOTE_USER="kali"
    REMOTE_PORT="22"

Then set up SSH keys:
    ssh-copy-id kali@YOUR_KALI_IP


DEFAULT PATHS SEARCHED:
    /var/www
    /usr/share/nginx
    /usr/share/wordpress
    /srv/www
    + any paths you add with -w


================================================================================
                              COMPETITION TIPS
================================================================================

1. BACKUP FIRST - Before touching anything!
2. Keep ./monitor.sh watch running in a separate terminal
3. After any restore, restart services: systemctl restart nginx apache2 mysql
4. Check ./monitor.sh files regularly for new suspicious files
5. Don't break scoring - test changes carefully
6. Document what you change and when

================================================================================
