#!/usr/bin/env bash
# harden-egress.sh
# Flips UFW default outgoing to deny, then allows only the outbound ports
# needed for a Linux SSSD client in an Active Directory environment.
#
# Run AFTER triage-firewall.sh. Must be run as root.
#
# IMPORTANT: Before enabling deny-outgoing, use ss and /etc/resolv.conf
# to identify any additional outbound dependencies (see comments at bottom).

set -euo pipefail

# ── Color helpers ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

if ! command -v ufw &>/dev/null; then
    err "UFW is not installed. Run triage-firewall.sh first."
    exit 1
fi

# ── Deny outgoing by default ──────────────────────────────────────────────────
info "Setting default outgoing policy to deny..."
ufw default deny outgoing

# ── AD / SSSD required outbound ports ─────────────────────────────────────────
# Each entry: "port/proto description"
AD_EGRESS=(
    # DNS — SSSD and system resolver
    "53/tcp    DNS (TCP zone transfers / large responses)"
    "53/udp    DNS (standard queries)"

    # Kerberos — authentication
    "88/tcp    Kerberos authentication"
    "88/udp    Kerberos authentication"

    # NTP — time sync (critical for Kerberos ticket validity)
    "123/udp   NTP time sync"

    # LDAP — SSSD identity lookups
    "389/tcp   LDAP"
    "389/udp   LDAP (CLDAP ping / DC locator)"

    # LDAPS — encrypted LDAP
    "636/tcp   LDAPS"

    # SMB — sysvol, netlogon, trust validation
    "445/tcp   SMB/CIFS"

    # Kerberos password change
    "464/tcp   Kerberos kpasswd"
    "464/udp   Kerberos kpasswd"

    # Global Catalog — cross-domain lookups
    "3268/tcp  LDAP Global Catalog"
    "3269/tcp  LDAPS Global Catalog"
)

info "Allowing AD/SSSD outbound ports..."
for entry in "${AD_EGRESS[@]}"; do
    rule=$(echo "$entry" | awk '{print $1}')
    desc=$(echo "$entry" | cut -d' ' -f2-)
    ufw allow out "$rule" comment "egress: $desc" 2>/dev/null || \
        warn "Could not add outbound rule: $rule"
    printf "    allow out %-12s  %s\n" "$rule" "$desc"
done

# ── Common infrastructure you probably also need ──────────────────────────────
# Uncomment any of these as needed for your environment.

OPTIONAL=(
    # Package management (apt, dnf, yum)
    "80/tcp    HTTP (package repos / CRL)"
    "443/tcp   HTTPS (package repos / OCSP / APIs)"

    # SMTP outbound (if this server sends mail)
    #"25/tcp    SMTP"
    #"587/tcp   SMTP submission (STARTTLS)"
    #"465/tcp   SMTPS"

    # Syslog forwarding
    #"514/tcp   Syslog (TCP)"
    #"514/udp   Syslog (UDP)"
    #"6514/tcp  Syslog over TLS"

    # Database clients (uncomment what applies)
    #"3306/tcp  MySQL/MariaDB"
    #"5432/tcp  PostgreSQL"
    #"1433/tcp  MSSQL"
    #"1521/tcp  Oracle"
    #"27017/tcp MongoDB"
    #"6379/tcp  Redis"

    # DHCP (if not statically addressed)
    #"67/udp    DHCP server"
    #"68/udp    DHCP client"

    # SNMP (monitoring)
    #"161/udp   SNMP"
    #"162/udp   SNMP traps"

    # ICMP — uncomment if you need outbound ping
    # (handled separately below since it's not port-based)
)

info "Allowing common infrastructure outbound ports..."
for entry in "${OPTIONAL[@]}"; do
    # Skip commented-out lines
    [[ "$entry" =~ ^# ]] && continue
    rule=$(echo "$entry" | awk '{print $1}')
    desc=$(echo "$entry" | cut -d' ' -f2-)
    ufw allow out "$rule" comment "egress: $desc" 2>/dev/null || \
        warn "Could not add outbound rule: $rule"
    printf "    allow out %-12s  %s\n" "$rule" "$desc"
done

# ── Uncomment to allow outbound ICMP (ping) ──────────────────────────────────
# ufw allow out proto icmp comment "egress: ICMP ping"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
ok "Egress hardening complete."
echo ""
ufw status verbose

echo ""
warn "If anything breaks, restore full outbound access with:"
echo "    sudo ufw default allow outgoing"
echo "Use 'ufw allow out 443/tcp' to allow other egress ports"
