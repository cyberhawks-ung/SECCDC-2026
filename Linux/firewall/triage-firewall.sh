#!/usr/bin/env bash
# triage-firewall.sh
# Reads current listening ports from ss, installs UFW, allows those ports,
# then enables UFW.
#
# Must be run as root.

set -euo pipefail

# ── Color helpers ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; }

# ── Root check ─────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

# ── Detect package manager & install UFW ───────────────────────────────────────
install_ufw() {
    if command -v ufw &>/dev/null; then
        ok "UFW is already installed."
        return
    fi

    info "Installing UFW..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq ufw
    elif command -v dnf &>/dev/null; then
        dnf install -y -q ufw
    elif command -v yum &>/dev/null; then
        yum install -y -q epel-release 2>/dev/null || true
        yum install -y -q ufw
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm ufw
    elif command -v zypper &>/dev/null; then
        zypper install -y ufw
    elif command -v apk &>/dev/null; then
        apk add ufw
    else
        err "No supported package manager found. Install UFW manually."
        exit 1
    fi

    if ! command -v ufw &>/dev/null; then
        err "UFW installation failed."
        exit 1
    fi
    ok "UFW installed successfully."
}

# ── Gather listening ports from ss ─────────────────────────────────────────────
gather_listening_ports() {
    info "Reading listening ports from ss -plunt..."

    declare -A seen
    RULES=()

    while IFS= read -r line; do
        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $5}')

        # Extract port (last colon-delimited field — handles IPv6 brackets)
        port="${local_addr##*:}"

        # Skip non-numeric (header row, etc.)
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        # Normalize protocol
        case "$proto" in
            tcp|tcp6) proto="tcp" ;;
            udp|udp6) proto="udp" ;;
            *) continue ;;
        esac

        key="${port}/${proto}"
        if [[ -z "${seen[$key]+x}" ]]; then
            seen[$key]=1
            RULES+=("$key")
        fi
    done < <(ss -plunt | tail -n +2)

    if [[ ${#RULES[@]} -eq 0 ]]; then
        warn "No listening ports found. UFW will block all incoming traffic."
    else
        ok "Found ${#RULES[@]} unique listening port/protocol pairs:"
        for rule in "${RULES[@]}"; do
            printf "    %s\n" "$rule"
        done
    fi
}

# ── Apply rules to UFW ─────────────────────────────────────────────────────────
apply_rules() {
    info "Setting UFW defaults (deny incoming, allow outgoing)..."
    ufw default deny incoming
    ufw default allow outgoing

    info "Allowing discovered listening ports..."
    for rule in "${RULES[@]}"; do
        ufw allow "$rule" comment "triage: listening service" 2>/dev/null || \
            warn "Could not add rule: $rule"
    done

    ok "All rules applied."
}

# ── Enable UFW ─────────────────────────────────────────────────────────────────
enable_ufw() {
    info "Enabling UFW..."
    echo "y" | ufw enable
    ok "UFW is now active."
    echo ""
    ufw status verbose
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  triage-firewall.sh — quick-stand-up host firewall"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    install_ufw
    gather_listening_ports
    apply_rules
    enable_ufw

    echo ""
    ok "Done. Review rules above and adjust as needed."
}

main "$@"

echo "Run 'ufw logging high' and inspect /var/log/ufw.log for outgoing traffic"
