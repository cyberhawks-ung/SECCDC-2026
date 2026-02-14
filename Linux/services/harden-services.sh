#!/usr/bin/env bash
# =============================================================================
# service_audit.sh
# Audits and manages system services based on classification files:
#   critical.txt  - Known critical services (alert if installed)
#   malicious.txt - Known malicious services (disable + alert)
#   real.txt      - Legitimate but unnecessary services (disable silently)
#
# Any installed service NOT found in any file is flagged for investigation.
# Must be run as root.
# =============================================================================

set -euo pipefail

# ---- Parse arguments ----
DRY_RUN=false

usage() {
    echo "Usage: $0 [--dry-run]"
    echo "  --dry-run   Report what would happen without making any changes"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ---- Configuration ----
CRITICAL_FILE="critical.txt"
MALICIOUS_FILE="malicious.txt"
REAL_FILE="real.txt"
LOG_FILE="service_audit_$(date +%Y%m%d_%H%M%S).log"

# ANSI colors
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'

# ---- Helper functions ----

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

alert() {
    local level="$1" msg="$2"
    case "$level" in
        CRITICAL)    log "${CYN}[CRITICAL NOTICE] $msg${RST}" ;;
        MALICIOUS)   log "${RED}[MALICIOUS ALERT] $msg${RST}" ;;
        INVESTIGATE) log "${YEL}[INVESTIGATE] $msg${RST}" ;;
        ERROR)       log "${RED}[ERROR] $msg${RST}" ;;
        INFO)        log "${GRN}[INFO] $msg${RST}" ;;
        DRYRUN)      log "${YEL}[DRY RUN] $msg${RST}" ;;
        *)           log "$msg" ;;
    esac
}

disable_service() {
    local svc="$1"

    if $DRY_RUN; then
        systemctl is-active --quiet "$svc" 2>/dev/null \
            && alert DRYRUN "Would stop active service: $svc"
        systemctl is-enabled --quiet "$svc" 2>/dev/null \
            && alert DRYRUN "Would disable enabled service: $svc"
        return 0
    fi

    # Actually stop the service
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        if systemctl stop "$svc" 2>/dev/null; then
            alert INFO "Stopped service: $svc"
        else
            alert ERROR "Failed to stop service: $svc"
        fi
    fi

    # Actually disable the service
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        if systemctl disable "$svc" 2>/dev/null; then
            alert INFO "Disabled service: $svc"
        else
            alert ERROR "Failed to disable service: $svc"
        fi
    fi
}

service_exists() {
    # Returns 0 if the service unit file exists on the system
    systemctl list-unit-files "${1}.service" 2>/dev/null | grep -q "$1"
}

# ---- Preflight checks ----

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root.${RST}" >&2
    exit 1
fi

for f in "$CRITICAL_FILE" "$MALICIOUS_FILE" "$REAL_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo -e "${RED}Error: Missing required file: $f${RST}" >&2
        exit 1
    fi
done

if $DRY_RUN; then
    log "${YEL}========== Service Audit Started (DRY RUN — no changes will be made) ==========${RST}"
else
    log "========== Service Audit Started =========="
fi

# ---- Load service lists into arrays (strip blanks & comments) ----

mapfile -t critical_services  < <(grep -v '^\s*#' "$CRITICAL_FILE"  | sed '/^\s*$/d')
mapfile -t malicious_services < <(grep -v '^\s*#' "$MALICIOUS_FILE" | sed '/^\s*$/d')
mapfile -t real_services      < <(grep -v '^\s*#' "$REAL_FILE"      | sed '/^\s*$/d')

# Build a lookup set of all known service names
declare -A known_services
for svc in "${critical_services[@]}" "${malicious_services[@]}" "${real_services[@]}"; do
    known_services["$svc"]=1
done

# ---- Phase 1: Disable services in real.txt ----

log ""
log "${CYN}--- Phase 1: Disabling unnecessary services (real.txt) ---${RST}"
for svc in "${real_services[@]}"; do
    if service_exists "$svc"; then
        alert INFO "Found installed real service: $svc — disabling"
        disable_service "$svc"
    fi
done

# ---- Phase 2: Disable and alert on malicious services ----

log ""
log "${CYN}--- Phase 2: Disabling & alerting on malicious services (malicious.txt) ---${RST}"
for svc in "${malicious_services[@]}"; do
    if service_exists "$svc"; then
        alert MALICIOUS "Malicious service INSTALLED on system: $svc — disabling immediately"
        disable_service "$svc"
    fi
done

# ---- Phase 3: Alert on critical services ----

log ""
log "${CYN}--- Phase 3: Alerting on critical services (critical.txt) ---${RST}"
for svc in "${critical_services[@]}"; do
    if service_exists "$svc"; then
        alert CRITICAL "Critical service found installed: $svc — verify it is expected"
    fi
done

# ---- Phase 4: Find unknown/unclassified services ----

log ""
log "${CYN}--- Phase 4: Identifying unknown services not in any list ---${RST}"
unknown_count=0

while IFS= read -r line; do
    # Each line from list-unit-files: "servicename.service   enabled/disabled/..."
    svc_full="${line%%.service*}"
    svc_name="$(echo "$svc_full" | xargs)"  # trim whitespace

    [[ -z "$svc_name" ]] && continue

    if [[ -z "${known_services[$svc_name]+_}" ]]; then
        alert INVESTIGATE "Unknown service not in any classification file: $svc_name"
        ((unknown_count++)) || true
    fi
done < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
         | awk '{print $1}')

# ---- Summary ----

log ""
log "========== Audit Summary =========="
log "  Real services in list:       ${#real_services[@]}"
log "  Malicious services in list:  ${#malicious_services[@]}"
log "  Critical services in list:   ${#critical_services[@]}"
log "  Unknown services found:      $unknown_count"
log "  Full log written to:         $LOG_FILE"
log "========== Service Audit Complete =========="
