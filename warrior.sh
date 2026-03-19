#!/usr/bin/env bash
set -u
IFS=$'\n\t'

VERSION="171"
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
START_TIME="$(date +%s)"
RUN_ID="$(date +%s)"
LOGFILE="/tmp/warrior_${RUN_ID}.log"

PROFILE="normal"
NO_COLOR=0

RED='\033[0;31m'
ORANGE='\033[38;5;208m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

TOTAL_RISK_POINTS=0
TOTAL_FINDINGS=0

declare -A SEVERITY_COUNT=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [INFO]=0)
declare -A CATEGORY_COUNT=()
declare -A SEEN=()

declare -a ALL_FINDINGS=()
declare -a ROOT_IMPACT_FINDINGS=()

lookup_kernel_reference() {
  local kernel="$1"
  local mm
  mm="$(printf '%s' "$kernel" | awk -F. '{print $1 "." $2}')"

  case "$mm" in
    4.4)  echo "Review legacy 4.4 kernel advisories and patch status." ;;
    4.9)  echo "Review legacy 4.9 kernel advisories and patch status." ;;
    5.4)  echo "Review 5.4 kernel advisories, including CVE-2021-3493 and CVE-2022-0847, against vendor patches." ;;
    5.8)  echo "Review 5.8 kernel advisories, including CVE-2022-0847, against vendor patches." ;;
    5.10) echo "Review 5.10 kernel advisories, including CVE-2022-2588, against vendor patches." ;;
    5.15) echo "Review current 5.15 vendor advisories for local privilege escalation issues." ;;
    6.1)  echo "Review current 6.1 vendor advisories for local privilege escalation issues." ;;
    *)    echo "" ;;
  esac
}

lookup_component_reference() {
  local component="$1"
  case "$component" in
    pkexec) echo "CVE-2021-4034" ;;
    sudo) echo "CVE-2021-3156" ;;
    docker.sock|/var/run/docker.sock) echo "Container runtime control surface present. Review local runtime exposure and related advisories." ;;
    containerd.sock|/run/containerd/containerd.sock) echo "Container runtime control socket present. Review runtime access policy." ;;
    podman.sock|/run/podman/podman.sock) echo "Podman service socket present. Review runtime access policy." ;;
    overlayfs) echo "CVE-2023-0386" ;;
    systemd) echo "Review installed systemd version against current vendor advisories." ;;
    cron) echo "Review scheduled task ownership, trust boundaries, and relevant local advisories." ;;
    openssh) echo "Review installed OpenSSH version against current vendor advisories." ;;
    polkit) echo "Review installed polkit and pkexec version against current vendor advisories." ;;
    *) echo "" ;;
  esac
}

capability_reference() {
  local line="$1"
  if echo "$line" | grep -Eq "cap_setuid|cap_sys_admin|cap_dac_override"; then
    echo "High-risk file capability present. Review binary purpose and trust boundary."
  else
    echo ""
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --quick) PROFILE="quick" ;;
      --normal) PROFILE="normal" ;;
      --deep) PROFILE="deep" ;;
      --no-color) NO_COLOR=1 ;;
      -h|--help)
        sed -n '1,40p' "$0"
        exit 0
        ;;
    esac
    shift
  done
}

init_colors() {
  if [ "$NO_COLOR" -eq 1 ]; then
    RED=''; ORANGE=''; YELLOW=''; GREEN=''; BLUE=''; CYAN=''; WHITE=''; NC=''
  fi
}

banner() {
  echo
  echo -e "${WHITE}WARRIOR ${VERSION}${NC}"
  echo -e "${CYAN}Host:${NC} ${HOSTNAME_VALUE}"
  echo -e "${CYAN}Mode:${NC} ${PROFILE}"
  echo -e "${CYAN}Log:${NC} ${LOGFILE}"
  echo -e "${CYAN}Policy:${NC} read-only reporting"
  echo
}

log_line() {
  echo "[$(date '+%H:%M:%S')] $1" >> "$LOGFILE"
}

section() {
  echo
  echo -e "${CYAN}--------------------------------------------------${NC}"
  echo -e "${WHITE}$1${NC}"
  echo -e "${CYAN}--------------------------------------------------${NC}"
}

dedupe() {
  local key="$1"
  [[ ${SEEN[$key]+x} ]] && return 1
  SEEN["$key"]=1
  return 0
}

risk_points_for_confidence() {
  local c="$1"
  if [ "$c" -ge 90 ]; then echo 10
  elif [ "$c" -ge 75 ]; then echo 7
  elif [ "$c" -ge 60 ]; then echo 5
  elif [ "$c" -ge 40 ]; then echo 3
  else echo 1
  fi
}

grade_finding() {
  local category="$1"
  local target="$2"
  local issue="$3"

  case "${category}|${target}|${issue}" in
    docker|/var/run/docker.sock|*"Docker socket exposed"*) echo "95|root" ;;
    sockets|/var/run/docker.sock|*"Privileged runtime socket present"*) echo "95|root" ;;
    cron|*|*"Writable cron command"*) echo "90|root" ;;
    systemd|*|*"Writable service target"*) echo "90|root" ;;
    sudo|*|*"Dangerous sudo rule"*) echo "85|root" ;;
    capabilities|*|*"High-risk file capability present"*) echo "80|root" ;;
    users|*|*"Privileged group membership"*) echo "65|root" ;;
    filesystem|*|*"Writable root-owned file"*) echo "85|root" ;;
    filesystem|*|*"Writable parent directory for privileged target"*) echo "55|root" ;;
    env|*|*"Writable PATH directory"*) echo "75|root" ;;
    secrets|*|*"SSH private key found"*) echo "80|user/service" ;;
    secrets|*|*"Cloud credential found"*) echo "80|user/service" ;;
    secrets|*|*"Database credential found"*) echo "70|user/service" ;;
    secrets|*|*"Service token found"*) echo "70|user/service" ;;
    secrets|*|*"Generic secret match"*) echo "55|user/service" ;;
    suid|*|*"SUID binary present"*) echo "50|root" ;;
    sgid|*|*"SGID binary present"*) echo "40|service/user" ;;
    acl|*|*"ACL entry grants additional access"*) echo "55|contextual" ;;
    process|*|*"Root script process observed"*) echo "40|root" ;;
    kernel|*|*"Kernel version detected"*) echo "60|root" ;;
    *) echo "30|unknown" ;;
  esac
}

color_for_confidence() {
  local c="$1"
  if [ "$NO_COLOR" -eq 1 ]; then echo ""; return; fi
  if [ "$c" -ge 90 ]; then echo "$RED"
  elif [ "$c" -ge 75 ]; then echo "$ORANGE"
  elif [ "$c" -ge 60 ]; then echo "$YELLOW"
  elif [ "$c" -ge 40 ]; then echo "$GREEN"
  else echo "$BLUE"
  fi
}

label_for_confidence() {
  local c="$1"
  if [ "$c" -ge 90 ]; then echo "Very High"
  elif [ "$c" -ge 75 ]; then echo "High"
  elif [ "$c" -ge 60 ]; then echo "Moderate"
  elif [ "$c" -ge 40 ]; then echo "Low"
  else echo "Informational"
  fi
}

record_finding() {
  local severity="$1" category="$2" target="$3" issue="$4" confidence="$5" impact="$6" points="$7"
  local row="${points}|${confidence}|${severity}|${category}|${target}|${issue}|${impact}"
  ALL_FINDINGS+=("$row")
  [ "$impact" = "root" ] && ROOT_IMPACT_FINDINGS+=("$row")
}

sort_desc_take() {
  local limit="$1"
  shift
  printf '%s\n' "$@" | awk 'NF' | sort -t'|' -k1,1nr -k2,2nr | head -n "$limit"
}

report_item() {
  local severity="$1"
  local category="$2"
  local target="$3"
  local issue="$4"
  local reference="${5:-}"
  local cve="${6:-}"

  local dkey="${severity}|${category}|${target}|${issue}|${reference}|${cve}"
  dedupe "$dkey" || return 0

  local grade confidence impact color band points
  grade="$(grade_finding "$category" "$target" "$issue")"
  confidence="${grade%%|*}"
  impact="${grade##*|}"
  color="$(color_for_confidence "$confidence")"
  band="$(label_for_confidence "$confidence")"
  points="$(risk_points_for_confidence "$confidence")"

  printf "%b[%-8s]%b %-12s %-26s %s\n" "$color" "$severity" "$NC" "$category" "$target" "$issue"
  printf "           %-12s %-26s %s\n" "" "Confidence" "${confidence}% (${band})"
  printf "           %-12s %-26s %s\n" "" "Impact" "$impact"
  printf "           %-12s %-26s %s\n" "" "Risk Points" "$points"
  [ -n "$reference" ] && printf "           %-12s %-26s %s\n" "" "Reference" "$reference"
  [ -n "$cve" ] && printf "           %-12s %-26s %s\n" "" "CVE / Label" "$cve"
  printf "           %-12s %-26s %s\n" "" "Note" "Manual validation required"
  echo

  TOTAL_RISK_POINTS=$((TOTAL_RISK_POINTS + points))
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
  SEVERITY_COUNT["$severity"]=$((SEVERITY_COUNT["$severity"] + 1))
  CATEGORY_COUNT["$category"]=$(( ${CATEGORY_COUNT[$category]:-0} + 1 ))

  record_finding "$severity" "$category" "$target" "$issue" "$confidence" "$impact" "$points"
  log_line "$severity|$category|$target|$issue|confidence=${confidence}|impact=${impact}|points=${points}|reference=${reference}|cve=${cve}"
}

correlated_item() {
  local severity="$1"
  local summary="$2"
  local impact="${3:-root}"
  local confidence="${4:-90}"

  local color band points
  color="$(color_for_confidence "$confidence")"
  band="$(label_for_confidence "$confidence")"
  points="$(risk_points_for_confidence "$confidence")"

  printf "%b[%-8s]%b %-12s %-26s %s\n" "$color" "$severity" "$NC" "correlated" "Likely risk path" "$summary"
  printf "           %-12s %-26s %s\n" "" "Confidence" "${confidence}% (${band})"
  printf "           %-12s %-26s %s\n" "" "Impact" "$impact"
  printf "           %-12s %-26s %s\n" "" "Note" "Manual validation required"
  echo

  TOTAL_RISK_POINTS=$((TOTAL_RISK_POINTS + points))
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
  SEVERITY_COUNT["$severity"]=$((SEVERITY_COUNT["$severity"] + 1))
  CATEGORY_COUNT["correlated"]=$(( ${CATEGORY_COUNT[correlated]:-0} + 1 ))

  local row="${points}|${confidence}|${severity}|correlated|Likely risk path|${summary}|${impact}"
  ALL_FINDINGS+=("$row")
  [ "$impact" = "root" ] && ROOT_IMPACT_FINDINGS+=("$row")
  log_line "$severity|correlated|Likely risk path|${summary}|confidence=${confidence}|impact=${impact}|points=${points}"
}

overall_risk_score() {
  if [ "$TOTAL_FINDINGS" -eq 0 ]; then echo 0; return; fi
  local raw
  raw=$(( TOTAL_RISK_POINTS * 100 / (TOTAL_FINDINGS * 10) ))
  [ "$raw" -gt 100 ] && raw=100
  echo "$raw"
}

overall_risk_label() {
  local s="$1"
  if [ "$s" -ge 85 ]; then echo "Critical Exposure"
  elif [ "$s" -ge 70 ]; then echo "High Exposure"
  elif [ "$s" -ge 50 ]; then echo "Moderate Exposure"
  elif [ "$s" -ge 30 ]; then echo "Low Exposure"
  else echo "Minimal Exposure"
  fi
}

overall_risk_color() {
  local s="$1"
  if [ "$NO_COLOR" -eq 1 ]; then echo ""; return; fi
  if [ "$s" -ge 85 ]; then echo "$RED"
  elif [ "$s" -ge 70 ]; then echo "$ORANGE"
  elif [ "$s" -ge 50 ]; then echo "$YELLOW"
  elif [ "$s" -ge 30 ]; then echo "$GREEN"
  else echo "$BLUE"
  fi
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

module_system() {
  section "System"
  local kernel
  kernel="$(uname -r 2>/dev/null)"
  report_item INFO kernel "$kernel" "Kernel version detected" "Kernel inventory" "$(lookup_kernel_reference "$kernel")"
}

module_docker() {
  section "Container"
  [ -S /var/run/docker.sock ] && report_item CRITICAL docker "/var/run/docker.sock" "Docker socket exposed" "Container runtime control surface detected" "$(lookup_component_reference docker.sock)"
}

module_sudo() {
  section "Sudo"
  cmd_exists sudo || return 0
  sudo -l 2>/dev/null | grep NOPASSWD | head -n 5 | while read -r line; do
    report_item HIGH sudo "$line" "Dangerous sudo rule" "Review sudoers policy and allowed command scope manually" "$(lookup_component_reference sudo)"
  done
}

module_suid() {
  section "SUID"
  find / -perm -4000 -type f 2>/dev/null | head -n 5 | while read -r f; do
    report_item INFO suid "$f" "SUID binary present" "Review whether the binary is expected and safely configured"
  done
}

module_service_chain() {
  section "Service chain"
  cmd_exists systemctl || return 0
  systemctl list-unit-files --type=service 2>/dev/null | head -n 8 | while read -r svc; do
    local name path
    name="$(echo "$svc" | awk '{print $1}')"
    [ -n "$name" ] || continue
    systemctl cat "$name" 2>/dev/null | grep ExecStart | head -n 2 | while read -r line; do
      path="$(echo "$line" | grep -oE '/[^ ]+' | head -n 1)"
      [ -n "$path" ] && report_item INFO systemd "$name" "Service target: $path" "Review service execution chain manually" "$(lookup_component_reference systemd)"
      [ -n "$path" ] && [ -w "$path" ] && report_item CRITICAL systemd "$path" "Writable service target" "Service target writability may affect trust boundary" "$(lookup_component_reference systemd)"
    done
  done
}

module_acl_parent() {
  section "ACL and parent directory analysis"
  cmd_exists getfacl && getfacl -R /etc 2>/dev/null | grep 'user:' | head -n 5 | while read -r line; do
    report_item INFO acl "/etc" "ACL entry grants additional access" "Review nonstandard ACLs manually"
  done

  find /usr /opt /usr/local -type f 2>/dev/null | head -n 8 | while read -r f; do
    local dir
    dir="$(dirname "$f")"
    [ -w "$dir" ] && report_item HIGH filesystem "$dir -> $f" "Writable parent directory for privileged target" "Parent directory control may affect trusted target"
  done
}

module_secret_ranking() {
  section "Secret ranking"

  find /home /root -type f \( -name "id_rsa" -o -name "id_ed25519" \) 2>/dev/null | head -n 3 | while read -r f; do
    report_item HIGH secrets "$f" "SSH private key found" "Private key material may enable additional access"
  done

  grep -rEi 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_|GOOGLE_APPLICATION_CREDENTIALS' /home /var/www /opt 2>/dev/null | head -n 5 | while read -r l; do
    report_item HIGH secrets "cloud credentials" "Cloud credential found" "Cloud credential material detected"
  done

  grep -rEi 'DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|DATABASE_URL' /home /var/www /opt 2>/dev/null | head -n 5 | while read -r l; do
    report_item HIGH secrets "database config" "Database credential found" "Database credential material detected"
  done

  grep -rEi 'token|bearer|api[_-]?key|secret' /home /var/www /opt 2>/dev/null | head -n 5 | while read -r l; do
    report_item INFO secrets "generic config" "Generic secret match" "Secret-like value found; classify manually"
  done
}

module_correlation() {
  section "Correlated findings"

  [ -S /var/run/docker.sock ] && id 2>/dev/null | grep -q docker && \
    correlated_item CRITICAL "User belongs to docker group and docker socket is exposed" root 95

  [ -r /etc/crontab ] && grep -v '^#' /etc/crontab 2>/dev/null | grep -oE '/[^ ]+' | head -n 5 | while read -r cmd; do
    [ -n "$cmd" ] && [ -w "$cmd" ] && correlated_item CRITICAL "Writable cron target detected: $cmd" root 90
  done

  cmd_exists systemctl && find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null | head -n 3 | while read -r p; do
    correlated_item HIGH "Writable systemd unit file present: $p" root 85
  done
}

module_summary() {
  section "Summary"
  local score label score_color
  score="$(overall_risk_score)"
  label="$(overall_risk_label "$score")"
  score_color="$(overall_risk_color "$score")"

  echo "Profile: $PROFILE"
  echo "Log file: $LOGFILE"
  echo "Findings: $TOTAL_FINDINGS"
  echo "Critical: ${SEVERITY_COUNT[CRITICAL]}"
  echo "High    : ${SEVERITY_COUNT[HIGH]}"
  echo "Medium  : ${SEVERITY_COUNT[MEDIUM]}"
  echo "Info    : ${SEVERITY_COUNT[INFO]}"
  echo
  echo "Per-category counts:"
  for key in "${!CATEGORY_COUNT[@]}"; do
    printf "  %-12s %s\n" "$key" "${CATEGORY_COUNT[$key]}"
  done | sort
  echo
  echo -e "${score_color}Overall Machine Risk Score: ${score}/100 (${label})${NC}"
  echo

  section "Top 5 highest-confidence findings"
  sort_desc_take 5 "${ALL_FINDINGS[@]}" | while IFS='|' read -r points confidence severity category target issue impact; do
    [ -n "${severity:-}" ] || continue
    printf "%-8s %-12s %-24s %s [confidence=%s%% impact=%s]\n" "$severity" "$category" "$target" "$issue" "$confidence" "$impact"
  done
  echo

  section "Top 3 likely root-impact paths"
  if [ "${#ROOT_IMPACT_FINDINGS[@]}" -eq 0 ]; then
    echo "No likely root-impact findings ranked."
  else
    sort_desc_take 3 "${ROOT_IMPACT_FINDINGS[@]}" | while IFS='|' read -r points confidence severity category target issue impact; do
      [ -n "${severity:-}" ] || continue
      printf "%-8s %-12s %-24s %s [confidence=%s%%]\n" "$severity" "$category" "$target" "$issue" "$confidence"
    done
  fi
  echo
}

main() {
  parse_args "$@"
  init_colors
  : > "$LOGFILE"
  banner
  module_system
  module_docker
  module_sudo
  module_suid
  [ "$PROFILE" != "quick" ] && module_service_chain
  [ "$PROFILE" = "deep" ] && module_acl_parent
  [ "$PROFILE" != "quick" ] && module_secret_ranking
  module_correlation
  module_summary
}

main "$@"
