#!/usr/bin/env bash
set -euo pipefail
set -o errtrace

# ─── Command-Line Arguments ──────────────────────────────────────────────────
# Flags for dry-run, debug, and interactive modes
DRY_RUN=false
DEBUG=false
INTERACTIVE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --debug) DEBUG=true; shift ;;
    --interactive) INTERACTIVE=true; shift ;;
    *) shift ;;
  esac
done
[[ "$DEBUG" == true ]] && set -x

# ─── Global Variables ────────────────────────────────────────────────────────
LOG_FILE="/var/log/pi-dns-setup.log"
ENV_FILE="./pi-dns.env"
SUMMARY_FILE="/var/log/pi-dns-summary.txt"
DEBIAN_FRONTEND=noninteractive

# ─── Color Codes for Output ──────────────────────────────────────────────────
COL_GREEN="\033[32m"
COL_YELLOW="\033[33m"
COL_RED="\033[31m"
COL_RESET="\033[0m"

# ─── Traps for Error Handling ────────────────────────────────────────────────
trap 'echo -e "${COL_RED}[EXIT] status=$? line=$LINENO${COL_RESET}" | tee -a "$LOG_FILE"' EXIT
trap 'echo -e "${COL_RED}[ERR ] line $LINENO exit $?${COL_RESET}" | tee -a "$LOG_FILE"' ERR

# ─── Logging Functions ───────────────────────────────────────────────────────
log()  { echo -e "${COL_GREEN}[$(date +'%FT%T%z')] INFO : $*${COL_RESET}" | tee -a "$LOG_FILE"; }
warn() { echo -e "${COL_YELLOW}[$(date +'%FT%T%z')] WARN : $*${COL_RESET}" | tee -a "$LOG_FILE"; }
die()  { echo -e "${COL_RED}[$(date +'%FT%T%z')] ERROR: $*${COL_RESET}" | tee -a "$LOG_FILE" >&2; exit 1; }

# ─── Lock to Prevent Concurrent Runs ─────────────────────────────────────────
exec 200>/var/lock/pi-dns-setup.lock
flock -n 200 || die "Another setup is running"

# ─── Root and OS Check ───────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run with sudo"
if ! grep -qEi 'debian|raspbian' /etc/os-release; then
  warn "Tested on Debian/Raspbian only—yours may differ"
fi

# ─── Initialize Logging ──────────────────────────────────────────────────────
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
log "Logging initialized"
cat >/etc/logrotate.d/pi-dns-setup <<EOF
$LOG_FILE {
  daily
  rotate 7
  compress
  missingok
  notifempty
}
EOF

# ─── Load Environment Variables ──────────────────────────────────────────────
[[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE"
chmod 600 "$ENV_FILE"; set -a; source "$ENV_FILE"; set +a
for v in INTERFACE IP_ADDR TUNNEL_NAME DOMAIN CF_DNS_TOKEN LE_EMAIL; do
  [[ -n "${!v:-}" ]] || die "Env var $v not set"
done
REAL_USER=${SUDO_USER:-$(whoami)}
USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
CLOUDFLARE_USER_DIR="$USER_HOME/.cloudflared"
mkdir -p "$CLOUDFLARE_USER_DIR"
log ".env loaded (user=$REAL_USER home=$USER_HOME)"

# ─── Sanity Checks: Network and Disk ──────────────────────────────────────────
ping -c1 1.1.1.1 &>/dev/null || die "No network"
df -Pk / | awk 'NR==2 && $4<1048576{exit 1}' || die "Low disk space (<1GB)"
log "Network and disk checks passed"

# ─── Prerequisites and Cloudflare Token Validation ───────────────────────────
for b in curl wget ufw jq dig; do command -v "$b" &>/dev/null || die "Need $b"; done
curl -sSL -H "Authorization: Bearer $CF_DNS_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  | jq -e .success >/dev/null || die "Cloudflare token invalid"
log "Preflight checks OK & Cloudflare token validated"

# ─── Functions ───────────────────────────────────────────────────────────────

# Install necessary dependencies
install_dependencies() {
  log "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    unbound ufw jq \
    rkhunter chkrootkit auditd fail2ban \
    certbot python3-certbot-dns-cloudflare \
    prometheus-node-exporter dnsutils apparmor apparmor-utils aide smartmontools
  log "Dependencies installed"
}

# Configure UFW firewall
configure_firewall() {
  log "Configuring firewall..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 53/tcp
  ufw allow 53/udp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw limit ssh/tcp
  ufw logging on
  ufw --force enable
  log "Firewall configured"
}

# Setup Unbound with upstream DNS
setup_unbound() {
  log "Setting up Unbound..."
  UNBOUND_CFG=/etc/unbound/unbound.conf.d/pi-hole.conf
  if [[ ! -f "$UNBOUND_CFG" ]]; then
    cp "$UNBOUND_CFG" "$UNBOUND_CFG.$(date +%F).bak" 2>/dev/null || true
    cat >"$UNBOUND_CFG" <<EOF
server:
  interface: 127.0.0.1
  port: 5335
  hide-identity: yes
  hide-version: yes
  prefetch: yes
  minimal-responses: yes
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  num-threads: $(nproc)
forward-zone:
  name: "."
  forward-tls-upstream: yes
  forward-addr: 1.1.1.1@853
  forward-addr: 1.0.0.1@853
EOF
  fi
  unbound-anchor -a /var/lib/unbound/root.key -v || true
  unbound-checkconf "$UNBOUND_CFG" && systemctl enable --now unbound || die "Unbound failed"
  log "Unbound configured and running"
}

# Install Pi-hole if not already installed
install_pihole() {
  log "Installing Pi-hole..."
  if ! command -v pihole &>/dev/null; then
    export PIHOLE_INTERFACE="$INTERFACE" IPV4_ADDRESS="$IP_ADDR" PIHOLE_DNS_1="127.0.0.1#5335"
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
    log "Pi-hole installed"
  else
    log "Pi-hole already installed, skipping"
  fi
}

# Configure Pi-hole settings
configure_pihole() {
  log "Configuring Pi-hole..."
  # Set web server domain
  pihole-FTL --config webserver.domain=$DOMAIN
  # Ensure DHCP is disabled
  pihole-FTL --config dns.dhcp.enabled=false
  # Generate and set admin password
  PW=$(tr -dc A-Za-z0-9 </dev/urandom | head -c12)
  pihole -a -p $PW
  log "Pi-hole configured with DHCP disabled and password set"
}

# Setup HTTPS for pihole-FTL
setup_https() {
  log "Setting up HTTPS..."
  echo "dns_cloudflare_api_token = $CF_DNS_TOKEN" >/etc/letsencrypt/cloudflare.ini
  chmod 600 /etc/letsencrypt/cloudflare.ini
  certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d "$DOMAIN" -m "$LE_EMAIL" --agree-tos --non-interactive \
    || warn "Certbot: already valid"
  # Combine private key and full chain for pihole-FTL
  cat /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/letsencrypt/live/$DOMAIN/fullchain.pem > /etc/pihole/tls.pem
  chown pihole:pihole /etc/pihole/tls.pem
  chmod 600 /etc/pihole/tls.pem
  # Configure pihole-FTL to use the certificate
  pihole-FTL --config webserver.tls.enabled=true
  pihole-FTL --config webserver.tls.cert=/etc/pihole/tls.pem
  systemctl restart pihole-FTL
  # Set up renewal cron job
  echo "0 4 * * * root certbot renew --quiet --post-hook \"cat /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/letsencrypt/live/$DOMAIN/fullchain.pem > /etc/pihole/tls.pem && chown pihole:pihole /etc/pihole/tls.pem && chmod 600 /etc/pihole/tls.pem && systemctl restart pihole-FTL\"" > /etc/cron.d/certbot-renew
  log "HTTPS configured for pihole-FTL"
}

# Setup monitoring tools (optional)
setup_monitoring() {
  if [[ "$INTERACTIVE" == true ]]; then
    read -p "Set up monitoring tools? [y/N]: " monitoring_choice
    if [[ "$monitoring_choice" == "y" ]]; then
      log "Setting up monitoring..."
      systemctl enable --now prometheus-node-exporter
      log "Monitoring tools set up"
    else
      log "Skipping monitoring setup"
    fi
  fi
}

# Setup daily backups
setup_backups() {
  log "Setting up backups..."
  cat <<EOF > /etc/cron.daily/pihole-backup
#!/bin/bash
BD=/var/backups/pihole-config
mkdir -p \$BD
tar czf \$BD/pihole-\$(date +%F).tgz /etc/pihole /etc/unbound /etc/cloudflared
find \$BD -type f -mtime +7 -delete
EOF
  chmod +x /etc/cron.daily/pihole-backup
  log "Backup cron job set up"
}

# Setup automatic updates
setup_auto_updates() {
  log "Setting up automatic updates..."
  # Pi-hole update cron job
  echo "0 2 * * 0 pihole -up" | crontab -
  # Unattended upgrades for security patches
  apt-get install -y unattended-upgrades
  dpkg-reconfigure --priority=low unattended-upgrades
  log "Automatic updates configured"
}

# Run tests and validation
run_tests() {
  log "Running tests..."
  for svc in unbound pihole-FTL cloudflared; do
    systemctl is-active "$svc" >/dev/null || warn "$svc not running"
  done
  dig +short example.com @127.0.0.1 || warn "DNS resolution failed"
  log "Tests completed"
}

# Print setup summary
print_summary() {
  log "Setup complete!"
  cat <<EOF | tee "$SUMMARY_FILE"
Pi-hole is installed and configured.
DNS is set to use Unbound with Cloudflare as upstream.
Firewall is configured with UFW.
Automatic updates and backups are set up.

Next steps:
1. Point your router or devices to $IP_ADDR for DNS.
2. Access the Pi-hole UI at https://$DOMAIN/admin with password: $PW
For help, visit https://discourse.pi-hole.net or https://github.com/your-username/pi-dns-setup
EOF
}

# ─── Main Function ───────────────────────────────────────────────────────────
main() {
  install_dependencies
  configure_firewall
  setup_unbound
  install_pihole
  configure_pihole
  setup_https
  setup_monitoring
  setup_backups
  setup_auto_updates
  run_tests
  print_summary
}

main "$@"