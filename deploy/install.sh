#!/usr/bin/env bash
# tetherd installer. Usage:
#   sudo bash install.sh install     first-time setup (asks 3 questions)
#   sudo bash install.sh update      pull the newest image and restart
#   sudo bash install.sh backup      write ~/tether-backup-<date>.tar.gz
#   sudo bash install.sh restore F   restore from a backup file
#   sudo bash install.sh uninstall   stop and remove everything
#   sudo bash install.sh ticket      print the server ticket again
#
# Non-interactive: set TETHER_DOMAIN, TETHER_EMAIL, TETHER_TUNNELS=yes|no before running.
set -euo pipefail

REPO="${TETHER_REPO:-https://github.com/jaredkotvas/tether}"
RAW="${TETHER_RAW:-https://raw.githubusercontent.com/jaredkotvas/tether/main/deploy}"
IMAGE="${TETHER_IMAGE:-ghcr.io/jaredkotvas/tetherd:latest}"
PORT=47711
WG_PORT=47712
WG_IFACE=tether0

OWNER="${SUDO_USER:-$(id -un)}"
HOME_DIR="$(getent passwd "$OWNER" | cut -d: -f6)"
DIR="$HOME_DIR/tether"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run with sudo"; }
compose() {
  local files=(-f "$DIR/docker-compose.yml")
  [ -f "$DIR/docker-compose.wg.yml" ] && grep -q '^TETHERD_WG_IFACE=' "$DIR/.env" && files+=(-f "$DIR/docker-compose.wg.yml")
  local profiles=()
  grep -q '^TETHER_RELAY=yes' "$DIR/.env" && profiles+=(--profile relay)
  docker compose --project-directory "$DIR" "${files[@]}" "${profiles[@]}" "$@"
}

ensure_docker() {
  if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    say "Installing Docker"
    curl -fsSL https://get.docker.com | sh
  fi
}

get_image() {
  if docker pull "$IMAGE" >/dev/null 2>&1; then return; fi
  say "Prebuilt image unavailable; building from source (takes a few minutes)"
  rm -rf "$DIR/src"
  git clone --depth 1 "$REPO" "$DIR/src"
  docker build -t "$IMAGE" -f "$DIR/src/deploy/Dockerfile" "$DIR/src"
}

fetch_files() {
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  for f in docker-compose.yml docker-compose.wg.yml; do
    if [ -f "$here/$f" ]; then cp "$here/$f" "$DIR/$f"; else curl -fsSL "$RAW/$f" -o "$DIR/$f"; fi
  done
}

ask() { # ask VAR "question" default
  local var=$1 q=$2 def=${3:-}
  if [ -n "${!var:-}" ]; then return; fi
  # Read from the terminal even when this script arrives through `curl | sudo bash`.
  if { : </dev/tty; } 2>/dev/null; then
    read -r -p "$q ${def:+[$def] }" ans </dev/tty; printf -v "$var" '%s' "${ans:-$def}"
  else printf -v "$var" '%s' "$def"; fi
}

setup_wireguard() {
  command -v wg >/dev/null || { apt-get update -qq && apt-get install -y -qq wireguard-tools; }
  if [ ! -f "/etc/wireguard/$WG_IFACE.conf" ]; then
    umask 077
    cat >"/etc/wireguard/$WG_IFACE.conf" <<EOF
[Interface]
Address = 10.77.0.1/24
ListenPort = $WG_PORT
PrivateKey = $(wg genkey)
EOF
  fi
  sysctl -q -w net.ipv4.ip_forward=1
  grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.d/99-tether.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-tether.conf
  systemctl enable --now "wg-quick@$WG_IFACE" >/dev/null
}

cmd_install() {
  need_root
  [ -f "$DIR/.env" ] && die "already installed in $DIR (use update)"
  ensure_docker
  mkdir -p "$DIR/data" "$DIR/relay"
  fetch_files

  local public_ip; public_ip="$(curl -fsS4 https://api.ipify.org || true)"
  ask TETHER_DOMAIN "Domain for your own relay (blank = use the free public relays):" ""
  [ -n "$TETHER_DOMAIN" ] && ask TETHER_EMAIL "Email for the Let's Encrypt certificate:" ""
  ask TETHER_TUNNELS "Offer WireGuard tunnels? (yes/no)" "no"

  local token; token="$(head -c 20 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')"
  {
    echo "TETHER_IMAGE=$IMAGE"
    echo "TETHERD_PORT=$PORT"
    echo "TETHERD_TOKEN=$token"
    [ -n "$public_ip" ] && echo "TETHERD_PUBLIC_ADDR=$public_ip:$PORT"
  } >"$DIR/.env"

  if [ -n "$TETHER_DOMAIN" ]; then
    echo "TETHER_RELAY=yes" >>"$DIR/.env"
    echo "TETHERD_RELAY_URL=https://$TETHER_DOMAIN" >>"$DIR/.env"
    cat >"$DIR/relay/relay.toml" <<EOF
enable_relay = true
http_bind_addr = "0.0.0.0:80"
enable_quic_addr_discovery = true
enable_metrics = false

[tls]
https_bind_addr = "0.0.0.0:443"
quic_bind_addr = "0.0.0.0:7842"
cert_mode = "LetsEncrypt"
hostname = "$TETHER_DOMAIN"
${TETHER_EMAIL:+contact = \"$TETHER_EMAIL\"}
cert_dir = "/data/certs"
prod_tls = true

[access]
shared_token = ["$token"]
EOF
  fi

  if [ "$TETHER_TUNNELS" = "yes" ]; then
    setup_wireguard
    {
      echo "TETHERD_WG_IFACE=$WG_IFACE"
      echo "TETHERD_WG_ENDPOINT=${TETHER_DOMAIN:-$public_ip}:$WG_PORT"
      echo "TETHERD_WG_SUBNET=10.77.0.0/24"
    } >>"$DIR/.env"
  fi
  chmod 600 "$DIR/.env"
  [ -f "$DIR/relay/relay.toml" ] && chmod 600 "$DIR/relay/relay.toml"
  chown -R "$OWNER": "$DIR"

  get_image
  compose up -d
  say "Waiting for the server ticket"
  for _ in $(seq 1 30); do [ -s "$DIR/data/ticket.txt" ] && break; sleep 1; done
  local ports="UDP $PORT"
  [ -n "$TETHER_DOMAIN" ] && ports="$ports, TCP 80 and 443, UDP 7842"
  [ "$TETHER_TUNNELS" = "yes" ] && ports="$ports, UDP $WG_PORT"
  say "Installed in $DIR. Allow $ports through your firewall."
  cmd_ticket
}

cmd_update() {
  need_root
  [ -f "$DIR/.env" ] || die "not installed"
  fetch_files
  get_image
  compose up -d
  say "Updated."
}

cmd_backup() {
  need_root
  local out; out="$HOME_DIR/tether-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  compose stop >/dev/null
  tar -czf "$out" -C "$DIR" .env data relay
  compose start >/dev/null
  chown "$OWNER": "$out"
  say "Backup written to $out"
}

cmd_restore() {
  need_root
  local file=${1:-}; [ -f "$file" ] || die "usage: restore <backup.tar.gz>"
  mkdir -p "$DIR"
  [ -f "$DIR/docker-compose.yml" ] || fetch_files
  [ -f "$DIR/.env" ] && compose down >/dev/null || true
  tar -xzf "$file" -C "$DIR"
  chown -R "$OWNER": "$DIR"
  get_image
  compose up -d
  say "Restored from $file"
}

cmd_uninstall() {
  need_root
  [ -d "$DIR" ] || die "not installed"
  if [ "${1:-}" != "-y" ] && { : </dev/tty; } 2>/dev/null; then
    read -r -p "Delete $DIR including keys, mail and cached files? (yes/no) " ok </dev/tty
    [ "$ok" = "yes" ] || exit 1
  fi
  [ -f "$DIR/.env" ] && compose down --rmi all >/dev/null 2>&1 || true
  if systemctl is-enabled "wg-quick@$WG_IFACE" >/dev/null 2>&1; then
    systemctl disable --now "wg-quick@$WG_IFACE" >/dev/null
    rm -f "/etc/wireguard/$WG_IFACE.conf" /etc/sysctl.d/99-tether.conf
  fi
  rm -rf "$DIR"
  say "Uninstalled."
}

cmd_ticket() {
  [ -s "$DIR/data/ticket.txt" ] || die "no ticket yet; check: docker compose -f $DIR/docker-compose.yml logs"
  say "Server ticket (paste into your app config):"
  cat "$DIR/data/ticket.txt"; echo
}

case "${1:-}" in
  install) cmd_install ;;
  update) cmd_update ;;
  backup) cmd_backup ;;
  restore) shift; cmd_restore "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  ticket) cmd_ticket ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
