#!/bin/bash
#
# pow-shield-php Installation Script (Updated)
# https://github.com/AfterPacket/pow-shield-php
#
# Updates in this version:
# - Cloudflare-safe real client IP restore via mod_remoteip (optional, default ON)
# - Weekly Cloudflare IP list updater (cron.d)
# - Fixes RewriteRule patterns (no leading slash in vhost context)
# - Adds ACME challenge bypass (Let's Encrypt renewals won't get gated)
# - Normalizes cookie regex to v2 format across vhosts
# - Ensures RewriteEngine On + correct GET/HEAD gating logic
# - ModSecurity include wiring for the PoW ratelimit rules (if installed)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DOMAIN=""
WEBROOT=""
SSL_CERT=""
SSL_KEY=""
ENABLE_SITE="no"
SKIP_MODSEC="no"
USE_LETSENCRYPT="no"
LETSENCRYPT_EMAIL=""
USE_DEFAULT_VHOST="no"
INTERACTIVE=1

# Cloudflare real IP restore (mod_remoteip)
CLOUDFLARE_REALIP="yes"   # default ON (safe even if you're not behind CF)
CF_IP_DIR="/etc/apache2/cloudflare"
CF_REMOTEIP_CONF="/etc/apache2/conf-available/remoteip-cloudflare.conf"
CF_UPDATER="/usr/local/sbin/update-cloudflare-ips.sh"
CF_CRON="/etc/cron.d/update-cloudflare-ips"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_banner() {
  cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                  pow-shield-php Installer                 ║
║           https://github.com/AfterPacket/pow-shield-php   ║
╚═══════════════════════════════════════════════════════════╝
EOF
}

usage() {
  cat << EOF
Usage: $0 [OPTIONS]

Interactive Installation Script for pow-shield-php

OPTIONS:
  -d, --domain DOMAIN           Domain name (e.g., example.com) [optional]
  -w, --webroot PATH            Web root directory path
  -c, --cert PATH               SSL certificate path (optional)
  -k, --key PATH                SSL key path (optional)
  -l, --letsencrypt EMAIL       Use Let's Encrypt with email
  -e, --enable                  Enable site with a2ensite after install
  -s, --skip-modsec             Skip ModSecurity installation
  --default-vhost               Install to default Apache vhost (no domain needed)
  --no-cloudflare-realip        Do NOT configure Cloudflare real-IP restore (mod_remoteip)
  -n, --non-interactive         Run without prompts (requires all flags)
  -h, --help                    Show this help message

EXAMPLES:
  # Interactive mode (recommended)
  sudo ./install.sh

  # Install to default vhost (VPS with IP only)
  sudo ./install.sh --default-vhost -w /var/www/html

  # Non-interactive with existing SSL
  sudo ./install.sh -d example.com -w /var/www/html -c /path/to/cert.pem -k /path/to/key.pem -e

  # Non-interactive with Let's Encrypt
  sudo ./install.sh -d example.com -w /var/www/html -l admin@example.com -e

  # Non-interactive, disable Cloudflare real IP restore
  sudo ./install.sh -d example.com -w /var/www/html --no-cloudflare-realip -e
EOF
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
  fi
}

check_dependencies() {
  log_info "Checking dependencies..."

  local missing_deps=()
  local pkg_deps=()

  # Commands -> packages
  if ! command -v apache2 >/dev/null 2>&1 && ! command -v apachectl >/dev/null 2>&1; then
    missing_deps+=("apache2")
    pkg_deps+=("apache2")
  fi

  if ! command -v php >/dev/null 2>&1; then
    missing_deps+=("php")
    pkg_deps+=("php" "libapache2-mod-php")
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    missing_deps+=("openssl")
    pkg_deps+=("openssl")
  fi

  if ! command -v curl >/dev/null 2>&1; then
    missing_deps+=("curl")
    pkg_deps+=("curl")
  fi

  if ! command -v sed >/dev/null 2>&1; then
    missing_deps+=("sed")
    pkg_deps+=("sed")
  fi

  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    log_warn "Missing dependencies: ${missing_deps[*]}"

    if [[ $INTERACTIVE -eq 1 ]]; then
      read -r -p "Install missing dependencies now? (y/n) [y]: " install_deps
      install_deps=${install_deps:-y}
      if [[ "$install_deps" =~ ^[Yy]$ ]]; then
        log_info "Installing dependencies..."
        apt-get update
        apt-get install -y "${pkg_deps[@]}"
        log_success "Dependencies installed"
      else
        log_error "Cannot proceed without dependencies"
        exit 1
      fi
    else
      log_info "Auto-installing dependencies..."
      apt-get update
      apt-get install -y "${pkg_deps[@]}"
      log_success "Dependencies installed"
    fi
  else
    log_success "All dependencies found"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -d|--domain)
        DOMAIN="$2"
        shift 2
        ;;
      -w|--webroot)
        WEBROOT="$2"
        shift 2
        ;;
      -c|--cert)
        SSL_CERT="$2"
        shift 2
        ;;
      -k|--key)
        SSL_KEY="$2"
        shift 2
        ;;
      -l|--letsencrypt)
        USE_LETSENCRYPT="yes"
        LETSENCRYPT_EMAIL="$2"
        shift 2
        ;;
      -e|--enable)
        ENABLE_SITE="yes"
        shift
        ;;
      -s|--skip-modsec)
        SKIP_MODSEC="yes"
        shift
        ;;
      --default-vhost)
        USE_DEFAULT_VHOST="yes"
        shift
        ;;
      --no-cloudflare-realip)
        CLOUDFLARE_REALIP="no"
        shift
        ;;
      -n|--non-interactive)
        INTERACTIVE=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

prompt_config() {
  if [[ $INTERACTIVE -eq 0 ]]; then
    if [[ "$USE_DEFAULT_VHOST" != "yes" ]] && [[ -z "$DOMAIN" ]] && [[ -z "$WEBROOT" ]]; then
      log_error "Non-interactive mode requires --domain and --webroot OR --default-vhost"
      usage
      exit 1
    fi
    if [[ -z "$WEBROOT" ]]; then
      WEBROOT="/var/www/html"
    fi
    return
  fi

  echo ""
  log_info "Starting interactive configuration..."
  echo ""

  # install type
  if [[ -z "$DOMAIN" ]]; then
    echo "You can install pow-shield-php to:"
    echo "  1) A specific domain (requires domain name)"
    echo "  2) Default Apache vhost (for VPS IP access)"
    echo ""
    read -r -p "Choose installation type (1/2) [2]: " install_type
    install_type=${install_type:-2}

    if [[ "$install_type" == "2" ]]; then
      USE_DEFAULT_VHOST="yes"
      log_info "Using default Apache vhost (IP-based access)"
    else
      while [[ -z "$DOMAIN" ]]; do
        read -r -p "Enter your domain name (e.g., example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
          log_error "Domain cannot be empty"
        fi
      done
    fi
  fi

  # webroot
  if [[ -z "$WEBROOT" ]]; then
    read -r -p "Enter web root path [/var/www/html]: " WEBROOT
    WEBROOT=${WEBROOT:-/var/www/html}
  fi

  # cloudflare realip
  echo ""
  read -r -p "Configure Cloudflare real client IP restore (mod_remoteip)? (y/n) [y]: " cf_choice
  cf_choice=${cf_choice:-y}
  if [[ ! "$cf_choice" =~ ^[Yy]$ ]]; then
    CLOUDFLARE_REALIP="no"
  fi

  # SSL
  if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
    echo ""
    log_info "SSL Configuration"
    echo "Note: Default vhost typically doesn't need SSL for IP access"
    read -r -p "Do you want to configure SSL anyway? (y/n) [n]: " want_ssl
    want_ssl=${want_ssl:-n}
    if [[ "$want_ssl" =~ ^[Yy]$ ]]; then
      prompt_ssl_config
    else
      log_info "Skipping SSL configuration for default vhost"
    fi
  else
    echo ""
    log_info "SSL Configuration"
    prompt_ssl_config
  fi

  # enable site
  echo ""
  if [[ "$USE_DEFAULT_VHOST" != "yes" ]]; then
    read -r -p "Enable site with a2ensite after installation? (y/n) [n]: " enable_choice
    enable_choice=${enable_choice:-n}
    if [[ "$enable_choice" =~ ^[Yy]$ ]]; then
      ENABLE_SITE="yes"
    fi
  else
    log_info "Using default vhost (no need to enable with a2ensite)"
    ENABLE_SITE="no"
  fi

  # modsecurity
  echo ""
  read -r -p "Install/configure ModSecurity? (y/n) [y]: " modsec_choice
  modsec_choice=${modsec_choice:-y}
  if [[ ! "$modsec_choice" =~ ^[Yy]$ ]]; then
    SKIP_MODSEC="yes"
  fi
}

prompt_ssl_config() {
  read -r -p "Do you have existing SSL certificates? (y/n) [n]: " has_ssl
  has_ssl=${has_ssl:-n}

  if [[ "$has_ssl" =~ ^[Yy]$ ]]; then
    read -r -p "Enter SSL certificate path: " SSL_CERT
    read -r -p "Enter SSL key path: " SSL_KEY

    if [[ ! -f "$SSL_CERT" ]]; then
      log_warn "Certificate file not found: $SSL_CERT"
      SSL_CERT=""
      SSL_KEY=""
    elif [[ ! -f "$SSL_KEY" ]]; then
      log_warn "Key file not found: $SSL_KEY"
      SSL_CERT=""
      SSL_KEY=""
    fi
  else
    if [[ -n "$DOMAIN" ]]; then
      echo ""
      read -r -p "Would you like to use Let's Encrypt for free SSL? (y/n) [y]: " use_le
      use_le=${use_le:-y}

      if [[ "$use_le" =~ ^[Yy]$ ]]; then
        USE_LETSENCRYPT="yes"
        read -r -p "Enter your email for Let's Encrypt: " LETSENCRYPT_EMAIL

        if [[ ! "$LETSENCRYPT_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
          log_warn "Invalid email format"
          USE_LETSENCRYPT="no"
          LETSENCRYPT_EMAIL=""
        fi
      fi
    fi
  fi
}

show_config_summary() {
  echo ""
  log_info "Configuration Summary:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
    echo "Mode:             Default Apache vhost (IP-based)"
    echo "Access:           http://YOUR_SERVER_IP"
  else
    echo "Domain:           $DOMAIN"
  fi

  echo "Web Root:         $WEBROOT"
  echo "Cloudflare IP:    $CLOUDFLARE_REALIP"

  if [[ "$USE_LETSENCRYPT" = "yes" ]]; then
    echo "SSL:              Let's Encrypt ($LETSENCRYPT_EMAIL)"
  elif [[ -n "$SSL_CERT" ]]; then
    echo "SSL Certificate:  $SSL_CERT"
    echo "SSL Key:          $SSL_KEY"
  else
    echo "SSL Certificate:  Not configured"
  fi

  echo "Enable Site:      $ENABLE_SITE"
  echo "Install ModSec:   $([ "$SKIP_MODSEC" = "yes" ] && echo "no" || echo "yes")"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  if [[ $INTERACTIVE -eq 1 ]]; then
    read -r -p "Proceed with installation? (y/n) [y]: " proceed
    proceed=${proceed:-y}
    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
      log_info "Installation cancelled"
      exit 0
    fi
  fi
}

install_certbot() {
  if [[ "$USE_LETSENCRYPT" != "yes" ]]; then
    return
  fi

  log_info "Checking for certbot..."
  if ! command -v certbot >/dev/null 2>&1; then
    log_info "Installing certbot..."
    apt-get update
    apt-get install -y certbot python3-certbot-apache
    log_success "Certbot installed"
  else
    log_success "Certbot already installed"
  fi
}

obtain_letsencrypt_cert() {
  if [[ "$USE_LETSENCRYPT" != "yes" ]]; then
    return
  fi

  log_info "Obtaining Let's Encrypt certificate for $DOMAIN..."

  local temp_vhost="/etc/apache2/sites-available/$DOMAIN-temp.conf"
  cat > "$temp_vhost" << EOF
<VirtualHost *:80>
  ServerName $DOMAIN
  ServerAlias www.$DOMAIN
  DocumentRoot $WEBROOT

  <Directory $WEBROOT>
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
EOF

  a2ensite "$DOMAIN-temp.conf" >/dev/null 2>&1
  systemctl reload apache2

  if certbot certonly --apache -d "$DOMAIN" -d "www.$DOMAIN" \
    --email "$LETSENCRYPT_EMAIL" \
    --agree-tos \
    --non-interactive; then

    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    log_success "Let's Encrypt certificate obtained"
  else
    log_error "Failed to obtain Let's Encrypt certificate"
    log_warn "Continuing without SSL..."
    USE_LETSENCRYPT="no"
  fi

  a2dissite "$DOMAIN-temp.conf" >/dev/null 2>&1 || true
  rm -f "$temp_vhost"
  systemctl reload apache2 || true
}

setup_cloudflare_realip() {
  if [[ "$CLOUDFLARE_REALIP" != "yes" ]]; then
    log_info "Cloudflare real IP restore: disabled"
    return
  fi

  log_info "Configuring Cloudflare real client IP restore (mod_remoteip)..."

  # Enable module
  if ! apachectl -M 2>/dev/null | grep -q remoteip_module; then
    a2enmod remoteip >/dev/null 2>&1
    log_success "Enabled module: remoteip"
  fi

  # Ensure dir
  install -d -m 0755 "$CF_IP_DIR"

  # Fetch initial lists
  curl -fsSL https://www.cloudflare.com/ips-v4 -o "$CF_IP_DIR/ips-v4.txt"
  curl -fsSL https://www.cloudflare.com/ips-v6 -o "$CF_IP_DIR/ips-v6.txt"
  chmod 0644 "$CF_IP_DIR/ips-v4.txt" "$CF_IP_DIR/ips-v6.txt"

  # Write conf
  cat > "$CF_REMOTEIP_CONF" << EOF
# Managed by pow-shield-php installer
# Trust CF-Connecting-IP ONLY when request comes from Cloudflare IPs
RemoteIPHeader CF-Connecting-IP
RemoteIPTrustedProxyList $CF_IP_DIR/ips-v4.txt
RemoteIPTrustedProxyList $CF_IP_DIR/ips-v6.txt
EOF

  a2enconf remoteip-cloudflare >/dev/null 2>&1 || true

  # Updater script
  cat > "$CF_UPDATER" << 'EOF'
#!/bin/bash
set -euo pipefail

DIR="/etc/apache2/cloudflare"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL https://www.cloudflare.com/ips-v4 -o "$TMP/ips-v4.txt"
curl -fsSL https://www.cloudflare.com/ips-v6 -o "$TMP/ips-v6.txt"

install -m 0644 "$TMP/ips-v4.txt" "$DIR/ips-v4.txt"
install -m 0644 "$TMP/ips-v6.txt" "$DIR/ips-v6.txt"

apachectl -t
systemctl reload apache2
EOF
  chmod 0755 "$CF_UPDATER"

  # Weekly cron (Sunday 04:10)
  cat > "$CF_CRON" << EOF
# Managed by pow-shield-php installer
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
10 4 * * 0 root $CF_UPDATER >/dev/null 2>&1
EOF
  chmod 0644 "$CF_CRON"

  log_success "Cloudflare real-IP restore configured"
}

install_pow_secret() {
  log_info "Setting up PoW secret..."
  install -d -m 0755 /etc/apache2

  local rotate_script="$SCRIPT_DIR/scripts/rotate-pow-secret.sh.example"
  if [[ ! -f "$rotate_script" ]]; then
    rotate_script="$SCRIPT_DIR/scripts/rotate-pow-secret.sh"
  fi

  if [[ -f "$rotate_script" ]]; then
    log_info "Installing secret rotation script..."
    install -m 0755 "$rotate_script" /usr/local/sbin/rotate-pow-secret.sh
    log_info "Generating initial secret..."
    /usr/local/sbin/rotate-pow-secret.sh
    log_success "Initial secret generated via rotation script"
  else
    log_info "Rotation script not found, creating secret manually..."
    bash -c 'umask 077; SECRET="$(openssl rand -base64 64 | tr -d "\n")"; \
      printf "%s\n" "# Managed by pow-shield-php" "SetEnv AB_POW_SECRET \"$SECRET\"" \
      > /etc/apache2/pow.env'
    chown root:root /etc/apache2/pow.env
    chmod 600 /etc/apache2/pow.env
    log_success "Initial secret created manually"
  fi

  log_success "PoW secret configured at /etc/apache2/pow.env"
}

deploy_pow_endpoints() {
  log_info "Deploying PoW endpoints to $WEBROOT..."

  mkdir -p "$WEBROOT"
  mkdir -p "$WEBROOT/__ab"

  if [[ -f "$SCRIPT_DIR/__ab/pow.php" ]]; then
    cp "$SCRIPT_DIR/__ab/pow.php" "$WEBROOT/__ab/"
    log_success "Copied pow.php"
  else
    log_error "pow.php not found in $SCRIPT_DIR/__ab/"
    exit 1
  fi

  if [[ -f "$SCRIPT_DIR/__ab/pow-verify.php" ]]; then
    cp "$SCRIPT_DIR/__ab/pow-verify.php" "$WEBROOT/__ab/"
    log_success "Copied pow-verify.php"
  else
    log_error "pow-verify.php not found in $SCRIPT_DIR/__ab/"
    exit 1
  fi

  # Optional tier file (if your repo includes it)
  if [[ -f "$SCRIPT_DIR/__ab/pow_tier.php" ]]; then
    cp "$SCRIPT_DIR/__ab/pow_tier.php" "$WEBROOT/__ab/"
    log_success "Copied pow_tier.php (tier support)"
  else
    log_warn "pow_tier.php not found in repo (__ab/). Tiering requires updated PoW PHP files."
  fi

  chown -R www-data:www-data "$WEBROOT/__ab"
  chmod 755 "$WEBROOT/__ab"
  chmod 644 "$WEBROOT/__ab"/*.php

  log_success "PoW endpoints deployed"
}

deploy_assets() {
  log_info "Deploying assets..."

  if [[ -d "$SCRIPT_DIR/assets" ]]; then
    mkdir -p "$WEBROOT/assets"
    cp -r "$SCRIPT_DIR/assets/"* "$WEBROOT/assets/" 2>/dev/null || true
    chown -R www-data:www-data "$WEBROOT/assets" 2>/dev/null || true
    log_success "Assets deployed"
  else
    log_warn "Assets directory not found, skipping..."
  fi
}

enable_apache_modules() {
  log_info "Enabling required Apache modules..."
  local modules=(rewrite headers ssl)
  for mod in "${modules[@]}"; do
    if ! apachectl -M 2>/dev/null | grep -q "${mod}_module"; then
      a2enmod "$mod" >/dev/null 2>&1
      log_success "Enabled module: $mod"
    fi
  done
}

configure_vhost() {
  log_info "Configuring Apache virtual hosts..."
  if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
    configure_default_vhost
  else
    configure_domain_vhost
  fi
}

pow_rewrite_block() {
  # This is emitted into vhosts. No leading "/" in RewriteRule patterns (vhost context).
  cat << 'EOF'
    RewriteEngine On

    # ---- 0) Always skip ACME challenge (Let's Encrypt) ----
    RewriteRule ^\.well-known/acme-challenge/ - [L]

    # ---- 1) Always skip /status/ (optional: comment this out if you want PoW on /status/) ----
    RewriteRule ^status/ - [L]

    # ---- 2) Always skip your GitHub API proxy path (example) ----
    RewriteRule ^api/github/users/AfterPacket/repos - [L]

    # ---- 3) Skip anti-bot endpoints themselves ----
    RewriteRule ^__ab/ - [L]

    # ---- 4) Only gate GET/HEAD (never gate POST; verify must work) ----
    RewriteCond %{REQUEST_METHOD} !^(GET|HEAD)$ [NC]
    RewriteRule ^ - [L]

    # ---- 5) Skip common static assets ----
    RewriteRule \.(?:css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|map)$ - [L,NC]

    # ---- 6) If missing abp cookie, internally serve PoW while keeping original URL ----
    # v2 cookie format: abp=v2.<b64url_payload>.<b64url_sig>
    RewriteCond %{HTTP:Cookie} !(^|;\s*)abp=v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(;|$) [NC]
    RewriteRule ^ /__ab/pow.php?next=%{REQUEST_URI}&qs=%{QUERY_STRING} [PT,L,NE]
EOF
}

configure_default_vhost() {
  log_info "Configuring default Apache vhost..."

  local default_vhost="/etc/apache2/sites-available/000-default.conf"
  local default_ssl_vhost="/etc/apache2/sites-available/default-ssl.conf"

  if [[ -f "$default_vhost" ]]; then
    local backup="$default_vhost.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$default_vhost" "$backup"
    log_info "Backed up default vhost to: $backup"
  fi

  log_info "Updating default HTTP vhost..."
  cat > "$default_vhost" << EOF
<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot $WEBROOT

  # Include PoW secret
  IncludeOptional /etc/apache2/pow.env

$(pow_rewrite_block)

  <Directory $WEBROOT>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>

  <Directory $WEBROOT/__ab>
    Options -Indexes
    AllowOverride None
    Require all granted
  </Directory>

  # Security Headers
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"

  ErrorLog \${APACHE_LOG_DIR}/error.log
  CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
  log_success "Updated default HTTP vhost"

  if [[ -n "$SSL_CERT" ]] && [[ -n "$SSL_KEY" ]]; then
    log_info "Creating default SSL vhost..."
    cat > "$default_ssl_vhost" << EOF
<IfModule mod_ssl.c>
  <VirtualHost _default_:443>
    ServerAdmin webmaster@localhost
    DocumentRoot $WEBROOT

    SSLEngine on
    SSLCertificateFile $SSL_CERT
    SSLCertificateKeyFile $SSL_KEY

    # Include PoW secret
    IncludeOptional /etc/apache2/pow.env

$(pow_rewrite_block)

    <Directory $WEBROOT>
      Options -Indexes +FollowSymLinks
      AllowOverride All
      Require all granted
    </Directory>

    <Directory $WEBROOT/__ab>
      Options -Indexes
      AllowOverride None
      Require all granted
    </Directory>

    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
  </VirtualHost>
</IfModule>
EOF
    a2ensite default-ssl.conf >/dev/null 2>&1 || true
    log_success "Created and enabled default SSL vhost"
  else
    log_info "No SSL configured for default vhost"
  fi
}

configure_domain_vhost() {
  local vhost_dir="/etc/apache2/sites-available"
  local vhost_ssl="$vhost_dir/$DOMAIN.conf"
  local vhost_redirect="$vhost_dir/$DOMAIN-redirect.conf"

  if [[ -f "$vhost_ssl" ]]; then
    log_warn "Existing vhost found: $vhost_ssl"
    local backup="$vhost_ssl.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$vhost_ssl" "$backup"
    log_info "Backed up to: $backup"
  fi

  log_info "Creating HTTP redirect vhost..."
  cat > "$vhost_redirect" << EOF
<VirtualHost *:80>
  ServerName $DOMAIN
  ServerAlias www.$DOMAIN

  RewriteEngine On
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

  ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-redirect-error.log
  CustomLog \${APACHE_LOG_DIR}/$DOMAIN-redirect-access.log combined
</VirtualHost>
EOF
  log_success "Created: $vhost_redirect"

  log_info "Creating HTTPS vhost..."

  local ssl_config=""
  if [[ -n "$SSL_CERT" ]] && [[ -n "$SSL_KEY" ]]; then
    ssl_config="    SSLCertificateFile $SSL_CERT
    SSLCertificateKeyFile $SSL_KEY"
    log_info "Using SSL certificates"
  else
    ssl_config="    # SSL certificates not configured
    # SSLCertificateFile /path/to/cert.pem
    # SSLCertificateKeyFile /path/to/key.pem"
    log_warn "SSL certificates not provided - you'll need to configure them manually"
  fi

  cat > "$vhost_ssl" << EOF
<VirtualHost *:443>
  ServerName $DOMAIN
  ServerAlias www.$DOMAIN
  DocumentRoot $WEBROOT

  SSLEngine on
$ssl_config

  # Include PoW secret
  IncludeOptional /etc/apache2/pow.env

$(pow_rewrite_block)

  <Directory $WEBROOT>
    Options -Indexes +FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>

  <Directory $WEBROOT/__ab>
    Options -Indexes
    AllowOverride None
    Require all granted
  </Directory>

  # Security Headers
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"

  ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
  CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
</VirtualHost>
EOF
  log_success "Created: $vhost_ssl"
}

install_modsecurity() {
  if [[ "$SKIP_MODSEC" = "yes" ]]; then
    log_info "Skipping ModSecurity installation"
    return
  fi

  log_info "Installing ModSecurity..."

  if apachectl -M 2>/dev/null | grep -q security2_module; then
    log_success "ModSecurity already installed"
  else
    apt-get update
    apt-get install -y libapache2-mod-security2
    a2enmod security2 >/dev/null 2>&1
    log_success "ModSecurity installed"
  fi

  local modsec_conf="/etc/modsecurity/modsecurity.conf"
  if [[ -f "$modsec_conf" ]]; then
    if grep -q "SecRuleEngine DetectionOnly" "$modsec_conf"; then
      log_info "Enabling ModSecurity engine..."
      sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$modsec_conf"
    fi
  fi

  if [[ -f "$SCRIPT_DIR/modsecurity/ab_pow_ratelimit.conf" ]]; then
    log_info "Installing PoW rate limit rules..."
    mkdir -p /etc/modsecurity
    cp "$SCRIPT_DIR/modsecurity/ab_pow_ratelimit.conf" /etc/modsecurity/ab_pow_ratelimit.conf
    chmod 0644 /etc/modsecurity/ab_pow_ratelimit.conf

    # Ensure the rules are actually included by Apache
    local sec2_conf="/etc/apache2/mods-enabled/security2.conf"
    if [[ -f "$sec2_conf" ]]; then
      if ! grep -q "/etc/modsecurity/ab_pow_ratelimit.conf" "$sec2_conf"; then
        echo "" >> "$sec2_conf"
        echo "# pow-shield-php: PoW endpoint rate limiting" >> "$sec2_conf"
        echo "IncludeOptional /etc/modsecurity/ab_pow_ratelimit.conf" >> "$sec2_conf"
      fi
    else
      # fallback include point
      local sec2_avail="/etc/apache2/mods-available/security2.conf"
      if [[ -f "$sec2_avail" ]] && ! grep -q "/etc/modsecurity/ab_pow_ratelimit.conf" "$sec2_avail"; then
        echo "" >> "$sec2_avail"
        echo "# pow-shield-php: PoW endpoint rate limiting" >> "$sec2_avail"
        echo "IncludeOptional /etc/modsecurity/ab_pow_ratelimit.conf" >> "$sec2_avail"
      fi
    fi

    log_success "Rate limit rules installed + included"
  else
    log_warn "Rate limit rules not found, skipping..."
  fi
}

install_systemd_rotation() {
  log_info "Installing systemd secret rotation..."

  local service_file="$SCRIPT_DIR/systemd/rotate-pow-secret.service.example"
  local timer_file="$SCRIPT_DIR/systemd/rotate-pow-secret.timer.example"

  if [[ ! -f "$service_file" ]]; then
    service_file="$SCRIPT_DIR/systemd/rotate-pow-secret.service"
  fi
  if [[ ! -f "$timer_file" ]]; then
    timer_file="$SCRIPT_DIR/systemd/rotate-pow-secret.timer"
  fi

  if [[ ! -f "$service_file" ]] || [[ ! -f "$timer_file" ]]; then
    log_warn "Systemd files not found, skipping rotation setup"
    return
  fi

  cp "$service_file" /etc/systemd/system/rotate-pow-secret.service
  cp "$timer_file" /etc/systemd/system/rotate-pow-secret.timer

  systemctl daemon-reload
  systemctl enable rotate-pow-secret.timer >/dev/null 2>&1
  systemctl start rotate-pow-secret.timer

  log_success "Systemd rotation configured and enabled"
}

test_apache_config() {
  log_info "Testing Apache configuration..."
  if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
    log_success "Apache configuration is valid"
    return 0
  else
    log_error "Apache configuration test failed!"
    apachectl configtest || true
    return 1
  fi
}

enable_site() {
  if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
    log_info "Using default vhost (already enabled)"
    return
  fi

  if [[ "$ENABLE_SITE" != "yes" ]]; then
    log_info "Site not enabled (use a2ensite manually when ready)"
    return
  fi

  log_info "Enabling site configuration..."
  a2ensite "$DOMAIN-redirect.conf" >/dev/null 2>&1
  a2ensite "$DOMAIN.conf" >/dev/null 2>&1
  log_success "Site enabled"
}

reload_apache() {
  log_info "Reloading Apache..."
  if systemctl reload apache2; then
    log_success "Apache reloaded successfully"
  else
    log_error "Failed to reload Apache"
    log_info "Check: systemctl status apache2"
    exit 1
  fi
}

show_completion() {
  echo ""
  log_success "Installation completed successfully!"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Next Steps:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  if [[ "$CLOUDFLARE_REALIP" == "yes" ]]; then
    echo "☁️  Cloudflare real IP restore enabled (mod_remoteip)"
    echo "   IP lists: $CF_IP_DIR/ips-v4.txt and ips-v6.txt"
    echo "   Updater:  $CF_UPDATER (weekly cron)"
    echo ""
  fi

  echo "🔐 Secret location:"
  echo "   /etc/apache2/pow.env"
  echo ""

  if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
    echo "🌐 Access your site at:"
    echo "   http://YOUR_SERVER_IP"
    if [[ -n "$SSL_CERT" ]]; then
      echo "   https://YOUR_SERVER_IP"
    fi
    echo ""
    echo "🔍 Test PoW endpoint:"
    echo "   curl -I http://YOUR_SERVER_IP/__ab/pow.php"
  else
    if [[ "$USE_LETSENCRYPT" = "yes" ]]; then
      echo "✅ Let's Encrypt SSL configured automatically"
      echo ""
    elif [[ -z "$SSL_CERT" ]]; then
      echo "⚠️  Configure SSL certificates in:"
      echo "   /etc/apache2/sites-available/$DOMAIN.conf"
      echo ""
      echo "   Or run: certbot --apache -d $DOMAIN"
      echo ""
    fi

    if [[ "$ENABLE_SITE" != "yes" ]]; then
      echo "📝 Enable the site when ready:"
      echo "   sudo a2ensite $DOMAIN-redirect.conf"
      echo "   sudo a2ensite $DOMAIN.conf"
      echo "   sudo systemctl reload apache2"
      echo ""
    fi

    echo "🔍 Test PoW endpoint:"
    echo "   curl -I https://$DOMAIN/__ab/pow.php"
    echo ""
    echo "📊 Check logs:"
    echo "   tail -f /var/log/apache2/$DOMAIN-error.log"
  fi

  echo ""
  echo "🔄 Secret rotation:"
  echo "   systemctl status rotate-pow-secret.timer"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

main() {
  show_banner
  check_root
  parse_args "$@"
  check_dependencies
  prompt_config
  show_config_summary

  log_info "Starting installation..."
  echo ""

  install_certbot
  obtain_letsencrypt_cert

  enable_apache_modules
  setup_cloudflare_realip

  install_pow_secret
  deploy_pow_endpoints
  deploy_assets

  configure_vhost
  install_modsecurity
  install_systemd_rotation

  if ! test_apache_config; then
    log_error "Apache configuration test failed. Fix errors before proceeding."
    exit 1
  fi

  enable_site
  reload_apache
  show_completion
}

main "$@"
