#!/bin/bash
#
# pow-shield-php Installation Script
# https://github.com/AfterPacket/pow-shield-php
#
# This script automates the installation and configuration of pow-shield-php
# with interactive prompts and safe deployment options.
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
INTERACTIVE=1

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

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
    -d, --domain DOMAIN         Domain name (e.g., example.com)
    -w, --webroot PATH          Web root directory path
    -c, --cert PATH             SSL certificate path (optional)
    -k, --key PATH              SSL key path (optional)
    -e, --enable                Enable site with a2ensite after install
    -s, --skip-modsec           Skip ModSecurity installation
    -n, --non-interactive       Run without prompts (requires all flags)
    -h, --help                  Show this help message

EXAMPLES:
    # Interactive mode (recommended)
    sudo ./install.sh

    # Non-interactive with existing SSL
    sudo ./install.sh -d example.com -w /var/www/html -c /path/to/cert.pem -k /path/to/key.pem -e

    # Non-interactive without SSL (will be configured for HTTP redirect only)
    sudo ./install.sh -d example.com -w /var/www/html -n

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
    
    for cmd in apache2 apachectl php openssl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: apt-get install apache2 php openssl"
        exit 1
    fi
    
    log_success "All dependencies found"
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
            -e|--enable)
                ENABLE_SITE="yes"
                shift
                ;;
            -s|--skip-modsec)
                SKIP_MODSEC="yes"
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
        # Validate required parameters in non-interactive mode
        if [[ -z "$DOMAIN" ]] || [[ -z "$WEBROOT" ]]; then
            log_error "Non-interactive mode requires --domain and --webroot"
            usage
            exit 1
        fi
        return
    fi
    
    echo ""
    log_info "Starting interactive configuration..."
    echo ""
    
    # Domain
    if [[ -z "$DOMAIN" ]]; then
        read -p "Enter your domain name (e.g., example.com): " DOMAIN
    fi
    
    # Webroot
    if [[ -z "$WEBROOT" ]]; then
        read -p "Enter web root path [/var/www/html]: " WEBROOT
        WEBROOT=${WEBROOT:-/var/www/html}
    fi
    
    # SSL Certificate
    echo ""
    log_info "SSL Configuration"
    read -p "Do you have existing SSL certificates? (y/n) [n]: " has_ssl
    has_ssl=${has_ssl:-n}
    
    if [[ "$has_ssl" =~ ^[Yy]$ ]]; then
        read -p "Enter SSL certificate path: " SSL_CERT
        read -p "Enter SSL key path: " SSL_KEY
        
        # Validate SSL files
        if [[ ! -f "$SSL_CERT" ]]; then
            log_warn "Certificate file not found: $SSL_CERT"
            SSL_CERT=""
            SSL_KEY=""
        elif [[ ! -f "$SSL_KEY" ]]; then
            log_warn "Key file not found: $SSL_KEY"
            SSL_CERT=""
            SSL_KEY=""
        fi
    fi
    
    # Enable site
    echo ""
    read -p "Enable site with a2ensite after installation? (y/n) [n]: " enable_choice
    if [[ "$enable_choice" =~ ^[Yy]$ ]]; then
        ENABLE_SITE="yes"
    fi
    
    # ModSecurity
    echo ""
    read -p "Install/configure ModSecurity? (y/n) [y]: " modsec_choice
    modsec_choice=${modsec_choice:-y}
    if [[ ! "$modsec_choice" =~ ^[Yy]$ ]]; then
        SKIP_MODSEC="yes"
    fi
}

show_config_summary() {
    echo ""
    log_info "Configuration Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Domain:           $DOMAIN"
    echo "Web Root:         $WEBROOT"
    echo "SSL Certificate:  ${SSL_CERT:-Not configured}"
    echo "SSL Key:          ${SSL_KEY:-Not configured}"
    echo "Enable Site:      $ENABLE_SITE"
    echo "Install ModSec:   $([ "$SKIP_MODSEC" = "yes" ] && echo "no" || echo "yes")"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if [[ $INTERACTIVE -eq 1 ]]; then
        read -p "Proceed with installation? (y/n) [y]: " proceed
        proceed=${proceed:-y}
        if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled"
            exit 0
        fi
    fi
}

install_pow_secret() {
    log_info "Setting up PoW secret..."
    
    # Create pow.env directory
    install -d -m 0755 /etc/apache2
    
    # Check if rotate script exists
    if [[ -f "$SCRIPT_DIR/scripts/rotate-pow-secret.sh.example" ]]; then
        log_info "Installing secret rotation script..."
        
        # Install rotation script
        install -m 0755 "$SCRIPT_DIR/scripts/rotate-pow-secret.sh.example" \
            /usr/local/sbin/rotate-pow-secret.sh
        
        # Run it to generate initial secret
        log_info "Generating initial secret..."
        /usr/local/sbin/rotate-pow-secret.sh
        
        log_success "Initial secret generated via rotation script"
    else
        # Fallback: create secret manually
        log_info "Rotation script not found, creating secret manually..."
        
        bash -c 'umask 077; SECRET="$(openssl rand -base64 64 | tr -d "\n")"; \
            printf "%s\n" "# Managed by pow-shield-php" "SetEnv AB_POW_SECRET \"$SECRET\"" \
            > /etc/apache2/pow.env'
        
        chown root:root /etc/apache2/pow.env
        chmod 600 /etc/apache2/pow.env
    fi
    
    log_success "PoW secret configured at /etc/apache2/pow.env"
}

deploy_pow_endpoints() {
    log_info "Deploying PoW endpoints to $WEBROOT..."
    
    # Create __ab directory
    mkdir -p "$WEBROOT/__ab"
    
    # Copy PoW files
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
    
    # Set permissions
    chown -R www-data:www-data "$WEBROOT/__ab"
    chmod 755 "$WEBROOT/__ab"
    chmod 644 "$WEBROOT/__ab"/*.php
    
    log_success "PoW endpoints deployed"
}

deploy_assets() {
    log_info "Deploying assets..."
    
    if [[ -d "$SCRIPT_DIR/assets" ]]; then
        mkdir -p "$WEBROOT/assets"
        cp -r "$SCRIPT_DIR/assets/"* "$WEBROOT/assets/"
        chown -R www-data:www-data "$WEBROOT/assets"
        log_success "Assets deployed"
    else
        log_warn "Assets directory not found, skipping..."
    fi
}

configure_vhost() {
    log_info "Configuring Apache virtual hosts..."
    
    local vhost_dir="/etc/apache2/sites-available"
    local vhost_ssl="$vhost_dir/$DOMAIN.conf"
    local vhost_redirect="$vhost_dir/$DOMAIN-redirect.conf"
    
    # Backup existing configs
    if [[ -f "$vhost_ssl" ]]; then
        log_warn "Existing vhost found: $vhost_ssl"
        local backup="$vhost_ssl.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$vhost_ssl" "$backup"
        log_info "Backed up to: $backup"
    fi
    
    # Create HTTP redirect vhost
    log_info "Creating HTTP redirect vhost..."
    cat > "$vhost_redirect" << EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    
    # Redirect all HTTP to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
    
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-redirect-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-redirect-access.log combined
</VirtualHost>
EOF
    
    log_success "Created: $vhost_redirect"
    
    # Create HTTPS vhost
    log_info "Creating HTTPS vhost..."
    
    # Determine SSL configuration
    local ssl_config=""
    if [[ -n "$SSL_CERT" ]] && [[ -n "$SSL_KEY" ]]; then
        ssl_config="    SSLCertificateFile $SSL_CERT
    SSLCertificateKeyFile $SSL_KEY"
        log_info "Using existing SSL certificates"
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
    
    # SSL Configuration
    SSLEngine on
$ssl_config
    
    # Include PoW secret
    IncludeOptional /etc/apache2/pow.env
    
    # PoW Protection Rules
    # Skip PoW for static assets and specific paths
    RewriteEngine On
    
    # Skip __ab endpoints (prevents loops)
    RewriteCond %{REQUEST_URI} !^/__ab/
    
    # Skip static assets
    RewriteCond %{REQUEST_URI} !\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|map|pdf|zip|txt|xml)$ [NC]
    
    # Only apply to GET/HEAD requests
    RewriteCond %{REQUEST_METHOD} ^(GET|HEAD)$
    
    # Check for abp cookie
    RewriteCond %{HTTP_COOKIE} !abp= [NC]
    
    # Redirect to PoW challenge
    RewriteRule ^(.*)$ /__ab/pow.php?next=\$1&qs=%{QUERY_STRING} [L,R=302]
    
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
    Header always set X-XSS-Protection "1; mode=block"
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
    
    # Check if already installed
    if apachectl -M 2>/dev/null | grep -q security; then
        log_success "ModSecurity already installed"
    else
        apt-get update
        apt-get install -y libapache2-mod-security2
        a2enmod security2
        log_success "ModSecurity installed"
    fi
    
    # Configure ModSecurity
    local modsec_conf="/etc/modsecurity/modsecurity.conf"
    if [[ -f "$modsec_conf" ]]; then
        if ! grep -q "SecRuleEngine On" "$modsec_conf"; then
            log_info "Enabling ModSecurity engine..."
            sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$modsec_conf"
        fi
    fi
    
    # Install PoW rate limit rules
    if [[ -f "$SCRIPT_DIR/modsecurity/ab_pow_ratelimit.conf" ]]; then
        log_info "Installing PoW rate limit rules..."
        mkdir -p /etc/modsecurity
        cp "$SCRIPT_DIR/modsecurity/ab_pow_ratelimit.conf" \
            /etc/modsecurity/ab_pow_ratelimit.conf
        log_success "Rate limit rules installed"
    else
        log_warn "Rate limit rules not found, skipping..."
    fi
}

install_systemd_rotation() {
    log_info "Installing systemd secret rotation..."
    
    # Check if systemd files exist
    if [[ ! -f "$SCRIPT_DIR/systemd/rotate-pow-secret.service.example" ]]; then
        log_warn "Systemd files not found, skipping rotation setup"
        return
    fi
    
    # Install service
    cp "$SCRIPT_DIR/systemd/rotate-pow-secret.service.example" \
        /etc/systemd/system/rotate-pow-secret.service
    
    # Install timer
    cp "$SCRIPT_DIR/systemd/rotate-pow-secret.timer.example" \
        /etc/systemd/system/rotate-pow-secret.timer
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable timer
    systemctl enable rotate-pow-secret.timer
    systemctl start rotate-pow-secret.timer
    
    log_success "Systemd rotation configured and enabled"
}

enable_apache_modules() {
    log_info "Enabling required Apache modules..."
    
    local modules=(rewrite ssl headers)
    for mod in "${modules[@]}"; do
        if ! apachectl -M 2>/dev/null | grep -q "${mod}_module"; then
            a2enmod "$mod"
            log_success "Enabled module: $mod"
        fi
    done
}

test_apache_config() {
    log_info "Testing Apache configuration..."
    
    if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
        log_success "Apache configuration is valid"
        return 0
    else
        log_error "Apache configuration test failed!"
        apachectl configtest
        return 1
    fi
}

enable_site() {
    if [[ "$ENABLE_SITE" != "yes" ]]; then
        log_info "Site not enabled (use a2ensite manually when ready)"
        return
    fi
    
    log_info "Enabling site configuration..."
    
    # Enable redirect vhost
    a2ensite "$DOMAIN-redirect.conf"
    
    # Enable main vhost
    a2ensite "$DOMAIN.conf"
    
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
    
    if [[ -z "$SSL_CERT" ]]; then
        echo "⚠️  Configure SSL certificates in:"
        echo "   /etc/apache2/sites-available/$DOMAIN.conf"
        echo ""
    fi
    
    if [[ "$ENABLE_SITE" != "yes" ]]; then
        echo "📝 Enable the site when ready:"
        echo "   sudo a2ensite $DOMAIN-redirect.conf"
        echo "   sudo a2ensite $DOMAIN.conf"
        echo "   sudo systemctl reload apache2"
        echo ""
    fi
    
    echo "🔍 Test PoW endpoints:"
    echo "   https://$DOMAIN/__ab/pow.php"
    echo ""
    echo "📊 Check logs:"
    echo "   tail -f /var/log/apache2/$DOMAIN-error.log"
    echo ""
    echo "🔐 Secret location:"
    echo "   /etc/apache2/pow.env"
    echo ""
    echo "🔄 Secret rotation:"
    echo "   systemctl status rotate-pow-secret.timer"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main installation flow
main() {
    show_banner
    check_root
    check_dependencies
    parse_args "$@"
    prompt_config
    show_config_summary
    
    log_info "Starting installation..."
    echo ""
    
    install_pow_secret
    deploy_pow_endpoints
    deploy_assets
    enable_apache_modules
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

# Run main
main "$@"
