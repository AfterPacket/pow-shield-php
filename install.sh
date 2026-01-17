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
USE_LETSENCRYPT="no"
LETSENCRYPT_EMAIL=""
USE_DEFAULT_VHOST="no"
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
    -d, --domain DOMAIN         Domain name (e.g., example.com) [optional]
    -w, --webroot PATH          Web root directory path
    -c, --cert PATH             SSL certificate path (optional)
    -k, --key PATH              SSL key path (optional)
    -l, --letsencrypt EMAIL     Use Let's Encrypt with email
    -e, --enable                Enable site with a2ensite after install
    -s, --skip-modsec           Skip ModSecurity installation
    --default-vhost             Install to default Apache vhost (no domain needed)
    -n, --non-interactive       Run without prompts (requires all flags)
    -h, --help                  Show this help message

EXAMPLES:
    # Interactive mode (recommended)
    sudo ./install.sh

    # Install to default vhost (VPS with IP only)
    sudo ./install.sh --default-vhost -w /var/www/html

    # Non-interactive with existing SSL
    sudo ./install.sh -d example.com -w /var/www/html -c /path/to/cert.pem -k /path/to/key.pem -e

    # Non-interactive with Let's Encrypt
    sudo ./install.sh -d example.com -w /var/www/html -l admin@example.com -e

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
    local pkg_deps=()
    
    # Check for commands and map to packages
    if ! command -v apache2 &> /dev/null; then
        missing_deps+=("apache2")
        pkg_deps+=("apache2")
    fi
    
    if ! command -v php &> /dev/null; then
        missing_deps+=("php")
        pkg_deps+=("php" "libapache2-mod-php")
    fi
    
    if ! command -v openssl &> /dev/null; then
        missing_deps+=("openssl")
        pkg_deps+=("openssl")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_warn "Missing dependencies: ${missing_deps[*]}"
        
        if [[ $INTERACTIVE -eq 1 ]]; then
            read -p "Install missing dependencies now? (y/n) [y]: " install_deps
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
    
    # Ask about default vhost first
    if [[ -z "$DOMAIN" ]]; then
        echo "You can install pow-shield-php to:"
        echo "  1) A specific domain (requires domain name)"
        echo "  2) Default Apache vhost (for VPS IP access)"
        echo ""
        read -p "Choose installation type (1/2) [2]: " install_type
        install_type=${install_type:-2}
        
        if [[ "$install_type" == "2" ]]; then
            USE_DEFAULT_VHOST="yes"
            log_info "Using default Apache vhost (IP-based access)"
        else
            # Domain
            while [[ -z "$DOMAIN" ]]; do
                read -p "Enter your domain name (e.g., example.com): " DOMAIN
                if [[ -z "$DOMAIN" ]]; then
                    log_error "Domain cannot be empty"
                fi
            done
        fi
    fi
    
    # Webroot
    if [[ -z "$WEBROOT" ]]; then
        if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
            read -p "Enter web root path [/var/www/html]: " WEBROOT
            WEBROOT=${WEBROOT:-/var/www/html}
        else
            read -p "Enter web root path [/var/www/html]: " WEBROOT
            WEBROOT=${WEBROOT:-/var/www/html}
        fi
    fi
    
    # SSL Configuration (skip for default vhost unless they want it)
    if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
        echo ""
        log_info "SSL Configuration"
        echo "Note: Default vhost typically doesn't need SSL for IP access"
        read -p "Do you want to configure SSL anyway? (y/n) [n]: " want_ssl
        want_ssl=${want_ssl:-n}
        
        if [[ ! "$want_ssl" =~ ^[Yy]$ ]]; then
            log_info "Skipping SSL configuration for default vhost"
        else
            prompt_ssl_config
        fi
    else
        echo ""
        log_info "SSL Configuration"
        prompt_ssl_config
    fi
    
    # Enable site (not needed for default vhost)
    echo ""
    if [[ "$USE_DEFAULT_VHOST" != "yes" ]]; then
        read -p "Enable site with a2ensite after installation? (y/n) [n]: " enable_choice
        if [[ "$enable_choice" =~ ^[Yy]$ ]]; then
            ENABLE_SITE="yes"
        fi
    else
        log_info "Using default vhost (no need to enable with a2ensite)"
        ENABLE_SITE="no"
    fi
    
    # ModSecurity
    echo ""
    read -p "Install/configure ModSecurity? (y/n) [y]: " modsec_choice
    modsec_choice=${modsec_choice:-y}
    if [[ ! "$modsec_choice" =~ ^[Yy]$ ]]; then
        SKIP_MODSEC="yes"
    fi
}

prompt_ssl_config() {
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
    else
        # Offer Let's Encrypt only if we have a domain
        if [[ -n "$DOMAIN" ]]; then
            echo ""
            read -p "Would you like to use Let's Encrypt for free SSL? (y/n) [y]: " use_le
            use_le=${use_le:-y}
            
            if [[ "$use_le" =~ ^[Yy]$ ]]; then
                USE_LETSENCRYPT="yes"
                read -p "Enter your email for Let's Encrypt: " LETSENCRYPT_EMAIL
                
                # Validate email
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
        read -p "Proceed with installation? (y/n) [y]: " proceed
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
    
    if ! command -v certbot &> /dev/null; then
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
    
    # Create a temporary vhost for certbot validation
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
    
    # Enable temporary vhost
    a2ensite "$DOMAIN-temp.conf" > /dev/null 2>&1
    systemctl reload apache2
    
    # Run certbot
    if certbot certonly --apache -d "$DOMAIN" -d "www.$DOMAIN" \
        --email "$LETSENCRYPT_EMAIL" \
        --agree-tos \
        --non-interactive \
        --redirect; then
        
        # Set SSL paths
        SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        
        log_success "Let's Encrypt certificate obtained"
    else
        log_error "Failed to obtain Let's Encrypt certificate"
        log_warn "Continuing without SSL..."
        USE_LETSENCRYPT="no"
    fi
    
    # Disable temporary vhost
    a2dissite "$DOMAIN-temp.conf" > /dev/null 2>&1 || true
    rm -f "$temp_vhost"
}

install_pow_secret() {
    log_info "Setting up PoW secret..."
    
    # Create pow.env directory
    install -d -m 0755 /etc/apache2
    
    # Check if rotate script exists
    local rotate_script="$SCRIPT_DIR/scripts/rotate-pow-secret.sh.example"
    if [[ ! -f "$rotate_script" ]]; then
        rotate_script="$SCRIPT_DIR/scripts/rotate-pow-secret.sh"
    fi
    
    if [[ -f "$rotate_script" ]]; then
        log_info "Installing secret rotation script..."
        
        # Install rotation script
        install -m 0755 "$rotate_script" /usr/local/sbin/rotate-pow-secret.sh
        
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
        
        log_success "Initial secret created manually"
    fi
    
    log_success "PoW secret configured at /etc/apache2/pow.env"
}

deploy_pow_endpoints() {
    log_info "Deploying PoW endpoints to $WEBROOT..."
    
    # Ensure webroot exists
    mkdir -p "$WEBROOT"
    
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
        cp -r "$SCRIPT_DIR/assets/"* "$WEBROOT/assets/" 2>/dev/null || true
        chown -R www-data:www-data "$WEBROOT/assets" 2>/dev/null || true
        log_success "Assets deployed"
    else
        log_warn "Assets directory not found, skipping..."
    fi
}

configure_vhost() {
    log_info "Configuring Apache virtual hosts..."
    
    if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
        configure_default_vhost
    else
        configure_domain_vhost
    fi
}

configure_default_vhost() {
    log_info "Configuring default Apache vhost..."
    
    local default_vhost="/etc/apache2/sites-available/000-default.conf"
    local default_ssl_vhost="/etc/apache2/sites-available/default-ssl.conf"
    
    # Backup existing default vhost
    if [[ -f "$default_vhost" ]]; then
        local backup="$default_vhost.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$default_vhost" "$backup"
        log_info "Backed up default vhost to: $backup"
    fi
    
    # Create HTTP default vhost with PoW
    log_info "Updating default HTTP vhost..."
    cat > "$default_vhost" << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $WEBROOT
    
    # Include PoW secret
    IncludeOptional /etc/apache2/pow.env
    
    # PoW Protection Rules
    RewriteEngine On
    
     # ---- 0) Always skip /status/ entirely ----
 #    RewriteRule ^/status/ - [L]

    # ---- 1) Always githup api   entirely ----
    RewriteRule ^/api/github/users/AfterPacket/repos - [L]


    # ---- 2) Skip anti-bot endpoints themselves ----
    RewriteRule ^/__ab/ - [L]

    # ---- 3) Only gate GET/HEAD (never gate POST; verify must work) ----
    RewriteCond %{REQUEST_METHOD} !^(GET|HEAD)$ [NC]
    RewriteRule ^ - [L]

    # ---- 4) Skip common static assets ----
    RewriteRule \.(?:css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|map)$ - [L,NC]

    # ---- 5) If missing abp cookie, internally serve PoW while keeping original URL ----
# v2 cookie format: abp=v2.<b64url_payload>.<b64url_sig>
RewriteCond %{HTTP:Cookie} !(^|;\s*)abp=v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(;|$) [NC]
RewriteRule ^ /__ab/pow.php?next=%{REQUEST_URI}&qs=%{QUERY_STRING} [PT,L,NE]

    
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
    
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
    
    log_success "Updated default HTTP vhost"
    
    # Create SSL vhost if SSL is configured
    if [[ -n "$SSL_CERT" ]] && [[ -n "$SSL_KEY" ]]; then
        log_info "Creating default SSL vhost..."
        
        cat > "$default_ssl_vhost" << EOF
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        ServerAdmin webmaster@localhost
        DocumentRoot $WEBROOT
        
        # SSL Configuration
        SSLEngine on
        SSLCertificateFile $SSL_CERT
        SSLCertificateKeyFile $SSL_KEY
        
        # Include PoW secret
        IncludeOptional /etc/apache2/pow.env
        
        # PoW Protection Rules
        RewriteEngine On
        
         # ---- 0) Always skip /status/ entirely ----
 #    RewriteRule ^/status/ - [L]

    # ---- 1) Always githup api   entirely ----
    RewriteRule ^/api/github/users/AfterPacket/repos - [L]


    # ---- 2) Skip anti-bot endpoints themselves ----
    RewriteRule ^/__ab/ - [L]

    # ---- 3) Only gate GET/HEAD (never gate POST; verify must work) ----
    RewriteCond %{REQUEST_METHOD} !^(GET|HEAD)$ [NC]
    RewriteRule ^ - [L]

    # ---- 4) Skip common static assets ----
    RewriteRule \.(?:css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|map)$ - [L,NC]

    # ---- 5) If missing abp cookie, internally serve PoW while keeping original URL ----
# v2 cookie format: abp=v2.<b64url_payload>.<b64url_sig>
RewriteCond %{HTTP:Cookie} !(^|;\s*)abp=v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(;|$) [NC]
RewriteRule ^ /__ab/pow.php?next=%{REQUEST_URI}&qs=%{QUERY_STRING} [PT,L,NE]

        
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
        
        ErrorLog \${APACHE_LOG_DIR}/error.log
        CustomLog \${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>
</IfModule>
EOF
        
        # Enable SSL site
        a2ensite default-ssl.conf > /dev/null 2>&1
        log_success "Created and enabled default SSL vhost"
    else
        log_info "No SSL configured for default vhost"
    fi
}

configure_domain_vhost() {
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
    
    # SSL Configuration
    SSLEngine on
$ssl_config
    
    # 0) Skip /status/ entirely (no PoW)
  RewriteRule ^status/ - [L]

  
  # 1) Skip the anti-bot endpoints themselves (prevents loops)
  RewriteRule ^__ab/ - [L]

  # 2) Only gate GET/HEAD (never gate POST; verify must work)
  RewriteRule ^ - [L]

  # 3) Skip common static assets
  RewriteRule \.(?:css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|map)$ - [L,NC]

  # 4) If missing PoW pass cookie, internally serve challenge while keeping original URL
  # Expect abp=ts.exp.uaHash.sig
  RewriteCond %{HTTP:Cookie} !(^|;\s*)abp=\d+\.\d+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(;|$) [NC]
  RewriteRule ^ /__ab/pow.php?next=%{REQUEST_URI}&qs=%{QUERY_STRING} [PT,L,NE]
    
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
    local service_file="$SCRIPT_DIR/systemd/rotate-pow-secret.service.example"
    local timer_file="$SCRIPT_DIR/systemd/rotate-pow-secret.timer.example"
    
    # Try without .example extension if not found
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
    
    # Install service
    cp "$service_file" /etc/systemd/system/rotate-pow-secret.service
    
    # Install timer
    cp "$timer_file" /etc/systemd/system/rotate-pow-secret.timer
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable timer
    systemctl enable rotate-pow-secret.timer > /dev/null 2>&1
    systemctl start rotate-pow-secret.timer
    
    log_success "Systemd rotation configured and enabled"
}

enable_apache_modules() {
    log_info "Enabling required Apache modules..."
    
    local modules=(rewrite ssl headers)
    for mod in "${modules[@]}"; do
        if ! apachectl -M 2>/dev/null | grep -q "${mod}_module"; then
            a2enmod "$mod" > /dev/null 2>&1
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
    if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
        log_info "Using default vhost (already enabled)"
        return
    fi
    
    if [[ "$ENABLE_SITE" != "yes" ]]; then
        log_info "Site not enabled (use a2ensite manually when ready)"
        return
    fi
    
    log_info "Enabling site configuration..."
    
    # Enable redirect vhost
    a2ensite "$DOMAIN-redirect.conf" > /dev/null 2>&1
    
    # Enable main vhost
    a2ensite "$DOMAIN.conf" > /dev/null 2>&1
    
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
    
    if [[ "$USE_DEFAULT_VHOST" == "yes" ]]; then
        echo "🌐 Access your site at:"
        echo "   http://YOUR_SERVER_IP"
        if [[ -n "$SSL_CERT" ]]; then
            echo "   https://YOUR_SERVER_IP"
        fi
        echo ""
        echo "🔍 Test PoW endpoint:"
        echo "   curl http://YOUR_SERVER_IP/__ab/pow.php"
    else
        if [[ "$USE_LETSENCRYPT" = "yes" ]]; then
            echo "✅ Let's Encrypt SSL configured automatically"
            echo "   Auto-renewal: certbot renew (runs automatically)"
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
        
        echo "🔍 Test PoW endpoints:"
        echo "   https://$DOMAIN/__ab/pow.php"
        echo ""
        echo "📊 Check logs:"
        echo "   tail -f /var/log/apache2/$DOMAIN-error.log"
    fi
    
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
    
    install_certbot
    obtain_letsencrypt_cert
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
