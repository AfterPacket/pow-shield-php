#!/bin/bash
#
# pow-shield-php Uninstallation Script
# https://github.com/AfterPacket/pow-shield-php
#
# This script removes pow-shield-php configuration and files
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
REMOVE_MODSEC="no"
REMOVE_SECRET="yes"
REMOVE_VHOSTS="yes"
REMOVE_ENDPOINTS="yes"
REMOVE_SYSTEMD="yes"
REMOVE_DEFAULT_VHOST="no"
INTERACTIVE=1
FORCE=0

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
║                pow-shield-php Uninstaller                 ║
║           https://github.com/AfterPacket/pow-shield-php   ║
╚═══════════════════════════════════════════════════════════╝
EOF
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Uninstallation Script for pow-shield-php

OPTIONS:
    -d, --domain DOMAIN         Domain name (e.g., example.com)
    -w, --webroot PATH          Web root directory path
    -m, --remove-modsec         Also remove ModSecurity rules
    -k, --keep-secret           Keep the PoW secret file
    --default-vhost             Restore default Apache vhost
    -f, --force                 Force removal without prompts
    -n, --non-interactive       Run without prompts
    -h, --help                  Show this help message

EXAMPLES:
    # Interactive mode (recommended)
    sudo ./uninstall.sh

    # Remove everything for specific domain
    sudo ./uninstall.sh -d example.com -w /var/www/html

    # Remove from default vhost
    sudo ./uninstall.sh --default-vhost -w /var/www/html

    # Force removal without prompts
    sudo ./uninstall.sh -d example.com -w /var/www/html -f

    # Keep secret file and remove ModSec rules
    sudo ./uninstall.sh -d example.com -w /var/www/html -k -m

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
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
            -m|--remove-modsec)
                REMOVE_MODSEC="yes"
                shift
                ;;
            -k|--keep-secret)
                REMOVE_SECRET="no"
                shift
                ;;
            --default-vhost)
                REMOVE_DEFAULT_VHOST="yes"
                shift
                ;;
            -f|--force)
                FORCE=1
                INTERACTIVE=0
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

detect_config() {
    log_info "Detecting existing configuration..."
    
    # Check if default vhost has PoW
    if grep -q "/__ab/pow.php" /etc/apache2/sites-available/000-default.conf 2>/dev/null; then
        log_info "Found PoW installation in default vhost"
        REMOVE_DEFAULT_VHOST="yes"
        if [[ -z "$WEBROOT" ]]; then
            WEBROOT=$(grep -oP 'DocumentRoot\s+\K\S+' /etc/apache2/sites-available/000-default.conf 2>/dev/null || echo "/var/www/html")
        fi
    fi
    
    # Try to find domain-based vhosts
    if [[ -z "$DOMAIN" ]] && [[ "$REMOVE_DEFAULT_VHOST" != "yes" ]]; then
        log_info "Searching for pow-shield-php installations..."
        
        local found_vhosts=()
        for vhost in /etc/apache2/sites-available/*.conf; do
            if [[ -f "$vhost" ]] && grep -q "/__ab/pow.php" "$vhost" 2>/dev/null; then
                local domain=$(basename "$vhost" .conf)
                domain=${domain%-redirect}
                if [[ "$domain" != "000-default" ]] && [[ "$domain" != "default-ssl" ]]; then
                    found_vhosts+=("$domain")
                fi
            fi
        done
        
        if [[ ${#found_vhosts[@]} -eq 0 ]] && [[ "$REMOVE_DEFAULT_VHOST" != "yes" ]]; then
            log_warn "No pow-shield-php installations found"
            return
        fi
        
        # Remove duplicates
        found_vhosts=($(echo "${found_vhosts[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        
        if [[ ${#found_vhosts[@]} -gt 0 ]]; then
            echo ""
            log_info "Found installations for:"
            for i in "${!found_vhosts[@]}"; do
                echo "  $((i+1))) ${found_vhosts[$i]}"
            done
            echo ""
            
            if [[ $INTERACTIVE -eq 1 ]]; then
                read -p "Select domain to uninstall (1-${#found_vhosts[@]}): " selection
                if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#found_vhosts[@]}" ]; then
                    DOMAIN="${found_vhosts[$((selection-1))]}"
                else
                    log_error "Invalid selection"
                    exit 1
                fi
            fi
        fi
    fi
    
    # Try to detect webroot from vhost
    if [[ -z "$WEBROOT" ]] && [[ -n "$DOMAIN" ]]; then
        local vhost="/etc/apache2/sites-available/$DOMAIN.conf"
        if [[ -f "$vhost" ]]; then
            WEBROOT=$(grep -oP 'DocumentRoot\s+\K\S+' "$vhost" 2>/dev/null || echo "")
        fi
    fi
    
    if [[ -z "$WEBROOT" ]]; then
        WEBROOT="/var/www/html"
    fi
}

prompt_config() {
    if [[ $INTERACTIVE -eq 0 ]] || [[ $FORCE -eq 1 ]]; then
        return
    fi
    
    echo ""
    log_warn "This will remove pow-shield-php configuration and files"
    echo ""
    
    if [[ "$REMOVE_DEFAULT_VHOST" == "yes" ]]; then
        echo "Mode: Removing from default Apache vhost"
    elif [[ -n "$DOMAIN" ]]; then
        echo "Domain: $DOMAIN"
    else
        read -p "Enter domain to uninstall (or press Enter for default vhost): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            REMOVE_DEFAULT_VHOST="yes"
        fi
    fi
    
    echo ""
    read -p "Remove PoW secret file? (y/n) [y]: " remove_secret
    remove_secret=${remove_secret:-y}
    if [[ ! "$remove_secret" =~ ^[Yy]$ ]]; then
        REMOVE_SECRET="no"
    fi
    
    read -p "Remove ModSecurity rules? (y/n) [y]: " remove_modsec
    remove_modsec=${remove_modsec:-y}
    if [[ "$remove_modsec" =~ ^[Yy]$ ]]; then
        REMOVE_MODSEC="yes"
    fi
}

show_uninstall_summary() {
    echo ""
    log_info "Uninstall Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ "$REMOVE_DEFAULT_VHOST" == "yes" ]]; then
        echo "Mode:                 Default vhost restoration"
    else
        echo "Domain:               ${DOMAIN:-Not specified}"
    fi
    
    echo "Web Root:             $WEBROOT"
    echo "Remove Secret:        $REMOVE_SECRET"
    echo "Remove ModSec Rules:  $REMOVE_MODSEC"
    echo "Remove Vhosts:        $REMOVE_VHOSTS"
    echo "Remove Endpoints:     $REMOVE_ENDPOINTS"
    echo "Remove Systemd:       $REMOVE_SYSTEMD"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if [[ $INTERACTIVE -eq 1 ]] && [[ $FORCE -eq 0 ]]; then
        read -p "Proceed with uninstallation? (y/n) [n]: " proceed
        proceed=${proceed:-n}
        if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
            log_info "Uninstallation cancelled"
            exit 0
        fi
    fi
}

restore_default_vhost() {
    if [[ "$REMOVE_DEFAULT_VHOST" != "yes" ]]; then
        return
    fi
    
    log_info "Restoring default Apache vhost..."
    
    local default_vhost="/etc/apache2/sites-available/000-default.conf"
    local default_ssl_vhost="/etc/apache2/sites-available/default-ssl.conf"
    
    # Backup current version
    if [[ -f "$default_vhost" ]]; then
        local backup="$default_vhost.removed.$(date +%Y%m%d_%H%M%S)"
        cp "$default_vhost" "$backup"
        log_info "Backed up modified vhost to: $backup"
    fi
    
    # Create clean default vhost
    cat > "$default_vhost" << 'EOF'
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
    
    log_success "Default vhost restored"
    
    # Remove default-ssl if it was created by installer
    if [[ -f "$default_ssl_vhost" ]] && grep -q "pow-shield-php" "$default_ssl_vhost" 2>/dev/null; then
        local backup="$default_ssl_vhost.removed.$(date +%Y%m%d_%H%M%S)"
        mv "$default_ssl_vhost" "$backup"
        a2dissite default-ssl.conf > /dev/null 2>&1 || true
        log_success "Removed default SSL vhost"
    fi
}

disable_and_remove_vhosts() {
    if [[ "$REMOVE_VHOSTS" != "yes" ]] || [[ -z "$DOMAIN" ]]; then
        return
    fi
    
    log_info "Removing Apache virtual hosts..."
    
    local vhost_ssl="/etc/apache2/sites-available/$DOMAIN.conf"
    local vhost_redirect="/etc/apache2/sites-available/$DOMAIN-redirect.conf"
    
    # Disable sites
    if [[ -f "$vhost_ssl" ]]; then
        a2dissite "$DOMAIN.conf" > /dev/null 2>&1 || true
        
        # Backup before removing
        local backup="$vhost_ssl.removed.$(date +%Y%m%d_%H%M%S)"
        mv "$vhost_ssl" "$backup"
        log_success "Backed up and removed: $vhost_ssl"
        log_info "Backup saved to: $backup"
    fi
    
    if [[ -f "$vhost_redirect" ]]; then
        a2dissite "$DOMAIN-redirect.conf" > /dev/null 2>&1 || true
        
        local backup="$vhost_redirect.removed.$(date +%Y%m%d_%H%M%S)"
        mv "$vhost_redirect" "$backup"
        log_success "Backed up and removed: $vhost_redirect"
    fi
}

remove_pow_endpoints() {
    if [[ "$REMOVE_ENDPOINTS" != "yes" ]]; then
        return
    fi
    
    log_info "Removing PoW endpoints..."
    
    if [[ -d "$WEBROOT/__ab" ]]; then
        # Backup before removing
        local backup="/tmp/__ab.backup.$(date +%Y%m%d_%H%M%S)"
        mv "$WEBROOT/__ab" "$backup"
        log_success "Backed up and removed: $WEBROOT/__ab"
        log_info "Backup saved to: $backup"
    else
        log_warn "PoW endpoints not found at: $WEBROOT/__ab"
    fi
}

remove_secret() {
    if [[ "$REMOVE_SECRET" != "yes" ]]; then
        log_info "Keeping PoW secret file"
        return
    fi
    
    log_info "Removing PoW secret..."
    
    if [[ -f "/etc/apache2/pow.env" ]]; then
        # Backup before removing
        local backup="/etc/apache2/pow.env.removed.$(date +%Y%m%d_%H%M%S)"
        mv /etc/apache2/pow.env "$backup"
        log_success "Backed up and removed: /etc/apache2/pow.env"
        log_info "Backup saved to: $backup"
    else
        log_warn "PoW secret file not found"
    fi
}

remove_systemd_rotation() {
    if [[ "$REMOVE_SYSTEMD" != "yes" ]]; then
        return
    fi
    
    log_info "Removing systemd rotation..."
    
    # Stop and disable timer
    if systemctl is-active --quiet rotate-pow-secret.timer 2>/dev/null; then
        systemctl stop rotate-pow-secret.timer
        log_success "Stopped timer"
    fi
    
    if systemctl is-enabled --quiet rotate-pow-secret.timer 2>/dev/null; then
        systemctl disable rotate-pow-secret.timer > /dev/null 2>&1
        log_success "Disabled timer"
    fi
    
    # Remove systemd files
    if [[ -f "/etc/systemd/system/rotate-pow-secret.service" ]]; then
        rm -f /etc/systemd/system/rotate-pow-secret.service
        log_success "Removed systemd service"
    fi
    
    if [[ -f "/etc/systemd/system/rotate-pow-secret.timer" ]]; then
        rm -f /etc/systemd/system/rotate-pow-secret.timer
        log_success "Removed systemd timer"
    fi
    
    # Remove rotation script
    if [[ -f "/usr/local/sbin/rotate-pow-secret.sh" ]]; then
        rm -f /usr/local/sbin/rotate-pow-secret.sh
        log_success "Removed rotation script"
    fi
    
    # Reload systemd
    systemctl daemon-reload
}

remove_modsecurity_rules() {
    if [[ "$REMOVE_MODSEC" != "yes" ]]; then
        log_info "Keeping ModSecurity rules"
        return
    fi
    
    log_info "Removing ModSecurity rules..."
    
    local found_rules=0
    
    # Check for both possible filenames
    for rules_file in "/etc/modsecurity/ab_pow_ratelimit.conf" \
                       "/etc/modsecurity/ab_pow_ratelimit_simple.conf"; do
        if [[ -f "$rules_file" ]]; then
            # Backup before removing
            local backup="${rules_file}.removed.$(date +%Y%m%d_%H%M%S)"
            mv "$rules_file" "$backup"
            log_success "Backed up and removed: $rules_file"
            log_info "Backup saved to: $backup"
            found_rules=1
        fi
    done
    
    if [[ $found_rules -eq 0 ]]; then
        log_warn "ModSecurity rules not found"
    fi
    
    # Remove includes from vhost configs
    log_info "Removing ModSecurity rule includes from vhosts..."
    
    local vhost_updated=0
    for vhost in /etc/apache2/sites-available/*.conf; do
        if [[ -f "$vhost" ]] && grep -q "ab_pow_ratelimit" "$vhost" 2>/dev/null; then
            # Backup vhost
            local backup="${vhost}.modsec-removed.$(date +%Y%m%d_%H%M%S)"
            cp "$vhost" "$backup"
            
            # Remove include lines
            sed -i '/ab_pow_ratelimit/d' "$vhost"
            sed -i '/Header.*Retry-After.*AB_RL/d' "$vhost"
            
            log_success "Cleaned ModSec includes from: $(basename $vhost)"
            vhost_updated=1
        fi
    done
    
    if [[ $vhost_updated -eq 0 ]]; then
        log_info "No vhost includes to remove"
    fi
}

test_apache_config() {
    log_info "Testing Apache configuration..."
    
    if apachectl configtest 2>&1 | grep -q "Syntax OK"; then
        log_success "Apache configuration is valid"
        return 0
    else
        log_warn "Apache configuration has issues"
        apachectl configtest 2>&1 | tail -n 10
        return 1
    fi
}

reload_apache() {
    log_info "Reloading Apache..."
    
    if systemctl reload apache2 2>/dev/null; then
        log_success "Apache reloaded successfully"
    else
        log_warn "Failed to reload Apache (may not be critical)"
        log_info "Try: systemctl status apache2"
    fi
}

show_completion() {
    echo ""
    log_success "Uninstallation completed!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if [[ "$REMOVE_DEFAULT_VHOST" == "yes" ]]; then
        echo "✅ Default vhost restored"
    else
        echo "✅ Virtual hosts removed"
    fi
    
    echo "✅ PoW endpoints removed"
    
    if [[ "$REMOVE_SECRET" = "yes" ]]; then
        echo "✅ PoW secret removed"
    else
        echo "⚠️  PoW secret kept at /etc/apache2/pow.env"
    fi
    
    if [[ "$REMOVE_SYSTEMD" = "yes" ]]; then
        echo "✅ Systemd rotation removed"
    fi
    
    if [[ "$REMOVE_MODSEC" = "yes" ]]; then
        echo "✅ ModSecurity rules removed"
        echo "✅ Vhost includes cleaned"
    else
        echo "⚠️  ModSecurity rules kept"
    fi
    
    echo ""
    echo "📦 All files were backed up before removal"
    echo "   Check /tmp and /etc/apache2/sites-available"
    echo ""
    
    # List backups
    local backup_count=$(find /tmp /etc/apache2/sites-available /etc/modsecurity -name "*.removed.*" -o -name "*.backup.*" 2>/dev/null | wc -l)
    if [[ $backup_count -gt 0 ]]; then
        echo "📁 Backup files created:"
        find /tmp /etc/apache2/sites-available /etc/modsecurity -name "*.removed.*" -o -name "*.backup.*" 2>/dev/null | head -n 10
        if [[ $backup_count -gt 10 ]]; then
            echo "   ... and $((backup_count - 10)) more"
        fi
        echo ""
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main uninstallation flow
main() {
    show_banner
    check_root
    parse_args "$@"
    detect_config
    prompt_config
    show_uninstall_summary
    
    log_info "Starting uninstallation..."
    echo ""
    
    restore_default_vhost
    disable_and_remove_vhosts
    remove_pow_endpoints
    remove_secret
    remove_systemd_rotation
    remove_modsecurity_rules
    
    if ! test_apache_config; then
        log_warn "Apache configuration has issues. Manual review recommended."
    fi
    
    reload_apache
    show_completion
}

# Run main
main "$@"
