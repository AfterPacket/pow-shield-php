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
    -m, --remove-modsec         Also remove ModSecurity
    -k, --keep-secret           Keep the PoW secret file
    -f, --force                 Force removal without prompts
    -n, --non-interactive       Run without prompts
    -h, --help                  Show this help message

EXAMPLES:
    # Interactive mode (recommended)
    sudo ./uninstall.sh

    # Remove everything for specific domain
    sudo ./uninstall.sh -d example.com -w /var/www/html

    # Force removal without prompts
    sudo ./uninstall.sh -d example.com -w /var/www/html -f

    # Keep secret file
    sudo ./uninstall.sh -d example.com -w /var/www/html -k

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
    
    # Try to find vhosts
    if [[ -z "$DOMAIN" ]]; then
        log_info "Searching for pow-shield-php installations..."
        
        local found_vhosts=()
        for vhost in /etc/apache2/sites-available/*.conf; do
            if [[ -f "$vhost" ]] && grep -q "/__ab/pow.php" "$vhost" 2>/dev/null; then
                local domain=$(basename "$vhost" .conf)
                domain=${domain%-redirect}
                found_vhosts+=("$domain")
            fi
        done
        
        if [[ ${#found_vhosts[@]} -eq 0 ]]; then
            log_warn "No pow-shield-php installations found"
            return
        fi
        
        # Remove duplicates
        found_vhosts=($(echo "${found_vhosts[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        
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
    
    if [[ -z "$DOMAIN" ]]; then
        read -p "Enter domain to uninstall: " DOMAIN
    fi
    
    if [[ -z "$DOMAIN" ]]; then
        log_error "Domain is required"
        exit 1
    fi
    
    echo ""
    read -p "Remove PoW secret file? (y/n) [y]: " remove_secret
    remove_secret=${remove_secret:-y}
    if [[ ! "$remove_secret" =~ ^[Yy]$ ]]; then
        REMOVE_SECRET="no"
    fi
    
    read -p "Remove ModSecurity rules? (y/n) [n]: " remove_modsec
    if [[ "$remove_modsec" =~ ^[Yy]$ ]]; then
        REMOVE_MODSEC="yes"
    fi
}

show_uninstall_summary() {
    echo ""
    log_info "Uninstall Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Domain:               $DOMAIN"
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

disable_and_remove_vhosts() {
    if [[ "$REMOVE_VHOSTS" != "yes" ]]; then
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
    if systemctl is-active --quiet rotate-pow-secret.timer; then
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
    
    if [[ -f "/etc/modsecurity/ab_pow_ratelimit.conf" ]]; then
        # Backup before removing
        local backup="/etc/modsecurity/ab_pow_ratelimit.conf.removed.$(date +%Y%m%d_%H%M%S)"
        mv /etc/modsecurity/ab_pow_ratelimit.conf "$backup"
        log_success "Backed up and removed: /etc/modsecurity/ab_pow_ratelimit.conf"
        log_info "Backup saved to: $backup"
    else
        log_warn "ModSecurity rules not found"
    fi
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

reload_apache() {
    log_info "Reloading Apache..."
    
    if systemctl reload apache2; then
        log_success "Apache reloaded successfully"
    else
        log_warn "Failed to reload Apache (may not be critical)"
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
    echo "✅ Virtual hosts removed"
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
    else
        echo "⚠️  ModSecurity rules kept"
    fi
    
    echo ""
    echo "📦 All files were backed up before removal"
    echo "   Check /tmp and /etc/apache2/sites-available"
    echo ""
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
    
    disable_and_remove_vhosts
    remove_pow_endpoints
    remove_secret
    remove_systemd_rotation
    remove_modsecurity_rules
    
    if ! test_apache_config; then
        log_warn "Apache configuration has issues. Check manually."
    fi
    
    reload_apache
    show_completion
}

# Run main
main "$@"
