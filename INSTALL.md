# Installation Guide

Complete guide for installing pow-shield-php on your server.

---

## 🚀 Quick Start (5 Minutes)

### 1. Clone Repository

```bash
git clone https://github.com/AfterPacket/pow-shield-php.git
cd pow-shield-php
```

### 2. Make Scripts Executable

```bash
chmod +x install.sh uninstall.sh
```

### 3. Run Installer

```bash
sudo ./install.sh
```

Follow the interactive prompts and you're done! 🎉

---

## 📋 Prerequisites

### Server Requirements
- **OS**: Debian/Ubuntu (or compatible)
- **Root Access**: Required for installation
- **Open Ports**: 80 (HTTP) and 443 (HTTPS)

### Software (Auto-installed)
The installer will automatically install:
- Apache 2.4+
- PHP 8+
- OpenSSL
- ModSecurity (optional)
- Certbot (if using Let's Encrypt)

---

## 🎯 Installation Methods

### Method 1: Interactive Installation (Recommended)

Best for first-time setup or if you're unsure about configuration.

```bash
sudo ./install.sh
```

**What it asks:**
1. Domain name (e.g., example.com)
2. Web root path (default: /var/www/html)
3. SSL configuration:
   - Use existing certificates?
   - Use Let's Encrypt?
4. Enable site immediately?
5. Install ModSecurity?

**Example Session:**
```
Enter your domain name (e.g., example.com): mysite.com
Enter web root path [/var/www/html]: /var/www/mysite
Do you have existing SSL certificates? (y/n) [n]: n
Would you like to use Let's Encrypt for free SSL? (y/n) [y]: y
Enter your email for Let's Encrypt: admin@mysite.com
Enable site with a2ensite after installation? (y/n) [n]: y
Install/configure ModSecurity? (y/n) [y]: y
```

### Method 2: Non-Interactive with Let's Encrypt

Perfect for automation scripts or when you know your configuration.

```bash
sudo ./install.sh \
  -d example.com \
  -w /var/www/html \
  -l admin@example.com \
  -e
```

### Method 3: Non-Interactive with Existing SSL

When you already have SSL certificates (e.g., from your hosting provider).

```bash
sudo ./install.sh \
  -d example.com \
  -w /var/www/html \
  -c /etc/ssl/certs/example.com.crt \
  -k /etc/ssl/private/example.com.key \
  -e
```

### Method 4: Minimal Install (No SSL, No ModSec)

For testing or development environments.

```bash
sudo ./install.sh \
  -d example.com \
  -w /var/www/html \
  -s \
  -n
```

---

## 🔧 Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-d, --domain DOMAIN` | Your domain name | `-d example.com` |
| `-w, --webroot PATH` | Web root directory | `-w /var/www/html` |
| `-c, --cert PATH` | SSL certificate path | `-c /path/to/cert.pem` |
| `-k, --key PATH` | SSL key path | `-k /path/to/key.pem` |
| `-l, --letsencrypt EMAIL` | Use Let's Encrypt | `-l admin@example.com` |
| `-e, --enable` | Enable site after install | `-e` |
| `-s, --skip-modsec` | Skip ModSecurity | `-s` |
| `-n, --non-interactive` | No prompts | `-n` |
| `-h, --help` | Show help | `-h` |

---

## 🔐 SSL Configuration

### Option A: Let's Encrypt (Recommended)

**Free, automatic, and renews automatically.**

```bash
sudo ./install.sh -d example.com -l admin@example.com -e
```

Requirements:
- Domain must point to your server (A record)
- Port 80 must be accessible
- Valid email address

The installer will:
1. Install certbot
2. Obtain certificates for `example.com` and `www.example.com`
3. Configure Apache automatically
4. Set up auto-renewal

**Certificate Renewal:**
Automatic! Certbot creates a systemd timer that renews certificates automatically.

Check renewal status:
```bash
sudo systemctl status certbot.timer
```

### Option B: Existing Certificates

If you already have SSL certificates:

```bash
sudo ./install.sh \
  -d example.com \
  -c /path/to/fullchain.pem \
  -k /path/to/privkey.pem \
  -e
```

**Common Certificate Locations:**
- Let's Encrypt: `/etc/letsencrypt/live/DOMAIN/`
- Self-signed: `/etc/ssl/certs/` and `/etc/ssl/private/`
- cPanel: `/var/cpanel/ssl/apache_tls/DOMAIN/`

### Option C: Configure Later

Install without SSL and add it later:

```bash
sudo ./install.sh -d example.com -n
```

Then edit `/etc/apache2/sites-available/example.com.conf` and add:
```apache
SSLCertificateFile /path/to/cert.pem
SSLCertificateKeyFile /path/to/key.pem
```

---

## 🛡️ ModSecurity Configuration

### Automatic Installation

By default, the installer sets up ModSecurity with PoW-specific rate limits.

**What it does:**
- Installs `libapache2-mod-security2`
- Enables ModSecurity engine
- Installs PoW rate limit rules (`ab_pow_ratelimit.conf`)
- Rate limits `/__ab/pow.php` and `/__ab/pow-verify.php`

### Skip ModSecurity

If you don't want ModSecurity:

```bash
sudo ./install.sh -d example.com -s
```

### Manual ModSecurity Setup

After installation:

```bash
# Install ModSecurity
sudo apt-get install libapache2-mod-security2
sudo a2enmod security2

# Enable engine
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' \
  /etc/modsecurity/modsecurity.conf

# Install PoW rules
sudo cp modsecurity/ab_pow_ratelimit.conf /etc/modsecurity/

# Reload Apache
sudo systemctl reload apache2
```

---

## 🔄 Secret Management

The installer automatically:
1. Creates `/etc/apache2/pow.env` with secure permissions (600)
2. Generates a 64-character random secret
3. Installs rotation script at `/usr/local/sbin/rotate-pow-secret.sh`
4. Sets up systemd timer for hourly rotation

### Manual Secret Rotation

```bash
# Rotate now
sudo /usr/local/sbin/rotate-pow-secret.sh

# Check rotation timer
sudo systemctl status rotate-pow-secret.timer

# View recent rotations
sudo journalctl -u rotate-pow-secret.service
```

### Disable Auto-Rotation

```bash
sudo systemctl stop rotate-pow-secret.timer
sudo systemctl disable rotate-pow-secret.timer
```

---

## ✅ Post-Installation

### 1. Verify Installation

**Check Apache status:**
```bash
sudo systemctl status apache2
```

**Test PoW endpoint:**
```bash
curl -I https://example.com/__ab/pow.php
```

Should return `200 OK`.

**Test protection:**
```bash
curl -I https://example.com/
```

Should redirect to `/__ab/pow.php`.

### 2. Check Logs

**Apache logs:**
```bash
sudo tail -f /var/log/apache2/example.com-error.log
sudo tail -f /var/log/apache2/example.com-access.log
```

**ModSecurity logs:**
```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

### 3. Test Rate Limiting

```bash
for i in {1..100}; do
  curl -sk https://example.com/__ab/pow.php >/dev/null -w "%{http_code}\n"
done
```

You should see `429 Too Many Requests` after ~60 requests.

---

## 🎨 Customization

### Change PoW Difficulty

Edit `/var/www/html/__ab/pow.php`:

```php
$DIFFICULTY = 18; // Increase for harder challenges (default: 16-18)
```

### Customize Challenge Page

Edit `/var/www/html/__ab/pow.php`:

```php
$MEME_SRC = '/assets/img/your-image.jpg';
$TITLE = 'Your Custom Title';
```

### Adjust Rate Limits

Edit `/etc/modsecurity/ab_pow_ratelimit.conf`:

```apache
# Change from 60 requests per minute to 100
SecAction "id:909001,phase:1,pass,initcol:ip=%{REMOTE_ADDR},setvar:ip.pow_requests=0"
```

### Skip Paths from PoW

Edit `/etc/apache2/sites-available/example.com.conf`:

```apache
# Skip /api endpoint
RewriteCond %{REQUEST_URI} !^/api/
```

---

## 🐛 Troubleshooting

### Installation Fails

**Check log output carefully:**
The installer shows colored output indicating issues.

**Common issues:**
1. Not running as root: `sudo ./install.sh`
2. Port 80/443 already in use: Check existing Apache config
3. Domain doesn't resolve: Update DNS first for Let's Encrypt

### Can't Access Site After Install

**1. Check if site is enabled:**
```bash
sudo apache2ctl -S | grep example.com
```

**2. Enable manually if needed:**
```bash
sudo a2ensite example.com.conf
sudo a2ensite example.com-redirect.conf
sudo systemctl reload apache2
```

**3. Check Apache config:**
```bash
sudo apachectl configtest
```

### Let's Encrypt Fails

**Common causes:**
- Domain doesn't point to server
- Port 80 blocked by firewall
- Existing webserver on port 80

**Solutions:**
```bash
# Check DNS
dig example.com

# Check port 80
sudo netstat -tulpn | grep :80

# Try manual certbot
sudo certbot certonly --standalone -d example.com
```

### Infinite Redirect Loop

**Cause:** Cloudflare or CDN caching PoW endpoints

**Solution:**
1. Bypass cache for `/__ab/*` in Cloudflare
2. Disable Bot Fight Mode
3. See `docs/cloudflare-notes.md`

### 429 Too Many Requests

**This is normal!** Rate limiting is working.

**To adjust:**
Edit `/etc/modsecurity/ab_pow_ratelimit.conf`

---

## 🔄 Updating

To update pow-shield-php:

```bash
cd pow-shield-php
git pull origin main

# Reinstall (preserves secret)
sudo ./install.sh -d example.com -w /var/www/html -e
```

The installer will:
- ✅ Backup existing config
- ✅ Preserve your secret
- ✅ Update files
- ✅ Reload Apache

---

## 🗑️ Uninstallation

See [UNINSTALL.md](UNINSTALL.md) or:

```bash
sudo ./uninstall.sh
```

---

## 📚 Additional Resources

- [README.md](README.md) - Project overview
- [docs/cloudflare-notes.md](docs/cloudflare-notes.md) - Cloudflare configuration
- [docs/installation-checklist.md](docs/installation-checklist.md) - Manual install checklist
- [docs/modsecurity-global-notes.md](docs/modsecurity-global-notes.md) - ModSecurity details

---

## 💬 Need Help?

- 🐛 [Open an issue](https://github.com/AfterPacket/pow-shield-php/issues)
- 📖 [Read the docs](https://github.com/AfterPacket/pow-shield-php/tree/main/docs)
- 💡 [Check discussions](https://github.com/AfterPacket/pow-shield-php/discussions)

---

**Happy Installing!** 🚀🛡️
