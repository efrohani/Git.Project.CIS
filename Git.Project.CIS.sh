#!/bin/bash

# CIS Advanced Audit Script with iptables, User Analysis, NTP, SSH, Web Servers & Logging Checks
set -euo pipefail

# Error handler
handle_error() {
    echo "[ERROR] At line $1: Command failed with exit code $2" | tee -a "$AUDIT_FILE"
    exit 1
}
trap 'handle_error $LINENO $?' ERR

# Get system IP address (excluding loopback and docker)
SERVER_IP=$(ip -4 addr show scope global | grep -v 'docker\|virbr\|127.0.0.1' | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1 2>/dev/null || echo "127.0.0.1")
SERVER_IP_CLEAN=${SERVER_IP//./_}

# Initial setup
AUDIT_DATE=$(date +"%Y-%m-%d_%H-%M-%S")
AUDIT_FILE="CIS_Audit_Report_${SERVER_IP_CLEAN}_${AUDIT_DATE}.txt"
: > "$AUDIT_FILE"

# Write to report function
write_report() {
    echo -e "$1" | tee -a "$AUDIT_FILE"
}

# Required commands check
REQUIRED_CMDS=("iptables" "getent" "awk" "cut" "ip" "netstat" "ss" "stat" "grep" "uptime" "find" "free" "nproc")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        write_report "[WARNING] Command $cmd not found. Some checks will be skipped."
    fi
done

## === START OF AUDIT REPORT ===
write_report "=== CIS Security Audit Report ==="
write_report "Start Time: $(date)"
write_report "Hostname: $(hostname)"
write_report "Current User: $(whoami)"
write_report "Kernel Version: $(uname -r)"
write_report "Server IP: ${SERVER_IP}"

## === System Information ===
write_report "\n=== System Information ==="
{
    echo "Distribution: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || echo "Unknown")"
    echo "Uptime: $(uptime 2>/dev/null || echo "Unknown")"
    echo "CPU Cores: $(nproc 2>/dev/null || echo "Unknown")"
    echo "Total RAM: $(free -h 2>/dev/null | awk '/Mem/{print $2}' || echo "Unknown")"
} >> "$AUDIT_FILE"

## === User Analysis ===
write_report "\n=== User Analysis ==="
{
    echo -e "\nUsers with valid shells:"
    getent passwd | awk -F: '$7 != "/usr/sbin/nologin" && $7 != "/bin/false" {print $1}' | while read -r user; do
        echo -n "User: $user - "
        [ -d "/home/$user" ] && echo "Home directory exists" || echo "No home directory"
    done

    echo -e "\nUsers with sudo access:"
    getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' || echo "No sudo group found"

    echo -e "\nLast user logins:"
    last -n 10 2>/dev/null | head -n -2 || echo "No login records found"
} >> "$AUDIT_FILE"

## === SSH Configuration ===
write_report "\n=== SSH Configuration ==="
{
    SSH_CONFIG="/etc/ssh/sshd_config"
    if [ -f "$SSH_CONFIG" ]; then
        echo -e "\nSSH Service Status:"
        systemctl is-active sshd 2>/dev/null && echo "Active" || echo "Inactive"
        
        echo -e "\nSSH Protocol Version:"
        grep -i "^Protocol" "$SSH_CONFIG" 2>/dev/null || echo "Protocol not specified (default: 2)"
        
        echo -e "\nPassword Authentication:"
        grep -i "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null || echo "PasswordAuthentication not specified (default: yes)"
        
        echo -e "\nRoot Login:"
        grep -i "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null || echo "PermitRootLogin not specified (default: yes)"
        
        echo -e "\nMax Auth Tries:"
        grep -i "^MaxAuthTries" "$SSH_CONFIG" 2>/dev/null || echo "MaxAuthTries not specified (default: 6)"
        
        echo -e "\nIdle Timeout:"
        grep -i "^ClientAliveInterval" "$SSH_CONFIG" 2>/dev/null || echo "ClientAliveInterval not specified (no timeout)"
        
        echo -e "\nX11 Forwarding:"
        grep -i "^X11Forwarding" "$SSH_CONFIG" 2>/dev/null || echo "X11Forwarding not specified (default: no)"
        
        echo -e "\nSSH Ciphers:"
        grep -i "^Ciphers" "$SSH_CONFIG" 2>/dev/null || echo "Ciphers not specified (default)"
        
        echo -e "\nSSH MACs:"
        grep -i "^MACs" "$SSH_CONFIG" 2>/dev/null || echo "MACs not specified (default)"
        
        echo -e "\nSSH Key Exchange Algorithms:"
        grep -i "^KexAlgorithms" "$SSH_CONFIG" 2>/dev/null || echo "KexAlgorithms not specified (default)"
        
        echo -e "\nSSH LogLevel:"
        grep -i "^LogLevel" "$SSH_CONFIG" 2>/dev/null || echo "LogLevel not specified (default: INFO)"
    else
        echo "SSH configuration file not found at $SSH_CONFIG"
    fi
} >> "$AUDIT_FILE"

## === Web Server Checks ===
write_report "\n=== Web Server Checks ==="
{
    # Check for Apache
    echo -e "\n=== Apache HTTP Server ==="
    if command -v apache2 &> /dev/null || command -v httpd &> /dev/null; then
        APACHE_CMD=$(command -v apache2 || command -v httpd)
        echo "[INSTALLED] Apache is installed at: $APACHE_CMD"
        
        echo -e "\nApache Version:"
        $APACHE_CMD -v 2>/dev/null || echo "Could not get Apache version"
        
        echo -e "\nApache Service Status:"
        systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null && echo "Active" || echo "Inactive"
        
        echo -e "\nApache Modules:"
        $APACHE_CMD -M 2>/dev/null | head -20 || echo "Could not list Apache modules"
        
        echo -e "\nApache Virtual Hosts:"
        if [ -d "/etc/apache2/sites-enabled" ]; then
            ls -la /etc/apache2/sites-enabled/ 2>/dev/null || echo "Could not list Apache sites"
        elif [ -d "/etc/httpd/conf.d" ]; then
            ls -la /etc/httpd/conf.d/ 2>/dev/null || echo "Could not list Apache conf.d"
        else
            echo "Could not find Apache virtual hosts directory"
        fi
        
        echo -e "\nApache Configuration Files:"
        find /etc/apache2 /etc/httpd -name "*.conf" -type f -exec ls -la {} \; 2>/dev/null | head -20 || echo "Could not list Apache config files"
    else
        echo "[NOT INSTALLED] Apache is not installed"
    fi

    # Check for Nginx
    echo -e "\n=== Nginx HTTP Server ==="
    if command -v nginx &> /dev/null; then
        echo "[INSTALLED] Nginx is installed at: $(command -v nginx)"
        
        echo -e "\nNginx Version:"
        nginx -v 2>&1 || echo "Could not get Nginx version"
        
        echo -e "\nNginx Service Status:"
        systemctl is-active nginx 2>/dev/null && echo "Active" || echo "Inactive"
        
        echo -e "\nNginx Configuration Test:"
        nginx -t 2>&1 || echo "Nginx configuration test failed"
        
        echo -e "\nNginx Server Blocks:"
        if [ -d "/etc/nginx/sites-enabled" ]; then
            ls -la /etc/nginx/sites-enabled/ 2>/dev/null || echo "Could not list Nginx sites"
        elif [ -f "/etc/nginx/nginx.conf" ]; then
            grep -i "server {" /etc/nginx/nginx.conf 2>/dev/null || echo "Could not find server blocks in nginx.conf"
        else
            echo "Could not find Nginx configuration directory"
        fi
        
        echo -e "\nNginx Configuration Files:"
        find /etc/nginx -name "*.conf" -type f -exec ls -la {} \; 2>/dev/null | head -20 || echo "Could not list Nginx config files"
    else
        echo "[NOT INSTALLED] Nginx is not installed"
    fi
} >> "$AUDIT_FILE"

## === Firewall Configuration (iptables) ===
write_report "\n=== Firewall Configuration (iptables) ==="
{
    echo -e "\niptables status:"
    if command -v iptables &> /dev/null; then
        iptables -L -n -v --line-numbers 2>/dev/null || echo "No iptables rules found"
    else
        echo "iptables command not available"
    fi

    echo -e "\nNAT Rules:"
    if command -v iptables &> /dev/null; then
        iptables -t nat -L -n -v --line-numbers 2>/dev/null || echo "No NAT rules found"
    fi

    echo -e "\nOpen Ports:"
    if command -v netstat &> /dev/null; then
        netstat -tulnp 2>/dev/null || echo "netstat failed"
    elif command -v ss &> /dev/null; then
        ss -tulnp 2>/dev/null || echo "ss failed"
    else
        echo "Neither netstat nor ss available"
    fi
} >> "$AUDIT_FILE"

## === Network Configuration ===
write_report "\n=== Network Configuration ==="
{
    echo -e "\nNetwork Interfaces:"
    if command -v ip &> /dev/null; then
        ip -br addr show 2>/dev/null || echo "ip command failed"
    else
        echo "ip command not found"
    fi

    echo -e "\nRouting Table:"
    if command -v ip &> /dev/null; then
        ip route 2>/dev/null || echo "Cannot retrieve routing table"
    fi

    echo -e "\nDefault Gateway:"
    if command -v ip &> /dev/null; then
        ip route | grep default 2>/dev/null || echo "No default gateway found"
    fi

    echo -e "\nDNS Configuration:"
    if [ -f "/etc/resolv.conf" ]; then
        cat /etc/resolv.conf 2>/dev/null || echo "Cannot read DNS configuration"
    else
        echo "No DNS configuration file found"
    fi
} >> "$AUDIT_FILE"

## === Filesystem Checks ===
write_report "\n=== Filesystem Checks ==="
{
    echo -e "\nSUID/SGID Files:"
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | head -20 || echo "No SUID/SGID files found or search failed"

    echo -e "\nWorld Writable Files:"
    find / -xdev -type f -perm -0002 -exec ls -ld {} \; 2>/dev/null | head -20 || echo "No world-writable files found or search failed"

    echo -e "\nFiles with no owner:"
    find / -xdev \( -nouser -o -nogroup \) -exec ls -ld {} \; 2>/dev/null | head -10 || echo "No orphaned files found or search failed"
} >> "$AUDIT_FILE"

## === Package Information ===
write_report "\n=== Package Information ==="
{
    echo -e "\nRecent Updates:"
    if [ -f /var/log/apt/history.log ]; then
        grep "apt upgrade" /var/log/apt/history.log | tail -5 || echo "No recent apt upgrade found"
    elif [ -f /var/log/dnf.log ]; then
        grep "Updated" /var/log/dnf.log | tail -5 || echo "No recent dnf upgrade found"
    elif [ -f /var/log/yum.log ]; then
        grep "Updated" /var/log/yum.log | tail -5 || echo "No recent yum upgrade found"
    else
        echo "No package manager logs found."
    fi

    echo -e "\nUpgradable Packages:"
    if command -v apt &> /dev/null; then
        apt list --upgradable 2>/dev/null || echo "All packages are up to date"
    elif command -v yum &> /dev/null; then
        yum check-update 2>/dev/null || echo "All packages are up to date"
    elif command -v dnf &> /dev/null; then
        dnf check-update 2>/dev/null || echo "All packages are up to date"
    else
        echo "Package manager not detected"
    fi
} >> "$AUDIT_FILE"

## === NTP Synchronization Check ===
write_report "\n=== NTP Synchronization Check ==="
{
    if command -v timedatectl &> /dev/null; then
        timedatectl status | grep -E "NTP|System clock synchronized" || echo "NTP not enabled"
    elif command -v ntpq &> /dev/null; then
        ntpq -p || echo "ntpq failed"
    elif command -v chronyc &> /dev/null; then
        chronyc sources || echo "chronyc failed"
    else
        echo "[WARNING] NTP tools not available"
    fi
} >> "$AUDIT_FILE"

## === Logging to Central Server (ELK / Splunk) ===
write_report "\n=== Central Logging Check (ELK / Splunk) ==="
{
    echo -e "\nChecking Filebeat:"
    if systemctl is-active filebeat &> /dev/null; then
        echo "[OK] Filebeat service is active"
        grep -E "output.elasticsearch|output.logstash" /etc/filebeat/filebeat.yml 2>/dev/null | grep -v "#" || echo "[WARNING] Filebeat output not configured"
    else
        echo "[INFO] Filebeat is not active"
    fi

    echo -e "\nChecking Splunk Forwarder:"
    if systemctl is-active splunkforwarder &> /dev/null; then
        echo "[OK] Splunk Forwarder is active"
        /opt/splunkforwarder/bin/splunk show deploy-poll 2>/dev/null || echo "[INFO] Splunk info not available"
    else
        echo "[INFO] Splunk Forwarder is not active"
    fi

    echo -e "\nChecking rsyslog remote targets:"
    grep -E '@[0-9a-zA-Z\.-]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || echo "[INFO] No remote rsyslog targets found"
} >> "$AUDIT_FILE"

## === CIS Security Checks ===
write_report "\n=== CIS Security Checks ==="
{
    echo -e "\n1.1.1 Disable cramfs:"
    lsmod | grep -q cramfs && echo "[WARNING] cramfs is enabled" || echo "[OK] cramfs is disabled"

    echo -e "\n1.1.2 Disable freevxfs:"
    lsmod | grep -q freevxfs && echo "[WARNING] freevxfs is enabled" || echo "[OK] freevxfs is disabled"

    echo -e "\n5.2.1 sshd_config Permissions:"
    if [ -f /etc/ssh/sshd_config ]; then
        PERM=$(stat -c "%a" /etc/ssh/sshd_config 2>/dev/null)
        [ "$PERM" -eq 600 ] && echo "[OK] sshd_config permissions are correct" || echo "[WARNING] Incorrect sshd_config permissions: $PERM"
    else
        echo "[INFO] sshd_config file not found"
    fi
} >> "$AUDIT_FILE"

## === END OF REPORT ===
write_report "\n=== Audit Complete ==="
write_report "End Time: $(date)"
write_report "\nNotes:"
write_report "1. This is a basic audit report"
write_report "2. Use advanced tools for full compliance checking"
write_report "3. Report saved at: $AUDIT_FILE"
write_report "4. Time synchronization with NTP was checked"
write_report "5. Logging to ELK/Splunk or remote rsyslog was inspected"
write_report "6. SSH configuration was thoroughly checked"
write_report "7. Web servers (Apache/Nginx) were checked"

echo "✅ Audit completed successfully. Report saved to $AUDIT_FILE"
