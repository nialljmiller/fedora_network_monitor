import glob
import gzip
import os
import re
import datetime
import subprocess
from collections import Counter
import smtplib
from email.mime.text import MIMEText
import geoip2.database

# Configuration
SMTP_USER = "cirrus.noreply@gmail.com"
SMTP_PASS = "jnlaisebvidlrioh"
EMAIL_TO = "niall.j.miller@gmail.com"
FAIL2BAN_JAIL = "sshd"
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"  # Adjust path if needed

# Apache logs to parse
APACHE_LOG_PATTERNS = [
    "/var/log/httpd/nialljmiller.com-access.log*",
    "/var/log/httpd/ssl_access_log*"
]

# Utility to filter IPs
def is_public_ip(ip):
    return not (
        ip.startswith("127.") or
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )

def geoip_lookup(ip, reader):
    try:
        response = reader.city(ip)
        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"
        return f"{ip} ({city}, {country})"
    except:
        return f"{ip} (Unknown Location)"

def parse_apache_logs():
    cutoff = datetime.datetime.now() - datetime.timedelta(days=1)
    ip_counter = Counter()
    total_hits = 0
    ts_pattern = re.compile(r'\[(\d{2}/\w+/\d{4}):(\d{2}):\d{2}:\d{2}')

    for pattern in APACHE_LOG_PATTERNS:
        for file in glob.glob(pattern):
            open_func = gzip.open if file.endswith('.gz') else open
            try:
                with open_func(file, 'rt', errors='ignore') as f:
                    for line in f:
                        match = ts_pattern.search(line)
                        if not match:
                            continue
                        timestamp = datetime.datetime.strptime(f"{match.group(1)} {match.group(2)}", "%d/%b/%Y %H")
                        if timestamp < cutoff:
                            continue
                        ip = line.split()[0]
                        if is_public_ip(ip):
                            ip_counter[ip] += 1
                            total_hits += 1
            except Exception:
                continue

    return total_hits, ip_counter.most_common(5)

def get_ssh_summary():
    try:
        f2b_output = subprocess.run(["sudo", "fail2ban-client", "status", FAIL2BAN_JAIL],
                                    capture_output=True, text=True).stdout
        total_banned = re.search(r"Total banned:\s+(\d+)", f2b_output)
        current_banned = re.search(r"Currently banned:\s+(\d+)", f2b_output)
        banned_ips = re.findall(r"Banned IP list:\s+(.+)", f2b_output)

        total_banned = total_banned.group(1) if total_banned else "?"
        current_banned = current_banned.group(1) if current_banned else "?"
        banned_ips_list = banned_ips[0].split() if banned_ips else []
        banned_ips_list = [ip for ip in banned_ips_list if is_public_ip(ip)]

    except Exception:
        total_banned = current_banned = "?"
        banned_ips_list = []

    try:
        journal_output = subprocess.run(
            ["journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager"],
            capture_output=True, text=True).stdout
        success_ips = re.findall(r"Accepted \w+ for \w+ from ([\d.]+)", journal_output)
        success_ips = [ip for ip in success_ips if is_public_ip(ip)]
        success_counter = Counter(success_ips)
    except Exception:
        success_counter = {}

    return {
        "total_banned": total_banned,
        "current_banned": current_banned,
        "banned_ips": banned_ips_list[:10],
        "success_logins": success_counter.most_common(5)
    }

def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)

def main():
    ssh = get_ssh_summary()
    web_hits, top_web_ips = parse_apache_logs()

    reader = geoip2.database.Reader(GEOIP_DB)

    lines = []
    lines.append("CIRRUS NETWORK SUMMARY")
    lines.append(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("\n-- SSH Access --")
    lines.append(f"Blocked (Total):    {ssh['total_banned']}")
    lines.append(f"Blocked (Current):  {ssh['current_banned']}")
    lines.append("Blocked IPs:")
    for ip in ssh['banned_ips']:
        lines.append(f"  {geoip_lookup(ip, reader)}")

    lines.append("Successful logins:")
    for ip, count in ssh['success_logins']:
        lines.append(f"  {geoip_lookup(ip, reader):<40} {count} times")

    lines.append("\n-- Web Server --")
    lines.append(f"Hits (24h):         {web_hits}")
    lines.append("Top IPs:")
    for ip, count in top_web_ips:
        lines.append(f"  {geoip_lookup(ip, reader):<40} {count} hits")

    reader.close()
    send_email("Cirrus Network Summary", "\n".join(lines))

main()
