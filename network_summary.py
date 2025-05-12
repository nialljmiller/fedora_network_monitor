#!/usr/bin/env python3
import subprocess
import datetime
from collections import Counter
import smtplib
from email.mime.text import MIMEText
import os
import re

# ---- CONFIG ----
SMTP_USER = "cirrus.noreply@gmail.com"
SMTP_PASS = "jnlaisebvidlrioh"
EMAIL_TO = "niall.j.miller@gmail.com"
APACHE_LOG = "/var/log/httpd/access_log"
FAIL2BAN_JAIL = "sshd"

def get_ssh_summary():
    try:
        fail2ban_output = subprocess.run(["sudo", "fail2ban-client", "status", FAIL2BAN_JAIL],
                                         capture_output=True, text=True).stdout
        total_banned = re.search(r"Total banned:\s+(\d+)", fail2ban_output)
        current_banned = re.search(r"Currently banned:\s+(\d+)", fail2ban_output)
        banned_ips = re.findall(r"Banned IP list:\s+(.+)", fail2ban_output)

        total_banned = total_banned.group(1) if total_banned else "?"
        current_banned = current_banned.group(1) if current_banned else "?"
        banned_ips_list = banned_ips[0].split() if banned_ips else []

    except Exception:
        total_banned = current_banned = "?"
        banned_ips_list = []

    try:
        journal_output = subprocess.run(
            ["journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager"],
            capture_output=True, text=True).stdout
        success_ips = re.findall(r"Accepted \w+ for \w+ from ([\d.]+)", journal_output)
        success_counter = Counter(success_ips)
    except Exception:
        success_counter = {}

    return {
        "total_banned": total_banned,
        "current_banned": current_banned,
        "banned_ips": banned_ips_list[:10],
        "success_logins": success_counter.most_common(5)
    }

def get_web_summary():
    if not os.path.exists(APACHE_LOG):
        return {"total_hits": 0, "top_ips": []}

    since = datetime.datetime.now() - datetime.timedelta(days=1)
    pattern = re.compile(r'\[(\d{2}/\w+/\d{4}):(\d{2}):\d{2}:\d{2}')
    ip_hits = Counter()
    hit_count = 0

    with open(APACHE_LOG, 'r', errors='ignore') as f:
        for line in f:
            match = pattern.search(line)
            if not match:
                continue
            timestamp = datetime.datetime.strptime(f"{match.group(1)} {match.group(2)}", "%d/%b/%Y %H")
            if timestamp > since:
                ip = line.split()[0]
                ip_hits[ip] += 1
                hit_count += 1

    return {"total_hits": hit_count, "top_ips": ip_hits.most_common(5)}

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
    web = get_web_summary()

    lines = []
    lines.append("CIRRUS NETWORK SUMMARY")
    lines.append(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("\n-- SSH Access --")
    lines.append(f"Blocked (Total):    {ssh['total_banned']}")
    lines.append(f"Blocked (Current):  {ssh['current_banned']}")
    lines.append("Blocked IPs:        " + ", ".join(ssh['banned_ips']) if ssh['banned_ips'] else "Blocked IPs:        None")
    lines.append("Successful logins:")
    for ip, count in ssh['success_logins']:
        lines.append(f"  {ip:<15}  {count} times")

    lines.append("\n-- Web Server --")
    lines.append(f"Hits (24h):         {web['total_hits']}")
    lines.append("Top IPs:")
    for ip, count in web['top_ips']:
        lines.append(f"  {ip:<15}  {count} hits")

    send_email("Cirrus Network Summary", "\n".join(lines))

if __name__ == "__main__":
    main()
