#!/usr/bin/env python3
import subprocess
import datetime
from collections import Counter
import smtplib
from email.mime.text import MIMEText

# ---- CONFIG ----
SMTP_USER = "cirrus.noreply@gmail.com"
SMTP_PASS = "jnlaisebvidlrioh"
EMAIL_TO = "niall.j.miller@gmail.com"
APACHE_LOG = "/var/log/httpd/access_log"

# ---- DATA COLLECTION ----
def get_ssh_activity():
    journal = subprocess.run(
        ["journalctl", "-u", "sshd", "--since", "24 hours ago"],
        stdout=subprocess.PIPE, text=True
    ).stdout.splitlines()

    failed = sum("Failed password" in line for line in journal)
    success_lines = [line for line in journal if "Accepted password" in line or "Accepted publickey" in line]
    success_ips = [line.split()[-4] for line in success_lines if "from" in line]
    return failed, success_ips

def get_apache_activity():
    try:
        with open(APACHE_LOG) as f:
            lines = [line.strip() for line in f.readlines()]
    except Exception as e:
        return 0, []

    since = datetime.datetime.now() - datetime.timedelta(days=1)
    recent = [line for line in lines if datetime.datetime.strptime(line.split("[")[1].split("]")[0].split()[0], "%d/%b/%Y:%H:%M:%S") > since]
    total = len(recent)
    ips = [line.split()[0] for line in recent]
    top = Counter(ips).most_common(5)
    return total, top

# ---- EMAIL SENDER ----
def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = f"Cirrus Server <{SMTP_USER}>"
    msg["To"] = EMAIL_TO

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)

# ---- MAIN ----
def main():
    ssh_failed, ssh_success = get_ssh_activity()
    web_hits, web_top_ips = get_apache_activity()

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    body = f"""\
📡 Cirrus Network Summary – {now}

🔐 SSH Activity:
  • Failed attempts: {ssh_failed}
  • Successful logins: {', '.join(ssh_success) if ssh_success else 'None'}

🌐 Web Server (Apache):
  • Total hits (24h): {web_hits}
  • Top 5 IPs:
"""
    for ip, count in web_top_ips:
        body += f"     - {ip}: {count} hits\n"

    send_email("Daily Cirrus Network Report", body)

if __name__ == "__main__":
    main()
