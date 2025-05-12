import subprocess
import datetime
import re
import glob
from collections import Counter, defaultdict
import geoip2.database
from email.mime.text import MIMEText
import smtplib

# --- Configuration ---
SMTP_USER = "cirrus.noreply@gmail.com"
SMTP_PASS = "jnlaisebvidlrioh"
EMAIL_TO = "niall.j.miller@gmail.com"
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
APACHE_LOGS = [
    "/var/log/httpd/nialljmiller.com-access.log",
    "/var/log/httpd/ssl_access_log"
]
PRIVATE_IP_PATTERNS = [re.compile(rf"^{p}\.") for p in ["10", "127", "192.168"]]
USERNAME_RE = re.compile(r"Failed password for (invalid user )?(\w+)")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# --- Utilities ---
def is_public_ip(ip):
    return all(not p.match(ip) for p in PRIVATE_IP_PATTERNS)

def geoip(ip, reader):
    try:
        r = reader.city(ip)
        city = r.city.name or "?"
        country = r.country.name or "?"
        return f"{city}, {country}"
    except:
        return "?, ?"

def collect_ssh_stats(reader):
    journal = subprocess.run(
        ["journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager"],
        capture_output=True, text=True).stdout

    fail_ips, success_ips = [], []
    fail_users, success_users = [], []
    fail_times, success_times = [], []

    for line in journal.splitlines():
        if "Failed password for" in line:
            m = USERNAME_RE.search(line)
            if m:
                fail_users.append(m.group(2))
            ipm = IP_RE.search(line)
            if ipm and is_public_ip(ipm.group(1)):
                fail_ips.append(ipm.group(1))
            dt = re.search(r'^\w+\s+\d+\s+\d+:\d+:\d+', line)
            if dt:
                fail_times.append(dt.group())
        elif "Accepted" in line:
            ipm = IP_RE.search(line)
            if ipm and is_public_ip(ipm.group(1)):
                success_ips.append(ipm.group(1))
            userm = re.search(r"for (\w+) from", line)
            if userm:
                success_users.append(userm.group(1))
            dt = re.search(r'^\w+\s+\d+\s+\d+:\d+:\d+', line)
            if dt:
                success_times.append(dt.group())

    return {
        "fail_ips": Counter(fail_ips),
        "success_ips": Counter(success_ips),
        "fail_users": Counter(fail_users),
        "success_users": Counter(success_users),
        "fail_times": fail_times,
        "success_times": success_times,
    }

def collect_fail2ban_stats():
    output = subprocess.run(
        ["sudo", "fail2ban-client", "status", "sshd"],
        capture_output=True, text=True).stdout
    tb = re.search(r"Total banned:\s+(\d+)", output)
    cb = re.search(r"Currently banned:\s+(\d+)", output)
    banned_ips = re.findall(r"Banned IP list:\s+(.+)", output)
    ip_list = banned_ips[0].split() if banned_ips else []
    ip_list = [ip for ip in ip_list if is_public_ip(ip)]
    return {
        "total_banned": tb.group(1) if tb else "?",
        "current_banned": cb.group(1) if cb else "?",
        "banned_ips": ip_list[:10]
    }

def collect_web_stats(reader):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=1)
    hits, agents, urls, ip_hits, countries = 0, Counter(), Counter(), Counter(), Counter()

    for logfile in APACHE_LOGS:
        try:
            with open(logfile, "r", errors="ignore") as f:
                for line in f:
                    try:
                        parts = line.split()
                        ip = parts[0]
                        if not is_public_ip(ip):
                            continue
                        ts = re.search(r'\[(\d{2}/\w+/\d{4}):', line)
                        if not ts: continue
                        log_time = datetime.datetime.strptime(ts.group(1), "%d/%b/%Y")
                        if log_time < cutoff:
                            continue
                        url = parts[6]
                        ua = " ".join(parts[11:]).strip('"')
                        geo = geoip(ip, reader)

                        hits += 1
                        ip_hits[ip] += 1
                        urls[url] += 1
                        agents[ua] += 1
                        countries[geo.split(", ")[-1]] += 1
                    except:
                        continue
        except FileNotFoundError:
            continue

    return {
        "hits": hits,
        "top_ips": ip_hits.most_common(5),
        "top_urls": urls.most_common(5),
        "top_agents": agents.most_common(5),
        "by_country": countries.most_common(5),
        "bots": sum(c for ua, c in agents.items() if re.search(r'bot|crawl|spider', ua, re.I))
    }

def make_ascii_table(title, data, col1="Item", col2="Count"):
    table = [f"{title}", f"{col1:<40} {col2}", "-"*55]
    for key, val in data:
        table.append(f"{key:<40} {val}")
    return "\n".join(table)

def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# --- Main ---
reader = geoip2.database.Reader(GEOIP_DB)
f2b = collect_fail2ban_stats()
ssh = collect_ssh_stats(reader)
web = collect_web_stats(reader)

lines = [
    f"CIRRUS NETWORK SUMMARY",
    f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "",
    "-- SSH Activity --",
    f"Blocked IPs (Current): {f2b['current_banned']}",
    f"Blocked IPs (Total):   {f2b['total_banned']}",
    "Top Blocked IPs:"
]
for ip in f2b['banned_ips']:
    lines.append(f"  {ip:<15} {geoip(ip, reader)}")

lines += [
    "",
    make_ascii_table("Top Failed SSH IPs", [(f"{ip} ({geoip(ip, reader)})", count) for ip, count in ssh["fail_ips"].most_common(5)]),
    "",
    make_ascii_table("Top Failed SSH Users", ssh["fail_users"].most_common(5), "Username", "Attempts"),
    "",
    make_ascii_table("Top Successful SSH IPs", [(f"{ip} ({geoip(ip, reader)})", count) for ip, count in ssh["success_ips"].most_common(5)]),
    "",
    make_ascii_table("Top Successful SSH Users", ssh["success_users"].most_common(5), "Username", "Logins"),
    "",
    f"SSH First Success Log: {ssh['success_times'][0] if ssh['success_times'] else 'N/A'}",
    f"SSH Last  Success Log: {ssh['success_times'][-1] if ssh['success_times'] else 'N/A'}",
    f"SSH First Failed Log:  {ssh['fail_times'][0] if ssh['fail_times'] else 'N/A'}",
    f"SSH Last  Failed Log:  {ssh['fail_times'][-1] if ssh['fail_times'] else 'N/A'}",
    "",
    "-- Web Server Activity --",
    f"Total Hits (24h):       {web['hits']}",
    f"Hits from Bots (est.):  {web['bots']}",
    "",
    make_ascii_table("Top Web IPs", [(f"{ip} ({geoip(ip, reader)})", count) for ip, count in web["top_ips"]]),
    "",
    make_ascii_table("Top Request URLs", web["top_urls"], "URL", "Hits"),
    "",
    make_ascii_table("Top User-Agents", web["top_agents"], "User-Agent", "Hits"),
    "",
    make_ascii_table("Hits by Country", web["by_country"], "Country", "Hits"),
    "",
    "-- Log Sources --",
    f"SSH: journalctl -u sshd --since '24 hours ago'",
    f"Fail2Ban Jail: sshd",
    f"Web logs: {', '.join(APACHE_LOGS)}",
    f"Filtered: local IPs, SCP traffic",
    f"GeoIP: MaxMind City DB"
]

reader.close()
send_email("Cirrus Daily Network Summary", "\n".join(lines))
