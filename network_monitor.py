#!/usr/bin/env python3
import subprocess
import curses
import re
import os
import time
from collections import defaultdict, Counter

# Parse SSH log lines
def parse_ssh_log():
    log_paths = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
    entries = []
    for log in log_paths:
        if os.path.exists(log):
            with open(log) as f:
                entries.extend(f.readlines())
    parsed_entries = []
    for entry in entries:
        m_fail = re.search(r'(Failed|Invalid user|authentication failure).*?for(?: invalid user)? (\S+) from (\S+)', entry)
        m_accept = re.search(r'Accepted (\S+) for (\S+) from (\S+)', entry)
        if m_fail:
            parsed_entries.append(('SSH_FAIL', m_fail.group(2), m_fail.group(3), m_fail.group(1)))
        elif m_accept:
            parsed_entries.append(('SSH_SUCCESS', m_accept.group(2), m_accept.group(3), m_accept.group(1)))
    return parsed_entries

# Parse Apache log lines
def parse_apache_log():
    log_paths = ['/var/log/httpd/access_log', '/var/log/httpd/ssl_access_log']
    entries = []
    for log in log_paths:
        if os.path.exists(log):
            with open(log) as f:
                entries.extend(f.readlines())
    parsed_entries = []
    for entry in entries:
        m = re.match(r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) .*', entry)
        if m:
            ip, time_str, method, url, protocol, status = m.groups()
            parsed_entries.append(('HTTP', ip, method, url, status))
    return parsed_entries

# Main dashboard
def dashboard(stdscr):
    curses.curs_set(0)
    current_screen = 0
    last_update = 0
    detailed_ssh_data = {}
    detailed_http_data = []

    while True:
        if time.time() - last_update > 5:
            ssh_log_entries = parse_ssh_log()
            apache_log_entries = parse_apache_log()
            detailed_ssh_data = defaultdict(lambda: {'success': 0, 'fail': 0, 'users': Counter()})

            for status, user, ip, _ in ssh_log_entries:
                if status == 'SSH_SUCCESS':
                    detailed_ssh_data[ip]['success'] += 1
                else:
                    detailed_ssh_data[ip]['fail'] += 1
                detailed_ssh_data[ip]['users'][user] += 1

            detailed_http_data = apache_log_entries[-50:]
            last_update = time.time()

        stdscr.erase()
        h, w = stdscr.getmaxyx()

        if current_screen == 0:
            stdscr.addstr(0, 0, "Security Dashboard (Press TAB for details, Q to quit)", curses.A_BOLD)
            stdscr.addstr(2, 0, "SSH Access Summary:", curses.A_UNDERLINE)
            row = 3
            for ip, stats in sorted(detailed_ssh_data.items(), key=lambda x: -(x[1]['fail']+x[1]['success']))[:10]:
                users = ', '.join(stats['users'].keys())
                stdscr.addstr(row, 0, f"{ip:<18} Success: {stats['success']:<3} Fail: {stats['fail']:<3} Users: {users}")
                row += 1

            row += 1
            stdscr.addstr(row, 0, "Recent HTTP Requests:", curses.A_UNDERLINE)
            row += 1
            for entry in detailed_http_data[-(h-row-2):]:
                ip, method, url, status = entry[1], entry[2], entry[3], entry[4]
                stdscr.addstr(row, 0, f"{ip:<18} {method:<6} {url[:w-30]:<40} Status: {status}")
                row += 1
        else:
            stdscr.addstr(0, 0, "Detailed Access Attempts (Press TAB for summary, Q to quit)", curses.A_BOLD)
            row = 2
            combined_entries = (ssh_log_entries + apache_log_entries)[-50:]
            for entry in reversed(combined_entries):
                if entry[0] in ('SSH_FAIL', 'SSH_SUCCESS'):
                    status, user, ip, method = entry
                    stdscr.addstr(row, 0, f"{ip:<18} SSH {status:<10} User: {user} ({method})")
                elif entry[0] == 'HTTP':
                    _, ip, method, url, status = entry
                    stdscr.addstr(row, 0, f"{ip:<18} HTTP {method:<6} {url[:w-35]:<40} Status: {status}")
                row += 1
                if row >= h - 1:
                    break

        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            break
        elif key == 9:
            current_screen = (current_screen + 1) % 2

if __name__ == "__main__":
    curses.wrapper(dashboard)
