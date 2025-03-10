#!/usr/bin/env python3
import subprocess
import re
import curses
import time
import argparse
import pwd
import shlex
import socket
import requests
from collections import Counter
import threading
import signal
import sys
import os

# Global variables
running = True
ip_locations = {}  # Cache for IP to location mapping

def get_ip_location(ip):
    """Get location information for an IP address using multiple services."""
    if ip in ip_locations:
        return ip_locations[ip]
    
    # Primary lookup using ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                city = data.get("city") or "Unknown"
                country = data.get("country") or "Unknown"
                location = f"{city}, {country}"
                ip_locations[ip] = location
                return location
    except Exception:
        pass

    # Fallback: ipinfo.io
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city", "Unknown")
            country = data.get("country", "Unknown")
            location = f"{city}, {country}"
            ip_locations[ip] = location
            return location
    except Exception:
        pass

    # Last resort: reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        ip_locations[ip] = f"({hostname})"
        return ip_locations[ip]
    except (socket.herror, socket.gaierror):
        ip_locations[ip] = "Unknown"
        return "Unknown"

def parse_line(line):
    """
    Parses a log line for SSH login events.
    Returns a tuple: (event_type, username, ip, method)
    where event_type is 'FAILED' or 'ACCEPTED', and method is e.g. "password" or "publickey".
    """
    # Failed patterns
    failed_patterns = [
        (r'Failed password for (invalid user )?(\S+) from (\S+)', "password"),
        (r'Failed (password|publickey) for .*? from (\S+) port', None),  # method captured
        (r'Invalid user (\S+) from (\S+)', "invalid_user"),
        (r'authentication failure.* rhost=(\S+)( user=(\S+))?', "auth_failure")
    ]
    
    for idx, (pattern, default_method) in enumerate(failed_patterns):
        m_failed = re.search(pattern, line)
        if m_failed:
            if idx == 0:
                username = m_failed.group(2)
                ip = m_failed.group(3)
                method = default_method
            elif idx == 1:
                method = m_failed.group(1)  # "password" or "publickey"
                username = "unknown"
                ip = m_failed.group(2)
            elif idx == 2:
                username = m_failed.group(1)
                ip = m_failed.group(2)
                method = default_method
            elif idx == 3:
                ip = m_failed.group(1)
                username = m_failed.group(3) if m_failed.group(3) else "unknown"
                method = default_method
            return ('FAILED', username, ip, method)
    
    # Accepted pattern
    accepted_pattern = r'Accepted (password|publickey) for (\S+) from (\S+)'
    m_accepted = re.search(accepted_pattern, line)
    if m_accepted:
        method = m_accepted.group(1)
        username = m_accepted.group(2)
        ip = m_accepted.group(3)
        return ('ACCEPTED', username, ip, method)
    
    return None

def get_active_files(monitor_user, limit=10):
    """Returns active file handles (using lsof) for the given user."""
    cmd = f"lsof -u {shlex.quote(monitor_user)}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            # Skip header line; you can add filtering if needed.
            return lines[1:limit+1]
        else:
            return ["No active files found."]
    except Exception as e:
        return [f"Error retrieving active files: {str(e)}"]

def get_recent_files(monitor_user, num_files=10):
    """Returns a list of strings showing recently accessed files for the given user.
       Note: This uses filesystem atime and may include routine program accesses."""
    try:
        user_info = pwd.getpwnam(monitor_user)
        home_dir = user_info.pw_dir
    except KeyError:
        return [f"User {monitor_user} not found."]
    
    cmd = f"find {shlex.quote(home_dir)} -type f -printf '%A@ %p\n' 2>/dev/null | sort -nr | head -n {num_files}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().splitlines()
        output = []
        for line in lines:
            parts = line.split(' ', 1)
            if len(parts) == 2:
                atime_epoch, path = parts
                try:
                    atime_epoch = float(atime_epoch)
                    atime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(atime_epoch))
                except Exception:
                    atime_str = atime_epoch
                output.append(f"{atime_str}  {path}")
        return output if output else ["No recent file accesses found."]
    except subprocess.TimeoutExpired:
        return ["File access scan timed out."]
    except Exception as e:
        return [f"Error: {str(e)}"]

def get_active_ssh_sessions():
    """Get list of currently active SSH sessions."""
    sessions = []
    # First, check the current SSH connection from the environment.
    if "SSH_CONNECTION" in os.environ:
        parts = os.environ["SSH_CONNECTION"].split()
        if len(parts) >= 4:
            source_ip = parts[0]
            user = os.environ.get("USER", "unknown")
            sessions.append(f"{user:<15} {source_ip:<15} active (current session)")
    
    # Then try 'who'
    try:
        result = subprocess.run("who | grep -i ssh", shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    user = parts[0]
                    # Extract IP from parentheses if available
                    ip_candidate = None
                    for part in parts:
                        if part.startswith("(") and part.endswith(")"):
                            ip_candidate = part.strip("()")
                            break
                    if ip_candidate:
                        sessions.append(f"{user:<15} {ip_candidate:<15} logged in")
        else:
            # Fallback using 'w'
            result = subprocess.run("w | grep -i ssh", shell=True, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    sessions.append(f"{parts[0]:<15} {parts[2]:<15} logged in")
    except Exception:
        pass
    
    if not sessions:
        sessions.append("No active SSH sessions detected.")
    return sessions

def get_banned_ips():
    """Get list of IPs banned by fail2ban."""
    try:
        check = subprocess.run("which fail2ban-client", shell=True, capture_output=True, text=True)
        if not check.stdout.strip():
            return ["fail2ban-client not found - can't retrieve banned IPs"]
        
        jails_result = subprocess.run("sudo fail2ban-client status | grep 'Jail list' | sed 's/^.*://g'", shell=True, capture_output=True, text=True)
        jails = jails_result.stdout.strip().split(', ')
        banned_ips = []
        
        for jail in jails:
            jail = jail.strip()
            if jail:
                cmd = f"sudo fail2ban-client status {jail} | grep 'Banned IP list' | sed 's/^.*://g'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                ips = result.stdout.strip().split()
                for ip in ips:
                    if ip:
                        banned_ips.append((ip, jail))
        
        if not banned_ips:
            return ["No IPs currently banned by fail2ban"]
        
        formatted_results = []
        for ip, jail in banned_ips:
            location = get_ip_location(ip)
            formatted_results.append(f"{ip:<15} ({jail}) - {location}")
        return formatted_results
    except Exception as e:
        return [f"Error retrieving banned IPs: {str(e)}"]

def get_auth_log_entries(num_entries=100):
    """Get recent SSH auth log entries from possible log sources and journalctl."""
    combined_entries = []
    log_files = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                cmd = f"grep -i 'ssh' {log_file} | tail -n {num_entries}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.stdout:
                    for line in result.stdout.splitlines():
                        parsed = parse_line(line)
                        if parsed:
                            result_type, username, ip, method = parsed
                            timestamp = time.strftime("%H:%M:%S")
                            entry = f"{timestamp}  {username:<15} {ip:<15} {method}"
                            combined_entries.append((result_type, entry, ip))
            except Exception:
                pass
    
    if not combined_entries:
        try:
            cmd = "journalctl -u sshd --since '1 hour ago' | grep -i 'ssh'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                for line in result.stdout.splitlines():
                    parsed = parse_line(line)
                    if parsed:
                        result_type, username, ip, method = parsed
                        timestamp = time.strftime("%H:%M:%S")
                        entry = f"{timestamp}  {username:<15} {ip:<15} {method}"
                        combined_entries.append((result_type, entry, ip))
        except Exception:
            pass
            
    failed_entries = [entry for type_entry, entry, _ in combined_entries if type_entry == 'FAILED']
    accepted_entries = [entry for type_entry, entry, _ in combined_entries if type_entry == 'ACCEPTED']
    
    for ip in set(ip for _, _, ip in combined_entries):
        get_ip_location(ip)  # Populate cache
    
    return failed_entries, accepted_entries

def get_top_attackers(failed_attempts, limit=5):
    """Return the top IPs with failed login attempts."""
    ip_pattern = r'.+\s+\S+\s+(\S+)\s+'
    ips = []
    for entry in failed_attempts:
        match = re.search(ip_pattern, entry)
        if match:
            ips.append(match.group(1))
    counter = Counter(ips)
    return counter.most_common(limit)

def signal_handler(sig, frame):
    """Handle termination signals."""
    global running
    running = False
    print("\nShutting down gracefully...")
    sys.exit(0)

def main(stdscr, monitor_user, max_entries=20):
    global running
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(1000)
    
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)     # Failed attempts
    curses.init_pair(2, curses.COLOR_GREEN, -1)   # Accepted logins
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Headings
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # Active files
    curses.init_pair(5, curses.COLOR_MAGENTA, -1) # Banned IPs
    
    failed_attempts = []
    accepted_attempts = []
    recent_files = get_recent_files(monitor_user)
    active_files = get_active_files(monitor_user)
    active_sessions = get_active_ssh_sessions()
    banned_ips = get_banned_ips()
    failed_attempts, accepted_attempts = get_auth_log_entries()
    
    file_update_interval = 30
    session_update_interval = 15
    banned_update_interval = 20
    log_update_interval = 10
    active_files_interval = 10
    
    last_file_update = 0
    last_session_update = 0
    last_banned_update = 0
    last_log_update = 0
    last_active_files_update = 0
    
    while running:
        current_time = time.time()
        
        if current_time - last_file_update >= file_update_interval:
            recent_files = get_recent_files(monitor_user)
            last_file_update = current_time
            
        if current_time - last_session_update >= session_update_interval:
            active_sessions = get_active_ssh_sessions()
            last_session_update = current_time
            
        if current_time - last_banned_update >= banned_update_interval:
            banned_ips = get_banned_ips()
            last_banned_update = current_time
            
        if current_time - last_log_update >= log_update_interval:
            failed_attempts, accepted_attempts = get_auth_log_entries()
            last_log_update = current_time

        if current_time - last_active_files_update >= active_files_interval:
            active_files = get_active_files(monitor_user)
            last_active_files_update = current_time
        
        max_y, max_x = stdscr.getmaxyx()
        stdscr.erase()
        title = "SSH Login & File Access Monitor Dashboard (press 'q' to quit, 'r' to refresh)"
        stdscr.addstr(0, 0, title[:max_x-1], curses.A_BOLD | curses.color_pair(3))
        row = 1
        
        # Banned IPs section
        stdscr.addstr(row, 0, "Banned IPs (fail2ban):", curses.A_BOLD | curses.color_pair(5))
        row += 1
        for entry in banned_ips[:max_entries//2]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3], curses.color_pair(5))
                row += 1
        
        row += 1
        
        # Top attackers
        top_attackers = get_top_attackers(failed_attempts)
        stdscr.addstr(row, 0, "Top Failed IPs:", curses.A_BOLD | curses.color_pair(3))
        row += 1
        for ip, count in top_attackers:
            if row < max_y:
                location = get_ip_location(ip)
                attacker_info = f"{ip:<15} ({count} attempts) - {location}"
                stdscr.addstr(row, 2, attacker_info[:max_x-3], curses.color_pair(1))
                row += 1
        
        row += 1
        
        # Failed SSH Attempts with method column
        stdscr.addstr(row, 0, "Failed SSH Attempts:", curses.A_BOLD | curses.color_pair(3))
        row += 1
        for entry in failed_attempts[-max_entries:]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3], curses.color_pair(1))
                row += 1
        
        row += 1
        
        # Successful SSH Logins with method column
        stdscr.addstr(row, 0, "Successful SSH Logins:", curses.A_BOLD | curses.color_pair(3))
        row += 1
        for entry in accepted_attempts[-max_entries:]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3], curses.color_pair(2))
                row += 1
        
        row += 1
        
        # Active SSH Sessions
        stdscr.addstr(row, 0, "Active SSH Sessions:", curses.A_BOLD | curses.color_pair(3))
        row += 1
        for entry in active_sessions[:max_entries]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3], curses.color_pair(2))
                row += 1
        
        row += 1
        
        # Active File Requests (via lsof)
        stdscr.addstr(row, 0, f"Active File Requests for '{monitor_user}':", curses.A_BOLD | curses.color_pair(4))
        row += 1
        for entry in active_files[:max_entries]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3], curses.color_pair(4))
                row += 1
        
        row += 1


        if row < max_y:
            stdscr.addstr(row, 0, f"Recently Accessed Files for '{monitor_user}':", curses.A_BOLD | curses.color_pair(3))
        row += 1

        for entry in recent_files[:max_entries]:
            if row < max_y:
                stdscr.addstr(row, 2, entry[:max_x-3])
                row += 1
        
        stdscr.refresh()
        c = stdscr.getch()
        if c == ord('q'):
            running = False
            break
        elif c == ord('r'):
            last_file_update = last_session_update = last_banned_update = last_log_update = last_active_files_update = 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH and File Access Monitor Dashboard")
    parser.add_argument("--user", type=str, default="root", help="User to monitor for file accesses (default: root)")
    parser.add_argument("--entries", type=int, default=10, help="Maximum entries to display per section (default: 10)")
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        curses.wrapper(main, args.user, args.entries)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        running = False
