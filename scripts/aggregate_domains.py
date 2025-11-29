import os
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
import glob
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(REPO_ROOT, "scripts", "logs")
OUTPUT_FILE = os.path.join(LOGS_DIR, "domain name.txt")
LOG_FILE = os.path.join(LOGS_DIR, "log")

def read_latest_log_info():
    if not os.path.exists(LOG_FILE):
        return None, None
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
            if content:
                parts = content.split(' ', 1)
                if len(parts) == 2:
                    domain, timestamp = parts
                    return domain, timestamp
    except Exception as e:
        print(f"Error reading log file: {e}")
    
    return None, None

def save_latest_log_info(domain, timestamp):
    formatted_time = format_timestamp(timestamp)
    
    if domain and formatted_time:
        with open(LOG_FILE, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(f"{domain} {formatted_time}")
    else:
        print(f"Warning: Invalid domain or timestamp: domain='{domain}', timestamp='{timestamp}', formatted='{formatted_time}'")

def merge_domain_counts(new_counts):
    existing_counts = {}
    
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.rsplit(' ', 1)
                        if len(parts) == 2:
                            domain, count = parts
                            try:
                                existing_counts[domain] = int(count)
                            except ValueError:
                                print(f"Warning: Invalid count format in line: {line}")
        except Exception as e:
            print(f"Error reading existing domain name.txt: {e}")
    
    for domain, count in new_counts.items():
        if domain in existing_counts:
            existing_counts[domain] += count
        else:
            existing_counts[domain] = count
    
    return existing_counts

def format_timestamp(timestamp):
    if not timestamp:
        return ""
    if isinstance(timestamp, str) and timestamp.isdigit() and len(timestamp) == 14:
        return timestamp
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y%m%d%H%M%S')
    except (ValueError, TypeError, AttributeError):
        try:
            match = re.search(r'(\d{4})-?(\d{2})-?(\d{2})T?(\d{2}):?(\d{2}):?(\d{2})', str(timestamp))
            if match:
                year, month, day, hour, minute, second = match.groups()
                return f"{year}{month}{day}{hour}{minute}{second}"
        except:
            pass
    
    print(f"Warning: Could not format timestamp: {timestamp}")
    return ""

def main():
    log_files = glob.glob(os.path.join(LOGS_DIR, "querylog*.json"))
    if not log_files:
        print("No querylog files found. No updates needed.")
        return
    last_domain, last_timestamp = read_latest_log_info()
    if last_domain and last_timestamp:
        print(f"Last processed log: domain={last_domain}, timestamp={last_timestamp}")
    log_files.sort()
    domain_counts = Counter()
    seen_events = set()
    latest_domain = None
    latest_timestamp = None
    total_events = 0
    for log_file in log_files:
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                line_index = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        domain = None
                        if 'QH' in entry:
                            domain = entry['QH']
                        timestamp = None
                        if 'T' in entry:
                            timestamp = entry['T']
                        client_ip = None
                        if 'IP' in entry:
                            client_ip = entry['IP']
                        query_type = None
                        if 'QT' in entry:
                            query_type = entry['QT']
                        if domain and timestamp:
                            formatted_current = format_timestamp(timestamp)
                            if last_domain and last_timestamp:
                                if (domain == last_domain and formatted_current == last_timestamp) or formatted_current < last_timestamp:
                                    continue
                            if latest_timestamp is None or timestamp > latest_timestamp:
                                latest_domain = domain
                                latest_timestamp = timestamp
                            event_key = None
                            if client_ip and query_type:
                                event_key = (domain, timestamp, client_ip, query_type)
                            else:
                                event_key = (domain, os.path.basename(log_file), line_index)
                            if event_key not in seen_events:
                                domain_counts[domain] += 1
                                seen_events.add(event_key)
                                total_events += 1
                    except json.JSONDecodeError:
                        pass
                    line_index += 1
        except Exception as e:
            print(f"Error processing {log_file}: {e}")
    if total_events == 0:
        print("No new events to process. No updates needed.")
        return
    merged_counts = merge_domain_counts(domain_counts)
    sorted_domains = sorted(merged_counts.items(), key=lambda x: (-x[1], x[0]))
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for domain, count in sorted_domains:
            f.write(f"{domain} {count}\n")
    print(f"Wrote '{OUTPUT_FILE}' with {len(sorted_domains)} domains. Unique events: {total_events}")
    if latest_domain and latest_timestamp:
        save_latest_log_info(latest_domain, latest_timestamp)
        print(f"Saved latest log info to '{LOG_FILE}'")
    for log_file in log_files:
        try:
            os.remove(log_file)
            print(f"Deleted: {os.path.basename(log_file)}")
        except Exception as e:
            print(f"Error deleting {log_file}: {e}")

if __name__ == "__main__":
    main()
