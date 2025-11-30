#!/usr/bin/env python3
import os
import json
import re
import sys
import glob
from collections import Counter
from datetime import datetime

sys.dont_write_bytecode = True

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(REPO_ROOT, "scripts", "logs")
OUTPUT_FILE = os.path.join(LOGS_DIR, "domain name.txt")
LOG_POINTER_FILE = os.path.join(LOGS_DIR, "log")

def format_timestamp(ts_str):
    if not ts_str:
        return ""
    ts_str = str(ts_str).strip()
    
    if ts_str.isdigit() and len(ts_str) == 14:
        return ts_str
        
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.strftime('%Y%m%d%H%M%S')
    except Exception:
        nums = re.findall(r'\d+', ts_str)
        joined = "".join(nums)
        if len(joined) >= 14:
            return joined[:14]
            
    return ""

def load_existing_domains(filepath):
    counts = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        domain = parts[0]
                        try:
                            count = int(parts[1])
                            counts[domain] = count
                        except ValueError:
                            pass
        except Exception as e:
            print(f"读取现有统计文件出错: {e}")
    return counts

def save_domains(filepath, counts):
    sorted_domains = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for domain, count in sorted_domains:
                f.write(f"{domain} {count}\n")
        print(f"已保存 {len(sorted_domains)} 个域名统计到 {os.path.basename(filepath)}")
    except Exception as e:
        print(f"保存统计文件出错: {e}")

def get_last_processed_log():
    if not os.path.exists(LOG_POINTER_FILE):
        return None, None
    try:
        with open(LOG_POINTER_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if ' ' in content:
                parts = content.split(' ', 1)
                return parts[0], parts[1]
    except Exception:
        pass
    return None, None

def update_last_processed_log(domain, timestamp):
    ts = format_timestamp(timestamp)
    if domain and ts:
        try:
            with open(LOG_POINTER_FILE, 'w', encoding='utf-8') as f:
                f.write(f"{domain} {ts}")
        except Exception as e:
            print(f"更新日志进度文件失败: {e}")

def process_logs():
    log_pattern = os.path.join(LOGS_DIR, "querylog*.json")
    files = glob.glob(log_pattern)
    
    if not files:
        print("未发现新的日志文件 (querylog*.json)")
        return

    last_domain, last_ts = get_last_processed_log()
    
    domain_counts = load_existing_domains(OUTPUT_FILE)
    
    new_events_count = 0
    latest_processed = {"domain": last_domain, "ts": last_ts}
    
    files.sort()
    
    for log_file in files:
        print(f"正在处理: {os.path.basename(log_file)}")
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        domain = entry.get('QH')
                        ts_raw = entry.get('T')
                        
                        if not domain or not ts_raw:
                            continue
                            
                        ts_formatted = format_timestamp(ts_raw)
                        
                        if last_ts and ts_formatted:
                            if ts_formatted < last_ts:
                                continue
                            if ts_formatted == last_ts and domain == last_domain:
                                continue
                                
                        if not latest_processed["ts"] or (ts_formatted and ts_formatted >= latest_processed["ts"]):
                            latest_processed["domain"] = domain
                            latest_processed["ts"] = ts_formatted
                            
                        domain_counts[domain] = domain_counts.get(domain, 0) + 1
                        new_events_count += 1
                        
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"处理文件 {log_file} 出错: {e}")

    if new_events_count > 0:
        print(f"新增处理 {new_events_count} 条记录")
        save_domains(OUTPUT_FILE, domain_counts)
        update_last_processed_log(latest_processed["domain"], latest_processed["ts"])
    else:
        print("没有符合条件的新记录")

    for f in files:
        try:
            os.remove(f)
            print(f"已删除日志文件: {os.path.basename(f)}")
        except OSError as e:
            print(f"删除文件失败 {f}: {e}")

if __name__ == "__main__":
    process_logs()
