#!/usr/bin/env python3
import os
import re
import sys
import time
import requests
import datetime
from typing import List, Set

sys.dont_write_bytecode = True

class AdGuardRuleManager:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.black_file = os.path.join(self.base_dir, "Black.txt")
        self.white_file = os.path.join(self.base_dir, "White.txt")
        self.pure_file = os.path.join(self.base_dir, "pure black.txt")
        
        self.domain_file = os.path.join(self.base_dir, "scripts", "logs", "domain name.txt")

        self.blacklist_sources = {
            "AdGuard DNS filter":        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            "秋风的规则":                "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
            #"GitHub加速":                "https://raw.githubusercontent.com/521xueweihan/GitHub520/refs/heads/main/hosts",
            #"DD自用":                   "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
            #"广告规则":                 "https://raw.githubusercontent.com/huantian233/HT-AD/main/AD.txt",
            "消失DD":                    "https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/dns.txt",
            "大萌主":                   "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
            "qy-Ads-Rule":           "https://raw.gitcode.com/rssv/qy-Ads-Rule/raw/main/black.txt",
            "下个ID见":                  "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
            "那个谁520":                "https://raw.githubusercontent.com/qq5460168/666/master/dns.txt",
            "TTDNS":                   "https://raw.githubusercontent.com/TTDNS/Cat/refs/heads/main/DNS.TXT",
            "茯苓的广告规则":            "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingBlockList.txt",
            "HG":                      "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
            "anti-ad":                  "https://anti-ad.net/easylist.txt",
            "adg-kall-dns":            "https://www.kbsml.com/wp-content/uploads/adblock/adguard/adg-kall-dns.txt",
            "DNS-Kuner":                 "https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/blacklist.txt",
            "666":                       "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt",
            #"StevenBlack":               "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
            #"neodevpro":                 "https://raw.githubusercontent.com/neodevpro/neodevhost/master/host",
        }

        self.whitelist_sources = {
            "茯苓允许列表":              "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/Master/FuLingRules/FuLingAllowList.txt",
            "个人自用白名单":            "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
            "DNS-Kuner":         "https://raw.githubusercontent.com/Kuner-mw/DNS-Kuner/main/FilterRules/allowlist.txt",
            #"BlueSkyXN":                 "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt",
            "那个谁520广告白名单":        "https://raw.githubusercontent.com/qq5460168/666/master/allow.txt",
            "AdGuardHome通用白名单":     "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
            #"jhsvip白名单":              "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
            #"liwenjie119白名单":         "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
            #"喵二白名单":                "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
            #"Cats-Team白名单":           "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
            #"浅笑白名单":                 "https://raw.githubusercontent.com/user001235/112/main/white.txt",
        }

        



        self.fallback_sources = ["anti-ad", "AdGuard DNS filter"]

    def get_beijing_time(self) -> str:
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get("https://www.baidu.com", headers=headers, timeout=3)
            if 'Date' in resp.headers:
                date_str = resp.headers['Date']
                gmt = datetime.datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S GMT')
                return (gmt + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def clean_rule(self, rule: str) -> str:
        rule = rule.strip().lstrip('\ufeff')
        
        if not rule or rule.startswith(('!', '#')):
            return None
            
        if ' # ' in rule:
            rule = rule.split(' # ')[0].strip()
        if ' ! ' in rule:
            rule = rule.split(' ! ')[0].strip()
            
        if rule.startswith(('-', '_', '+', ':', '?', '[')):
            return None
            
        if '://' in rule:
            return None

        if rule.startswith('/') and rule.endswith('/'):
            pass
        elif '/' in rule:
             return None
        
        if not (rule.startswith('/') and rule.endswith('/')):
             rule = rule.strip(':/')

        if rule.startswith('.'):
            if re.match(r'^\.\d+x\d+', rule):
                return None
            rule = "||" + rule.lstrip('.')

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rule):
            parts = rule.split()
            
            if len(parts) == 1:
                ip_only = parts[0].rstrip('^')
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_only):
                    return f"||{ip_only}^"
                else:
                    return None
                
            if len(parts) >= 2:
                ip = parts[0]
                domain = parts[1]
                
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                    return None
                    
                if ip in ['0.0.0.0', '127.0.0.1', '::1']:
                    return f"||{domain}^"
                else:
                    return f"{ip} {domain}"

        if '^' in rule:
            caret_idx = rule.find('^')
            dollar_idx = rule.find('$', caret_idx)
            
            if dollar_idx != -1:
                base_rule = rule[:caret_idx+1]
                modifiers = rule[dollar_idx:]
                rule = base_rule + modifiers
            else:
                rule = rule[:caret_idx+1]
            
        if len(rule) < 3:
            return None
        if not any(c.isalpha() for c in rule) and not any(c.isdigit() for c in rule):
            return None
            
        if rule.isalnum() and '.' not in rule and not rule.startswith(('||', '@@')):
             return None
             
        check_part = rule
        if rule.startswith('@@||'): check_part = rule[4:]
        elif rule.startswith('||'): check_part = rule[2:]
        
        domain_part = check_part.split('$')[0]
        
        domain_part_clean = domain_part.rstrip('^')
        
        invalid_chars = set('|+,;!\\')
        if any(char in invalid_chars for char in domain_part_clean):
            return None
            
        if rule.startswith('*') and not rule.startswith('||'):
             clean_d = rule.lstrip('*').rstrip('^')
             return f"||{clean_d}^"

        return rule

    def format_whitelist_rule(self, rule: str) -> str:
        cleaned = self.clean_rule(rule)
        if not cleaned:
            return None
            
        if cleaned.startswith("@@"):
            return cleaned
            
        domain = re.sub(r'[@|]', '', cleaned)
        domain = domain.strip()
        if not domain:
            return None
            
        suffix = "" if domain.endswith('^') else "^"
        return f"@@||{domain}{suffix}"

    def fetch_rules(self, sources: dict) -> List[str]:
        rules = []
        for name, url in sources.items():
            print(f"正在下载: {name}...")
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    for line in lines:
                        cl = self.clean_rule(line)
                        if cl:
                            rules.append(cl)
                else:
                    print(f"下载失败 {name}: HTTP {resp.status_code}")
            except Exception as e:
                print(f"下载出错 {name}: {e}")
        return rules

    def save_file(self, filepath, rules, header_info):
        try:
            with open(filepath, 'w', encoding='utf-8-sig') as f:
                f.write(header_info)
                for r in rules:
                    f.write(r + "\n")
            print(f"已保存: {os.path.basename(filepath)} ({len(rules)} 条规则)")
        except Exception as e:
            print(f"保存失败 {filepath}: {e}")

    def load_domain_list(self) -> Set[str]:
        domains = set()
        if os.path.exists(self.domain_file):
            try:
                with open(self.domain_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.startswith('#') and line.strip():
                            parts = line.split()
                            if parts:
                                domains.add(parts[0].lower())
                print(f"加载域名库: {len(domains)} 条")
            except Exception as e:
                print(f"读取域名文件失败: {e}")
        else:
            print(f"提示: 未找到域名统计文件 {self.domain_file}，pure black.txt 将包含所有黑名单规则")
        return domains

    def run(self):
        print("=== 开始执行 AdGuard 规则更新 ===")
        start_time = self.get_beijing_time()
        
        print("--- 正在获取黑名单源 ---")
        raw_black = self.fetch_rules(self.blacklist_sources)
        
        print("--- 正在获取白名单源 ---")
        raw_white = self.fetch_rules(self.whitelist_sources)
        
        blacklist_set = set()
        whitelist_set = set()
        
        for r in raw_black:
            if r.startswith("@@"):
                whitelist_set.add(r)
            else:
                blacklist_set.add(r)
                
        for r in raw_white:
            fmt = self.format_whitelist_rule(r)
            if fmt:
                whitelist_set.add(fmt)
                
        white_domains = set()
        for w in whitelist_set:
            d = w.replace("@@||", "").replace("^", "")
            white_domains.add(d)
            
        conflict_count = 0
        final_blacklist = []
        for b in blacklist_set:
            if b.startswith("||") and b.endswith("^"):
                d = b[2:-1]
                if d in white_domains:
                    conflict_count += 1
                    continue
            final_blacklist.append(b)
            
        if conflict_count > 0:
            print(f"已移除 {conflict_count} 条与白名单冲突的黑名单规则")
            
        final_blacklist.sort()
        final_whitelist = sorted(list(whitelist_set))
        
        matched_blacklist = []
        domain_db = self.load_domain_list()
        
        fallback_source_rules = set()
        if self.fallback_sources:
            print(f"--- 正在获取兜底规则源 ---")
            fallback_sources_dict = {name: self.blacklist_sources[name] 
                                    for name in self.fallback_sources 
                                    if name in self.blacklist_sources}
            fallback_rules_raw = self.fetch_rules(fallback_sources_dict)
            for r in fallback_rules_raw:
                if not r.startswith("@@"):
                    fallback_source_rules.add(r)
            print(f"兜底规则源共 {len(fallback_source_rules)} 条规则")
        
        if domain_db:
            print(f"正在根据域名库过滤黑名单...")
            matched_count = 0
            
            for rule in final_blacklist:
                if rule in fallback_source_rules:
                    continue
                
                domain = ""
                if rule.startswith("||") and rule.endswith("^"):
                    domain = rule[2:-1]
                elif rule.startswith("||"):
                    parts = rule[2:].split('^')
                    if parts:
                        domain = parts[0]
                elif not rule.startswith(('*', '/')):
                    parts = rule.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                
                if domain and domain.lower() in domain_db:
                    matched_blacklist.append(rule)
                    matched_count += 1
            
            matched_blacklist.extend(list(fallback_source_rules))
            print(f"过滤完成: 匹配的黑名单 {matched_count} 条 + 兜底规则 {len(fallback_source_rules)} 条 = 总计 {len(matched_blacklist)} 条")
        else:
            matched_blacklist = final_blacklist

        black_header = f"# 更新时间: {start_time}\n"
        black_header += f"# 总规则数: {len(final_blacklist) + len(final_whitelist)} (黑: {len(final_blacklist)}, 白: {len(final_whitelist)})\n"
        black_header += f"# 作者: dongone33 (Merged by Script)\n"
        black_header += "# ------------------------------------------\n\n"
        self.save_file(self.black_file, final_blacklist + final_whitelist, black_header)
        
        white_header = f"# 更新时间: {start_time}\n"
        white_header += f"# 白名单规则数: {len(final_whitelist)}\n"
        white_header += f"# 作者: dongone33 (Merged by Script)\n"
        white_header += "# ------------------------------------------\n\n"
        self.save_file(self.white_file, final_whitelist, white_header)
        
        pure_header = f"# 更新时间: {start_time}\n"
        pure_header += f"# 纯黑名单规则数: {len(matched_blacklist) + len(final_whitelist)} (黑: {len(matched_blacklist)}, 白: {len(final_whitelist)})\n"
        pure_header += f"# 说明: 与域名库匹配的黑名单 + 兜底规则源({', '.join(self.fallback_sources)}) + 全量白名单\n"
        pure_header += f"# 作者: dongone33 (Merged by Script)\n"
        pure_header += "# ------------------------------------------\n\n"
        self.save_file(self.pure_file, matched_blacklist + final_whitelist, pure_header)
        
        print("=== 规则更新完成 ===")

if __name__ == "__main__":
    manager = AdGuardRuleManager()
    manager.run()
