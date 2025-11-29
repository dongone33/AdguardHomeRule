import os
import re
import requests
import datetime
from urllib.parse import urlparse
from typing import Set, List, Tuple

class AdGuardRulesSimplifier:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.domain_file = os.path.join(self.base_dir, "scripts", "logs", "domain name.txt")
        self.output_file = os.path.join(self.base_dir, "pure black.txt")
        
        self.black_url = os.path.join(self.base_dir, "Black.txt")
        self.white_file = os.path.join(self.base_dir, "White.txt")
        self.autumn_url = "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
        self.github_url = "https://raw.githubusercontent.com/521xueweihan/GitHub520/refs/heads/main/hosts"
    
    def read_updated_time_from_black(self) -> str:
        try:
            if os.path.exists(self.black_url):
                with open(self.black_url, 'r', encoding='utf-8', errors='ignore') as f:
                    for _ in range(10):
                        line = f.readline()
                        if not line:
                            break
                        s = line.strip().lstrip('\ufeff')
                        m = re.match(r"^#\s*更新时间[:：]\s*(.+)$", s)
                        if m:
                            return m.group(1).strip()
        except Exception:
            pass
        return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        
    def download_rules(self, url: str) -> List[str]:
        if os.path.exists(url):
            try:
                print(f"读取本地规则: {url}")
                with open(url, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.rstrip('\n') for line in f]
            except Exception as e:
                print(f"读取本地规则失败 {url}: {e}")
                return []
        try:
            print(f"正在下载规则: {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text.splitlines()
        except Exception as e:
            print(f"下载规则失败 {url}: {e}")
            return []
    
    def load_domain_list(self) -> Set[str]:
        domains = set()
        if os.path.exists(self.domain_file):
            try:
                with open(self.domain_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domain = line.split()[0] if line.split() else line
                            domains.add(domain.lower())
                print(f"加载了 {len(domains)} 个域名")
            except Exception as e:
                print(f"读取域名文件失败: {e}")
        else:
            print("域名文件不存在")
        return domains
    
    def remove_comments(self, rules: List[str]) -> List[str]:
        cleaned_rules = []
        for rule in rules:
            rule = rule.strip().lstrip('\ufeff')
            if rule and not rule.startswith(('@', '!', '#')):
                cleaned_rules.append(rule)
        return cleaned_rules

    def sanitize_caret_suffixes(self, rules: List[str]) -> List[str]:
        cleaned = []
        for rule in rules:
            s = str(rule).strip().lstrip('\ufeff')
            if not s:
                continue
            idx = s.find('^')
            if idx != -1:
                s = s[:idx + 1]
            cleaned.append(s)
        return cleaned

    def sanitize_file_in_place(self, path: str):
        try:
            if not os.path.exists(path):
                return
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            out_lines = []
            for raw in lines:
                s = raw.strip().lstrip('\ufeff')
                if not s or s.startswith('#') or s.startswith('!'):
                    out_lines.append(s + '\n')
                    continue
                idx = s.find('^')
                if idx != -1:
                    s = s[:idx + 1]
                out_lines.append(s + '\n')
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(out_lines)
            print(f"已就地清理: {path}")
        except Exception as e:
            print(f"清理失败 {path}: {e}")

    def load_whitelist_from_white(self) -> List[str]:
        whitelist = []
        if os.path.exists(self.white_file):
            try:
                with open(self.white_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        s = line.strip().lstrip('\ufeff')
                        if not s or s.startswith('#') or s.startswith('!'):
                            continue
                        whitelist.append(s)
                print(f"读取 White.txt 白名单规则: {len(whitelist)} 条")
            except Exception as e:
                print(f"读取 White.txt 失败: {e}")
        else:
            print("White.txt 文件不存在，跳过追加白名单")
        return whitelist

    def load_whitelist_from_black(self) -> List[str]:
        lines = self.download_rules(self.black_url)
        out = []
        for line in lines:
            s = str(line).strip().lstrip('\ufeff')
            if s and s.startswith('@@'):
                out.append(s)
        out = self.sanitize_caret_suffixes(out)
        print(f"从 Black.txt 提取白名单规则: {len(out)} 条")
        return out
    
    def extract_pipe_rules(self, rules: List[str]) -> Tuple[List[str], List[str]]:
        pipe_rules = []
        remaining_rules = []
        
        for rule in rules:
            rule = rule.strip()
            if rule.startswith('|'):
                pipe_rules.append(rule)
            else:
                remaining_rules.append(rule)
        
        print(f"提取了 {len(pipe_rules)} 个|开头的规则")
        return pipe_rules, remaining_rules
    
    def extract_domain_from_rule(self, rule: str) -> str:
        if rule.startswith('||'):
            domain = rule[2:].split('^')[0].split('/')[0].split(':')[0]
        elif rule.startswith('|'):
            try:
                parsed = urlparse(rule[1:])
                domain = parsed.netloc or parsed.path.split('/')[0]
            except:
                domain = rule[1:].split('/')[0].split(':')[0]
        else:
            domain = rule.split('/')[0].split(':')[0]
        
        return domain.lower().strip()
    
    def match_domains_and_restore(self, pipe_rules: List[str], remaining_rules: List[str], 
                                 domain_set: Set[str]) -> List[str]:
        restored_rules = remaining_rules.copy()
        matched_count = 0
        
        for rule in pipe_rules:
            domain = self.extract_domain_from_rule(rule)
            if domain in domain_set:
                restored_rules.append(rule)
                matched_count += 1
        
        print(f"匹配并恢复了 {matched_count} 个规则")
        return restored_rules
    
    def process_hosts_file(self, hosts_lines: List[str]) -> List[str]:
        adguard_rules = []
        for line in hosts_lines:
            line = line.strip().lstrip('\ufeff')
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                    domain = parts[1]
                    adguard_rules.append(f"||{domain}^")
        return adguard_rules
    
    def merge_and_deduplicate(self, *rule_lists: List[str]) -> List[str]:
        all_rules = set()
        
        for rules in rule_lists:
            for rule in rules:
                rule = rule.strip().lstrip('\ufeff')
                if rule and not rule.startswith(('@', '!', '#')):
                    all_rules.add(rule)
        
        return sorted(list(all_rules))

    def reverse_rules(self, rules: List[str]) -> List[str]:
        return list(reversed(rules))
    
    def save_rules(self, rules: List[str], filename: str = None, black_count: int = None, updated_time: str = None, whitelist_rules: List[str] = None, whitelist_count: int = None, skip_white: bool = False):
        if filename is None:
            filename = self.output_file
        if updated_time is None:
            updated_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        # 规则计数
        if rules is None:
            rules = []
        if whitelist_rules is None:
            whitelist_rules = []
        if black_count is None:
            black_count = len([r for r in rules if str(r).strip()])
        if whitelist_count is None:
            whitelist_count = len([w for w in whitelist_rules if str(w).strip()])
        total_count = black_count if skip_white else (black_count + whitelist_count)

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# 更新时间: {updated_time}\n")
                if skip_white:
                    f.write(f"# 总规则数：{total_count} (黑名单: {black_count})\n")
                else:
                    f.write(f"# 总规则数：{total_count} (黑名单: {black_count}, 白名单: {whitelist_count})\n")
                f.write(f"# 作者名称: Menghuibanxian  酷安名: 梦半仙\n")
                f.write(f"# 作者主页: https://github.com/Menghuibanxian/AdguardHome\n")
                f.write("\n")
                for rule in rules:
                    if str(rule).strip():
                        f.write(rule + "\n")
                if not skip_white:
                    for w in whitelist_rules:
                        if str(w).strip():
                            f.write(w + "\n")
            print(f"规则已保存到: {filename}")
            if skip_white:
                print(f"黑名单: {black_count}，总计: {total_count}")
            else:
                print(f"黑名单: {black_count}，白名单: {whitelist_count}，总计: {total_count}")
        except Exception as e:
            print(f"保存规则失败: {e}")
    
    def run(self, override_time: str = None, skip_white: bool = False):
        print("=== AdGuard规则简化器 ===")
        print("\n1. 加载域名列表...")
        domain_set = self.load_domain_list()
        print("\n2. 处理Black.txt规则...")
        # 先就地清理 Black.txt 源文件中的 ^ 后缀
        self.sanitize_file_in_place(self.black_url)
        # 同步就地清理 White.txt 源文件中的 ^ 后缀
        self.sanitize_file_in_place(self.white_file)
        black_rules = self.download_rules(self.black_url)
        if not black_rules:
            print("无法下载Black.txt规则，跳过处理")
            return
        black_rules = self.remove_comments(black_rules)
        black_rules = self.sanitize_caret_suffixes(black_rules)
        print(f"删除注释后剩余 {len(black_rules)} 个规则")
        pipe_rules, remaining_rules = self.extract_pipe_rules(black_rules)
        final_black_rules = self.match_domains_and_restore(pipe_rules, remaining_rules, domain_set)
        print("\n3. 处理秋风规则...")
        autumn_rules = self.download_rules(self.autumn_url)
        autumn_rules = self.remove_comments(autumn_rules)
        autumn_rules = self.sanitize_caret_suffixes(autumn_rules)
        print(f"秋风规则: {len(autumn_rules)} 个")
        print("\n4. 处理GitHub加速规则...")
        github_hosts = self.download_rules(self.github_url)
        github_rules = self.process_hosts_file(github_hosts)
        github_rules = self.sanitize_caret_suffixes(github_rules)
        print(f"GitHub加速规则: {len(github_rules)} 个")
        print("\n5. 合并规则并去重...")
        final_rules = self.merge_and_deduplicate(final_black_rules, autumn_rules, github_rules)
        final_rules = self.reverse_rules(final_rules)
        print("\n6. 保存最终规则并追加白名单...")
        updated_time = override_time if override_time else self.read_updated_time_from_black()
        if skip_white:
            whitelist_rules = []
        else:
            whitelist_rules = self.load_whitelist_from_black()
        black_count = len([r for r in final_rules if str(r).strip()])
        white_count = len([w for w in whitelist_rules if str(w).strip()])
        self.save_rules(final_rules, updated_time=updated_time, black_count=black_count, whitelist_rules=whitelist_rules, whitelist_count=white_count, skip_white=skip_white)
        print("\n=== 处理完成 ===")

if __name__ == "__main__":
    import sys
    simplifier = AdGuardRulesSimplifier()
    override_time = None
    skip_white = False
    if "--timestamp" in sys.argv:
        try:
            idx = sys.argv.index("--timestamp")
            override_time = sys.argv[idx+1]
        except Exception:
            pass
    if "--skip-white" in sys.argv:
        skip_white = True
    simplifier.run(override_time, skip_white)
