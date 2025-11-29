import os
import re
import requests
import time
import json
import datetime

def get_beijing_time():
    urls = [
        "https://quan.suning.com/getSysTime.do",
        "https://www.baidu.com",
        "https://a.jd.com/js/union_ajax.js",
        "https://pages.github.com",
        "https://consumer.huawei.com",
        "https://www.mi.com",
        "http://quan.suning.com/getSysTime.do"
    ]
    
    for url in urls:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, timeout=3, headers=headers)
            
            if 'Date' in response.headers:
                date_str = response.headers['Date']
                gmt_time = datetime.datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S GMT')
                beijing_time = gmt_time + datetime.timedelta(hours=8)
                return beijing_time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            continue
    
    print("获取北京时间失败，使用本地时间")
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

COMBINED_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Black.txt")
WHITE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "White.txt")

BLACKLIST_SOURCES = {
    "AdGuard DNS filter     ": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "秋风的规则              ": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "GitHub加速              ": "https://raw.githubusercontent.com/521xueweihan/GitHub520/refs/heads/main/hosts",
    "消失DD                  ": "https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/dns.txt",
    "下个ID见                ": "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
    "StevenBlack 　　　　     ": "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
    "neodevpro   　　　　     ": "https://raw.githubusercontent.com/neodevpro/neodevhost/master/host"
}

WHITELIST_SOURCES = {
}


def remove_comments_and_blank_lines(rules):
    result = []
    for raw in rules:
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        line = re.sub(r"\s[!#].*$", "", line).strip()
        if line:
            result.append(line)
    return result

def extract_whitelist_from_blacklist(blacklist_rules):
    whitelist_rules = [rule for rule in blacklist_rules if rule.startswith("@@")]
    filtered_blacklist = [rule for rule in blacklist_rules if not rule.startswith("@@")]
    return filtered_blacklist, whitelist_rules

def deduplicate_rules(rules):
    seen = set()
    result = []
    for rule in rules:
        if rule not in seen:
            seen.add(rule)
            result.append(rule)
    return result

def parse_rule_components(rule: str):
    s = rule.strip()
    comps = {
        "is_comment": s.startswith("#") or s.startswith("!"),
        "is_regex": s.startswith("/") and s.endswith("/"),
        "is_whitelist": s.startswith("@@"),
        "is_hosts": False,
        "is_basic_adguard": False,
        "domain": None,
        "has_modifiers": False,
        "modifiers": []
    }
    if not s or comps["is_comment"]:
        return comps
    m = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([^\s#]+)', s)
    if m:
        comps["is_hosts"] = True
        comps["domain"] = m.group(1).strip()
        return comps
    if "$" in s:
        comps["has_modifiers"] = True
        mods = s[s.find("$")+1:]
        comps["modifiers"] = [x.strip() for x in mods.split(",") if x.strip()]
    if s.startswith("@@||"):
        rest = s[4:]
        dm = re.match(r'^([^\^\$\s]+)', rest)
        if dm:
            comps["is_basic_adguard"] = True
            comps["domain"] = dm.group(1)
            return comps
    if s.startswith("||"):
        rest = s[2:]
        dm = re.match(r'^([^\^\$\s]+)', rest)
        if dm:
            comps["is_basic_adguard"] = True
            comps["domain"] = dm.group(1)
            return comps
    if ' ' not in s and not s.startswith('|'):
        rest = s[2:] if s.startswith("@@") else s
        dm = re.match(r'^([^\^\$\s]+)', rest)
        if dm:
            dom = dm.group(1)
            if re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+$', dom) and "*" not in dom:
                comps["domain"] = dom
    return comps

def format_whitelist_rule(rule):
    s = rule.strip()
    if not s:
        return s
    if s.startswith("@@"):
        return s
    if s.startswith("||") or s.startswith("|"):
        return "@@" + s
    dm = re.match(r"^([A-Za-z0-9.-]+\.[A-Za-z0-9.-]+)$", s)
    if dm:
        return "@@||" + dm.group(1) + "^"
    return s

def download_blacklist_sources():
    all_blacklist_rules = []
    
    print(f"开始下载 {len(BLACKLIST_SOURCES)} 个黑名单源...")
    for name, url in BLACKLIST_SOURCES.items():
        try:
            print(f"正在下载 {name} ({url})...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            rules = response.text.split("\n")
            cleaned_rules = remove_comments_and_blank_lines(rules)
            
            all_blacklist_rules.extend(cleaned_rules)
            print(f"成功下载 {name}，获取到 {len(cleaned_rules)} 条规则")
            time.sleep(1)
        except Exception as e:
            print(f"下载 {name} 失败 ({url}): {e}")
    print(f"所有黑名单源下载完成，共获取到 {len(all_blacklist_rules)} 条规则")
    return all_blacklist_rules

def download_whitelist_sources():
    all_whitelist_rules = []
    
    print(f"开始下载 {len(WHITELIST_SOURCES)} 个白名单源...")
    for name, url in WHITELIST_SOURCES.items():
        try:
            print(f"正在下载 {name} ({url})...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            rules = response.text.split("\n")
            cleaned_rules = remove_comments_and_blank_lines(rules)
            
            all_whitelist_rules.extend(cleaned_rules)
            print(f"成功下载 {name}，获取到 {len(cleaned_rules)} 条规则")
            time.sleep(1)
        except Exception as e:
            print(f"下载 {name} 失败 ({url}): {e}")
    print(f"所有白名单源下载完成，共获取到 {len(all_whitelist_rules)} 条规则")
    return all_whitelist_rules

def extract_domains_from_rules(rules, is_whitelist=False):
    domains = set()
    for rule in rules:
        c = parse_rule_components(rule)
        if c["domain"] and "*" not in c["domain"]:
            if not is_whitelist and (c["has_modifiers"] or c["is_regex"]):
                continue
            domains.add(c["domain"])
    return domains

def remove_conflicting_rules(blacklist_rules, whitelist_rules):
    blacklist_domains = extract_domains_from_rules(blacklist_rules, is_whitelist=False)
    whitelist_domains = extract_domains_from_rules(whitelist_rules, is_whitelist=True)
    conflicting_domains = blacklist_domains.intersection(whitelist_domains)
    print(f"发现 {len(conflicting_domains)} 个潜在冲突域名（保留两侧规则，避免误删）")
    
    filtered_blacklist = []
    processed_domains = set()
    for rule in blacklist_rules:
        c = parse_rule_components(rule)
        if c["domain"] and not c["has_modifiers"] and not c["is_regex"] and "*" not in c["domain"]:
            if c["domain"] in processed_domains:
                continue
            processed_domains.add(c["domain"])
        filtered_blacklist.append(rule)
    
    filtered_whitelist = whitelist_rules[:]
    print(f"过滤后白名单规则数量: {len(filtered_whitelist)}")
    
    return filtered_blacklist, filtered_whitelist

def process_rules(rules):
    original_rules = []
    extracted_rules = []
    
    for line in rules:
        if line.startswith("|"):
            extracted_rules.append(line)
        else:
            original_rules.append(line)
    
    usable_original = []
    for line in original_rules:
        if (not line or
            "!" in line or "$" in line or
            "/" in line or
            line.startswith((".", "-"))):
            continue
        usable_original.append(line)
    
    usable_extracted = []
    for line in extracted_rules:
        if (not line or "!" in line or
            "/" in line):
            continue
        usable_extracted.append(line)
    
    final_rules = usable_extracted + usable_original
    return final_rules

def sanitize_caret_suffixes(rules):
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

def main(generate_white_file=True, override_time: str = None):
    print("开始处理AdGuardHome规则...")
    
    current_time = override_time if override_time else get_beijing_time()
    
    blacklist_rules = download_blacklist_sources()
    
    filtered_blacklist, extracted_whitelist = extract_whitelist_from_blacklist(blacklist_rules)
    print(f"从黑名单中提取的白名单规则数量: {len(extracted_whitelist)}")
    print(f"过滤后的黑名单规则数量: {len(filtered_blacklist)}")
    
    deduplicated_blacklist = deduplicate_rules(filtered_blacklist)
    print(f"去重后的黑名单规则数量: {len(deduplicated_blacklist)}")
    
    downloaded_whitelist = download_whitelist_sources()
    print(f"下载的白名单规则数量: {len(downloaded_whitelist)}")
    
    merged_whitelist = extracted_whitelist + downloaded_whitelist
    
    deduplicated_whitelist = deduplicate_rules(merged_whitelist)
    print(f"合并去重后的白名单规则数量: {len(deduplicated_whitelist)}")
    
    final_blacklist, filtered_whitelist = remove_conflicting_rules(deduplicated_blacklist, deduplicated_whitelist)
    print(f"移除冲突规则后的黑名单数量: {len(final_blacklist)}")
    print(f"过滤后的白名单数量: {len(filtered_whitelist)}")
    
    blacklist_content_lines = []
    for rule in final_blacklist:
        if not (rule.startswith('[') and rule.endswith(']')):
            blacklist_content_lines.append(rule)
    
    processed_blacklist = process_rules(blacklist_content_lines)
    processed_blacklist = sanitize_caret_suffixes(processed_blacklist)
    
    whitelist_content_lines = []
    for rule in filtered_whitelist:
        if not (rule.startswith('[') and rule.endswith(']')):
            whitelist_content_lines.append(rule)
    
    formatted_whitelist_content_lines = []
    for line in whitelist_content_lines:
        line = line.strip()
        if not line:
            continue
        formatted_rule = format_whitelist_rule(line)
        formatted_whitelist_content_lines.append(formatted_rule)

    filtered_whitelist_lines = []
    for line in formatted_whitelist_content_lines:
        if str(line).strip() and not (
            "!" in line or
            "/" in line or
            line.startswith((".", "-"))
        ):
            filtered_whitelist_lines.append(line)

    normalized_whitelist_lines = []
    for line in filtered_whitelist_lines:
        s = str(line).strip()
        if s.startswith('@@||'):
            normalized_whitelist_lines.append(s)
        else:
            sanitized = re.sub(r'[@|]', '', s)
            normalized_whitelist_lines.append('@@||' + sanitized)
    normalized_whitelist_lines = sanitize_caret_suffixes(normalized_whitelist_lines)

    blacklist_count = sum(1 for l in processed_blacklist if str(l).strip())
    whitelist_count = len(normalized_whitelist_lines)
    total_count = blacklist_count + whitelist_count
    
    with open(COMBINED_FILE, "w", encoding="utf-8") as f:
        f.write(f"# 更新时间: {current_time}\n")
        f.write(f"# 总规则数：{total_count} (黑名单: {blacklist_count}, 白名单: {whitelist_count})\n")
        f.write(f"# 作者名称: Menghuibanxian  酷安名: 梦半仙\n")
        f.write(f"# 作者主页: https://github.com/Menghuibanxian/AdguardHome\n")
        f.write("\n")
        
        for line in processed_blacklist:
            if str(line).strip():
                f.write(f"{line}\n")
        
        for line in normalized_whitelist_lines:
            f.write(f"{line}\n")

    if generate_white_file:
        with open(WHITE_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 更新时间: {current_time}\n")
            f.write(f"# 白名单规则数：{len(normalized_whitelist_lines)}\n")
            f.write(f"# 作者名称: Menghuibanxian  酷安名: 梦半仙\n")
            f.write(f"# 作者主页: https://github.com/Menghuibanxian/AdguardHome\n")
            f.write("\n")
            
            for line in normalized_whitelist_lines:
                f.write(f"{line}\n")
        # 额外就地清理，确保 ^ 之后无任何字符
        try:
            with open(WHITE_FILE, 'r', encoding='utf-8', errors='ignore') as rf:
                lines = rf.readlines()
            out = []
            for raw in lines:
                s = raw.strip().lstrip('\ufeff')
                if not s:
                    out.append('\n')
                    continue
                idx = s.find('^')
                if idx != -1:
                    s = s[:idx+1]
                out.append(s + '\n')
            with open(WHITE_FILE, 'w', encoding='utf-8') as wf:
                wf.writelines(out)
        except Exception:
            pass
        
        print("AdGuardHome规则处理完成！Black.txt和White.txt文件已生成。")
    else:
        # 如果不需要生成White.txt文件，删除已存在的文件
        if os.path.exists(WHITE_FILE):
            os.remove(WHITE_FILE)
        print("AdGuardHome规则处理完成！Black.txt文件已生成。")

if __name__ == "__main__":
    import sys
    generate_white_file = "--no-white-file" not in sys.argv
    override_time = None
    if "--timestamp" in sys.argv:
        try:
            idx = sys.argv.index("--timestamp")
            override_time = sys.argv[idx+1]
        except Exception:
            pass
    main(generate_white_file, override_time)
