import requests
import yaml
import json
import os
import re

# --- 1. 自定义 Dumper：强制单引号 + 缩进 ---
class QuotedDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(QuotedDumper, self).increase_indent(flow, False)

def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

QuotedDumper.add_representer(str, quoted_presenter)
# ----------------------------------------

def download_file(url):
    try:
        print(f"Downloading: {url}")
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return ""

def filter_lines(content, rule):
    lines = content.splitlines()
    filtered_lines = []
    
    # 锚点正则 (用于处理 |http...)
    re_start_anchor = re.compile(r'^\|https?://([a-zA-Z0-9.-]+)(?:[:/].*|\||\^)?$')
    re_end_anchor = re.compile(r'^([a-zA-Z0-9.-]+)\|(?:\^)?$')

    # 定义“无效字符集合”：域名中不应该出现这些符号
    # / : ? = 路径或参数
    # ^ = AdBlock 分隔符（如果出现在中间）
    invalid_chars = ['/', ':', '?', '^']

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        if rule['type'] == 'adblock':
            domain_candidate = ""
            is_wildcard_rule = False

            # --- 1. 提取规则中的域名部分 ---
            
            # Case A: 以 || 开头 (AdBlock 核心规则)
            if line.startswith('||'):
                # 去掉开头的 || 和结尾的 ^
                domain_candidate = line[2:].rstrip('^')
                # 标记处理方式：如果不含通配符，可能需要加 +.
                if '*' not in domain_candidate:
                    is_wildcard_rule = False # 需要加 +.
                else:
                    is_wildcard_rule = True  # 原样保留

            # Case B: 起始锚点 |http://...
            elif line.startswith('|'):
                match_start = re_start_anchor.match(line)
                if match_start:
                    domain_candidate = match_start.group(1)
                    is_wildcard_rule = True # 精确匹配，不需要加 +.

            # Case C: 结束锚点 ...|
            elif line.endswith('|'):
                match_end = re_end_anchor.match(line)
                if match_end:
                    domain_candidate = match_end.group(1)
                    is_wildcard_rule = True

            # Case D: 普通行 (纯域名或通配符)
            else:
                domain_candidate = line.rstrip('^')
                if '*' in domain_candidate:
                    is_wildcard_rule = True
                else:
                    # 如果不是 || 开头，通常认为是精确域名
                    is_wildcard_rule = True 

            # --- 2. 严格的有效性检查 (Pure Domain Check) ---
            
            # 如果提取失败，跳过
            if not domain_candidate:
                continue

            # 关键修复：检查是否包含非法字符 (路径、端口、参数、分隔符)
            # 例如: acronymfinder.com/*/housebanners 包含 / -> 丢弃
            if any(char in domain_candidate for char in invalid_chars):
                continue
                
            # --- 3. 添加到结果列表 ---
            
            # 如果是 || 提取出来的纯域名 (不含*)，转换为 +.domain
            if line.startswith('||') and not is_wildcard_rule:
                filtered_lines.append(f"+.{domain_candidate}")
            else:
                filtered_lines.append(domain_candidate)
        
        elif rule['type'] == 'domain':
             filtered_lines.append(line)

    return sorted(list(set(filtered_lines)))

def generate_clash_domain_list(rule, domains, filename):
    data = {
        "payload": domains
    }
    content = yaml.dump(data, Dumper=QuotedDumper, sort_keys=False, allow_unicode=True)
    
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def generate_adguard_home_list(rule, domains, filename):
    lines = []
    for domain in domains:
        if rule['exclude_action'] == 'IGNORE':
             # 还原逻辑：
             if domain.startswith('+.'):
                 clean_domain = domain[2:]
                 lines.append(f"||{clean_domain}^")
             elif '*' not in domain and not domain.startswith('.'):
                 lines.append(f"||{domain}^")
             else:
                 lines.append(domain)
    
    content = "\n".join(lines)
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def main():
    if not os.path.exists('generated_rules'):
        os.makedirs('generated_rules')

    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    for rule in config['rules_list']:
        print(f"Processing rule: {rule['name']}")
        
        content = ""
        if isinstance(rule['url'], list):
            print(f"Detected multiple URLs for {rule['name']}, merging...")
            for u in rule['url']:
                file_content = download_file(u)
                content += file_content + "\n"
        else:
            content = download_file(rule['url'])

        if not content:
            print(f"Skipping {rule['name']} due to empty content.")
            continue

        filtered_domains = filter_lines(content, rule)
        
        clash_filename = f"{rule['file_prefix']}-clash_reject_hostnames.yaml"
        generate_clash_domain_list(rule, filtered_domains, clash_filename)

        agh_filename = f"{rule['file_prefix']}-rejection-unbound_dns.conf" 
        generate_adguard_home_list(rule, filtered_domains, agh_filename)

if __name__ == "__main__":
    main()
