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
    
    # 锚点正则保持不变 (用于处理 |http... 和 ...|)
    re_start_anchor = re.compile(r'^\|https?://([a-zA-Z0-9.-]+)(?:[:/].*|\||\^)?$')
    re_end_anchor = re.compile(r'^([a-zA-Z0-9.-]+)\|(?:\^)?$')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        if rule['type'] == 'adblock':
            # --- 修复核心：使用 startswith 处理 ||，不再依赖严格正则 ---
            
            # Case 1: 以 || 开头 (AdBlock 核心规则)
            if line.startswith('||'):
                # 去掉开头的 || 和结尾的 ^
                domain = line[2:].rstrip('^')
                
                # 策略：如果域名包含通配符 *，直接保留 (Clash 不支持 +.*)
                # 否则，加上 +. 前缀 (Clash 推荐的子域名匹配)
                if '*' in domain:
                    filtered_lines.append(domain)
                else:
                    filtered_lines.append(f"+.{domain}")
                continue

            # Case 2: |http... (起始锚点)
            match_start = re_start_anchor.match(line)
            if match_start:
                filtered_lines.append(match_start.group(1))
                continue

            # Case 3: ...| (结束锚点)
            match_end = re_end_anchor.match(line)
            if match_end:
                filtered_lines.append(match_end.group(1))
                continue
            
            # Case 4: 其他纯域名或通配符规则
            # 只要不包含 URL 特殊字符，就认为是有效规则
            if not any(c in line for c in ['/', ':', '?']):
                 clean_line = line.rstrip('^')
                 filtered_lines.append(clean_line)
        
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
             # 1. 遇到 +. 开头的，还原为 ||
             if domain.startswith('+.'):
                 clean_domain = domain[2:]
                 lines.append(f"||{clean_domain}^")
             
             # 2. 遇到不含 * 的普通域名 (精确匹配)，还原为 || (覆盖更广)
             elif '*' not in domain and not domain.startswith('.'):
                 lines.append(f"||{domain}^")
             
             # 3. 带 * 的规则，原样保留 (AdGuard 支持 *.example.com)
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
