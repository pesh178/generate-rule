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
    
    # --- 正则定义 (基于您提供的 Clash 文档) ---
    
    # 1. 匹配 ||domain (匹配域名及其子域名) -> 转换为 +.domain
    # Clash 文档: "+.baidu.com 匹配 tieba.baidu.com 和 ... baidu.com"
    re_domain_suffix = re.compile(r'^\|\|([a-zA-Z0-9.-]+)(?:\^)?$')
    
    # 2. 匹配 |http开头 (起始锚点) -> 提取域名作为精确匹配
    re_start_anchor = re.compile(r'^\|https?://([a-zA-Z0-9.-]+)(?:[:/].*|\||\^)?$')
    
    # 3. 匹配 结尾| (结束锚点) -> 提取域名作为精确匹配
    re_end_anchor = re.compile(r'^([a-zA-Z0-9.-]+)\|(?:\^)?$')

    # 4. 匹配普通 AdBlock 格式 (||domain^)
    re_basic_adblock = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^$')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        if rule['type'] == 'adblock':
            # Case 1: ||domain -> 输出 +.domain (Clash "Plus" 通配符)
            match_suffix = re_domain_suffix.match(line)
            if match_suffix:
                domain = match_suffix.group(1)
                # 修改点：使用 +. 前缀，完美覆盖 根域名+子域名
                filtered_lines.append(f"+.{domain}")
                continue

            # Case 2: |http://... -> 精确匹配 (不加前缀)
            match_start = re_start_anchor.match(line)
            if match_start:
                domain = match_start.group(1)
                filtered_lines.append(domain) 
                continue

            # Case 3: domain| -> 精确匹配 (不加前缀)
            match_end = re_end_anchor.match(line)
            if match_end:
                domain = match_end.group(1)
                filtered_lines.append(domain)
                continue
            
            # Case 4: 普通 AdBlock ||domain^ -> +.domain
            match_basic = re_basic_adblock.match(line)
            if match_basic:
                domain = match_basic.group(1)
                filtered_lines.append(f"+.{domain}")
                continue
            
            # Case 5: 纯域名或通配符 (*.baidu.com)
            # 只要不包含 url 特殊字符，直接保留
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
    # 生成 Clash 规则文件
    content = yaml.dump(data, Dumper=QuotedDumper, sort_keys=False, allow_unicode=True)
    
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def generate_adguard_home_list(rule, domains, filename):
    lines = []
    for domain in domains:
        if rule['exclude_action'] == 'IGNORE':
             # 还原逻辑：将 Clash 的 +. 转换回 AdGuard 的 ||
             if domain.startswith('+.'):
                 clean_domain = domain[2:] # 去掉 +.
                 lines.append(f"||{clean_domain}^")
             
             # 处理其他情况（如精确匹配或带 * 的）
             elif '*' not in domain and not domain.startswith('.'):
                 # 精确匹配，AdGuard 通常也接受 || 覆盖，或者原样
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
