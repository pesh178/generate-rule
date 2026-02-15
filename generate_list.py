import requests
import yaml
import json
import os
import re

def download_file(url):
    try:
        print(f"Downloading: {url}")
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return ""

def filter_lines(content, rule):
    lines = content.splitlines()
    filtered_lines = []
    
    # 预编译正则，提高效率
    # 匹配以 || 开头，以 ^ 结尾的 AdBlock 规则
    adblock_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^$')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        if rule['type'] == 'adblock':
            # 处理 AdBlock 格式: ||example.com^
            match = adblock_pattern.match(line)
            if match:
                domain = match.group(1)
                filtered_lines.append(domain)
            # 处理纯域名格式 (兼容某些列表)
            elif not any(c in line for c in ['/', ':', '*', '?']):
                 filtered_lines.append(line)
        
        elif rule['type'] == 'domain':
             filtered_lines.append(line)

    return sorted(list(set(filtered_lines)))

def generate_clash_domain_list(rule, domains, filename):
    payload = {
        "payload": domains
    }
    
    # 如果是 Domain Set (Premium) 或 Rule Set (Meta)，格式略有不同
    # 这里生成最通用的 yaml 列表格式，供 payload 引用
    content = yaml.dump(payload, sort_keys=False)
    
    # 修正 yaml 输出，使其符合 Clash Rule Provider 的 payload 格式
    # 通常 Clash Premium Rule Set 不需要 'payload:' 键，而是直接列表，或者 specific format
    # 但根据文件名 clash_reject_hostnames.yaml，通常用于 RULE-SET
    
    # 更加通用的方式：直接列出域名，或者按照 payload 格式
    # 这里采用标准 payload 格式:
    # payload:
    #   - 'domain1'
    #   - 'domain2'
    
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def generate_adguard_home_list(rule, domains, filename):
    lines = []
    for domain in domains:
        if rule['exclude_action'] == 'IGNORE':
             # 生成如 ||example.com^ 的格式
             lines.append(f"||{domain}^")
    
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
        
        # --- 修改开始：支持多 URL 合并下载 ---
        content = ""
        if isinstance(rule['url'], list):
            print(f"Detected multiple URLs for {rule['name']}, merging...")
            for u in rule['url']:
                file_content = download_file(u)
                content += file_content + "\n" # 添加换行符防止粘连
        else:
            content = download_file(rule['url'])
        # --- 修改结束 ---

        if not content:
            print(f"Skipping {rule['name']} due to empty content.")
            continue

        filtered_domains = filter_lines(content, rule)
        
        # 生成 Clash 格式
        clash_filename = f"{rule['file_prefix']}-clash_reject_hostnames.yaml"
        # 注意：这里如果不同的 rule 使用相同的 file_prefix，后一个会覆盖前一个
        # 所以合并规则必须在 config.json 里把 URL 写在一起，作为一个 rule 处理
        generate_clash_domain_list(rule, filtered_domains, clash_filename)

        # 生成 AdGuard Home / Quantumult X (list) 格式
        # 这里为了演示生成一个通用的 rejection list
        agh_filename = f"{rule['file_prefix']}-rejection-unbound_dns.conf" 
        generate_adguard_home_list(rule, filtered_domains, agh_filename)
        
        # 还可以生成 Quantumult X snippet 等，视需求增加函数

if __name__ == "__main__":
    main()
