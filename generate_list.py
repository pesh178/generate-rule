import requests
import yaml
import json
import os
import re

# --- 核心修复：自定义 Dumper 类，强制列表缩进 ---
class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentDumper, self).increase_indent(flow, False)
# ---------------------------------------------

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
    # 如果您需要给域名加上前缀（如 DOMAIN-SUFFIX,），请在下面这行修改
    # 目前是生成纯域名列表，配合 Clash 的 'domain' behavior 使用
    # 如果需要 classical 格式，可以将下面这行改为:
    # final_domains = [f"DOMAIN-SUFFIX,{d}" for d in domains]
    final_domains = domains 

    payload = {
        "payload": final_domains
    }
    
    # 使用自定义的 IndentDumper 进行转储，确保缩进正确
    content = yaml.dump(payload, Dumper=IndentDumper, sort_keys=False, allow_unicode=True)
    
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def generate_adguard_home_list(rule, domains, filename):
    lines = []
    for domain in domains:
        if rule['exclude_action'] == 'IGNORE':
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
        
        # 支持多 URL 合并下载
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
        
        # 生成 Clash 格式
        clash_filename = f"{rule['file_prefix']}-clash_reject_hostnames.yaml"
        generate_clash_domain_list(rule, filtered_domains, clash_filename)

        # 生成 AdGuard Home 格式
        agh_filename = f"{rule['file_prefix']}-rejection-unbound_dns.conf" 
        generate_adguard_home_list(rule, filtered_domains, agh_filename)

if __name__ == "__main__":
    main()
