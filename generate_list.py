import requests
import yaml
import json
import os
import re

# --- 1. 自定义 Dumper 类：强制缩进 + 强制单引号 ---
class QuotedDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(QuotedDumper, self).increase_indent(flow, False)

# 强制字符串使用单引号 ' ' 风格
def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style="'")

QuotedDumper.add_representer(str, quoted_presenter)
# -----------------------------------------------------------

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
    
    # 预编译正则：匹配 ||example.com^
    adblock_pattern = re.compile(r'^\|\|([a-zA-Z0-9.-]+)\^$')
    
    for line in lines:
        line = line.strip()
        # 跳过注释和空行
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        if rule['type'] == 'adblock':
            # 1. 尝试匹配 AdBlock 格式 ||domain^
            match = adblock_pattern.match(line)
            if match:
                domain = match.group(1)
                # 【修改点】: AdBlock 规则自动加点前缀，符合您要求的 '.blogger.com' 格式
                filtered_lines.append(f".{domain}")
            
            # 2. 尝试匹配纯域名或通配符域名
            # 【修改点】: 允许 * 号存在，不再过滤 wildcard
            elif not any(c in line for c in ['/', ':', '?']):
                 filtered_lines.append(line)
        
        elif rule['type'] == 'domain':
             filtered_lines.append(line)

    # 去重并排序
    return sorted(list(set(filtered_lines)))

def generate_clash_domain_list(rule, domains, filename):
    # 【修改点】: 不再添加 DOMAIN-SUFFIX 前缀，直接使用域名列表
    final_domains = domains

    # 使用小写 payload 以保持最大兼容性（Clash 标准）
    # 如果您必须使用大写 Payload，请手动修改下方键名为 "Payload"
    payload = {
        "payload": final_domains
    }
    
    # 使用自定义 QuotedDumper 确保输出格式为: - 'domain.com'
    content = yaml.dump(payload, Dumper=QuotedDumper, sort_keys=False, allow_unicode=True)
    
    output_path = os.path.join('generated_rules', filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Generated {output_path} with {len(domains)} rules.")

def generate_adguard_home_list(rule, domains, filename):
    lines = []
    for domain in domains:
        if rule['exclude_action'] == 'IGNORE':
             # 保持逻辑：AdGuard 格式仍然是 ||domain^
             # 注意：如果是从 ||domain^ 转换来的 .domain，这里需要处理一下去除点？
             # 或者简化处理，如果域名以 . 开头，去掉它再加 ||
             clean_domain = domain.lstrip('.')
             lines.append(f"||{clean_domain}^")
    
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
        
        # 保持逻辑：支持多 URL 合并
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
        
        # 生成 Clash 格式 (新格式: Payload list)
        clash_filename = f"{rule['file_prefix']}-clash_reject_hostnames.yaml"
        generate_clash_domain_list(rule, filtered_domains, clash_filename)

        # 生成 AdGuard Home 格式
        agh_filename = f"{rule['file_prefix']}-rejection-unbound_dns.conf" 
        generate_adguard_home_list(rule, filtered_domains, agh_filename)

if __name__ == "__main__":
    main()
