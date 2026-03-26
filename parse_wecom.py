import urllib.request
import re
import json
import ipaddress
import os

def load_state(filename):
    """读取本地旧的状态文件"""
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_state(filename, data_set):
    """保存新的状态文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        for item in sorted(list(data_set)):
            f.write(f"{item}\n")

def main():
    url = "https://work.weixin.qq.com/h5app/wework_domain_ip/latest"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
    except Exception as e:
        print(f"获取失败: {e}")
        exit(1)

    text = re.sub(r'<[^>]+>', ' ', content)

    # 正则匹配
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b'
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?:/[0-9]{1,3})?\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|cn|net|org|io)\b'

    raw_ips = re.findall(ipv4_pattern, text) + re.findall(ipv6_pattern, text)
    raw_domains = re.findall(domain_pattern, text)

    # 1. 整理并规范化抓取到的最新数据
    latest_ips = set()
    for ip in raw_ips:
        try:
            if '/' not in ip:
                ip_obj = ipaddress.ip_address(ip)
                ip = f"{ip}/32" if isinstance(ip_obj, ipaddress.IPv4Address) else f"{ip}/128"
            else:
                ipaddress.ip_network(ip, strict=False)
            latest_ips.add(ip)
        except ValueError:
            pass

    latest_domains = set()
    for d in raw_domains:
        d = d.lower()
        try:
            ipaddress.ip_address(d)
        except ValueError:
            latest_domains.add(d)

    # 2. 加载旧数据并进行 Diff 对比
    old_ips = load_state("ips.txt")
    old_domains = load_state("domains.txt")

    added_ips = latest_ips - old_ips
    removed_ips = old_ips - latest_ips
    added_domains = latest_domains - old_domains
    removed_domains = old_domains - latest_domains

    has_changes = bool(added_ips or removed_ips or added_domains or removed_domains)

    # 输出变化日志，方便在 Action 日志中查看
    if has_changes:
        print("发现规则变动！")
        if added_domains: print(f"[+] 新增域名 ({len(added_domains)}): {', '.join(added_domains)}")
        if removed_domains: print(f"[-] 移除域名 ({len(removed_domains)}): {', '.join(removed_domains)}")
        if added_ips: print(f"[+] 新增 IP ({len(added_ips)}): {', '.join(added_ips)}")
        if removed_ips: print(f"[-] 移除 IP ({len(removed_ips)}): {', '.join(removed_ips)}")
    else:
        print("规则未发生任何变动，无需更新。")

    # 3. 将结果传递给 GitHub Actions
    env_file = os.getenv('GITHUB_OUTPUT')
    if env_file:
        with open(env_file, 'a') as f:
            f.write(f"changed={'true' if has_changes else 'false'}\n")

    # 如果没有变化，直接退出，不生成新文件
    if not has_changes:
        return

    # 4. 有变化则更新本地状态并生成配置源文件
    save_state("ips.txt", latest_ips)
    save_state("domains.txt", latest_domains)

    sorted_domains = sorted(list(latest_domains))
    sorted_ips = sorted(list(latest_ips))

    # 生成 Sing-box JSON
    singbox_rules = {
        "version": 1,
        "rules": [
            {
                "domain_suffix": sorted_domains,
                "ip_cidr": sorted_ips
            }
        ]
    }
    with open("wecom.json", "w", encoding="utf-8") as f:
        json.dump(singbox_rules, f, indent=2)

    # 生成 Mihomo YAML
    with open("wecom.yaml", "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for d in sorted_domains:
            f.write(f"  - DOMAIN-SUFFIX,{d}\n")
        for ip in sorted_ips:
            if ':' in ip:
                f.write(f"  - IP-CIDR6,{ip}\n")
            else:
                f.write(f"  - IP-CIDR,{ip}\n")

if __name__ == "__main__":
    main()