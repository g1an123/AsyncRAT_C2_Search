import subprocess
import ipaddress
import csv
import time
import datetime
'''
本脚本功能如下：
    1. 扫描ip段，可指定C B段
    2. 扫描ip，可指定端口
    3. 扫描文件 csv需要格式

todo:
    1.对单个ip进行扫描（由于时间过久，故尝试端口改为高频端口（完成）
    2.遍历ip段进行公网扫描(完成)
    3.对文件内提供的ip端口进行扫描(完成)
    4.bug解决，碰到不相关服务或者版本不一致，会长时间无法断开
    解决方案：服务探测为tls服务
'''
# 设置全局变量以存储当前的输出文件和开始时间
current_output_file = None
start_time = None

portlist=[6606,7707,8808,6666,7777,6000]

def ip_scan(ip, port=None):
    global current_output_file
    ports_to_scan = portlist if port is None else [port]
    for port in ports_to_scan:
        with open(current_output_file, 'a') as f:

            print(f"============================================")
            print(f"Scanning {ip}:{port}\n")            #输出辅助排错

            f.write(f"============================================\n")
            f.write(f"Scanning {ip}:{port}\n")
        command = ["python3", "C2主机发现.py", ip, str(port)]
        result = subprocess.run(command, capture_output=True, text=True)
        output_lines = result.stdout.split('\n')
        with open(current_output_file, 'a') as f:
            for line in output_lines:
                f.write(line + '\n')
                print(line)


def process_target_csv(csv_file):
    with open(csv_file, 'r', newline='') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header if exists
        for row in reader:
            if len(row) >= 2:
                ip = row[0]
                port = int(row[1])
                ip_scan(ip, port)

def scan_ip_range(host, subnet):
    global current_output_file, start_time
    if subnet == 'C':
        ip_network = ipaddress.ip_network(host + '/24', strict=False)
    elif subnet == 'B':
        ip_network = ipaddress.ip_network(host + '/16', strict=False)
    else:
        print("Invalid subnet specification. Please use 'C' or 'B'.")
        return

    start_time = time.time()
    while True:
        current_time = time.time()
        if current_time - start_time >= 180:
            start_time = current_time
            current_output_file = f"output_{int(current_time)}.txt"

        for ip in ip_network.hosts():
            ip_str = str(ip)
            with open(current_output_file, 'a') as f:
                f.write(f"Scanning IP: {ip_str}\n")
                print(f"Scanning IP: {ip_str}")
            for port in portlist:
                ip_scan(ip_str, port)

def scan_ip_range_from_file(file_path):
    global current_output_file, start_time

    with open(file_path, 'r') as f:
        ip_ranges = f.readlines()

    start_time = time.time()
    for ip_range in ip_ranges:
        ip_network = ipaddress.ip_network(ip_range.strip(), strict=False)

        while True:
            current_time = time.time()
            if current_time - start_time >= 180:
                start_time = current_time
                current_output_file = f"output_{int(current_time)}.txt"

            for ip in ip_network.hosts():
                ip_str = str(ip)
                with open(current_output_file, 'a') as f:
                    f.write(f"Scanning IP: {ip_str}\n"+str(datetime.datetime.now())+"\n")
                    print(f"Scanning IP: {ip_str}"+"\n"+str(datetime.datetime.now()))
                for port in portlist:
                    ip_scan(ip_str, port)

def count_asyncrat_servers(output_file):
    count = 0
    with open(output_file, 'r') as f:
        for line in f:
            if "[+] AsyncRAT Server found" in line:
                count += 1
    return count

if __name__=="__main__":
    current_output_file = f"output_{int(time.time())}.txt"

    # scan_ip_range("186.137.33.1", "C") # 扫描ip段，可指定C B段
    # ip_scan("218.204.179.10")          # 扫描单个ip
    # ip_scan("161.97.151.222",7788)     # 扫描单个端口
    # process_target_csv("target1.csv")    # 扫描文件
    # scan_ip_range_from_file("ip_range.txt") # 从文件中获取ip段扫描

    # print(count_asyncrat_servers(current_output_file))  # 输出存活结果
