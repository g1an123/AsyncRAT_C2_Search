import socket
import ssl
import binascii
import nmap
import subprocess
import sys
'''
本脚本已经实现功能如下：
    检测单一端口是否含有以下AsyncRAT Server特征：
        1. 检测TLS握手包是否含有AsyncRAT Server 字样，fofa语法
        2. 检测返回包中是否含有AsyncRAT 心跳包报文 包括低版本
        3. 检测JARM指纹

todo：
    1.对单一主机进行验证是否为C2 Server
    2.批量验证不同主机不同端口
    3.寻找更多特征

'''
total = 0


# 检测TLS握手包是否含有AsyncRAT字样
def sniff_tls_handshake(hostname, port):
    global total
    try:
        nm = nmap.PortScanner()
        nm.scan(hostname, arguments='--script ssl-cert -p ' + str(port) + ' -Pn')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    for script in nm[host][proto][port]['script']:
                        if "AsyncRAT" in nm[host][proto][port]['script'][script]:
                            # print(nm[host][proto][port]['script'][script]) #debug tls信息
                            return True
        total += 1
        return False
    except Exception as e:
        total += 1
        print("发生异常:", e)
        print("not_tls_service")
        return "not_tls"


# 检测返回包中是否含有AsyncRAT 心跳包报文
def check_and_disconnect(response):
    hex_string = binascii.hexlify(response).decode('utf-8')
    return "0000001f8b08000000000004006b5c1690989c9d5ab2a4203f2f1d009e9331870d000000" in hex_string


# 检测返回包中是否含有AsyncRAT低版本 心跳包报文
def check2_and_disconnect(response):
    hex_string = binascii.hexlify(response).decode('utf-8')
    return "a65061636b6574a86368617445786974" in hex_string


# 发送十六进制数据到服务器
def send_hex_data(hex_data, host, port, mode, timeout=5):
    try:
        data = binascii.unhexlify(hex_data)
    except binascii.Error as e:
        print("十六进制数据格式错误:", e)
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile="./certificate.pem", keyfile="./privatekey.pem")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ssl_sock = context.wrap_socket(sock, server_hostname=host)

    try:
        ssl_sock.settimeout(timeout)  # 设置超时时间
        ssl_sock.connect((host, port))
        ssl_sock.sendall(data)

        while True:
            response = ssl_sock.recv(1024)
            if not response:
                break
            else:
                # 检测点---------------------------
                if mode == 1:
                    if check_and_disconnect(response):
                        ssl_sock.close()
                        return True
                else:
                    if check2_and_disconnect(response):
                        ssl_sock.close()
                        return True

    except Exception as e:
        # print("发生异常:", e)
        pass
    finally:
        ssl_sock.close()


# 检测JARM指纹
def check_jarm(ip, port):
    global total
    command = ["python3", "jarm.py", ip, "-p", str(port)] #单纯图方便，懒得改了
    result = subprocess.run(command, capture_output=True, text=True)
    output_lines = result.stdout.split('\n')
    for line in output_lines:
        if line.startswith("JARM:"):
            extracted_jarm = line.split("JARM:")[1].strip()
            if extracted_jarm == "22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9":
                print("[+] JARM检测为AsyncRAT Server")
                return
            elif extracted_jarm == "06b06b00006b06b06b06b06b06b06b2bb1101b28b790bf5d9d4dcad463fdc2":
                print("[+] JARM检测为AsyncRAT Server(win7)")
                return
    print("[-] JARM检测不为AsyncRAT Server")
    total += 1
    print(extracted_jarm)


# 检测心跳包
def heartbeat_Packet(host, port):
    global total

    hex_data = "350000001c0000001f8b08000000000004006b5a1690989c9d5ab22420332f7db96f6a7171627aeab2273bba5fecdd0b0061cb9caf1c000000".replace(
        " ", "")

    hex_data_low = "2700000082a65061636b6574a450696e67a74d657373616765b14350552032342520202052414d203633252800000082a65061636b6574a463686174aa5772697465496e707574af6d61633a2031313131313131310d0a".replace(
        " ", "")

    # 发送十六进制数据到服务器
    if (send_hex_data(hex_data, host, port, mode=1)):
        print("[+] 心跳包回显")

    elif (send_hex_data(hex_data_low, host, port, mode=2)):
        print("[+] 低版本心跳包回显")

    else:
        print("[-] 无心跳包回显")
        total += 1


def main(host, port):
    # 检测TLS握手包是否含有AsyncRAT 字样
    sniff_result = sniff_tls_handshake(host, port)
    if str(sniff_result) != "not_tls":
        if sniff_result:
            print("[+] 'AsyncRAT' found in TLS handshake.")
        else:
            print("[-] 'AsyncRAT' not found in TLS handshake.")

        # 心跳包检测
        heartbeat_Packet(host, port)

        # JARM检验
        check_jarm(host, port)

        if total >= 3:
            print("[-] not AsyncRAT Server")
        else:
            print("[+] AsyncRAT Server found")



if __name__ == "__main__":
    host = "185.87.150.199"  # 默认host
    port = 2222  # 默认port

    # 参数输入执行 python3 C2.py host port
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])

    main(host, port)