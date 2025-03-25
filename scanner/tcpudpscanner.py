import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import sr1


def tcp_scan(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"{port}(tcp) открыт")
        s.close()
    except Exception as e:
        print(f"Ошибка при сканировании {port}: {e}")

def scan_tcps(ip, start_port, end_port):
    with ThreadPoolExecutor(max_workers=25) as task:
        for port in range(start_port, end_port + 1):
            task.submit(tcp_scan, ip, port)

def udp_scan(ip, port):
    try:
        packet = IP(dst=ip) / UDP(dport=port)
        response = sr1(packet, timeout=1, verbose=0)
        if (response != None) and response.haslayer(ICMP):
            print(f"{port}(udp) закрыт")
        else:
            print(f"{port}(udp) открыт")
    except Exception as e:
        print(f"Ошибка при сканировании {port}: {e}")

def scan_udps(ip, start_port, end_port):
    print(f"Сканирование UDP портов на {ip}...")
    with ThreadPoolExecutor(max_workers=25) as task:
        for port in range(start_port, end_port + 1):
            task.submit(udp_scan, ip, port)

def main():
    ip = socket.gethostbyname(socket.gethostname())
    start = int(input("Введите от какого порта начать сканирование: "))
    end = int(input("Введите до какого порта сканировать: "))
    scan_tcps(ip, start, end)
    scan_udps(ip, start, end)



if __name__ == "__main__":
    main()
