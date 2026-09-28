# just a cheaper more temu-esque version of nmap

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp


PORTS = range(1, 65535)  
THREADS = 300
TIMEOUT = 0.2


def discover_hosts(network):
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for _, received in result:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts


def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def probe_service(sock, port, target):
    try:
        sock.settimeout(0.5)

        # http
        if port in [80, 8080]:
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            data = sock.recv(1024).decode(errors="ignore")
            return "HTTP", data.split("\r\n")[0]

        # https
        elif port == 443:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                data = ssock.recv(1024).decode(errors="ignore")
                return "HTTPS", data.split("\r\n")[0]

        # ssh
        elif port == 22:
            return "SSH", sock.recv(1024).decode(errors="ignore").strip()

        # ftp
        elif port == 21:
            return "FTP", sock.recv(1024).decode(errors="ignore").strip()

        # smtp
        elif port == 25:
            return "SMTP", sock.recv(1024).decode(errors="ignore").strip()

        # gen.
        else:
            data = sock.recv(1024).decode(errors="ignore").strip()
            return "Unknown", data if data else "No banner"

    except:
        return "Unknown", "No response"

# -p- scan
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)

            if s.connect_ex((target, port)) == 0:
                service, banner = probe_service(s, port, target)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner
                }

    except:
        pass

    return None

# os guess? (mnoo rough)
def guess_os(open_ports):
    ports = [p["port"] for p in open_ports]

    if 445 in ports:
        return "Likely Windows"
    elif 22 in ports and 80 in ports:
        return "Likely Linux"
    elif 548 in ports:
        return "Likely macOS"
    else:
        return "Unknown"

# host scan
def scan_host(host):
    ip = host["ip"]
    mac = host["mac"]
    hostname = resolve_host(ip)

    print(f"\n[+] {ip} ({hostname}) [{mac}]")

    results = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in PORTS]

        for f in futures:
            r = f.result()
            if r:
                results.append(r)
                print(f"  ├─ {r['port']} | {r['service']} | {r['banner']}")

    os_guess = guess_os(results)
    print(f"  └─ OS Guess: {os_guess}")

# main
network = input("Enter network (e.g. 192.168.1.0/24): ")

hosts = discover_hosts(network)
print(f"\nFound {len(hosts)} hosts\n")

for h in hosts:
    scan_host(h)

print("\n--- Done ---")
