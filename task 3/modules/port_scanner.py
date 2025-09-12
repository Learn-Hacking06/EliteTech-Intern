import socket
from concurrent.futures import ThreadPoolExecutor
from utils.helper import is_valid_ip

# Common ports to scan
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080
]

def scan_port(target, port):
    """Scan a single port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            return port
    except:
        pass
    finally:
        sock.close()
    return None

def scan_ports(target, ports=None):
    """Scan multiple ports using threads."""
    if not is_valid_ip(target):
        return "Invalid IP address"
    
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)
    
    for port in results:
        if port:
            open_ports.append(port)

    if open_ports:
        return sorted(open_ports)
    else:
        return "No open common ports found"

