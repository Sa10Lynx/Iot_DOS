import pyshark
import pandas as pd

cap = pyshark.FileCapture(r"C:\Users\ASUS\Tanush\Major_Project\dos_attack.pcapng")

orig_pkts = 0
resp_pkts = 0
orig_bytes = 0
resp_bytes = 0
durations = []

for pkt in cap:
    try:
        if 'TCP' in pkt:
            orig_pkts += 1
            orig_bytes += int(pkt.length)
            durations.append(float(pkt.sniff_timestamp))
    except:
        pass

duration = max(durations) - min(durations)

features = {
    "rate": orig_pkts / duration,
    "sbytes": orig_bytes,
    "sload": orig_bytes / duration,
    "dmean": resp_bytes if resp_pkts else 0,
    "dpkts": resp_pkts,
    "tcprtt": duration,
    "synack": duration * 0.4,
    "ackdat": duration * 0.6,
    "ct_srv_src": orig_pkts,
    "ct_srv_dst": orig_pkts,
    "ct_dst_ltm": orig_pkts
}

df = pd.DataFrame([features])
print(df)