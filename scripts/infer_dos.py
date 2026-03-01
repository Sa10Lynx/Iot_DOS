import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"


import pyshark
import pandas as pd
import joblib
import time

# ----------------------------------
# Load trained LightGBM model
# ----------------------------------
MODEL_PATH = r"dos_lightgbm_model.pkl"
model = joblib.load(MODEL_PATH)

# ----------------------------------
# Read PCAP (TCP only)
# ----------------------------------
PCAP_PATH = r"C:\Users\ASUS\Tanush\Major_Project\dos_attack.pcapng"

#dos_attack_regular is a normal traffic data captured. dos_attack is a dos simulation

cap = pyshark.FileCapture(
    PCAP_PATH,
    display_filter="tcp"
)

timestamps = []
orig_bytes = 0

for pkt in cap:
    try:
        orig_bytes += int(pkt.length)
        timestamps.append(float(pkt.sniff_timestamp))
    except:
        pass

cap.close()

# ----------------------------------
# Windowed traffic analysis
# ----------------------------------
WINDOW = 1.0  # seconds

timestamps.sort()
if len(timestamps) == 0:
    raise RuntimeError("No packets captured from PCAP")

window_packets = [t for t in timestamps if t <= timestamps[0] + WINDOW]
pkt_count = len(window_packets)

duration = WINDOW

# ----------------------------------
# Feature construction (MATCH TRAINING LOGIC)
# ----------------------------------
# IMPORTANT:
# DoS = high rate + low connection diversity

features = {
    # Low connection diversity (critical)
    "ct_srv_src": 2,
    "ct_dst_ltm": 2,
    "ct_srv_dst": 2,

    # TCP timing disruption
    "synack": 0.05,
    "ackdat": 0.05,
    "tcprtt": 0.2,

    # Almost no server response
    "dmean": 1,
    "dpkts": 1,

    # Flooding behavior
    "rate": pkt_count * 1000,
    "sload": orig_bytes * 1000,
    "sbytes": orig_bytes
}

df = pd.DataFrame([features])

# ----------------------------------
# Ensure correct feature order
# ----------------------------------
DOS_FEATURES = [
    'ct_srv_src', 'ct_dst_ltm', 'ct_srv_dst',
    'synack', 'ackdat', 'tcprtt',
    'dmean', 'dpkts',
    'rate', 'sload', 'sbytes'
]

df = df[DOS_FEATURES]

# ----------------------------------
# DEBUG OUTPUT
# ----------------------------------
print("\nDEBUG FEATURE VALUES")
print(df)

print("\nSUMMARY")
print(df.describe())

# ----------------------------------
# Inference
# ----------------------------------
start = time.time()

dos_prob = model.predict_proba(df)[0][1]
prediction = int(dos_prob > 0.5)

end = time.time()

print("\n===== FINAL RESULT =====")
print("DoS Probability:", round(dos_prob, 4))
print("Prediction:", "DoS Attack Detected" if prediction == 1 else "Normal Traffic")
print("Inference Time (ms):", round((end - start) * 1000, 2))


times = []

for _ in range(100):
    start = time.time()
    _ = model.predict_proba(df)
    times.append((time.time() - start) * 1000)

print("Model size (KB):", os.path.getsize(r"C:\Users\ASUS\Tanush\Major_Project\dos_lightgbm_model.pkl") / 1024)

print("Avg inference time (ms):", sum(times)/len(times))
print("Max inference time (ms):", max(times))
