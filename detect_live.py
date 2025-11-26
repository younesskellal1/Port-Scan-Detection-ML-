# detect_live.py
import joblib
import pandas as pd
import time
import traceback

from live_extract import sniff_packets
from dashboard_server import (
    start_server_thread,
    add_alert,
    increment_packet,
    increment_scan,
    PORT_STATS,
    update_pipeline_status
)
from dashboard_server import METRICS

# Start the dashboard server in background thread
start_server_thread()

# Load model & training features
model = joblib.load("portscan_rf.pkl")
TRAIN_FEATURES = pd.read_csv("feature_list.csv").iloc[:,0].tolist()

print("🔍 Port Scan Live Detection — running...")

def safe_predict(df):
    # Ensure columns same order
    for col in TRAIN_FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[TRAIN_FEATURES].fillna(0)
    try:
        probs = model.predict_proba(df)[:,1] if hasattr(model, "predict_proba") else None
        preds = model.predict(df)
        return preds, probs
    except Exception as e:
        print("Prediction error:", e)
        traceback.print_exc()
        return None, None

# Process packets - start with smaller batches for responsiveness
BATCH_SIZE = 5  # Smaller batch for faster detection
packet_count = 0
last_packet_time = time.time()
last_status_time = time.time()

print("📡 Starting packet capture on Wi-Fi interface...")
print("💡 Make sure you have network traffic or run a scan")

while True:
    loop_start = time.perf_counter()
    # Collect a batch of packets
    df = sniff_packets(interface="Wi-Fi", count=BATCH_SIZE, max_attempts=BATCH_SIZE * 3)
    if df is None or len(df) == 0:
        # Print status every 3 seconds if no packets
        if time.time() - last_status_time > 3:
            print("⏳ No packets captured yet... (check interface/permissions)")
            last_status_time = time.time()
        time.sleep(0.2)  # Sleep when no packets
        continue
    
    packet_count += len(df)
    last_packet_time = time.time()
    last_status_time = time.time()
    if packet_count <= 10 or packet_count % 20 == 0:  # Print first 10 and then every 20
        print(f"✅ Captured {len(df)} packets (total: {packet_count})")

    ts = int(time.time())
    
    # Process all packets in batch
    preds, probs = safe_predict(df)
    if preds is None:
        continue

    # Process each packet in the batch
    for idx in range(len(df)):
        increment_packet(ts)
        
        pred = int(preds[idx])
        prob = float(probs[idx]) if probs is not None else None

        # Extract metadata
        try:
            src_ip = df.iloc[idx]["_meta_ip_src"] if "_meta_ip_src" in df.columns else "unknown"
        except:
            src_ip = "unknown"
        try:
            dst_port_val = df.iloc[idx]["_meta_tcp_dstport"] if "_meta_tcp_dstport" in df.columns else None
            dst_port = int(dst_port_val) if dst_port_val is not None and not pd.isna(dst_port_val) else None
        except:
            dst_port = None

        details = {
            "probability": prob,
            "batch_index": idx
        }

        if pred == 1:
            increment_scan(ts)
            add_alert(ts, src_ip, dst_port, pred, prob, details)
            print(f"🚨 ALERT {time.strftime('%Y-%m-%d %H:%M:%S')} - {src_ip}:{dst_port} prob={prob:.3f}")
        else:
            # non-suspect but still track port stats
            if dst_port:
                PORT_STATS[dst_port] += 1

    # Only print summary for batches, not every packet
    if len(df) > 1:
        scan_count = sum(1 for p in preds if p == 1)
        if scan_count > 0:
            print(f"📊 Batch: {len(df)} packets, {scan_count} scans detected")

    loop_ms = (time.perf_counter() - loop_start) * 1000
    queue_depth = max(0, int(loop_ms // 50) - 1)
    update_pipeline_status(
        last_loop_ms=round(loop_ms, 2),
        queue_depth=max(queue_depth, 0),
        timestamp=ts,
        notes=f"Batch size: {len(df)}"
    )

    # No sleep - process continuously for faster detection
