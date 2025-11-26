# live_extract.py
import pyshark
import pandas as pd
import numpy as np
import time

TRAIN_FEATURES = pd.read_csv("feature_list.csv").iloc[:,0].astype(str).tolist()

def packet_to_row(pkt):
    row = {}
    metadata = {}

    def safe(f):
        try:
            return f()
        except:
            return np.nan

    # Basic
    row["frame_info.len"] = safe(lambda: int(pkt.length))
    row["frame_info.cap_len"] = safe(lambda: int(pkt.cap_len))

    if "IP" not in pkt:
        return None
    metadata["ip.src"] = safe(lambda: pkt.ip.src)
    metadata["ip.dst"] = safe(lambda: pkt.ip.dst)
    row["ip.ttl"] = safe(lambda: int(pkt.ip.ttl))
    row["ip.proto"] = safe(lambda: int(pkt.ip.proto))
    row["ip.len"] = safe(lambda: int(pkt.ip.len))
    row["ip.flags"] = safe(lambda: int(pkt.ip.flags, 16) if isinstance(pkt.ip.flags, str) else int(pkt.ip.flags))
    row["ip.checksum"] = safe(lambda: int(pkt.ip.checksum, 16) if isinstance(pkt.ip.checksum, str) else int(pkt.ip.checksum))
    row["ip.flags.df"] = safe(lambda: int(pkt.ip.flags_df))
    row["ip.flags.mf"] = safe(lambda: int(pkt.ip.flags_mf))

    if "TCP" not in pkt:
        return None
    tcp = pkt.tcp
    metadata["tcp.srcport"] = safe(lambda: int(tcp.srcport))
    metadata["tcp.dstport"] = safe(lambda: int(tcp.dstport))
    row["tcp.seq"] = safe(lambda: int(tcp.seq))
    row["tcp.ack"] = safe(lambda: int(tcp.ack))
    row["tcp.window_size"] = safe(lambda: int(tcp.window_size_value))
    row["tcp.flags"] = safe(lambda: int(tcp.flags, 16) if isinstance(tcp.flags, str) else int(tcp.flags))
    row["tcp.checksum"] = safe(lambda: int(tcp.checksum, 16) if isinstance(tcp.checksum, str) else int(tcp.checksum))
    row["tcp.hdr_len"] = safe(lambda: int(tcp.hdr_len))

    return row, metadata

def sniff_packets(interface="Wi-Fi", count=10, max_attempts=200):
    try:
        cap = pyshark.LiveCapture(interface=interface)
        rows = []
        metas = []
        attempts = 0
        
        # Use sniff() with packet_count limit - this is non-blocking up to the count
        # We'll capture up to 'count' packets, but return early if we have some
        try:
            # Capture packets with a limit
            for pkt in cap.sniff_continuously():
                attempts += 1
                
                row = packet_to_row(pkt)
                if row:
                    feature_row, meta = row
                    rows.append(feature_row)
                    metas.append(meta)
                
                # Return when we have enough valid packets or hit max attempts
                if len(rows) >= count or attempts >= max_attempts:
                    break
                    
                # Quick timeout check to avoid blocking too long
                if attempts > 50 and len(rows) == 0:
                    # If we've tried 50 times with no valid packets, return None
                    break
                    
        except KeyboardInterrupt:
            raise
        except Exception as e:
            # Only print error if we got no packets
            if len(rows) == 0:
                pass  # Silent - might just be no packets available
    except Exception as e:
        # Only print if it's a real error (not just no packets)
        if "No such device" in str(e) or "Permission denied" in str(e):
            print(f"❌ Capture error: {e}")
            print("💡 Try running as administrator or check interface name")
        return None

    if len(rows) == 0:
        return None

    df = pd.DataFrame(rows)
    meta_df = pd.DataFrame(metas)
    for f in TRAIN_FEATURES:
        if f not in df.columns:
            df[f] = 0
    feature_df = df[TRAIN_FEATURES].fillna(0)
    feature_df["_meta_ip_src"] = meta_df["ip.src"]
    feature_df["_meta_ip_dst"] = meta_df["ip.dst"]
    feature_df["_meta_tcp_srcport"] = meta_df["tcp.srcport"]
    feature_df["_meta_tcp_dstport"] = meta_df["tcp.dstport"]
    return feature_df
