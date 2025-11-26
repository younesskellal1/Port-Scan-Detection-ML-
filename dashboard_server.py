# dashboard_server.py
import time
import threading
import csv
import os
import io
from collections import defaultdict, Counter

from flask import Flask, jsonify, render_template, send_file, request, Response
from flask_socketio import SocketIO, emit

try:
    import eventlet  # type: ignore  # noqa: F401
    _ASYNC_MODE = "eventlet"
except ImportError:
    _ASYNC_MODE = "threading"
    print("⚠️  eventlet not found; falling back to threading async mode.")

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

app = Flask(__name__, template_folder="templates", static_folder="static")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=_ASYNC_MODE)

# Shared metrics & data structures (updated by detect_live.py)
METRICS = {
    "timestamps": [],           # list of unix timestamps
    "scan_counts": [],          # cumulative scans
    "packets": 0,
    "scans": 0,
    "packet_timestamps": [],    # recent packet timestamps for rate calculation
    "scan_timestamps": [],      # recent scan timestamps for rate calculation
}

PORT_STATS = Counter()         # dst_port -> count
IP_STATS = Counter()           # src_ip -> count
IP_PORT_MATRIX = defaultdict(lambda: Counter())  # src_ip -> Counter(dst_port -> count)
ALERTS = []                    # list of dicts (time, src, dstport, prob, details)
LAST_SUSPECT = None            # dict for last suspicious packet
ALERT_COUNTER = 0
BLOCKLIST = set()
PIPELINE_STATUS = {
    "queue_depth": 0,
    "last_loop_ms": 0,
    "timestamp": None,
    "notes": ""
}

LOG_FILE = os.path.join("logs", "detection_log.csv")
os.makedirs("logs", exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","src_ip","dst_port","prediction","probability","details"])


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/metrics")
def metrics():
    ratio = (METRICS["scans"] / METRICS["packets"]) if METRICS["packets"] > 0 else 0
    
    # Calculate real-time rates
    current_time = int(time.time())
    
    # Packet rate (packets per second in last 10 seconds)
    recent_packets = [t for t in METRICS["packet_timestamps"] if (current_time - t) <= 10]
    packet_rate_ps = len(recent_packets) / 10.0 if len(recent_packets) > 0 else 0
    
    # Scan rate (scans per minute in last 60 seconds)
    recent_scans = [t for t in METRICS["scan_timestamps"] if (current_time - t) <= 60]
    scan_rate_pm = len(recent_scans) * 60.0 / 60.0 if len(recent_scans) > 0 else 0
    
    # Scan rate per hour (extrapolated from last 60 seconds)
    scan_rate_ph = scan_rate_pm * 60.0
    
    return jsonify({
        "timestamps": METRICS["timestamps"][-200:],
        "scan_counts": METRICS["scan_counts"][-200:],
        "packets": METRICS["packets"],
        "scans": METRICS["scans"],
        "ratio": ratio,
        "packet_rate_ps": round(packet_rate_ps, 2),
        "scan_rate_pm": round(scan_rate_pm, 2),
        "scan_rate_ph": round(scan_rate_ph, 2)
    })


@app.route("/top_ports")
def top_ports():
    top = PORT_STATS.most_common(15)
    return jsonify(top)


@app.route("/top_ips")
def top_ips():
    top = IP_STATS.most_common(15)
    return jsonify(top)


@app.route("/ip_port_matrix")
def ip_port_matrix():
    # return only top 50 IPs for payload size
    return jsonify({ip: dict(cnt) for ip, cnt in list(IP_PORT_MATRIX.items())[:50]})


@app.route("/alerts")
def alerts_endpoint():
    # latest 200 alerts (or all if less than 200)
    return jsonify(ALERTS[-200:])


@app.route("/alert_stats")
def alert_stats():
    """Return alert statistics"""
    total_alerts = len(ALERTS)
    acknowledged = sum(1 for a in ALERTS if a.get("acknowledged", False))
    unacknowledged = total_alerts - acknowledged
    
    # Calculate alert rate (alerts per hour)
    alert_rate = 0
    if len(ALERTS) >= 2:
        # Get time range from first to last alert
        first_time = ALERTS[0]["timestamp"]
        last_time = ALERTS[-1]["timestamp"]
        time_span_hours = (last_time - first_time) / 3600.0
        if time_span_hours > 0:
            alert_rate = total_alerts / time_span_hours
    
    # Recent alerts (last hour)
    current_time = int(time.time())
    recent_alerts = sum(1 for a in ALERTS if (current_time - a["timestamp"]) <= 3600)
    
    # High severity alerts (probability > 0.7)
    high_severity = sum(1 for a in ALERTS if a.get("probability", 0) > 0.7)
    
    return jsonify({
        "total": total_alerts,
        "acknowledged": acknowledged,
        "unacknowledged": unacknowledged,
        "alert_rate_per_hour": round(alert_rate, 2),
        "recent_alerts_1h": recent_alerts,
        "high_severity": high_severity,
        "acknowledged_percent": round((acknowledged / total_alerts * 100) if total_alerts > 0 else 0, 1)
    })


@app.route("/last_suspect")
def last_suspect():
    return jsonify(LAST_SUSPECT or {})


@app.route("/export_logs")
def export_logs():
    return send_file(LOG_FILE, as_attachment=True)


# helper: add an alert (called by detect_live)
def add_alert(ts, src_ip, dst_port, prediction, probability, details=None):
    global LAST_SUSPECT, ALERT_COUNTER
    entry = {
        "id": ALERT_COUNTER,
        "timestamp": int(ts),
        "src_ip": src_ip,
        "dst_port": int(dst_port) if dst_port is not None else None,
        "prediction": int(prediction),
        "probability": float(probability) if probability is not None else None,
        "details": details or {},
        "acknowledged": False
    }
    ALERT_COUNTER += 1
    ALERTS.append(entry)
    # Keep only last 1000 alerts in memory to prevent unbounded growth
    if len(ALERTS) > 1000:
        ALERTS.pop(0)
    LAST_SUSPECT = entry
    # append to CSV
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([entry["timestamp"], entry["src_ip"], entry["dst_port"], entry["prediction"], entry["probability"], str(entry["details"])])

    # update counters
    IP_STATS[entry["src_ip"]] += 1
    if entry["dst_port"] is not None:
        PORT_STATS[entry["dst_port"]] += 1
        IP_PORT_MATRIX[entry["src_ip"]][entry["dst_port"]] += 1

    # Emit real-time event
    socketio.emit("new_alert", entry, namespace="/dashboard")


def increment_packet(ts):
    METRICS["packets"] += 1
    ts_int = int(ts)
    METRICS["timestamps"].append(ts_int)
    METRICS["scan_counts"].append(METRICS["scans"])
    METRICS["packet_timestamps"].append(ts_int)
    # keep sizes moderate - keep last 60 seconds of timestamps for rate calculation
    current_time = ts_int
    METRICS["packet_timestamps"] = [t for t in METRICS["packet_timestamps"] if (current_time - t) <= 60]
    METRICS["timestamps"] = METRICS["timestamps"][-200:]
    METRICS["scan_counts"] = METRICS["scan_counts"][-200:]
    # also emit compact metrics update
    socketio.emit("metrics", {
        "packets": METRICS["packets"],
        "scans": METRICS["scans"],
        "ratio": (METRICS["scans"]/METRICS["packets"]) if METRICS["packets"]>0 else 0,
        "timestamp": ts_int
    }, namespace="/dashboard")


def increment_scan(ts):
    METRICS["scans"] += 1
    ts_int = int(ts)
    METRICS["timestamps"].append(ts_int)
    METRICS["scan_counts"].append(METRICS["scans"])
    METRICS["scan_timestamps"].append(ts_int)
    # keep sizes moderate - keep last 60 seconds of timestamps for rate calculation
    current_time = ts_int
    METRICS["scan_timestamps"] = [t for t in METRICS["scan_timestamps"] if (current_time - t) <= 60]
    METRICS["timestamps"] = METRICS["timestamps"][-200:]
    METRICS["scan_counts"] = METRICS["scan_counts"][-200:]
    
    # Log milestone thresholds
    scan_count = METRICS["scans"]
    if scan_count in [100, 200, 500, 1000, 2000, 5000] or (scan_count > 0 and scan_count % 10000 == 0):
        print(f"⚠️  Milestone: {scan_count} scans detected (total)")
    
    socketio.emit("metrics", {
        "packets": METRICS["packets"],
        "scans": METRICS["scans"],
        "ratio": (METRICS["scans"]/METRICS["packets"]) if METRICS["packets"]>0 else 0,
        "timestamp": ts_int
    }, namespace="/dashboard")


# Expose helpers for import
def update_pipeline_status(**status):
    PIPELINE_STATUS.update(status)


__all__ = [
    "app",
    "socketio",
    "METRICS",
    "add_alert",
    "increment_packet",
    "increment_scan",
    "PORT_STATS",
    "IP_STATS",
    "IP_PORT_MATRIX",
    "ALERTS",
    "LAST_SUSPECT",
    "BLOCKLIST",
    "PIPELINE_STATUS",
    "update_pipeline_status"
]


def start_server(host="0.0.0.0", port=5000):
    print(f"🌐 Starting Flask-SocketIO dashboard at http://127.0.0.1:{port}")
    # note: runtime async mode depends on availability (eventlet -> threading fallback)
    socketio.run(app, host=host, port=port, debug=False)


def start_server_thread():
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    return t


@app.route("/alert/<int:alert_id>")
def alert_details(alert_id):
    alert = next((a for a in ALERTS if a["id"] == alert_id), None)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    ip_history = [a for a in ALERTS if a["src_ip"] == alert["src_ip"]][-20:]
    return jsonify({
        "alert": alert,
        "ip_history": ip_history,
        "blocklisted": alert["src_ip"] in BLOCKLIST
    })


@app.route("/alert/<int:alert_id>/ack", methods=["POST"])
def acknowledge_alert(alert_id):
    alert = next((a for a in ALERTS if a["id"] == alert_id), None)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    alert["acknowledged"] = True
    return jsonify({"status": "ok", "alert_id": alert_id})


@app.route("/actions/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing ip"}), 400
    BLOCKLIST.add(ip)
    block_file = os.path.join("logs", "blocklist.txt")
    os.makedirs("logs", exist_ok=True)
    with open(block_file, "a", encoding="utf-8") as f:
        f.write(f"{int(time.time())},{ip}\n")
    return jsonify({"status": "blocked", "ip": ip, "blocklist_size": len(BLOCKLIST)})


@app.route("/export_logs_filtered")
def export_logs_filtered():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Missing ip"}), 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "src_ip", "dst_port", "prediction", "probability", "details"])
    with open(LOG_FILE, newline="") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if len(row) >= 2 and row[1] == ip:
                writer.writerow(row)
    output.seek(0)
    filename = f"filtered_{ip.replace(':','_')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/ml_info")
def ml_info():
    """Return ML model information including feature importances"""
    try:
        import joblib
        import pandas as pd
        import os
        
        model_path = "portscan_rf.pkl"
        feature_path = "feature_list.csv"
        
        if not os.path.exists(model_path):
            return jsonify({
                "error": "Model file not found",
                "model_type": None,
                "feature_count": 0,
                "feature_importances": []
            })
        
        model = joblib.load(model_path)
        
        # Handle pipeline (scaler + smote + classifier)
        classifier = model
        model_type = model.__class__.__name__
        
        # If it's a pipeline, extract the classifier
        if hasattr(model, 'named_steps') or (hasattr(model, 'steps') and isinstance(model.steps, list)):
            # It's a pipeline - get the classifier step
            if hasattr(model, 'named_steps'):
                # imblearn pipeline
                if 'classifier' in model.named_steps:
                    classifier = model.named_steps['classifier']
                    model_type = f"Pipeline({classifier.__class__.__name__})"
            elif hasattr(model, 'steps'):
                # sklearn pipeline
                for name, step in model.steps:
                    if hasattr(step, 'feature_importances_') or hasattr(step, 'predict'):
                        classifier = step
                        model_type = f"Pipeline({step.__class__.__name__})"
                        break
        
        # Get feature importances if available (Random Forest, etc.)
        feature_importances = []
        feature_count = 0
        
        if os.path.exists(feature_path):
            features = pd.read_csv(feature_path).iloc[:, 0].tolist()
            feature_count = len(features)
            
            if hasattr(classifier, 'feature_importances_'):
                importances = classifier.feature_importances_
                # Sort by importance
                feature_importances = sorted(
                    zip(features, importances.tolist()),
                    key=lambda x: x[1],
                    reverse=True
                )[:20]  # Top 20 features
                feature_importances = [{"feature": f, "importance": round(imp, 6)} for f, imp in feature_importances]
        
        return jsonify({
            "model_type": model_type,
            "feature_count": feature_count,
            "feature_importances": feature_importances,
            "has_importances": hasattr(classifier, 'feature_importances_')
        })
    except Exception as e:
        import traceback
        error_msg = str(e)
        error_trace = traceback.format_exc()
        print(f"ML Info Error: {error_msg}")
        print(error_trace)
        # Always return JSON, even on error
        response = jsonify({
            "error": error_msg,
            "model_type": None,
            "feature_count": 0,
            "feature_importances": [],
            "traceback": error_trace if app.debug else None
        })
        response.status_code = 200  # Ensure 200 status
        return response


@app.route("/system_stats")
def system_stats():
    cpu = psutil.cpu_percent(interval=None) if psutil else None
    ram = psutil.virtual_memory().percent if psutil else None
    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "pipeline": PIPELINE_STATUS,
        "packets": METRICS["packets"],
        "scans": METRICS["scans"],
        "blocklist_size": len(BLOCKLIST)
    })
