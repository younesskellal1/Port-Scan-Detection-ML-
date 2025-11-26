// static/main.js
const socket = io("/dashboard");

let scanLineChart, portsBarChart, ipsBarChart;
let selectedAlert = null;

const modalEl = document.getElementById("alertModal");
const modalAlertJson = document.getElementById("modalAlertJson");
const modalHistory = document.getElementById("modalHistory");
const modalMeta = document.getElementById("modalMeta");
const ackBtn = document.getElementById("ackBtn");
const blockBtn = document.getElementById("blockBtn");
const exportIpBtn = document.getElementById("exportIpBtn");
const modalClose = document.getElementById("modalClose");

function initCharts(){
    const ctxLine = document.getElementById("scanLine").getContext("2d");
    scanLineChart = new Chart(ctxLine, {
        type: "line",
        data: { labels: [], datasets: [{ label:"Cumulative Scans", data: [], borderWidth:2 }] },
        options: { animation:false }
    });

    const ctxPorts = document.getElementById("portsBar").getContext("2d");
    portsBarChart = new Chart(ctxPorts, {
        type: "bar",
        data: { labels: [], datasets: [{ label:"Hits", data: [] }] },
        options:{animation:false}
    });

    const ctxIps = document.getElementById("ipsBar").getContext("2d");
    ipsBarChart = new Chart(ctxIps, {
        type: "bar",
        data: { labels: [], datasets: [{ label:"Hits", data: [] }] },
        options:{animation:false}
    });

}

initCharts();
attachAlertRowHandler();
attachModalHandlers();

function attachAlertRowHandler(){
    const tbody = document.querySelector("#alertsTable tbody");
    tbody.addEventListener("click", (e)=>{
        const row = e.target.closest("tr[data-alert-id]");
        if(!row) return;
        const alertId = row.dataset.alertId;
        openAlertModal(alertId);
    });
}

function attachModalHandlers(){
    modalClose.addEventListener("click", closeModal);
    modalEl.addEventListener("click", (e)=>{
        if(e.target === modalEl) closeModal();
    });
    ackBtn.addEventListener("click", acknowledgeCurrentAlert);
    blockBtn.addEventListener("click", blockCurrentAlertIp);
    exportIpBtn.addEventListener("click", exportCurrentAlertLogs);
}

function openAlertModal(alertId){
    fetch(`/alert/${alertId}`)
        .then(r=>r.json())
        .then(data=>{
            if(data.error){
                alert(data.error);
                return;
            }
            selectedAlert = data.alert;
            modalMeta.innerText = `${data.alert.src_ip} → ${data.alert.dst_port || "?"} • ID ${data.alert.id} ${data.alert.acknowledged ? "(ack)" : ""}`;
            modalAlertJson.innerText = JSON.stringify(data.alert, null, 2);
            modalHistory.innerText = JSON.stringify(data.ip_history, null, 2);
            modalEl.classList.add("show");
        }).catch(err=>{
            console.error(err);
            alert("Impossible de charger l'alerte");
        });
}

function closeModal(){
    modalEl.classList.remove("show");
    selectedAlert = null;
}

async function acknowledgeCurrentAlert(){
    if(!selectedAlert) return;
    try{
        await fetch(`/alert/${selectedAlert.id}/ack`, {method:"POST"});
        selectedAlert.acknowledged = true;
        modalAlertJson.innerText = JSON.stringify(selectedAlert, null, 2);
        refreshMetrics();
    }catch(e){
        console.error(e);
    }
}

async function blockCurrentAlertIp(){
    if(!selectedAlert) return;
    try{
        await fetch("/actions/block_ip", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({ip: selectedAlert.src_ip})
        });
        refreshMetrics();
    }catch(e){
        console.error(e);
    }
}

function exportCurrentAlertLogs(){
    if(!selectedAlert) return;
    window.location = `/export_logs_filtered?ip=${encodeURIComponent(selectedAlert.src_ip)}`;
}

async function refreshMetrics(){
    try{
        const r = await fetch("/metrics");
        const json = await r.json();
        document.getElementById("packets").innerText = json.packets;
        document.getElementById("scans").innerText = json.scans;
        document.getElementById("ratio").innerText = json.ratio.toFixed(3);
        
        // Real-time rates
        document.getElementById("packetRate").innerText = (json.packet_rate_ps || 0).toFixed(2);
        document.getElementById("scanRate").innerText = (json.scan_rate_pm || 0).toFixed(2);
        document.getElementById("scanRateHour").innerText = (json.scan_rate_ph || 0).toFixed(1);

        scanLineChart.data.labels = json.timestamps.map(t => new Date(t*1000).toLocaleTimeString());
        scanLineChart.data.datasets[0].data = json.scan_counts;
        scanLineChart.update();

        // Alert statistics
        const alertStats = await fetch("/alert_stats").then(r=>r.json()).catch(()=>({
            total: 0, acknowledged: 0, unacknowledged: 0, alert_rate_per_hour: 0,
            recent_alerts_1h: 0, high_severity: 0, acknowledged_percent: 0
        }));
        document.getElementById("alertTotal").innerText = alertStats.total;
        document.getElementById("alertUnack").innerText = alertStats.unacknowledged;
        document.getElementById("alertAck").innerText = alertStats.acknowledged;
        document.getElementById("alertAckPercent").innerText = `${alertStats.acknowledged_percent}%`;
        document.getElementById("alertRate").innerText = alertStats.alert_rate_per_hour.toFixed(1);
        document.getElementById("alertRecent").innerText = alertStats.recent_alerts_1h;
        document.getElementById("alertHighSev").innerText = alertStats.high_severity;

        // ports & ips
        const p = await fetch("/top_ports").then(r=>r.json());
        portsBarChart.data.labels = p.map(x=>x[0]);
        portsBarChart.data.datasets[0].data = p.map(x=>x[1]);
        portsBarChart.update();

        const ips = await fetch("/top_ips").then(r=>r.json());
        ipsBarChart.data.labels = ips.map(x=>x[0]);
        ipsBarChart.data.datasets[0].data = ips.map(x=>x[1]);
        ipsBarChart.update();

        // alerts table
        const alerts = await fetch("/alerts").then(r=>r.json());
        const tbody = document.querySelector("#alertsTable tbody");
        tbody.innerHTML = "";
        alerts.slice(-30).reverse().forEach(a=>{
            const tr = document.createElement("tr");
            tr.classList.add("alert-row");
            if(a.acknowledged) tr.classList.add("ack");
            tr.dataset.alertId = a.id;
            tr.innerHTML = `<td>${new Date(a.timestamp*1000).toLocaleTimeString()}</td><td>${a.src_ip}</td><td>${a.dst_port}</td><td>${(a.probability||0).toFixed(3)}</td>`;
            tbody.appendChild(tr);
        });

        // last suspect
        const last = await fetch("/last_suspect").then(r=>r.json());
        document.getElementById("lastSuspect").innerText = JSON.stringify(last, null, 2);

        const sys = await fetch("/system_stats").then(r=>r.json());
        if(sys.cpu !== null && sys.cpu !== undefined){
            document.getElementById("cpu").innerText = `${sys.cpu.toFixed(1)}%`;
        }
        if(sys.ram !== null && sys.ram !== undefined){
            document.getElementById("ram").innerText = `${sys.ram.toFixed(1)}%`;
        }
        document.getElementById("loopTime").innerText = `${(sys.pipeline?.last_loop_ms ?? 0)} ms`;
        document.getElementById("queueDepth").innerText = sys.pipeline?.queue_depth ?? 0;
        document.getElementById("blockCount").innerText = sys.blocklist_size ?? 0;

        // ML Info
        try {
            const mlResponse = await fetch("/ml_info");
            if (!mlResponse.ok) {
                throw new Error(`HTTP ${mlResponse.status}: ${mlResponse.statusText}`);
            }
            const contentType = mlResponse.headers.get("content-type");
            if (!contentType || !contentType.includes("application/json")) {
                const text = await mlResponse.text();
                throw new Error(`Expected JSON but got: ${contentType}\nResponse: ${text.substring(0, 200)}`);
            }
            const mlInfo = await mlResponse.json();
            let mlText = `Model: ${mlInfo.model_type || "Unknown"}\n`;
            mlText += `Features: ${mlInfo.feature_count || 0}\n\n`;
            if(mlInfo.feature_importances && mlInfo.feature_importances.length > 0){
                mlText += "Top Features (by importance):\n";
                mlInfo.feature_importances.slice(0, 10).forEach((item, idx) => {
                    mlText += `${idx+1}. ${item.feature}: ${item.importance.toFixed(4)}\n`;
                });
            } else if(mlInfo.error){
                mlText += `Error: ${mlInfo.error}`;
            } else {
                mlText += "Feature importances not available";
            }
            document.getElementById("mlInfo").innerText = mlText;
        } catch(e) {
            document.getElementById("mlInfo").innerText = `Error loading ML info:\n${e.message}`;
            console.error("ML Info fetch error:", e);
        }

    }catch(e){
        console.error("refresh error", e);
    }
}

// initial load
refreshMetrics();
setInterval(refreshMetrics, 1000);

// socket events: new alert -> add to table quickly
socket.on("new_alert", function(data){
    // prepend to alerts
    const tbody = document.querySelector("#alertsTable tbody");
    const tr = document.createElement("tr");
    tr.classList.add("alert-row");
    if(data.acknowledged) tr.classList.add("ack");
    tr.dataset.alertId = data.id;
    tr.innerHTML = `<td>${new Date(data.timestamp*1000).toLocaleTimeString()}</td><td>${data.src_ip}</td><td>${data.dst_port}</td><td>${(data.probability||0).toFixed(3)}</td>`;
    tbody.prepend(tr);
});

// export btn
document.getElementById("exportBtn").addEventListener("click", ()=>{
    window.location = "/export_logs";
});
