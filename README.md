# Port Scan Detection with Machine Learning

Real-time port scan detection system using machine learning with a live SOC dashboard.

## Overview

This project implements an end-to-end machine learning-based port scan detection system that:
- Trains ML models (Random Forest, Decision Tree, Logistic Regression) on labeled network traffic
- Performs real-time detection on live network packets using pyshark
- Provides an interactive SOC-style web dashboard for monitoring and alerting

## Features

- **Offline Training**: Train ML models on CSV datasets of normal and port scan traffic
- **Live Detection**: Real-time packet capture and classification using pyshark
- **SOC Dashboard**: Interactive web dashboard with:
  - Real-time metrics (packets, scans, rates)
  - Top ports and IPs visualization
  - Alert management (acknowledge, block IPs, export logs)
  - System health monitoring
  - Model information and feature importances

## Project Structure

```
projetcyber/
├── model.py                 # Training script for ML models
├── detect_live.py          # Live detection pipeline
├── live_extract.py         # Packet capture and feature extraction
├── dashboard_server.py     # Flask-SocketIO backend server
├── datasets.rar
├── templates/
│   └── dashboard.html     # Dashboard frontend
├── static/
│   └── main.js            # Dashboard JavaScript
├── feature_list.csv       # List of features used by the model
├── portscan_rf.pkl        #model        
└── .gitignore             # Git ignore file

```

## Requirements

```bash
pip install pandas numpy scikit-learn imbalanced-learn matplotlib seaborn pyshark flask flask-socketio joblib
```

## Usage

### 1. Train the Model

```bash
python model.py
```

This will:
- Load `normal_dataset.csv` and `malicious_dataset.csv`
- Preprocess and train multiple models
- Save the best model as `portscan_rf.pkl`
- Generate confusion matrices and performance metrics

### 2. Run Live Detection

```bash
python detect_live.py
```

This will:
- Start the dashboard server (accessible at http://127.0.0.1:5000)
- Begin capturing packets from the Wi-Fi interface
- Classify packets in real-time and display alerts on the dashboard

## Model Performance

The Random Forest model achieves:
- **Accuracy**: ~99.9%
- **Precision**: ~99.9%
- **Recall**: ~99.9%
- **F1-Score**: ~99.9%

## Dashboard Features

- **Global Metrics**: Total packets, scans, risk ratio, packet/scan rates
- **Visualizations**: Time series charts, top ports bar chart, top IPs bar chart
- **Alert Management**: View, acknowledge, and block suspicious IPs
- **Export**: Download detection logs as CSV
- **System Stats**: CPU, RAM, pipeline performance metrics




