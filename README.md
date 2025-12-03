# 🛡️ Network Security Analyzer & Threat Detection Toolkit  
**Python | Scapy | Wireshark**

A lightweight network analysis and threat detection toolkit built to inspect packet-level behavior, identify anomalies, and generate forensic-ready security logs. This project uses Scapy for packet parsing, hybrid detection logic for anomalies, and Wireshark for validation.

---

## 🚀 Features

### 🔎 Packet Analysis
- Processes PCAP files to analyze **TCP, UDP, ICMP, and HTTP** traffic.
- Extracts source/destination IPs, ports, protocol layers, flags, and packet metadata.
- Performs low-level inspection similar to Wireshark using Scapy.

### 🛑 Threat & Anomaly Detection
- Detects common suspicious behaviors:
  - Malformed packets  
  - SYN scans / port scans  
  - Abnormal TTL values  
  - Oversized or irregular packets  
  - Rare or unexpected protocol usage
- Hybrid rules:
  - **Signature-based detection**
  - **Statistical anomaly detection**

### 📂 Structured Logging
- Generates JSON-based security logs for forensic analysis.
- Records timestamps, source/destination, detection type, and packet metadata.

### 🧪 Validation with Wireshark
- All detection outputs are cross-verified using Wireshark for accuracy.
- Ensures protocol alignment and correct interpretation of packet structure.

---

---

## 🧰 Tech Stack

- **Python**
- **Scapy**
- **Pandas**
- **Wireshark**
- **Google Colab / Jupyter Notebook**

---

## 📊 Outputs

The toolkit generates:

- **Packet Summary:** Protocol counts, metadata, and communication patterns  
- **Threat Alerts:** Suspicious packets with rule-based justification  
- **Forensic Log Files:** JSON logs for post-analysis or security review  

---

## 📦 How to Use

1. Upload your `.pcap` file to the notebook or provide a path.
2. Run the notebook cells (Google Colab recommended).
3. View packet summaries and anomaly detection results.
4. Download structured `alert_log.json` for further analysis.

---

## 🔐 Use Cases

- Network traffic inspection  
- Security research and education  
- Log generation for SOC workflows  
- Detecting suspicious or malicious network behavior  
- Comparing Scapy vs. Wireshark packet interpretation  

---

## 🛠️ Future Enhancements

- Machine-learning-based anomaly classification  
- Support for encrypted traffic fingerprinting  
- DNS/HTTP/SSL-specific deep inspection  
- Dashboard for visual traffic analytics  

---




