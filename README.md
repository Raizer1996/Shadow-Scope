# ShadowScope 🛰️

**ShadowScope** is a powerful, terminal-based IOC (Indicator of Compromise) enrichment and analysis tool. It aggregates data from multiple threat intelligence sources to provide a comprehensive risk assessment for IPs, Domains, URLs, and File Hashes.

![ShadowScope Banner](https://via.placeholder.com/800x200.png?text=ShadowScope+Banner)

## 🚀 Features

*   **Multi-Source Enrichment**:
    *   **VirusTotal**: Malicious detection counts and analysis stats.
    *   **AbuseIPDB**: Confidence scores and usage types (ISP, Data Center).
    *   **Shodan**: Host tags (VPN, Proxy), open ports, and vulnerabilities.
    *   **IPQualityScore**: Fraud and risk scoring.
    *   **IPinfo**: Organization and ASN details.
    *   **Tor Detection**: Identifies active Tor exit nodes.
    *   **WHOIS**: Domain creation dates and registrar info.
*   **Multi-Sandbox Analysis**:
    *   **FileScan.IO**: Full file/URL analysis with report links.
    *   **Hybrid Analysis**: (Optional) Automated malware analysis.
    *   **Joe Sandbox**: (Optional) Deep malware analysis.
*   **Smart Risk Scoring**:
    *   Calculates a composite risk score (0-100).
    *   Color-coded risk levels: **Safe**, **Low**, **Medium**, **High**, **Critical**.
    *   Automatic flagging of VPNs, Proxies, and Tor nodes.
*   **Sleek CLI Interface**:
    *   Interactive menu system.
    *   Rich text formatting with tables and colors.
    *   "Sniper Scope" banner and visual effects.

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/ShadowScope.git
    cd ShadowScope
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure API Keys**:
    *   Copy the example environment file:
        ```bash
        cp ioc_tool/.env.example ioc_tool/.env
        ```
    *   Edit `ioc_tool/.env` and add your API keys:
        *   `VT_API_KEY` (VirusTotal)
        *   `ABUSEIPDB_API_KEY` (AbuseIPDB)
        *   `SHODAN_API_KEY` (Shodan)
        *   `FILE_SCAN_IO` (FileScan.IO)
        *   ...and others.

## 💻 Usage

**Interactive Mode:**
```bash
python3 -m ioc_tool.main
```

**Quick Shortcuts:**
*   **Enrich an IP/Domain/Hash:**
    ```bash
    python3 -m ioc_tool.main -1 8.8.8.8
    ```
*   **Analyze a File/URL:**
    ```bash
    python3 -m ioc_tool.main -2 sample.exe
    ```
*   **Shodan Scan:**
    ```bash
    python3 -m ioc_tool.main -3 1.1.1.1
    ```

## 🛡️ License

This project is for educational and defensive purposes only. Use responsibly.
