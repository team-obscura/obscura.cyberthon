from flask import Flask, render_template_string, jsonify, request, redirect, url_for
import plotly.graph_objs as go
import nmap
import shodan
import requests
import os
import datetime

app = Flask(__name__)
app.secret_key = "dummy key"

# ---------- CONFIGURATION ----------
# Update this path to where nmap.exe is located.
NMAP_PATH = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
if not os.path.exists(NMAP_PATH):
    NMAP_PATH = None  # Fall back to system PATH

#  common ports targeted
COMMON_VULN_PORTS = {21, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389}
# Define which ports are considered vulnerable when open.
VULNERABLE_PORTS = {21, 23,110,80,3306}

# Fake honeypot data for demonstration purposes.
FAKE_HONEYPOT_DATA = [
    {"ip": "203.0.113.5", "attack_type": "SSH Brute Force", "timestamp": "2025-02-02 08:15:00"},
    {"ip": "198.51.100.12", "attack_type": "Telnet Scan", "timestamp": "2025-02-02 08:45:00"},
    {"ip": "192.0.2.45", "attack_type": "RDP Exploit Attempt", "timestamp": "2025-02-02 14:30:00"}
]

# API keys.
SHODAN_API_KEY = "EJV3A4Mka2wPs7P8VBCO6xcpRe27iNJu"
VIRUSTOTAL_API_KEY = "e9fde638c9b799d84ae3c6c26666c91c921f2b37d3c6e6011146b186d0287552"

# ---------- NMAP NETWORK SCANNING ----------
def scan_network(target):
    try:
        if NMAP_PATH:
            scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH, 'nmap'))
        else:
            scanner = nmap.PortScanner()
    except nmap.PortScannerError as e:
        return {"error": f"nmap initialization error: {e}"}

    start_time = datetime.datetime.now()
    port_string = ",".join(str(port) for port in sorted(COMMON_VULN_PORTS))
    # We scan all specified ports (open, closed, or filtered) with version detection.
    scanner.scan(hosts=target, arguments=f"-sV -T5 -p {port_string}")
    end_time = datetime.datetime.now()
    scan_duration = (end_time - start_time).total_seconds()

    results = {"target": target, "scan_duration": scan_duration, "hosts": []}

    for host in scanner.all_hosts():
        host_state = scanner[host].state()
        host_status = "online" if host_state.lower() == "up" else "offline"
        host_info = {
            "host": host,
            "status": host_status,
            "ports": []
        }
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                port_state = scanner[host][proto][port].get('state', 'unknown')
                service = scanner[host][proto][port].get('name', 'unknown')
                version = scanner[host][proto][port].get('version', '')
                product = scanner[host][proto][port].get('product', '')
                # A port is considered vulnerable if it is open and in the vulnerable ports list.
                is_vulnerable = (port_state.lower() == "open") and (int(port) in VULNERABLE_PORTS)
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "state": port_state,
                    "service": service,
                    "version": version,
                    "banner": product,
                    "vulnerable": is_vulnerable
                }
                host_info["ports"].append(port_info)
        results["hosts"].append(host_info)
    return results

# ---------- HONEYPOT ATTACK LOGGING ----------
HONEYPOT_LOG_FILE = "honeypot_attacks.log"
def get_honeypot_attacks():
    attacks = []
    if os.path.exists(HONEYPOT_LOG_FILE):
        with open(HONEYPOT_LOG_FILE, "r") as f:
            for line in f.readlines():
                try:
                    ip, attack_type, timestamp = line.strip().split(",")
                    attacks.append({"ip": ip, "attack_type": attack_type, "timestamp": timestamp})
                except ValueError:
                    continue
    if not attacks:
        attacks = FAKE_HONEYPOT_DATA
    return attacks

# ---------- THREAT INTELLIGENCE ----------
def get_shodan_info(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host_data = api.host(ip)
        shodan_info = {
            "ip_str": host_data.get("ip_str", ip),
            "organization": host_data.get("org", "N/A"),
            "country_name": host_data.get("country_name", "N/A"),
            "open_ports": host_data.get("ports", []),
            "vulns": host_data.get("vulns", []),
            "last_update": host_data.get("last_update", "N/A")
        }
        return shodan_info
    except shodan.APIError as e:
        err_msg = str(e)
        if "Forbidden" in err_msg:
            err_msg = "Access forbidden. Please check your Shodan API key and permissions."
        return {"error": err_msg}

def get_virustotal_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        vt_data = response.json()
        attributes = vt_data.get("data", {}).get("attributes", {})
        detailed_info = {
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "reputation": attributes.get("reputation", "N/A"),
            "country": attributes.get("country", "N/A"),
            "as_owner": attributes.get("as_owner", "N/A"),
            "network": attributes.get("network", "N/A")
        }
        return {"data": detailed_info}
    else:
        return {"error": f"VirusTotal API returned status code {response.status_code}"}

# ---------- ROUTES ----------
@app.route("/")
def dashboard():
    # Sample data for static graphs.
    hosts = ["Host1", "Host2", "Host3"]
    vulnerabilities = [5, 3, 8]
    honeypot_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    attack_counts = [2, 7, 4]

    scan_fig = go.Figure(data=[go.Bar(x=hosts, y=vulnerabilities, marker_color="blue")])
    scan_fig.update_layout(
        title="Network Vulnerabilities per Host",
        xaxis_title="Host",
        yaxis_title="Vulnerability Count"
    )

    honeypot_fig = go.Figure(data=[go.Bar(x=honeypot_ips, y=attack_counts, marker_color="red")])
    honeypot_fig.update_layout(
        title="Honeypot Attack Counts",
        xaxis_title="IP Address",
        yaxis_title="Attack Count severity"
    )

    scan_fig_dict = scan_fig.to_dict()
    honeypot_fig_dict = honeypot_fig.to_dict()

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Obscura Security Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; color: #333; text-align: center; }
            header { background: #333; color: #fff; padding: 15px; font-size: 22px; margin-bottom: 20px; }
            .container { padding: 20px; }
            .button, .hyperlink {
                display: inline-block;
                margin: 10px;
                padding: 15px;
                font-size: 18px;
                text-decoration: none;
                background: #007BFF;
                color: #fff;
                border-radius: 5px;
            }
            .button:hover, .hyperlink:hover { background: #0056b3; }
            input { padding: 10px; margin: 10px; width: 250px; border: 1px solid #ccc; }
            button { padding: 10px; cursor: pointer; background: #28a745; color: #fff; border: none; border-radius: 5px; }
            button:hover { background: #218838; }
            .graph-container { display: flex; justify-content: center; flex-wrap: wrap; margin-top: 20px; }
            .graph { width: 45%; margin: 10px; }
            .results { text-align: left; max-width: 600px; margin: auto; background: #fff; padding: 15px; border: 1px solid #ccc; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .vulnerable { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <header>Obscura Security Dashboard</header>
        <div class="container">
            <!-- Scan Target Section -->
            <div>
                <input type="text" id="scan_target" placeholder="Enter target IP or hostname">
                <button onclick="scanTarget()">Scan Target</button>
            </div>
            <div id="scan-results-display" class="results"></div>
            <br>
            <!-- Hyperlink to view detailed scan results -->
            <div id="detailed-scan-link"></div>
            <br>
            <!-- Honeypot Logs -->
            <a href="/honeypot-results" class="button">View Honeypot Logs</a>
            <br>
            <!-- Threat Check Section -->
            <div>
                <input type="text" id="threat_ip" placeholder="Enter IP for Threat Check">
                <button onclick="checkThreat()">Check Threat</button>
            </div>
            <div id="threat-results" class="results"></div>
            <br>
            <div class="graph-container">
                <div class="graph" id="scan_graph"></div>
                <div class="graph" id="honeypot_graph"></div>
            </div>
        </div>

        <script>
            function scanTarget() {
                let target = document.getElementById("scan_target").value;
                if (!target) {
                    alert("Please enter a target IP or hostname.");
                    return;
                }
                document.getElementById("scan-results-display").innerHTML = "Scanning " + target + "...";
                // Clear any previous hyperlink
                document.getElementById("detailed-scan-link").innerHTML = "";
                fetch("/scan-results?target=" + encodeURIComponent(target))
                    .then(response => response.json())
                    .then(data => {
                        let output = "<h3>Scan Results for " + target + ":</h3>";
                        if (data.error) {
                            output += "<p>Error: " + data.error + "</p>";
                        } else {
                            output += "<p>Scan Duration: " + data.scan_duration + " seconds</p>";
                            data.hosts.forEach(host => {
                                output += "<hr><p><b>Host:</b> " + host.host + " (" + host.status + ")</p>";
                                if (host.ports.length) {
                                    output += "<p><b>Scanned Ports (summary):</b></p><ul>";
                                    host.ports.forEach(port => {
                                        let flag = port.vulnerable ? "OPEN/VULNERABLE" : port.state.toUpperCase();
                                        output += "<li>" + port.port + "/" + port.protocol + ": " + port.service;
                                        if (port.version) { output += " (" + port.version + ")"; }
                                        output += " <span class='vulnerable'>[" + flag + "]</span></li>";
                                    });
                                    output += "</ul>";
                                } else {
                                    output += "<p>No port information returned.</p>";
                                }
                            });
                            // Add hyperlink for detailed view
                            let detailsURL = "/scan-details?target=" + encodeURIComponent(target);
                            output += "<p><a href='" + detailsURL + "' class='hyperlink'>View Detailed Scan Results</a></p>";
                        }
                        document.getElementById("scan-results-display").innerHTML = output;
                    })
                    .catch(err => {
                        document.getElementById("scan-results-display").innerHTML = "Error scanning target: " + err;
                    });
            }

            function checkThreat() {
                let ip = document.getElementById("threat_ip").value;
                if (!ip) {
                    alert("Please enter an IP address for threat intelligence.");
                    return;
                }
                document.getElementById("threat-results").innerHTML = "Checking threat intelligence for " + ip + "...";
                fetch(`/threat/${ip}`)
                    .then(response => response.json())
                    .then(data => {
                        let shodanData = data.shodan;
                        let vtData = data.virustotal;
                        let output = "<h3>Threat Intelligence:</h3>";
                        if (shodanData.error) {
                            output += `<p><b>Shodan Error:</b> ${shodanData.error}</p>`;
                        } else {
                            output += `<p><b>Shodan Info:</b></p><ul>`;
                            output += `<li><b>IP:</b> ${shodanData.ip_str}</li>`;
                            output += `<li><b>Organization:</b> ${shodanData.organization}</li>`;
                            output += `<li><b>Country:</b> ${shodanData.country_name}</li>`;
                            output += `<li><b>Open Ports:</b> ${shodanData.open_ports.join(", ") || "N/A"}</li>`;
                            output += `<li><b>Vulnerabilities:</b> ${shodanData.vulns.length ? shodanData.vulns.join(", ") : "None"}</li>`;
                            output += `<li><b>Last Update:</b> ${shodanData.last_update}</li>`;
                            output += `</ul>`;
                        }
                        if (vtData.error) {
                            output += `<p><b>VirusTotal Error:</b> ${vtData.error}</p>`;
                        } else if (vtData.data) {
                            output += `<p><b>VirusTotal Info:</b></p><ul>`;
                            output += `<li><b>Malicious:</b> ${vtData.data.last_analysis_stats.malicious || 0}</li>`;
                            output += `<li><b>Suspicious:</b> ${vtData.data.last_analysis_stats.suspicious || 0}</li>`;
                            output += `<li><b>Harmless:</b> ${vtData.data.last_analysis_stats.harmless || 0}</li>`;
                            output += `<li><b>Reputation:</b> ${vtData.data.reputation}</li>`;
                            output += `<li><b>Country:</b> ${vtData.data.country}</li>`;
                            output += `<li><b>AS Owner:</b> ${vtData.data.as_owner}</li>`;
                            output += `<li><b>Network:</b> ${vtData.data.network}</li>`;
                            output += `</ul>`;
                        } else {
                            output += `<p><b>VirusTotal:</b> No data available.</p>`;
                        }
                        document.getElementById("threat-results").innerHTML = output;
                    })
                    .catch(err => {
                        document.getElementById("threat-results").innerHTML = "Error retrieving threat intelligence: " + err;
                    });
            }

            // Render static graphs.
            Plotly.newPlot("scan_graph", {{ scan_fig_dict|tojson|safe }});
            Plotly.newPlot("honeypot_graph", {{ honeypot_fig_dict|tojson|safe }});

        </script>
    </body>
    </html>
    """, scan_fig_dict=scan_fig_dict, honeypot_fig_dict=honeypot_fig_dict)

@app.route("/scan-results")
def scan_results():
    target = request.args.get('target', '192.168.1.1')
    results = scan_network(target)
    if isinstance(results, dict) and "error" in results:
        return jsonify(results), 500
    return jsonify(results)

# New route for detailed scan results.
@app.route("/scan-details")
def scan_details():
    target = request.args.get('target')
    if not target:
        return "No target specified.", 400
    results = scan_network(target)
    if "error" in results:
        return f"<h3>Error scanning target {target}: {results['error']}</h3>"
    
    # Build a simple HTML page with detailed scan info.
    detailed_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Detailed Scan Results for {{ target }}</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; color: #333; padding: 20px; }
            h1 { text-align: center; }
            .host-section { background: #fff; margin: 20px auto; padding: 15px; border: 1px solid #ccc; border-radius: 5px; max-width: 800px; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #007BFF; color: white; }
            .vulnerable { color: red; font-weight: bold; }
            a { display: inline-block; margin-top: 20px; text-decoration: none; background: #007BFF; color: #fff; padding: 10px 15px; border-radius: 5px; }
            a:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <h1>Detailed Scan Results for {{ target }}</h1>
        {% for host in results.hosts %}
        <div class="host-section">
            <h2>Host: {{ host.host }} ({{ host.status }})</h2>
            <p>Scan Duration: {{ results.scan_duration }} seconds</p>
            {% if host.ports %}
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Banner</th>
                        <th>Vulnerable?</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port in host.ports %}
                    <tr>
                        <td>{{ port.port }}</td>
                        <td>{{ port.protocol }}</td>
                        <td>{{ port.state }}</td>
                        <td>{{ port.service }}</td>
                        <td>{{ port.version }}</td>
                        <td>{{ port.banner }}</td>
                        <td>{% if port.vulnerable %}<span class="vulnerable">Yes</span>{% else %}No{% endif %}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No port information available.</p>
            {% endif %}
        </div>
        {% endfor %}
        <div style="text-align: center;"><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></div>
    </body>
    </html>
    """
    return render_template_string(detailed_html, target=target, results=results)

@app.route("/honeypot-results")
def honeypot_results():
    return jsonify(get_honeypot_attacks())

@app.route("/threat/<ip>")
def threat_check(ip):
    shodan_data = get_shodan_info(ip)
    virustotal_data = get_virustotal_info(ip)
    return jsonify({"shodan": shodan_data, "virustotal": virustotal_data})

if __name__ == "__main__":
    app.run(debug=True)
