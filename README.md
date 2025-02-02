# obscura.cyberthon
Introducing OBSCURA the network analysis suite– foresight in fortress. This cutting-edge platform takes a proactive stance against threats, deploying honeypots to lure attackers, spotting unauthorized devices, and identifying weak protocols in real-time. With the help of AI, it constantly monitors your network, flagging vulnerabilities like open ports and outdated protocols, then offers tailored recommendations to fortify your defenses.
But that’s not all. By tapping into global threat intelligence sources like Shodan, VirusTotal, the suite cross-references the latest exploits with your network logs, providing you with up-to-the-minute insights on emerging risks.

 Its intuitive dashboard makes managing, monitoring, and responding to security threats straightforward, whether you're running a small setup or a sprawling enterprise network.

FEATURES:
1. Network Vulnerability Scanning (Nmap)
•	Uses Nmap to scan network hosts and services.
•	Detects open ports, running services, and their versions.
•	Identifies misconfigurations, weak protocols, and potential attack vectors
Use case:
Helps security analysts identify unpatched services, unauthorized devices, and exposed attack surfaces in an enterprise network.
2. AI/ML-Based Anomaly Detection (Autoencoder)
•	Uses Autoencoder ML models to detect unusual network activity.
•	Trains on normal network behavior and flags suspicious deviations.
•	Identifies possible zero-day attacks and lateral movements within the network.
Use case:
Detects insider threats, suspicious traffic spikes, and unusual service interactions.
3. NIST Protocol Compliance Checks
•	Ensures SSH, TLS, and IPSec protocols meet NIST-recommended security standards.
•	Scans for outdated or weak cryptographic protocols.
•	Flags non-compliant security settings that expose the network to attacks.
Ensures that all critical communication protocols in the network are properly configured and secured against known vulnerabilities.
4. Honeypot-Based Attack Detection
•	Deploys a low-interaction honeypot to attract and detect attackers.
•	Logs malicious IPs attempting SSH brute-force, malware injections, etc.
•	Integrates with the dashboard to display real-time attack attempts.
Use Case:
Detects unauthorized login attempts, malware distribution, and port scanning activities in an organization’s network.
5. Threat Intelligence Integration (Shodan & VirusTotal)
•	Uses Shodan API to gather external intelligence on detected IPs.
•	Queries VirusTotal API to check if a scanned IP is flagged for malicious activities.
•	Provides global threat context to improve vulnerability assessment.
Use Case:
Helps SOC teams identify whether an attacker’s IP is already known for cyberattacks, improving response times.
6. Real-Time Dashboard (AdminLTE + Plotly)
•	Provides an interactive dashboard with real-time threat insights.
•	Displays graphical analytics (e.g., affected hosts, vulnerability distribution).
•	Uses color-coded risk levels to highlight critical security threats.
Use Case:
Allows network security teams to visually analyze network weaknesses and prioritize risk mitigation.
7. PDF Reporting (Detailed Security Reports)
•	Generates PDF reports listing all detected vulnerabilities & risks.
•	Saves reports in structured format for future audits.
•	Includes attack logs, risk scores, and compliance findings.
Use cases:
Helps compliance officers and CISOs generate security audit reports for regulatory documentation.

WHAT MAKES OBSCURA UNIQUE?
What truly sets this platform-obscura apart is the fusion of dynamic honeypot data, AI driven guidance, and external intelligence.This powerful trifecta doesn’t just react to threats –it anticipates, neutralizes, and outmaneuvers them, ensuring your network infrastructure stays one step ahead. Whether safeguarding a handful of devices or fortifying an entire enterprise, this platform scales effortlessly, offering customisable security solutions tailored to your unique needs.
how it works?
Obscura scans networks using Nmap and detects anomalies with AI-powered analysis. It integrates Shodan & VirusTotal for real-time threat intelligence and tracks attacks using a honeypot. A dashboard provides interactive analytics, while automated PDF reports ensure compliance and security assessments.
why obscura?
What sets Obscura apart from other platforms is its ability to combine AI-driven anomaly detection, real-time threat intelligence, and honeypot-based attack tracking in a single solution. Unlike traditional tools that rely on signature-based detection, Obscura leverages Autoencoder AI models to identify zero-day threats and unusual network behavior. It goes beyond standard vulnerability scanning by integrating Shodan and VirusTotal APIs, providing global threat intelligence for faster incident response. Additionally, its built-in honeypot actively attracts attackers, logging unauthorized access attempts in real time. With an intuitive dashboard, automated compliance checks, and detailed security reports, Obscura delivers a proactive and comprehensive approach to modern cybersecurity
