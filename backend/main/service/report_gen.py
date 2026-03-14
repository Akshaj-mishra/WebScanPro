import json
import datetime
import os
from fpdf import FPDF
import markdown
from jinja2 import Template

class ReportGenerator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.scan_time = datetime.datetime.now()
        self.report_data = {
            "scan_info": {
                "target": target_url,
                "scan_date": self.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                "tool_version": "WebScanPro v1.0"
            },
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "statistics": {},
            "remediation": []
        }
    
    def add_sql_results(self, sql_results):
        """Add SQL injection results to report"""
        for result in sql_results:
            for payload, response in result["results"].items():
                if "VULNERABLE" in response:
                    self.report_data["vulnerabilities"]["critical"].append({
                        "type": "SQL Injection",
                        "url": result["url"],
                        "payload": payload,
                        "evidence": response,
                        "remediation": "Use parameterized queries, input validation, and least privilege principles"
                    })
    
    def add_xss_results(self, xss_results):
        """Add XSS results to report"""
        # Reflected XSS
        for xss in xss_results.get("reflected_xss", []):
            severity = xss.get("severity", "MEDIUM").lower()
            if severity == "high":
                self.report_data["vulnerabilities"]["high"].append({
                    "type": "Reflected XSS",
                    "url": xss["url"],
                    "parameter": xss["parameter"],
                    "payload": xss["payload"],
                    "remediation": "Implement proper output encoding, use Content Security Policy (CSP)"
                })
            else:
                self.report_data["vulnerabilities"]["medium"].append({
                    "type": "Reflected XSS",
                    "url": xss["url"],
                    "parameter": xss["parameter"],
                    "payload": xss["payload"],
                    "remediation": "Implement proper output encoding"
                })
        
        # Stored XSS
        for xss in xss_results.get("stored_xss", []):
            self.report_data["vulnerabilities"]["high"].append({
                "type": "Stored XSS",
                "url": xss["form_action"],
                "payload": xss["payload"],
                "remediation": "Implement input validation, output encoding, and Content Security Policy"
            })
    
    def add_auth_results(self, auth_results):
        """Add authentication testing results"""
        if auth_results.get("weak_credentials") and isinstance(auth_results["weak_credentials"], dict):
            self.report_data["vulnerabilities"]["critical"].append({
                "type": "Weak Credentials",
                "details": f"Found working credentials: {auth_results['weak_credentials']['username']}:{auth_results['weak_credentials']['password']}",
                "remediation": "Implement strong password policy, enable account lockout, use MFA"
            })
        
        if not auth_results.get("brute_force", {}).get("rate_limiting_detected", True):
            self.report_data["vulnerabilities"]["high"].append({
                "type": "Missing Rate Limiting",
                "details": "No rate limiting detected on login endpoint",
                "remediation": "Implement rate limiting and account lockout mechanisms"
            })
        
        if auth_results.get("session_fixation", {}).get("fixation_possible", False):
            self.report_data["vulnerabilities"]["high"].append({
                "type": "Session Fixation",
                "details": "Session ID does not change after login",
                "remediation": "Regenerate session ID after successful authentication"
            })
        
        # Cookie security issues
        for cookie in auth_results.get("cookie_security", []):
            if not cookie.get("secure_flag"):
                self.report_data["vulnerabilities"]["medium"].append({
                    "type": "Insecure Cookie",
                    "details": f"Cookie '{cookie['cookie_name']}' missing Secure flag",
                    "remediation": "Set Secure flag on all cookies"
                })
            if not cookie.get("httponly_flag"):
                self.report_data["vulnerabilities"]["low"].append({
                    "type": "Insecure Cookie",
                    "details": f"Cookie '{cookie['cookie_name']}' missing HttpOnly flag",
                    "remediation": "Set HttpOnly flag on session cookies"
                })
    
    def add_idor_results(self, idor_results):
        """Add IDOR results to report"""
        for vuln in idor_results.get("vulnerabilities", []):
            severity = "high" if vuln.get("sensitive_data_detected") else "medium"
            self.report_data["vulnerabilities"][severity].append({
                "type": "IDOR",
                "url": vuln["url"],
                "id_tested": vuln["id_tested"],
                "sensitive_data": vuln.get("sensitive_data_detected", False),
                "remediation": "Implement proper access controls, use indirect references, validate user permissions"
            })
    
    def calculate_statistics(self):
        """Calculate report statistics"""
        total = 0
        for severity in self.report_data["vulnerabilities"]:
            count = len(self.report_data["vulnerabilities"][severity])
            total += count
            self.report_data["statistics"][severity] = count
        
        self.report_data["statistics"]["total"] = total
        self.report_data["statistics"]["risk_score"] = self.calculate_risk_score()
    
    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }
        
        total_weight = 0
        max_possible = 100
        
        for severity, count in self.report_data["statistics"].items():
            if severity in weights:
                total_weight += count * weights[severity]
        
        return min(100, total_weight)
    
    def generate_html_report(self, filename="security_report.html"):
        """Generate HTML report"""
        self.calculate_statistics()
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebScanPro Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
                h1 { color: #333; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
                .stat-card { background: #34495e; color: white; padding: 15px; border-radius: 5px; text-align: center; }
                .vuln-section { margin: 20px 0; padding: 15px; border-left: 4px solid; }
                .critical { border-color: #c0392b; }
                .high { border-color: #e67e22; }
                .medium { border-color: #f1c40f; }
                .low { border-color: #3498db; }
                .vuln-item { background: #ecf0f1; padding: 10px; margin: 10px 0; border-radius: 3px; }
                .remediation { background: #d4edda; padding: 10px; margin-top: 5px; border-radius: 3px; }
                .risk-score { font-size: 48px; font-weight: bold; color: {% if risk_score > 70 %}red{% elif risk_score > 40 %}orange{% else %}green{% endif %}; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>WebScanPro Security Report</h1>
                    <p>Target: {{ scan_info.target }}</p>
                    <p>Scan Date: {{ scan_info.scan_date }}</p>
                    <p>Tool Version: {{ scan_info.tool_version }}</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <h3>Risk Score</h3>
                        <div class="risk-score">{{ statistics.risk_score }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Critical</h3>
                        <h2>{{ statistics.critical }}</h2>
                    </div>
                    <div class="stat-card">
                        <h3>High</h3>
                        <h2>{{ statistics.high }}</h2>
                    </div>
                    <div class="stat-card">
                        <h3>Medium</h3>
                        <h2>{{ statistics.medium }}</h2>
                    </div>
                    <div class="stat-card">
                        <h3>Low</h3>
                        <h2>{{ statistics.low }}</h2>
                    </div>
                    <div class="stat-card">
                        <h3>Total</h3>
                        <h2>{{ statistics.total }}</h2>
                    </div>
                </div>
                
                {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
                    {% if vulnerabilities[severity] %}
                    <div class="vuln-section {{ severity }}">
                        <h2>{{ severity.upper() }} Severity Vulnerabilities</h2>
                        {% for vuln in vulnerabilities[severity] %}
                        <div class="vuln-item">
                            <h3>{{ vuln.type }}</h3>
                            <p><strong>URL:</strong> {{ vuln.url }}</p>
                            {% if vuln.parameter %}<p><strong>Parameter:</strong> {{ vuln.parameter }}</p>{% endif %}
                            {% if vuln.payload %}<p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>{% endif %}
                            {% if vuln.details %}<p><strong>Details:</strong> {{ vuln.details }}</p>{% endif %}
                            {% if vuln.evidence %}<p><strong>Evidence:</strong> {{ vuln.evidence }}</p>{% endif %}
                            <div class="remediation">
                                <strong>Remediation:</strong> {{ vuln.remediation }}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(**self.report_data)
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def generate_json_report(self, filename="security_report.json"):
        """Generate JSON report"""
        self.calculate_statistics()
        
        with open(filename, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        
        return filename
    
    def generate_pdf_report(self, filename="security_report.pdf"):
        """Generate PDF report"""
        self.calculate_statistics()
        
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(200, 10, "WebScanPro Security Report", ln=True, align="C")
        pdf.ln(10)
        
        # Scan info
        pdf.set_font("Arial", "", 12)
        pdf.cell(200, 10, f"Target: {self.report_data['scan_info']['target']}", ln=True)
        pdf.cell(200, 10, f"Scan Date: {self.report_data['scan_info']['scan_date']}", ln=True)
        pdf.cell(200, 10, f"Tool Version: {self.report_data['scan_info']['tool_version']}", ln=True)
        pdf.ln(10)
        
        # Statistics
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, "Statistics", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.cell(200, 10, f"Risk Score: {self.report_data['statistics']['risk_score']}/100", ln=True)
        pdf.cell(200, 10, f"Critical: {self.report_data['statistics']['critical']}", ln=True)
        pdf.cell(200, 10, f"High: {self.report_data['statistics']['high']}", ln=True)
        pdf.cell(200, 10, f"Medium: {self.report_data['statistics']['medium']}", ln=True)
        pdf.cell(200, 10, f"Low: {self.report_data['statistics']['low']}", ln=True)
        pdf.cell(200, 10, f"Total: {self.report_data['statistics']['total']}", ln=True)
        pdf.ln(10)
        
        # Vulnerabilities
        for severity in ['critical', 'high', 'medium', 'low']:
            if self.report_data['vulnerabilities'][severity]:
                pdf.set_font("Arial", "B", 14)
                pdf.cell(200, 10, f"{severity.upper()} Severity Vulnerabilities", ln=True)
                pdf.set_font("Arial", "", 10)
                
                for vuln in self.report_data['vulnerabilities'][severity][:5]:  # Limit to 5 per severity for PDF
                    pdf.cell(200, 10, f"Type: {vuln['type']}", ln=True)
                    pdf.cell(200, 10, f"URL: {vuln['url'][:80]}...", ln=True)
                    pdf.multi_cell(200, 10, f"Remediation: {vuln['remediation']}")
                    pdf.ln(5)
                
                pdf.ln(5)
        
        pdf.output(filename)
        return filename