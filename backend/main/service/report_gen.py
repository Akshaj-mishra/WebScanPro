import os
import json
import datetime
import google.generativeai as genai
from dotenv import load_dotenv

class ReportGenerator:
    def __init__(self, target_url):
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel("gemini-2.5-flash")
        
        self.target_url = target_url
        self.findings = []

    def add_sql_results(self, sql_results):
        for result in sql_results:
            if "VULNERABLE" in str(result.get("result", "")):
                self.findings.append({
                    "type": "SQL Injection",
                    "endpoint": result.get("action"),
                    "severity": "CRITICAL",
                    "details": result.get("result")
                })

    def add_xss_results(self, xss_results):
        for xss in xss_results.get("reflected_xss", []):
            self.findings.append({
                "type": "Reflected XSS",
                "endpoint": xss["url"],
                "severity": xss.get("severity", "MEDIUM"),
                "details": f"Payload {xss['payload']} reflected in {xss['parameter']}"
            })

    def add_idor_results(self, idor_results):
        for vuln in idor_results.get("vulnerabilities", []):
            self.findings.append({
                "type": "IDOR",
                "endpoint": vuln["url"],
                "severity": "HIGH" if vuln.get("sensitive_data_detected") else "MEDIUM",
                "details": f"Accessed resource ID {vuln['id_tested']} without auth."
            })

    def generate_ai_summary(self):
       
        if not self.findings:
            return "No significant vulnerabilities were detected during this scan."

        prompt = f"""
        You are a Senior Cyber Security Analyst. Review these vulnerability findings for {self.target_url}:
        
        {json.dumps(self.findings, indent=2)}
        
        Provide a professional security report including:
        1. Executive Summary
        2. Detailed Analysis of each finding
        3. Actionable Remediation Steps (referencing OWASP Top 10 where applicable)
        4. Risk Assessment Score (0-100)
        
        Format the output in clear Markdown.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating AI report: {str(e)}"