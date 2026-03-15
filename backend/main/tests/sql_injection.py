import requests
import time
from bs4 import BeautifulSoup

class SQLInjector:
    
    def __init__(self, session, timeout=10):
        self.session = session # Received from Scanner
        self.timeout = timeout

    # Remove the self.login() call from here

    # Inside SQLInjector class
    def send_payload(self, form, payload):
        url = form["action"]
        method = form["method"]
        data = {}

        for field in form["inputs"]:
            # Don't overwrite the submit button or tokens if they have default values
            if field["name"].lower() in ["submit", "user_token"]:
                data[field["name"]] = field["value"]
            else:
                data[field["name"]] = payload # Inject here

        if method == "post":
            r = self.session.post(url, data=data)
        else:
            r = self.session.get(url, params=data)
        
        return self.analyze_response(r, 0, form.get("baseline_len", 0))



    def analyze_response(self, response, delay, baseline_len):
        if not response:
            return "Error: No response"
            
        text = response.text.lower()
        

        if "login.php" in response.url:
            return "Session Expired/Redirected"
            

        error_msgs = ["sql syntax", "mysql_fetch", "driver error", "sqlite/error"]
        if any(msg in text for msg in error_msgs):
            return "VULNERABLE: SQL Error Detected"


        if delay > 5:
            return f"VULNERABLE: Time-based delay ({round(delay, 2)}s)"


        if baseline_len > 0:
            current_len = len(response.text)
            diff = abs(current_len - baseline_len)
            
            
            if diff > 500: 
                return "Potential Boolean-based Bypass"

        return "Normal response"