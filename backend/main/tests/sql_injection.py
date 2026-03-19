import requests
import time
from bs4 import BeautifulSoup
from main.service.sql_generator import GeminiFeedbackAgent 


class SQLInjector:
    
    def __init__(self, session, timeout=10):
        self.session = session 
        self.timeout = timeout


    def send_payload(self, form, payload):
        url = form["action"]
        method = form["method"]
        data = {}

        for field in form["inputs"]:
            if field["name"].lower() in ["submit", "user_token"]:
                data[field["name"]] = field["value"]
            else:
                data[field["name"]] = payload 

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


        if text.count("first name") > 1:
            return "VULNERABLE: Multiple rows returned"


        if baseline_len > 0:
            current_len = len(response.text)
            diff = abs(current_len - baseline_len)

        if diff > 50:
            return f"Potential Boolean-based Bypass (diff={diff})"

        return "Normal response"