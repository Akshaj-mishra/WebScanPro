import requests
import time


class SQLInjector:
    def __init__(self, timeout=6):
        self.timeout = timeout

    def send_payload(self, form, payload):
        url = form["action"]
        method = form["method"]

        data = {}

        for field in form["inputs"]:
            if field["name"]:
                data[field["name"]] = payload

        try:
            start = time.time()

            if method == "post":
                r = requests.post(url, data=data, timeout=self.timeout)
            else:
                r = requests.get(url, params=data, timeout=self.timeout)

            delay = time.time() - start

            return self.analyze_response(r, delay)

        except Exception as e:
            return f"Request error: {str(e)}"

    def analyze_response(self, response, delay):
        text = response.text.lower()

        if response.status_code in [403, 406]:
            return "WAF block detected"

        if "sql" in text and "error" in text:
            return "SQL error message leaked"

        if delay > 4:
            return "Possible time-based injection"

        if response.status_code == 200:
            return "Normal page returned"

        return f"HTTP {response.status_code}"