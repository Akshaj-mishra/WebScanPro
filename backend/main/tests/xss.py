import html
from bs4 import BeautifulSoup

class XSSInjector:
    def __init__(self, session):
        self.session = session 

    def send_payload(self, form, payload):
        url = form["action"]
        method = form.get("method", "get").lower()
        data = {}

        for field in form["inputs"]:
            data[field["name"]] = payload

        try:
            if method == "post":
                r = self.session.post(url, data=data, timeout=5)
            else:
                r = self.session.get(url, params=data, timeout=5)
            
            return self.analyze_response(r, payload)
        except Exception as e:
            return f"Error: {str(e)}"

    def analyze_response(self, response, payload):
        if not response:
            return "No response"
        
        content = response.text
        
        
        if payload in content:
            
            soup = BeautifulSoup(content, "html.parser")
            
          
            if any(payload in str(tag) for tag in soup.find_all(['script', 'img', 'body', 'svg'])):
                return "VULNERABLE: Reflected XSS (Unsanitized)"
            
            return "Payload Reflected (Possible Mitigation/Escaped)"
            
        return "Not Vulnerable"