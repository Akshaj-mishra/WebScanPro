import requests
from bs4 import BeautifulSoup
from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import AdvancedXSSInjector
from main.tests.idor import IDORTester

class Scanner:
    def __init__(self, base_url, username="admin", password="password"):
        self.base_url = base_url.rstrip("/")
        self.login_url = f"{self.base_url}/login.php"
        self.security_url = f"{self.base_url}/security.php"
        self.session = requests.Session()
        
       
        self._authenticate(username, password)
        
        
        self.crawler = WebCrawler(self.base_url, session=self.session)
        self.sql_injector = SQLInjector(session=self.session) 
        self.xss_injector = AdvancedXSSInjector(session=self.session)
        self.idor_tester = IDORTester(session=self.session)

    def _authenticate(self, username, password):
        try:
         
            resp = self.session.get(self.login_url)
            soup = BeautifulSoup(resp.text, "html.parser")
            user_token = soup.find("input", {"name": "user_token"})["value"]

           
            login_data = {
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": user_token
            }
            self.session.post(self.login_url, data=login_data)
            
      
            self.session.get(f"{self.security_url}?security=low&seclev_submit=Submit")
            print("[+] Authentication successful and security level set to LOW.")
        except Exception as e:
            print(f"[-] Login Failed: {e}")

    def run_targeted_scan(self, url):
        print(f"--- Starting Targeted Scan on: {url} ---")
        
   
        surface = self.crawler.scan(url) 
        if not surface:
         
            surface = [{"url": url, "forms": []}]
            
        results = {}

        
        if "sqli" in url:
            results["sql_injection"] = self.test_sql_logic(surface)
        elif "xss_r" in url or "xss_s" in url:
            results["xss"] = self.xss_injector.scan_all_xss(url, [f for p in surface for f in p["forms"]])
        elif "idor" in url or "open_redirect" in url:
            results["idor"] = self.idor_tester.scan_for_idor(url, surface)
        else:
           
            results["discovery"] = self.crawler.run()

        return results

    def test_sql_logic(self, surface):
        findings = []
        for page in surface:
            for form in page["forms"]:
                res = self.sql_injector.send_payload(form, "' OR '1'='1")
                findings.append({"action": form["action"], "result": res})
        return findings

    def test_xss_logic(self, surface, url):
        
        return self.xss_injector.scan_all_xss(url, [f for p in surface for f in p["forms"]])


if __name__ == "__main__":

    target = "http://localhost/DVWA/vulnerabilities/sqli/"
    scanner = Scanner("http://localhost/DVWA")
    report = scanner.run_targeted_scan(target)
