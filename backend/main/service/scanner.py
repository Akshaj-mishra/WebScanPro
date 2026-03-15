import requests
from bs4 import BeautifulSoup
from crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import AdvancedXSSInjector
from main.tests.idor import IDORTester

class Scanner:
    def __init__(self, base_url, username="admin", password="password"):
        self.base_url = base_url.rstrip("/")
        self.login_url = f"{self.base_url}/login.php"
        self.security_url = f"{self.base_url}/security.php"
        self.session = requests.Session()
        
        # 1. Perform Login immediately
        self._authenticate(username, password)
        
        # 2. Share this authenticated session with all modules
        self.crawler = WebCrawler(self.base_url, session=self.session)
        self.sql_injector = SQLInjector(session=self.session) 
        self.xss_injector = AdvancedXSSInjector(session=self.session)
        self.idor_tester = IDORTester(session=self.session)

    def _authenticate(self, username, password):
        try:
            # Get user_token from login page
            resp = self.session.get(self.login_url)
            soup = BeautifulSoup(resp.text, "html.parser")
            user_token = soup.find("input", {"name": "user_token"})["value"]

            # Post Login Data
            login_data = {
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": user_token
            }
            self.session.post(self.login_url, data=login_data)
            
            # Set DVWA Security level to 'low' [cite: 37]
            self.session.get(f"{self.security_url}?security=low&seclev_submit=Submit")
            print("[+] Authentication successful and security level set to LOW.")
        except Exception as e:
            print(f"[-] Login Failed: {e}")

    def run_targeted_scan(self, url):
        print(f"--- Starting Targeted Scan on: {url} ---")
        
        # Discover forms on the specific page [cite: 40, 41]
        surface = self.crawler.scan(url) 
        if not surface:
            # If crawl returns None, try to wrap the URL in a list for processing
            surface = [{"url": url, "forms": []}]
            
        results = {}

        # Route based on URL suffix [cite: 15]
        if "sqli" in url:
            results["sql_injection"] = self.test_sql_logic(surface)
        elif "xss_r" in url or "xss_s" in url:
            results["xss"] = self.xss_injector.scan_all_xss(url, [f for p in surface for f in p["forms"]])
        elif "idor" in url or "open_redirect" in url:
            results["idor"] = self.idor_tester.scan_for_idor(url, surface)
        else:
            # Fallback to full discovery 
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
        # Test reflected XSS via parameters and forms
        return self.xss_injector.scan_all_xss(url, [f for p in surface for f in p["forms"]])

# Example Execution
if __name__ == "__main__":
    # Test specific SQLi endpoint
    target = "http://localhost/DVWA/vulnerabilities/sqli/"
    scanner = Scanner("http://localhost/DVWA")
    report = scanner.run_targeted_scan(target)
    print(json.dumps(report, indent=2))