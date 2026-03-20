import requests
from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import AdvancedXSSInjector
from main.tests.idor import IDORTester
from main.service.testrouter import TestRouter

# Note: In the future, you can import and call functions from auth_test.py here
# from main.tests.auth_test import check_cookie_security, test_weak_credentials

class Scanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        
        # Setup session with a common User-Agent
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanPro/1.0"
        })

        # Initialize all specialized security components
        self.crawler = WebCrawler(self.base_url, session=self.session)
        self.sql_injector = SQLInjector(session=self.session)
        self.xss_injector = AdvancedXSSInjector(session=self.session)
        self.idor_tester = IDORTester(session=self.session)
        self.router = TestRouter()
        
        # Result store for both recursive and targeted scans
        self.results = {
            "sql_injection": [],
            "xss": [],
            "idor": [],
            "auth": []
        }

    def _on_page_discovered(self, page):
        """
        CALLBACK HANDLER: This is triggered by the WebCrawler every time 
        a new URL is successfully visited.
        """
        url = page.get("url")
        forms = page.get("forms", [])
        
        # Route the URL to determine which specific security tests to fire
        tests = self.router.decide_tests(page)
        
        if tests:
            print(f"[LIVE TEST] {url} → Executing: {tests}")

        for test in tests:
            if test == "sql_injection":
                # Execute the SQL logic specifically for this page's discovered forms
                res = self._test_sql_logic([page])
                self.results["sql_injection"].extend(res)

            elif test == "xss":
                # Trigger Reflected and Stored XSS checks
                res = self.xss_injector.scan_all_xss(url, forms)
                self.results["xss"].append(res)

            elif test == "idor":
                # Specifically targets paths like 'vulnerabilities/bac/log_viewer.php'
                res = self.idor_tester.scan_for_idor(self.base_url, [page])
                self.results["idor"].append(res)

            elif test == "auth":
                # Specifically targets paths like 'vulnerabilities/authbypass'
                auth_finding = {
                    "url": url,
                    "test_category": "Authentication & Session Security",
                    "details": "Triggering Auth Bypass and Brute Force simulations...",
                    "status": "In Progress"
                }
                self.results["auth"].append(auth_finding)

    def run_full_recursive_scan(self):
        """
        Automated mode: Crawls the entire site and executes tests 
        asynchronously as pages are found.
        """
        print(f"[*] Starting Automated Recursive Scan: {self.base_url}")
        self.results = {"sql_injection": [], "xss": [], "idor": [], "auth": []} # Reset State
        
        # Pass the callback to the crawler's scan method
        self.crawler.scan(self.base_url, callback=self._on_page_discovered)
        
        return self.results

    def run_targeted_scan(self, target_url):
        """
        API mode: Scans only the specific URL provided (used by app.py).
        """
        print(f"[*] Starting Targeted Scan: {target_url}")
        self.results = {"sql_injection": [], "xss": [], "idor": [], "auth": []} # Reset State
        
        # Pull data for just this page
        page_data_list = self.crawler.scan(target_url)
        
        if page_data_list:
            self._on_page_discovered(page_data_list[0])
            
        return self.results

    def _test_sql_logic(self, surface):
        """Core payload execution for SQL Injection testing."""
        findings = []
        payloads = ["' OR 1=1 -- ", "' OR '1'='1' -- ", "' OR 1=1 #"]

        for page in surface:
            for form in page.get("forms", []):
                for payload in payloads:
                    try:
                        res = self.sql_injector.send_payload(form, payload)
                        findings.append({
                            "url": page["url"],
                            "action": form.get("action"),
                            "payload": payload,
                            "result": res
                        })
                    except Exception as e:
                        findings.append({
                            "url": page["url"], 
                            "error": f"Payload execution failed: {str(e)}"
                        })
        return findings

if __name__ == "__main__":
    # Local Testing Block
    TARGET_BASE = "http://localhost/DVWA"
    scanner = Scanner(TARGET_BASE)
    
    # Execute full automation
    report_data = scanner.run_full_recursive_scan()
    
    print("\n" + "="*40)
    print("      WEB SCAN PRO: SUMMARY REPORT")
    print("="*40)
    for category, findings in report_data.items():
        print(f"{category.upper():<15} : {len(findings)} events")