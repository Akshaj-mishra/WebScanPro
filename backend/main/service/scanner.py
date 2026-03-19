import requests
from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import AdvancedXSSInjector
from main.tests.idor import IDORTester
from main.service.testrouter import TestRouter  

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


    def run_full_scan(self):
        surface = self.crawler.run()

        results = {
            "sql_injection": [],
            "xss": [],
            "idor": []
        }

        for page in surface:
            url = page.get("url")
            forms = page.get("forms", [])

            # 🔥 ROUTER DECIDES
            tests = self.router.decide_tests(page)

            print(f"[ROUTER] {url} → {tests}")

            # 🔹 Run SQLi
            if "sql_injection" in tests:
                sql_results = self._test_sql_logic([page])
                results["sql_injection"].extend(sql_results)

            # 🔹 Run XSS
            if "xss" in tests:
                xss_results = self.xss_injector.scan_all_xss(url, forms)
                results["xss"].append(xss_results)

            # 🔹 Run IDOR
            if "idor" in tests:
                idor_results = self.idor_tester.scan_for_idor(self.base_url, [page])
                results["idor"].append(idor_results)

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
