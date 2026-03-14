from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.tests.xss import XSSInjector
from main.tests.xss_enhanced import AdvancedXSSInjector
from main.tests.idor import IDORTester
from main.service.sql_generator import GeminiFeedbackAgent
from main.service.report_generator import ReportGenerator
import json

class Scanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.sql_injector = SQLInjector()
        self.xss_injector = AdvancedXSSInjector(self.sql_injector.session)
        self.idor_tester = IDORTester(self.sql_injector.session)
        self.crawler = WebCrawler(self.base_url, session=self.sql_injector.session)
        self.ai = GeminiFeedbackAgent()
        self.report_gen = ReportGenerator(base_url)
        
    def crawl(self):
        """Crawl the target website"""
        print(f"[+] Crawling target: {self.base_url}")
        surface = self.crawler.run()
        print(f"[+] Found {len(surface)} pages with forms")
        return surface

    def test_sql_injection(self, surface):
        """Test for SQL injection vulnerabilities"""
        print("\n[+] Testing for SQL Injection...")
        sql_results = []
        
        for page in surface:
            for form in page["forms"]:
                print(f"    Testing form at: {form['action']}")
                
                
                seed_payloads = self.sql_injector.payloads["error_based"][:5]
                
                history = {}
                def tester(payload):
                    return self.sql_injector.send_payload(form, payload)

                
                for payload in seed_payloads:
                    history[payload] = tester(payload)
                
                
                ai_results = self.ai.adaptive_loop(tester, initial_history=history, max_rounds=2)

                sql_results.append({
                    "url": form["action"],
                    "results": ai_results
                })
        
        # Add to report
        self.report_gen.add_sql_results(sql_results)
        return sql_results

    def test_xss(self, surface):
        """Test for XSS vulnerabilities"""
        print("\n[+] Testing for XSS...")
        all_xss_results = {
            "reflected_xss": [],
            "stored_xss": []
        }
        
        for page in surface:
            url = page["url"]
            forms = page["forms"]
            
            # Test each form for XSS
            for form in forms:
                print(f"    Testing XSS on form: {form['action']}")
                results = self.xss_injector.scan_all_xss(url, [form], {})
                all_xss_results["reflected_xss"].extend(results.get("reflected_xss", []))
                
                # Check for stored XSS
                for payload in self.xss_injector.xss_payloads["basic"]:
                    stored_result = self.xss_injector.test_stored_xss(form, payload)
                    if stored_result.get("vulnerable"):
                        all_xss_results["stored_xss"].append(stored_result)
        
        # Add to report
        self.report_gen.add_xss_results(all_xss_results)
        print(f"    Found {len(all_xss_results['reflected_xss'])} reflected XSS, {len(all_xss_results['stored_xss'])} stored XSS")
        return all_xss_results

    def test_idor(self, surface):
        """Test for IDOR vulnerabilities"""
        print("\n[+] Testing for IDOR...")
        idor_results = self.idor_tester.scan_for_idor(self.base_url, surface)
        
        # Add to report
        self.report_gen.add_idor_results(idor_results)
        print(f"    Found {idor_results.get('vulnerable_count', 0)} IDOR vulnerabilities")
        return idor_results

    def load_auth_results(self):
        """Load authentication test results from file"""
        try:
            with open("security_report.json", "r") as f:
                auth_results = json.load(f)
                self.report_gen.add_auth_results(auth_results)
                return auth_results
        except FileNotFoundError:
            print("[-] Auth results not found. Run auth_test.py first.")
            return None

    def run_full_scan(self):
        """Run complete security scan"""
        print("=" * 50)
        print("WebScanPro - Full Security Scan")
        print("=" * 50)
        
        # Step 1: Crawl
        surface = self.crawl()
        
        if not surface:
            print("[-] No forms found. Exiting.")
            return
        
        # Step 2: SQL Injection
        sql_results = self.test_sql_injection(surface)
        
        # Step 3: XSS
        xss_results = self.test_xss(surface)
        
        # Step 4: IDOR
        idor_results = self.test_idor(surface)
        
        # Step 5: Auth (load from file)
        auth_results = self.load_auth_results()
        
        # Step 6: Generate reports
        print("\n[+] Generating reports...")
        html_report = self.report_gen.generate_html_report()
        json_report = self.report_gen.generate_json_report()
        
        try:
            pdf_report = self.report_gen.generate_pdf_report()
            print(f"    PDF Report: {pdf_report}")
        except:
            print("    PDF generation skipped (fpdf may not be installed)")
        
        print(f"    HTML Report: {html_report}")
        print(f"    JSON Report: {json_report}")
        
        # Summary
        print("\n" + "=" * 50)
        print("SCAN COMPLETE - SUMMARY")
        print("=" * 50)
        print(f"SQL Injection tests: {len(sql_results)} forms tested")
        print(f"XSS vulnerabilities: {xss_results['summary'].get('total_vulnerabilities', 0)}")
        print(f"IDOR vulnerabilities: {idor_results.get('vulnerable_count', 0)}")
        print(f"Risk Score: {self.report_gen.report_data['statistics'].get('risk_score', 'N/A')}/100")
        
        return {
            "surface": surface,
            "sql_results": sql_results,
            "xss_results": xss_results,
            "idor_results": idor_results,
            "auth_results": auth_results,
            "report_files": {
                "html": html_report,
                "json": json_report
            }
        }


if __name__ == "__main__":
    scanner = Scanner("http://localhost/DVWA")
    scanner.run_full_scan()