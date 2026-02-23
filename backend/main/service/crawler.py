import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse

class WebCrawler:
    def __init__(self, base_url, session):
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.session = session 
        self.visited_urls = set()
        self.target_data = []

    def get_inputs(self, soup, url):
        forms_found = []
        baseline_len = len(soup.get_text())

        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            form_action = urljoin(url, action) if action and action != "#" else url

            form_details = {
                "url": url,
                "action": form_action,
                "method": form.get("method", "get").lower(),
                "baseline_len": baseline_len,
                "inputs": []
            }

            for input_tag in form.find_all(["input", "textarea"]):
                name = input_tag.get("name")
                if name:
                    form_details["inputs"].append({
                        "name": name,
                        "value": input_tag.get("value", "") 
                    })
            
            if form_details["inputs"]:
                forms_found.append(form_details)
        return forms_found

    def scan(self, url):
        if url in self.visited_urls or not url.startswith(self.base_url):
            return
        
        try:
            self.visited_urls.add(url)
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            
            forms = self.get_inputs(soup, url)
            if forms:
                self.target_data.append({"url": url, "forms": forms})

            for a_tag in soup.find_all("a", href=True):
                full_url = urljoin(url, a_tag["href"]).split('#')[0]
                self.scan(full_url)
        except Exception as e:
            print(f"Crawler error at {url}: {e}")

    def run(self):
        self.scan(self.base_url)
        return self.target_data