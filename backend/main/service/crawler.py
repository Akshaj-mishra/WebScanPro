import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.target_data = []

    def get_links(self, soup, current_url):
        links = []
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(current_url, a_tag["href"])
            if link.startswith(self.base_url) and link not in self.visited_urls:
                links.append(link)
        return links

    def get_inputs(self, soup, url):
        forms_found = []
        for form in soup.find_all("form"):
            form_details = {
                "url": url,
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }
            for input_tag in form.find_all(["input", "textarea", "select"]):
                form_details["inputs"].append({
                    "type": input_tag.get("type"),
                    "name": input_tag.get("name")
                })
            forms_found.append(form_details)
        return forms_found

    def scan(self, url):
        if url in self.visited_urls:
            return
        
        try:
            self.visited_urls.add(url)
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            
            page_metadata = {
                "url": url,
                "forms": self.get_inputs(soup, url)
            }
            self.target_data.append(page_metadata)

            return self.target_data

        except Exception as e:
            return {"error": str(e)}