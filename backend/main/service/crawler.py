import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.visited_urls = set()
        self.target_data = []

    def is_valid_link(self, link):
        return link.startswith(self.base_url)

    def get_links(self, soup, current_url):
        links = []

        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(current_url, a_tag["href"])
            full_url = full_url.split("#")[0]  # remove anchors

            if self.is_valid_link(full_url) and full_url not in self.visited_urls:
                links.append(full_url)

        return links

    def get_inputs(self, soup, url):
        forms_found = []

        for form in soup.find_all("form"):
            form_details = {
                "url": url,
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for input_tag in form.find_all(["input", "textarea", "select"]):
                form_details["inputs"].append({
                    "type": input_tag.get("type", "text"),
                    "name": input_tag.get("name"),
                    "value": input_tag.get("value", "")
                })

            forms_found.append(form_details)

        return forms_found

    def scan(self, url):
        if url in self.visited_urls:
            return

        try:
            print(f"Crawling: {url}")
            self.visited_urls.add(url)

            response = requests.get(url, timeout=5)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Save form info
            self.target_data.append({
                "url": url,
                "forms": self.get_inputs(soup, url)
            })

            # Crawl other internal links
            for link in self.get_links(soup, url):
                self.scan(link)

        except Exception as e:
            print(f"Error on {url}: {e}")

    def run(self):
        self.scan(self.base_url)
        return self.target_data


# Example usage
if __name__ == "__main__":
    crawler = WebCrawler("http://localhost:3000")
    results = crawler.run()

    for page in results:
        print(page)
