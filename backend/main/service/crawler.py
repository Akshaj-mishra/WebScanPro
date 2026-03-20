import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class WebCrawler:
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip("/") + "/"
        self.session = session or requests.Session()

        self.visited_urls = set()
        self.target_data = []


        self.login()
        self.set_security_low()


    def login(self):
        login_url = urljoin(self.base_url, "login.php")

        print("[*] Fetching login page...")
        res = self.session.get(login_url)

        soup = BeautifulSoup(res.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        user_token = token_input.get("value") if token_input else ""

        login_data = {
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }

        if user_token:
            login_data["user_token"] = user_token

        print("[*] Sending login request...")
        response = self.session.post(login_url, data=login_data)

        if "login.php" in response.url:
            print("[-] Login failed.")
            raise Exception("Login failed")

        print("[+] Login successful!")


    def set_security_low(self):
        security_url = urljoin(self.base_url, "security.php")

        res = self.session.get(security_url)
        soup = BeautifulSoup(res.text, "html.parser")

        token_input = soup.find("input", {"name": "user_token"})
        token = token_input.get("value") if token_input else ""

        data = {
            "security": "low",
            "seclev_submit": "Submit"
        }

        if token:
            data["user_token"] = token

        self.session.post(security_url, data=data)
        print("[+] Security set to LOW")


    def get_inputs(self, soup, url):
        forms_found = []

        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            form_action = urljoin(url, action) if action and action != "#" else url

            form_details = {
                "url": url,
                "action": form_action,
                "method": form.get("method", "get").lower(),
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


    def scan(self, url, callback=None): # Added callback parameter
        if url in self.visited_urls or not url.startswith(self.base_url):
            return []

        try:
            print(f"[*] Crawling: {url}")
            res = self.session.get(url)
            self.visited_urls.add(url)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = self.get_inputs(soup, url)

            page_data = {"url": url, "forms": forms}
            
            # --- NEW: Trigger tests immediately if a callback is provided ---
            if callback:
                callback(page_data)

            self.target_data.append(page_data)

            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if "logout" in href.lower(): continue
                
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                    clean_url = full_url.split("#")[0].rstrip("/")
                    self.scan(clean_url, callback=callback) # Pass callback recursively

            return [page_data]
        except Exception as e:
            print(f"[-] Error: {url} -> {e}")
            return []

    def run(self):
        print("[*] Starting full crawl...")
        self.scan(self.base_url)
        return self.target_data