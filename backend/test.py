import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


BASE_URL = "http://localhost/dvwa/index.php"
LOGIN_URL = urljoin(BASE_URL, "login.php")
USERNAME = "admin"
PASSWORD = "password"

session = requests.Session()

def login():
    initial_res = session.get(LOGIN_URL)
    soup = BeautifulSoup(initial_res.text, "html.parser")
    user_token = ""
    token_input = soup.find("input", {"name": "user_token"})
    if token_input:
        user_token = token_input.get("value")


    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login"
    }
    
    if user_token:
        login_data["user_token"] = user_token
        
    response = session.post(LOGIN_URL, data=login_data)
    
    
    if "login.php" in response.url and "Login failed" in response.text:
        print("[-] Login failed. Check credentials.")
        return False
    
    
    security_url = urljoin(BASE_URL, "security.php")
    sec_res = session.get(security_url)
    sec_soup = BeautifulSoup(sec_res.text, "html.parser")
    sec_token = sec_soup.find("input", {"name": "user_token"})
    
    security_data = {"security": "low", "seclev_submit": "Submit"}
    if sec_token:
        security_data["user_token"] = sec_token.get("value")
        
    session.post(security_url, data=security_data)
    
    print("[+] Successfully authenticated and bypassed redirects.")
    return True





def crawl(start_url):
    visited = set()
    to_visit = [start_url]
    discovered_paths = set()

    print("[*] Starting crawl...")

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue
        
        try:
            res = session.get(url)
            visited.add(url)
            
            curr_path = urlparse(res.url).path
            print(f"[*] Visiting: {curr_path}")

            if curr_path not in discovered_paths:
                print(f"    [NEW PATH] {curr_path}")
                discovered_paths.add(curr_path)

            soup = BeautifulSoup(res.text, "html.parser")
            links = soup.find_all("a", href=True)
            
            for link in links:
                href = link["href"]
                
                if "logout" in href.lower():
                    continue
                
                full_url = urljoin(url, href)
                
                if urlparse(full_url).netloc == urlparse(BASE_URL).netloc:
                    clean_url = full_url.split('#')[0].rstrip('/')
                    if clean_url not in visited and clean_url not in to_visit:
                        to_visit.append(clean_url)
                        
        except Exception as e:
            print(f"[-] Error crawling {url}: {e}")

if __name__ == "__main__":
    if login():
        crawl(BASE_URL)