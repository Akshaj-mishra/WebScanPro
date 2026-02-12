from main.service.crawler import WebCrawler







class Scaner :
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
    
    def crawl (self):
        
        try:
            surface = WebCrawler(self.base_url)
            return surface.run()
        except Exception as e:
            return {"error": str(e)}

    
    def payloads ():
        ...
        