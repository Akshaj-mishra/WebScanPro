import re
from urllib.parse import urlparse, parse_qs


class TestRouter:
    def decide_tests(self, page):
        
        url = page.get("url", "")
        forms = page.get("forms", [])
        tests = set()
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
       
        if "xss" in url:
            tests.add("xss")

        if "sqli" in url or "sql" in url:
            tests.add("sql_injection")

        if "idor" in url:
            tests.add("idor")

        return list(tests)