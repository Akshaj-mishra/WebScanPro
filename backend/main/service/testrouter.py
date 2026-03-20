class TestRouter:
    def decide_tests(self, page):
        url = page.get("url", "").lower()
        tests = set()

       
        if "vulnerabilities/bac/log_viewer.php" in url:
            tests.add("idor")
        
        if "vulnerabilities/authbypass" in url:
            tests.add("auth")  
            
        if "vulnerabilities/sqli" in url: 
            tests.add("sql_injection")
            
        if "vulnerabilities/xss_r" in url: 
            tests.add("xss")

        return list(tests)