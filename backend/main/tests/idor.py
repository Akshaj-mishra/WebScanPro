import requests
from urllib.parse import urljoin, urlparse
import re

class IDORTester:
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []
        
    def extract_ids_from_response(self, response_text, pattern=r'[0-9]{1,5}'):
        """Extract potential IDs from response"""
        ids = re.findall(pattern, response_text)
        return list(set(ids[:10]))  
    
    def test_endpoint_access(self, base_url, resource_pattern, ids_to_test):
        """Test if IDs can be accessed without proper authorization"""
        results = []
        
        for test_id in ids_to_test:
            try:
                
                test_url = resource_pattern.replace("{id}", str(test_id))
                full_url = urljoin(base_url, test_url)
                
               
                response = self.session.get(full_url, timeout=5)
                
               
                if response.status_code == 200:
                   
                    sensitive_patterns = ['email', 'username', 'password', 'ssn', 'credit', 
                                         'address', 'phone', 'private', 'profile']
                    
                    content_lower = response.text.lower()
                    has_sensitive_data = any(pattern in content_lower for pattern in sensitive_patterns)
                    
                    if has_sensitive_data:
                        results.append({
                            "url": full_url,
                            "id_tested": test_id,
                            "status_code": response.status_code,
                            "vulnerable": True,
                            "sensitive_data_detected": True,
                            "response_size": len(response.text)
                        })
                    else:
                        results.append({
                            "url": full_url,
                            "id_tested": test_id,
                            "status_code": response.status_code,
                            "vulnerable": True,
                            "sensitive_data_detected": False,
                            "response_size": len(response.text)
                        })
                else:
                    results.append({
                        "url": full_url,
                        "id_tested": test_id,
                        "status_code": response.status_code,
                        "vulnerable": False,
                        "error": "Access denied or resource not found"
                    })
                    
            except Exception as e:
                results.append({
                    "url": full_url if 'full_url' in locals() else resource_pattern,
                    "id_tested": test_id,
                    "vulnerable": False,
                    "error": str(e)
                })
        
        return results
    
    def scan_for_idor(self, base_url, crawled_pages):
        """Main IDOR scanning function"""
        idor_results = []
        
        
        idor_patterns = [
            "/user/profile/{id}",
            "/api/users/{id}",
            "/download/file/{id}",
            "/order/details/{id}",
            "/account/{id}/settings",
            "/document/view/{id}",
            "/profile.php?id={id}",
            "/view.php?record={id}",
            "/download.php?file={id}",
            "/user.php?user_id={id}"
        ]
        
        
        for page in crawled_pages:
            url = page.get("url", "")
            
            
            url_ids = re.findall(r'[=/](\d+)[/?&]', url)
            
            for pattern in idor_patterns:
                
                if url_ids:
                    results = self.test_endpoint_access(base_url, pattern, url_ids[:3])
                    idor_results.extend(results)
                
                
                sequential_ids = [str(i) for i in range(1, 6)]  
                results = self.test_endpoint_access(base_url, pattern, sequential_ids)
                idor_results.extend(results)
        
        
        vulnerable = [r for r in idor_results if r.get("vulnerable", False)]
        return {
            "total_tests": len(idor_results),
            "vulnerable_count": len(vulnerable),
            "vulnerabilities": vulnerable[:10],  
            "all_results": idor_results[:20]  
        }