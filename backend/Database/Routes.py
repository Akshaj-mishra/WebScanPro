def result():
    var = {
        "target": "http://localhost/login",
        "authentication_tests": {
            "weak_credentials": {
                "tested_user": "admin",
                "status": "vulnerable",
                "valid_password": "passward"
            },
            "brute_force_protection": {
                "attempts_tested": 20,
                "rate_limiting_detected": False,
                "account_lockout": False,
                "status": "vulnerable"
            }
        },
        "session_tests": {
            "cookie_security": {
                "cookie_name": "sessionid",
                "secure_flag": False,
                "httponly_flag": False,
                "samesite_flag": False,
                "status": "insecure"
            },
            "session_fixation": {
                "session_changed_after_login": False,
                "status": "vulnerable"
            },
            "session_hijacking": {
                "cookie_reuse_successful": True,
                "status": "vulnerable"
            }
        },
        "XSS": [
            {
                "payload": "<script>alert(1)</script>",
                "status": "vulnerable"
            },
            {
                "payload": "<img src=x onerror=alert(1)>",
                "status": "vulnerable"
            },
            {
                "payload": "<svg onload=alert(1)>",
                "status": "filtered"
            }
        ]  
    }
    return var
    return var