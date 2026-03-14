import requests
import time
import json

LOGIN_URL = "http://localhost/login"
PROTECTED_URL = "http://localhost/dashboard"

USERNAME = "admin"

PASSWORD_LIST = [
    "admin",
    "password",
    "123456",
    "admin123",
    "test123",
    "letmein",
    "qwerty"
]

FAILURE_MESSAGE = "Invalid login"

session = requests.Session()

report = {
    "target": LOGIN_URL,
    "cookie_security": [],
    "weak_credentials": None,
    "brute_force": None,
    "session_fixation": None,
    "session_hijacking": None
}


def check_cookie_security():

    response = session.get(LOGIN_URL)

    for cookie in session.cookies:

        cookie_data = {
            "cookie_name": cookie.name,
            "secure_flag": cookie.secure,
            "httponly_flag": cookie.has_nonstandard_attr("HttpOnly")
        }

        report["cookie_security"].append(cookie_data)



def test_weak_credentials():

    for password in PASSWORD_LIST:

        data = {
            "username": USERNAME,
            "password": password
        }

        response = session.post(LOGIN_URL, data=data)

        if FAILURE_MESSAGE not in response.text:

            report["weak_credentials"] = {
                "username": USERNAME,
                "password": password,
                "status": "accepted"
            }

            return password

    report["weak_credentials"] = "No weak credentials found"
    return None



def brute_force_simulation():

    attempts = 20
    rate_limit_detected = False

    for i in range(attempts):

        data = {
            "username": USERNAME,
            "password": "wrongpassword"
        }

        response = session.post(LOGIN_URL, data=data)

        if response.status_code == 429:
            rate_limit_detected = True
            break

        time.sleep(0.5)

    report["brute_force"] = {
        "attempts": attempts,
        "rate_limiting_detected": rate_limit_detected
    }



def session_fixation_test():

    initial_session = session.cookies.get_dict()

    data = {
        "username": USERNAME,
        "password": "test123"
    }

    session.post(LOGIN_URL, data=data)

    new_session = session.cookies.get_dict()

    fixation_possible = initial_session == new_session

    report["session_fixation"] = {
        "initial_session": initial_session,
        "new_session": new_session,
        "fixation_possible": fixation_possible
    }



def session_hijack_test():

    cookies = session.cookies.get_dict()

    hijack_session = requests.Session()

    response = hijack_session.get(PROTECTED_URL, cookies=cookies)

    hijack_success = response.status_code == 200

    report["session_hijacking"] = {
        "cookies_used": cookies,
        "hijack_successful": hijack_success
    }



if __name__ == "__main__":

    check_cookie_security()
    test_weak_credentials()
    brute_force_simulation()
    session_fixation_test()
    session_hijack_test()

    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("Security report generated: security_report.json")