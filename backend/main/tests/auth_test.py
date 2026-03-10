import requests
import time
import logging

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

logging.basicConfig(
    filename="auth_session_test.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

session = requests.Session()

def check_cookie_security():

    response = session.get(LOGIN_URL)

    for cookie in session.cookies:

        print(f"Cookie: {cookie.name}")

        if not cookie.secure:
            logging.warning(f"{cookie.name} cookie missing Secure flag")

        if not cookie.has_nonstandard_attr("HttpOnly"):
            logging.warning(f"{cookie.name} cookie missing HttpOnly flag")

        print("Secure:", cookie.secure)
        print("HttpOnly:", cookie.has_nonstandard_attr("HttpOnly"))
        print("-" * 30)



def test_weak_credentials():

    print("\n[+] Testing weak credentials...")

    for password in PASSWORD_LIST:

        data = {
            "username": USERNAME,
            "password": password
        }

        response = session.post(LOGIN_URL, data=data)

        if FAILURE_MESSAGE not in response.text:

            print(f"[!] Weak credential found: {USERNAME}:{password}")
            logging.error(f"Weak credential accepted: {USERNAME}:{password}")
            return password

        else:
            print(f"[-] Tried: {password}")

    logging.info("No weak credentials found")
    return None



def brute_force_simulation():

    print("\n[+] Simulating brute-force attack...")

    attempts = 20

    for i in range(attempts):

        data = {
            "username": USERNAME,
            "password": "wrongpassword"
        }

        response = session.post(LOGIN_URL, data=data)

        print(f"Attempt {i+1}: {response.status_code}")

        if response.status_code == 429:
            logging.info("Rate limiting detected")
            print("[+] Rate limiting detected")
            return

        time.sleep(0.5)

    logging.warning("No rate limiting detected")



def session_fixation_test():

    print("\n[+] Testing session fixation...")

    initial_session = session.cookies.get_dict()

    data = {
        "username": USERNAME,
        "password": "test123"
    }

    session.post(LOGIN_URL, data=data)

    new_session = session.cookies.get_dict()

    if initial_session == new_session:
        logging.warning("Session fixation possible")
        print("[!] Session ID did not change after login")

    else:
        print("[+] Session ID changed after login")



def session_hijack_test():

    print("\n[+] Simulating session hijacking...")

    cookies = session.cookies.get_dict()

    hijack_session = requests.Session()

    response = hijack_session.get(PROTECTED_URL, cookies=cookies)

    if response.status_code == 200:
        logging.warning("Session hijacking possible")
        print("[!] Session hijacking successful")

    else:
        print("[+] Session protected")



if __name__ == "__main__":



    check_cookie_security()

    test_weak_credentials()

    brute_force_simulation()

    session_fixation_test()

    session_hijack_test()

