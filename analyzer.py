import re
from collections import Counter

FAILED_LOGIN_PATTERN = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

def analyze_log(file_path):
    with open(file_path, "r") as file:
        log_data = file.read()

    failed_ips = re.findall(FAILED_LOGIN_PATTERN, log_data)
    ip_count = Counter(failed_ips)

    print("Suspicious Login Attempts:\n")
    for ip, count in ip_count.items():
        if count >= 3:
            print(f"IP: {ip} | Failed Attempts: {count}")

if __name__ == "__main__":
    analyze_log("sample_log.txt")
