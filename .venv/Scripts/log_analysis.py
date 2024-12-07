import re
import csv

from collections import Counter

# Specify the log file and output CSV file
LOG_FILE = 'sample.log'  # Ensure this file is in the same directory as this script
CSV_FILE = 'log_analysis_results.csv'  # Output will be saved in the same directory

# Function to parse the log file
def parse_log(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found. Please ensure it is in the same directory as this script.")
        exit()

# Function to count requests per IP address
def count_requests_per_ip(log_lines):
    ip_counter = Counter()
    for line in log_lines:
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_counter[ip] += 1
    return ip_counter

# Function to find the most frequently accessed endpoint
def most_frequent_endpoint(log_lines):
    endpoint_counter = Counter()
    for line in log_lines:
        match = re.search(r'"(?:GET|POST) (\S+)', line)
        if match:
            endpoint = match.group(1)
            endpoint_counter[endpoint] += 1
    if endpoint_counter:
        endpoint, count = endpoint_counter.most_common(1)[0]
        return endpoint, count
    return None, 0

# Function to detect suspicious activity
def detect_suspicious_activity(log_lines, threshold=10):
    """
    Detects brute-force login attempts by flagging IPs with excessive failed login attempts.
    - Failed logins are identified by HTTP status code 401 or "Invalid credentials" in the log entry.
    - IPs exceeding the threshold are flagged.
    """
    failed_login_counter = Counter()
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:  # Detect failed login attempts
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_login_counter[ip] += 1
    # Filter IPs exceeding the threshold
    flagged_ips = {ip: count for ip, count in failed_login_counter.items() if count > threshold}
    return flagged_ips

# Function to save results to a CSV file
def save_to_csv(requests_per_ip, frequent_endpoint, suspicious_activity, output_file):
    try:
        with open(output_file, 'w', newline='') as file:
            writer = csv.writer(file)

            # Write Requests per IP
            writer.writerow(['Requests per IP'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in requests_per_ip.items():
                writer.writerow([ip, count])

            # Write Most Accessed Endpoint
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint'])
            writer.writerow(['Endpoint', 'Access Count'])
            writer.writerow(frequent_endpoint)

            # Write Suspicious Activity
            writer.writerow([])
            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
        print(f"Results successfully saved to '{output_file}'!")
    except Exception as e:
        print(f"Error saving to CSV: {e}")

# Main script
if __name__ == '__main__':
    # Parse the log file
    log_lines = parse_log(LOG_FILE)

    # Analyze the log
    requests_per_ip = count_requests_per_ip(log_lines)
    frequent_endpoint, access_count = most_frequent_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines, threshold=10)

    # Display results in the terminal
    print("\nRequests per IP:")
    for ip, count in requests_per_ip.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{frequent_endpoint} (Accessed {access_count} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to a CSV file
    save_to_csv(requests_per_ip, (frequent_endpoint, access_count), suspicious_activity, CSV_FILE)
