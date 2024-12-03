import re
import csv
from collections import Counter


# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# Log file path
log_file_path = 'file.log'

# Regular expressions for parsing log data
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (/[^\s]*)'
failed_login_pattern = r'\".*\" 401 '

# Initialize counters
ip_counter = Counter()
endpoint_counter = Counter()
failed_login_counter = Counter()

# Process the log file
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        # Count requests per IP address
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip_counter[ip_match.group()] += 1

        # Count requests per endpoint
        endpoint_match = re.search(endpoint_pattern, line)
        if endpoint_match:
            endpoint_counter[endpoint_match.group(1)] += 1

        # Detect failed login attempts
        if re.search(failed_login_pattern, line) and ip_match:
            failed_login_counter[ip_match.group()] += 1

# Sort results
sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
sorted_endpoints = sorted(endpoint_counter.items(), key=lambda x: x[1], reverse=True)
suspicious_ips = {ip: count for ip, count in failed_login_counter.items() if count > FAILED_LOGIN_THRESHOLD}

# Display results in the terminal
print("\nIP Address           Request Count")
print("=" * 35)
for ip, count in sorted_ips:
    print(f"{ip:<20} {count:<15}")

if sorted_endpoints:
    most_frequent_endpoint, access_count = sorted_endpoints[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent_endpoint} (Accessed {access_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print("IP Address           Failed Login Attempts")
    print("=" * 35)
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count:<15}")
else:
    print("No suspicious activity detected.")

# Save output to a CSV file
csv_file_path = 'log_analysis_results.csv'
with open(csv_file_path, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)

    # Write Requests per IP
    csv_writer.writerow(['Requests per IP'])
    csv_writer.writerow(['IP Address', 'Request Count'])
    csv_writer.writerows(sorted_ips)
    csv_writer.writerow([])

    # Write Most Accessed Endpoint
    csv_writer.writerow(['Most Frequently Accessed Endpoint'])
    csv_writer.writerow(['Endpoint', 'Access Count'])
    csv_writer.writerow([most_frequent_endpoint, access_count])
    csv_writer.writerow([])

    # Write Suspicious Activity
    csv_writer.writerow(['Suspicious Activity'])
    csv_writer.writerow(['IP Address', 'Failed Login Count'])
    for ip, count in suspicious_ips.items():
        csv_writer.writerow([ip, count])

print(f"\nResults saved to {csv_file_path}")
