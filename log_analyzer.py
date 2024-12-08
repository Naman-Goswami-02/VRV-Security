import re
import csv
from collections import defaultdict


FAILED_LOGIN_THRESHOLD = 10


log_file_path = 'sampleee.log'  # Update this path


ip_requests = defaultdict(int)
endpoint_requests = defaultdict(int)
failed_logins = defaultdict(int)


with open(log_file_path, 'r') as file:
    for line in file:
        
        ip_match = re.match(r'(\S+)', line)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_requests[ip_address] += 1

      
        endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (.+?) HTTP', line)
        status_code_match = re.search(r'"\s(\d{3})\s', line)

        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_requests[endpoint] += 1

        if status_code_match and status_code_match.group(1) == '401':
            failed_logins[ip_address] += 1


sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)


most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1], default=(None, 0))


suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}


print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

if suspicious_activity:
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")


with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['IP Address', 'Request Count'])
    csv_writer.writerows(sorted_ip_requests)

    csv_writer.writerow([])
    csv_writer.writerow(['Endpoint', 'Access Count'])
    csv_writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    csv_writer.writerow([])
    csv_writer.writerow(['IP Address', 'Failed Login Count'])
    for ip, count in suspicious_activity.items():
        csv_writer.writerow([ip, count])

print("\nResults saved to log_analysis_results.csv")