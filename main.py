
from pathlib import Path
from datetime import datetime
import ipaddress


LOG_FILE = Path("logs/sample.log")
SUSPICIOUS_THRESHOLD = 3

def parse_log_line(line):
    """Parse one log line and validate its fields."""
    fields = line.strip().split(",")

    if len(fields) != 5:
        return None

    timestamp, ip_address, username, event_type, status = fields

    try:
        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    if not username.strip():
        return None

    if event_type != "LOGIN":
        return None

    if status not in {"FAILED", "SUCCESS"}:
        return None

    return {
        "timestamp": timestamp,
        "ip_address": ip_address,
        "username": username,
        "event_type": event_type,
        "status": status,
    }

def get_alert_level(attempts):
    if attempts >= SUSPICIOUS_THRESHOLD:
        return "WARNING"

    return "INFO"

def analyze_logs():
    successful_logins = 0
    failed_logins = 0

    failed_attempts_by_ip = {}
    consecutive_failures_by_ip = {}
    failed_attempts_by_username = {}
    failed_attempts_by_hour = {}
    longest_consecutive_failures_by_ip = {}

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            record = parse_log_line(line)

            if record is None:
                print(f"Invalid log format on line {line_number}")
                continue

            ip_address = record["ip_address"]
            username = record["username"]

            if record["status"] == "SUCCESS":
                successful_logins += 1
                consecutive_failures_by_ip[ip_address] = 0

            elif record["status"] == "FAILED":
                failed_logins += 1

                failed_attempts_by_ip[ip_address] = (
                    failed_attempts_by_ip.get(ip_address, 0) + 1
                )

                consecutive_failures_by_ip[ip_address] = (
                    consecutive_failures_by_ip.get(ip_address, 0) + 1
                )
                longest_consecutive_failures_by_ip[ip_address] = max(
                   longest_consecutive_failures_by_ip.get(ip_address, 0),
                   consecutive_failures_by_ip[ip_address],
                 )

                failed_attempts_by_username[username] = (
                    failed_attempts_by_username.get(username, 0) + 1
                )

                timestamp = datetime.strptime(
                    record["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
                hour = timestamp.strftime("%H:00")

                failed_attempts_by_hour[hour] = (
                    failed_attempts_by_hour.get(hour, 0) + 1
                )

    return (
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    consecutive_failures_by_ip,
    longest_consecutive_failures_by_ip,
    failed_attempts_by_username,
    failed_attempts_by_hour,
)



def generate_report(
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    longest_consecutive_failures_by_ip,
    failed_attempts_by_username,
    failed_attempts_by_hour,
    suspicious_ips,
    suspicious_accounts,
):
    report_file = Path("report.txt")

    with report_file.open("w", encoding="utf-8") as report:
        report.write("Security Log Analyzer Report\n")
        report.write("============================\n")
        report.write(f"Report generated: {datetime.now()}\n")
        report.write(f"Successful logins: {successful_logins}\n")
        report.write(f"Failed logins: {failed_logins}\n")

        total_logins = successful_logins + failed_logins

        if total_logins > 0:
            success_rate = successful_logins / total_logins * 100
            failure_rate = failed_logins / total_logins * 100

            report.write(f"Success rate: {success_rate:.1f}%\n")
            report.write(f"Failure rate: {failure_rate:.1f}%\n")

            report.write("\nFailed Login Attempts by Hour\n")

        for hour, attempts in sorted(failed_attempts_by_hour.items()):
            report.write(f"{hour}: {attempts} failed attempts\n")

        report.write("\nFailed Attempts by IP (Ranked)\n")

        for ip_address, attempts in sorted(
            failed_attempts_by_ip.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            report.write(f"{ip_address}: {attempts} failed attempts\n")

        report.write("\nLongest Consecutive Failed Logins by IP\n")

        for ip_address, attempts in sorted(
            longest_consecutive_failures_by_ip.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            report.write(
                f"{ip_address}: {attempts} consecutive failed logins\n"
            )

        report.write("\nFailed Attempts by Username\n")

        for username, attempts in sorted(
            failed_attempts_by_username.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            report.write(f"{username}: {attempts} failed attempts\n")

        report.write("\nSecurity Findings Summary\n")
        report.write("=========================\n")
        report.write(f"IPs requiring review: {len(suspicious_ips)}\n")
        report.write(
            f"Accounts requiring review: {len(suspicious_accounts)}\n"
        )

        if suspicious_ips:
            report.write("IPs: " + ", ".join(suspicious_ips) + "\n")

        if suspicious_accounts:
            report.write(
                "Accounts: " + ", ".join(suspicious_accounts) + "\n"
            )

        if suspicious_ips or suspicious_accounts:
            report.write(
                "Overall assessment: Suspicious login patterns "
                "require review.\n"
            )
        else:
            report.write(
                "Overall assessment: No activity exceeded "
                "the configured thresholds.\n"
            )

        report.write("\nSecurity Warnings\n")
        report.write("=================\n")

        for ip_address, attempts in failed_attempts_by_ip.items():
            if attempts >= SUSPICIOUS_THRESHOLD:
                report.write(
                    f"WARNING: IP {ip_address} has "
                    f"{attempts} failed login attempts\n"
                )

        for username, attempts in failed_attempts_by_username.items():
            if attempts >= SUSPICIOUS_THRESHOLD:
                report.write(
                    f"WARNING: Account '{username}' has "
                    f"{attempts} failed login attempts\n"
                )

    return report_file 


def display_results(
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    longest_consecutive_failures_by_ip,
    failed_attempts_by_username,
    failed_attempts_by_hour,
    suspicious_ips,
    suspicious_accounts,
):
    print("\n--- Login Analysis Summary ---")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {failed_logins}")

    total_logins = successful_logins + failed_logins

    print("\n--- Login Success and Failure Rates ---")

    if total_logins > 0:
        success_rate = successful_logins / total_logins * 100
        failure_rate = failed_logins / total_logins * 100

        print(f"Successful login rate: {success_rate:.1f}%")
        print(f"Failed login rate: {failure_rate:.1f}%")
    else:
        print("No valid login records available for analysis.")

    print("\n--- Failed Login Attempts by Hour ---")

    for hour, attempts in sorted(failed_attempts_by_hour.items()):
        print(f"{hour}: {attempts} failed attempts")

    print("\n--- Failed Attempts by IP (Ranked) ---")

    for ip_address, attempts in sorted(
        failed_attempts_by_ip.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        level = get_alert_level(attempts)
        print(f"{level}: {ip_address} - {attempts} failed attempts")

        print("\n--- Consecutive Failed Login Detection ---")

    for ip_address, attempts in longest_consecutive_failures_by_ip.items():
        if attempts >= SUSPICIOUS_THRESHOLD:
            print(
                f"WARNING: {ip_address} has "
                f"{attempts} consecutive failed logins"
            )


    print("\n--- Failed Attempts by Username (Ranked) ---")

    for username, attempts in sorted(
        failed_attempts_by_username.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        level = get_alert_level(attempts)
        print(f"{level}: {username} - {attempts} failed attempts")

    print("\n--- Suspicious Account Activity ---")

    for username in suspicious_accounts:
        print(
            f"WARNING: Account '{username}' has "
            f"{failed_attempts_by_username[username]} failed login attempts"
        )

    print("\n--- Security Findings Summary ---")
    print(f"IPs requiring review: {len(suspicious_ips)}")
    print(f"Accounts requiring review: {len(suspicious_accounts)}")

    if suspicious_ips:
        print("IPs:", ", ".join(suspicious_ips))

    if suspicious_accounts:
        print("Accounts:", ", ".join(suspicious_accounts))



def main():

    if not LOG_FILE.exists():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    
    (
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    consecutive_failures_by_ip,
    longest_consecutive_failures_by_ip,
    failed_attempts_by_username,
    failed_attempts_by_hour,
  ) = analyze_logs()

    suspicious_ips = [
    ip_address
    for ip_address, attempts in failed_attempts_by_ip.items()
    if attempts >= SUSPICIOUS_THRESHOLD
    ]

    suspicious_accounts = [
    username
    for username, attempts in failed_attempts_by_username.items()
    if attempts >= SUSPICIOUS_THRESHOLD
    ]

    display_results(
    successful_logins,
    failed_logins,
    failed_attempts_by_ip,
    longest_consecutive_failures_by_ip,
    failed_attempts_by_username,
    failed_attempts_by_hour,
    suspicious_ips,
    suspicious_accounts,
 )
    report_file = generate_report(
        successful_logins,
        failed_logins,
        failed_attempts_by_ip,
        longest_consecutive_failures_by_ip,
        failed_attempts_by_username,
        failed_attempts_by_hour,
        suspicious_ips,
        suspicious_accounts,
    )

    print(f"\nReport saved to: {report_file}")

   
if __name__ == "__main__":
    
 main()
