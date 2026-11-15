import json
import csv


def load_events(path):
    """Read the CloudTrail JSON file and return the list of events."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)                   # read the whole file
    except FileNotFoundError:
        print(f"Error: file '{path}' not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: file '{path}' is not valid JSON.")
        return []
    return data.get("Records", [])                # empty list if no Records


def get_user(record):
    """Return the user name of an event."""
    identity = record.get("userIdentity", {})
    if identity.get("type") == "Root":
        return "root"                             # root has no userName
    return identity.get("userName", "unknown")


def check_event(record):
    """Return the list of reasons why an event is risky."""
    reasons = []
    name = record.get("eventName")
    if name == "ConsoleLogin":
        result = record.get("responseElements", {}).get("ConsoleLogin")
        mfa = record.get("additionalEventData", {}).get("MFAUsed")
        if result == "Failure":
            reasons.append("Failed console login")
        elif result == "Success" and mfa == "No":
            reasons.append("Login without MFA")   # only on successful logins
    if record.get("userIdentity", {}).get("type") == "Root":
        reasons.append("Root account activity")
    if name == "StopLogging":
        reasons.append("CloudTrail logging stopped")
    return reasons


def count_by_key(events, key):
    """Count how many times each value of a key appears."""
    counts = {}
    for record in events:
        value = record.get(key, "unknown")
        counts[value] = counts.get(value, 0) + 1  # start at 0 if new value
    return counts


def get_risk(reason):
    """Return the risk level of a reason."""
    levels = {
        "CloudTrail logging stopped": "HIGH",
        "Root account activity": "HIGH",
        "Login without MFA": "MEDIUM",
        "Failed console login": "LOW",
        "Region used only once": "LOW",
    }
    return levels.get(reason, "LOW")              # LOW if reason not in the list


def build_findings(events):
    """Return one finding per reason found in the events."""
    findings = []
    regions = count_by_key(events, "awsRegion")
    for record in events:
        reasons = check_event(record)
        region = record.get("awsRegion", "unknown")
        if regions.get(region) == 1:
            reasons.append("Region used only once")   # rare region
        for reason in reasons:
            finding = {
                "time": record.get("eventTime", ""),
                "user": get_user(record),
                "ip": record.get("sourceIPAddress", ""),
                "event": record.get("eventName", ""),
                "reason": reason,
                "risk": get_risk(reason),
            }
            findings.append(finding)              # one finding per reason
    return findings


def write_csv(findings, path):
    """Write the findings in a CSV file."""
    fields = ["time", "user", "ip", "event", "reason", "risk"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()                      # header line
        for finding in findings:
            writer.writerow(finding)              # one row per finding


def main():
    """Run the program."""
    events = load_events("cloudtrail_sample.json")
    print(f"Number of events: {len(events)}")
    print("Events per IP:")
    ips = count_by_key(events, "sourceIPAddress")
    for ip in ips:
        print(f"  {ip}: {ips[ip]}")
    print("Events per region:")
    regions = count_by_key(events, "awsRegion")
    for region in regions:
        print(f"  {region}: {regions[region]}")
    findings = build_findings(events)
    print(f"Number of findings: {len(findings)}")
    write_csv(findings, "findings.csv")
    print("Findings saved in findings.csv")


if __name__ == "__main__":
    main()
