import json     # converts JSON text to Python dictionaries and lists, and back.
import csv      # writes table files that Excel can open.

#Constants (in capital)

INPUT_FILE = "cloudtrail_sample.json"             # read only
CSV_FILE = "findings.csv"
JSON_FILE = "report.json"
FAILED_LOGIN_LIMIT = 3                            # failed logins before alert


def load_events(path):        # a function that receives a file name (path)
    """Read the CloudTrail JSON file and return the list of events."""
    try:
        with open(path, "r", encoding="utf-8") as f:       # "r" means read mode. Python can’t write to a file opened in "r" mode, which is how we guarantee the input file is never modified.
            data = json.load(f)                   # reads the whole file and turns the JSON text into Python objects.
    except FileNotFoundError:        # the file doesn’t exist
        print(f"Error: file '{path}' not found.")    # The f before the quotes lets Python replace {path} with the variable’s value
        return []
    except json.JSONDecodeError:     # the file exists but isn’t valid JSON (cut, corrupted)
        print(f"Error: file '{path}' is not valid JSON.")
        return []
    return data.get("Records", [])                # empty list if no Records ( dictionary.get(label, value_if_missing)) -> .get(key, default) reads a value from a dictionary without crashing. If the key is missing, it returns the default you chose, or None if you didn’t choose one.

# Who did it?
def get_user(record):
    """Return the user name of an event."""
    identity = record.get("userIdentity", {})      # Get the user identity information, default to an empty dictionary : there are 3 possible cases: root account ({"type": "Root"}, with no userName) , broken event (no userIdentity at all) , normal user ({"type": "IAMUser", "userName": "alice"}) and The function handles all 3 without crashing.
    if identity.get("type") == "Root":
        return "root"                             # root has no userName
    return identity.get("userName", "unknown")

# Is it risky, and why?
def check_event(record):
    """Return the list of reasons why an event is risky."""
    reasons = []   # Empty list at the end means the event is normal while Non-empty list means the event is risky, and the list says why.
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

# count how many times each value appears
def count_by_key(events, key):
    """Count how many times each value of a key appears."""
    counts = {}
    for record in events:
        value = record.get(key, "unknown")
        counts[value] = counts.get(value, 0) + 1  # start at 0 if new value
    return counts

# risk levels: HIGH, MEDIUM, LOW
def get_risk(reason):
    """Return the risk level of a reason."""
    levels = {
        # typical of an attacker taking control or hiding
        "CloudTrail logging stopped": "HIGH",
        "Root account activity": "HIGH",
        # weak protection or an attack attempt, but no proof of damage
        "Login without MFA": "MEDIUM",
        "Possible brute force": "MEDIUM",
        #often innocent (typo, trip), but worth a look
        "Failed console login": "LOW",
        "Region used only once": "LOW",
    }
    return levels.get(reason, "LOW")              # LOW if reason not in the list

# make a finding dictionary for one event and one reason (one result line)
def make_finding(record, reason):
    """Return one finding dictionary for an event and a reason."""
    finding = {
        "time": record.get("eventTime", ""),
        "user": get_user(record),
        "ip": record.get("sourceIPAddress", ""),
        "event": record.get("eventName", ""),
        "reason": reason,
        "risk": get_risk(reason),
    }
    return finding

# Find IPs with too many failed logins
def find_brute_force(events):
    """Return one finding per IP with too many failed logins."""
    failures = {}
    last_failure = {}
    for record in events:
        if "Failed console login" in check_event(record):
            ip = record.get("sourceIPAddress", "unknown")
            failures[ip] = failures.get(ip, 0) + 1    # count per IP
            last_failure[ip] = record                 # keep the last one
    findings = []
    for ip in failures:
        if failures[ip] >= FAILED_LOGIN_LIMIT:
            findings.append(make_finding(last_failure[ip], "Possible brute force"))
    return findings

# Build the findings list (put it all together and return every finding)
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
            findings.append(make_finding(record, reason))  # one finding per reason
    for finding in find_brute_force(events):
        findings.append(finding)                  # one alert per IP
    return findings

# Write the findings in a CSV file
def write_csv(findings, path):
    
    fields = ["time", "user", "ip", "event", "reason", "risk"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()                      # header line
        for finding in findings:
            writer.writerow(finding)              # one row per finding

# Build the summary dictionary
def build_summary(events, findings):
    """Return a summary of the analysis."""
    summary = {
        "total_events": len(events),
        "total_findings": len(findings),
        "findings_per_risk": count_by_key(findings, "risk"),
        "findings": findings,
    }
    return summary

# Write the summary in a JSON file
def write_json(summary, path):
    """Write the summary in a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)           # indent makes it readable

# Print the counts of values in a dictionary
def print_counts(title, counts):
    """Print a title and one line per counted value."""
    print(title)
    for value in counts:
        print(f"  {value}: {counts[value]}")

# Main program
def main():
    """Run the program."""
    events = load_events(INPUT_FILE)              # load
    if not events:
        print("No events to analyse.")
        return                                    # stop, keep old results
    findings = build_findings(events)             # check
    summary = build_summary(events, findings)
    write_csv(findings, CSV_FILE)                 # export
    write_json(summary, JSON_FILE)
    print(f"Events read: {summary['total_events']}")
    print_counts("Events per IP:", count_by_key(events, "sourceIPAddress"))
    print_counts("Events per region:", count_by_key(events, "awsRegion"))
    print(f"Findings: {summary['total_findings']}")
    print_counts("Findings per risk:", summary["findings_per_risk"])
    print(f"Results saved in {CSV_FILE} and {JSON_FILE}")
    print_counts("Events per name:", count_by_key(events, "eventName"))


if __name__ == "__main__":
    main()