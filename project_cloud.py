import json


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


def main():
    """Run the program."""
    events = load_events("cloudtrail_sample.json")
    print(f"Number of events: {len(events)}")
    for record in events:
        reasons = check_event(record)
        if reasons:
            print(get_user(record), record.get("eventName"), reasons)  # risky events only


if __name__ == "__main__":
    main()
