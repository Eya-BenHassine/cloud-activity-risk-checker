# Cloud Activity Risk Checker

Course project, M1 Cybersecurity.

## What the script does

`project_cloud.py` reads a simplified AWS CloudTrail log in JSON format and looks for risky events.

It flags these events:

| Reason                     | Rule                                                | Risk   |
|----------------------------|-----------------------------------------------------|--------|
| CloudTrail logging stopped | eventName is StopLogging                            | HIGH   |
| Root account activity      | userIdentity type is Root                           | HIGH   |
| Login without MFA          | successful ConsoleLogin with MFAUsed "No"           | MEDIUM |
| Failed console login       | ConsoleLogin with result "Failure"                  | LOW    |
| Region used only once      | the event's region appears only one time in the log | LOW    |

It also counts the events per source IP address and per AWS region, and prints a short summary.

## Requirements

Python 3. The script uses only the standard library (`json` and `csv`), so nothing needs to be installed.

## How to run

Put `project_cloud.py` and `cloudtrail_sample.json` in the same folder, then run:

```
python project_cloud.py
```

On Linux or macOS, use `python3` instead of `python`.

To analyse another log file, change `INPUT_FILE` at the top of the script.

## Files

| File                     | Role                                                                                    |
|--------------------------|-----------------------------------------------------------------------------------------|
| `project_cloud.py`       | the script                                                                              |
| `cloudtrail_sample.json` | input: 20 invented CloudTrail events (read only, never modified)                        |
| `findings.csv`           | output: one line per finding (time, user, ip, event, reason, risk)                      |
| `report.json`            | output: total events, total findings, findings per risk level, and the list of findings |

The sample log uses only documentation IP addresses (203.0.113.x, 198.51.100.x, 192.0.2.x) and invented users (alice, bob, admin).

## Error handling

If the input file is missing or is not valid JSON, the script prints a clear message and stops without crashing. In this case the old output files are not overwritten.

```
Error: file 'nofile.json' not found.
No events to analyse.
```

## Limits

- The input is a simplified CloudTrail format, not a full real export (real logs can be split in many gzip files).
- The rules are simple and fixed in the code. There are no thresholds, for example 3 failed logins are reported as 3 separate LOW findings, not as one brute force alert.
- "Region used only once" depends on the size of the log: in a small log, a normal region can look rare.
- The risk levels are a personal choice for this project, not an official scale.
- The whole file is loaded in memory, so very large logs are not supported.
- The script only reports. It does not block anything or send alerts.