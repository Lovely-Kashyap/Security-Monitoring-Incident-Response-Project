# Incident Scenarios and Response

## Incident 1: Brute Force Attack

Evidence:
Multiple LOGIN_FAILED events

Severity:
HIGH

Response Steps:
1. System automatically locks account
2. Log event recorded
3. Administrator reviews logs
4. User notified


## Incident 2: Unauthorized Access Attempt

Evidence:
LOGIN_FAILED event

Severity:
MEDIUM

Response:
Monitor IP activity
Alert administrator


## Incident 3: Normal User Login

Evidence:
LOGIN_SUCCESS event

Severity:
LOW

Response:
No action required
Log stored for audit
