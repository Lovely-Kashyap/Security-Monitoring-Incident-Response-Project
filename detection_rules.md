# Detection Rules

## Rule 1: Brute Force Detection
Condition:
If LOGIN_FAILED occurs 3 times from same IP

Detection:
ACCOUNT_LOCKED event triggered

Reason:
Indicates brute force attack attempt


## Rule 2: Unauthorized Login Attempt
Condition:
LOGIN_FAILED event detected

Detection:
Flag suspicious authentication attempt

Reason:
Possible credential guessing


## Rule 3: Successful Authentication Monitoring
Condition:
LOGIN_SUCCESS event

Detection:
Record user access

Reason:
Track legitimate access


## Rule 4: Access After Login
Condition:
DASHBOARD_ACCESS event

Detection:
Verify authenticated session usage

Reason:
Ensure session integrity
