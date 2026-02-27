# Detection Rules

This document defines the detection logic used in the monitoring system.


## Rule 1: Failed Login Attempt

Condition: Login attempt with incorrect password

Log Event: LOGIN_FAILED

Severity: Medium

Reason: May indicate password guessing or brute force attempt.


## Rule 2: Brute Force Attack

Condition: 3 or more failed login attempts

Log Event: BRUTE_FORCE_DETECTED

Severity: High

Reason: Multiple failed attempts indicate brute force attack.


## Rule 3: SQL Injection Attempt

Condition: Input contains SQL keywords such as:
            * SELECT  
            * UNION  
            * DROP  
            * ' OR '1'='1  

Log Event: SQL_INJECTION_ATTEMPT

Severity: Critical

Reason: Indicates database attack attempt.


## Rule 4: Account Lock

Condition: Too many failed login attempts

Log Event: LOGIN_BLOCKED

Severity: High


## Rule 5: Suspicious Registration Attempt

Condition: Duplicate email or suspicious input

Log Event: REGISTER_FAILED

Severity: Medium
