# Incident Response Plan

This document defines how security incidents are handled.


## Incident 1: Brute Force Attack

Detection: Multiple failed login attempts detected in logs.

Severity: High

Response Steps:

* Identify attacker IP address
* Review login logs
* Lock affected account
* Monitor further activity
* Implement stronger authentication controls


## Incident 2: SQL Injection Attempt

Detection: Malicious input detected in login or registration fields.

Severity: Critical

Response Steps:

* Identify source IP
* Block IP address
* Review database integrity
* Check for unauthorized access
* Strengthen input validation


## Incident 3: Unauthorized Access Attempt

Detection: Repeated login failures or suspicious activity.

Severity: Medium

Response Steps:

* Monitor user activity
* Verify account owner
* Reset password if needed
* Review logs


## Incident Documentation

All incidents are recorded in:
* security.log  
* alerts.log
