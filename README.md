# Security Monitoring & Incident Response Project

## Overview
This project simulates a Security Operations Center (SOC) environment by monitoring a web application, detecting suspicious activities, generating alerts, and defining incident response procedures.

The goal is to demonstrate how real organizations monitor logs, detect attacks, and respond to security incidents.

This project includes:
• Web application with security event logging  
• Real-time log monitoring script  
• Alert generation system  
• Incident detection logic  
• Incident response documentation  


## Features

### Security Logging
The application logs all security-relevant events into: security.log

Example events:
* LOGIN_ATTEMPT  
* LOGIN_FAILED  
* BRUTE_FORCE_DETECTED  
* SQL_INJECTION_ATTEMPT  
* REGISTER_ATTEMPT  


### Alert Generation
Critical and suspicious events are written to: alerts.log

These simulate SOC alerts.


### Real-Time Monitoring
monitor.py continuously monitors logs and detects incidents.


### Dashboard

The web application provides:
• User login system  
• Log viewing interface  
• Alert viewing interface  


## Project Structure

```
security-monitoring-incident-response-project/
│
├── app.py
├── monitor.py
├── security.log
├── alerts.log
├── users.db
│
├── README.md
├── detection_rules.md
├── incident-response.md
└── future-improvemnets.md
```


## Technologies Used

Python  
Flask  
SQLite  
bcrypt  
Logging module  


## How to Run

Step 1:
```
pip install flask bcrypt
```

Step 2:
```
python app.py
```

Step 3: (In another terminal)
```
python monitor.py
```


## Attack Simulation

Examples:
Brute force login attempt  
SQL injection input  

Example payload:
admin' OR '1'='1


## Learning Outcomes

* Log monitoring  
* Threat detection  
* Incident classification  
* SOC workflow simulation  
* Security alert generation  


## Author

**Lovely Kashyap**

Cyber Security & Ethical Hacking Intern - Cryptonic Area
