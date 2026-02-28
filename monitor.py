import time

LOG="security.log"

print("Security Monitoring started...")

with open(LOG,"r") as file:

    file.seek(0,2)

    while True:

        line=file.readline()

        if not line:
            time.sleep(1)
            continue


        if "CRITICAL" in line:

            print("[HIGH ALERT]",line.strip())

            with open("alerts.log","a") as alert:
                alert.write(line)


        elif "WARNING" in line:

            print("[MEDIUM ALERT]",line.strip())