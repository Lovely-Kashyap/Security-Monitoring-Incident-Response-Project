from flask import Flask, render_template_string, request, redirect, session
import sqlite3
import bcrypt
import logging
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secretKEY"


# LOGGING CONFIG

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

ALERT_FILE = "alerts.log"


def log_event(level, event, details=""):
    ip = request.remote_addr
    message = f"{event} | IP={ip} | {details}"

    if level == "INFO":
        logging.info(message)

    elif level == "WARNING":
        logging.warning(message)
        create_alert("MEDIUM", message)

    elif level == "CRITICAL":
        logging.critical(message)
        create_alert("HIGH", message)


def create_alert(severity, message):
    with open(ALERT_FILE, "a") as f:
        f.write(f"{datetime.now()} | {severity} ALERT | {message}\n")


# DATABASE

conn = sqlite3.connect("users.db")
conn.execute("""
CREATE TABLE IF NOT EXISTS users(
username TEXT,
email TEXT UNIQUE,
password TEXT)
""")
conn.close()


# ATTACK DETECTION

sql_patterns = [
    r"'.*or.*'",
    r"union.*select",
    r"--",
    r";",
    r"drop",
    r"select.*from"
]


def detect_attack(input_text):

    for pattern in sql_patterns:
        if re.search(pattern, input_text.lower()):
            log_event(
                "CRITICAL",
                "SQL_INJECTION_ATTEMPT",
                f"payload={input_text}"
            )
            return True

    return False


# STYLE

style = """
<style>

body{
background:#0b132b;
font-family:Arial;
color:white;
display:flex;
justify-content:center;
align-items:center;
height:100vh;
}

.card{
background:#1c2541;
padding:30px;
width:420px;
border-radius:10px;
box-shadow:0 0 15px black;
}

input,button{
width:100%;
padding:10px;
margin-top:10px;
border-radius:5px;
border:none;
}

button{
background:#3a86ff;
color:white;
cursor:pointer;
}

button:hover{
background:#265df2;
}

.error{
color:#ff595e;
}

a{
color:#8ecae6;
}

</style>
"""


# REGISTER

@app.route("/", methods=["GET","POST"])
def register():

    error=""

    if request.method=="POST":

        username=request.form["username"]
        email=request.form["email"]
        password=request.form["password"]

        log_event("INFO","REGISTER_ATTEMPT",f"user={username}")

        if detect_attack(username) or detect_attack(email):
            error="Suspicious input detected"
            return redirect("/")

        if len(password)<8:
            error="Password too short"

        else:

            conn=sqlite3.connect("users.db")

            existing=conn.execute(
                "SELECT * FROM users WHERE email=?",
                (email,)
            ).fetchone()

            if existing:

                log_event(
                    "WARNING",
                    "REGISTER_FAILED",
                    "duplicate email"
                )

                error="Email exists"

            else:

                hashed=bcrypt.hashpw(
                    password.encode(),
                    bcrypt.gensalt()
                ).decode()

                conn.execute(
                    "INSERT INTO users VALUES(?,?,?)",
                    (username,email,hashed)
                )

                conn.commit()
                conn.close()

                log_event(
                    "INFO",
                    "REGISTER_SUCCESS",
                    f"user={username}"
                )

                return redirect("/login")

            conn.close()


    return render_template_string(style+"""

    <div class="card">

    <h2>Register</h2>

    <form method="post">

    <input name="username" placeholder="username" required>

    <input name="email" placeholder="email" required>

    <input type="password"
    name="password"
    placeholder="password"
    required>

    <button>Register</button>

    </form>

    <div class="error">"""+error+"""</div>

    <a href="/login">Login</a>

    </div>
    """)


# LOGIN

@app.route("/login", methods=["GET","POST"])
def login():

    error=""

    session.setdefault("attempts",0)
    session.setdefault("locked",False)

    if request.method=="POST":

        username=request.form["username"]
        password=request.form["password"]

        if detect_attack(username):
            error="Attack detected"
            return redirect("/login")

        if session["locked"]:

            log_event(
                "CRITICAL",
                "LOGIN_BLOCKED",
                "account locked"
            )

            error="Account locked"

        else:

            log_event(
                "INFO",
                "LOGIN_ATTEMPT",
                f"user={username}"
            )

            conn=sqlite3.connect("users.db")

            user=conn.execute(
                "SELECT * FROM users WHERE username=? OR email=?",
                (username,username)
            ).fetchone()

            conn.close()

            if user:

                stored=user[2].encode()

                if bcrypt.checkpw(
                    password.encode(),
                    stored):

                    session["user"]=user[0]
                    session["attempts"]=0

                    log_event(
                        "INFO",
                        "LOGIN_SUCCESS",
                        f"user={username}"
                    )

                    return redirect("/dashboard")


            session["attempts"]+=1

            log_event(
                "WARNING",
                "LOGIN_FAILED",
                f"user={username}"
            )

            if session["attempts"]>=3:

                session["locked"]=True

                log_event(
                    "CRITICAL",
                    "BRUTE_FORCE_DETECTED",
                    f"user={username}"
                )

                error="Account locked"


    return render_template_string(style+"""

    <div class="card">

    <h2>Login Page</h2>

    <form method="post">

    <input name="username"
    placeholder="username or email"
    required>

    <input type="password"
    name="password"
    placeholder="password"
    required>

    <button>Login</button>

    </form>

    <div class="error">"""+error+"""</div>

    <a href="/">Register</a>

    </div>
    """)


# DASHBOARD

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    log_event(
        "INFO",
        "DASHBOARD_ACCESS",
        f"user={session['user']}"
    )

    return render_template_string(style+"""

    <div class="card">

    <h2>Dashboard</h2>

    <p>Welcome, """+session["user"]+"""</p>

    <a href="/logs">
    <button>View Security Logs</button>
    </a>

    <a href="/alerts">
    <button>View Alerts</button>
    </a>

    <a href="/logout">
    <button>Logout</button>
    </a>

    </div>
    """)


# VIEW LOGS

@app.route("/logs")
def view_logs():

    with open("security.log","r") as f:
        logs=f.read()

    return f"<pre>{logs}</pre>"


@app.route("/alerts")
def view_alerts():

    try:
        with open("alerts.log","r") as f:
            logs=f.read()
    except:
        logs="No alerts yet"

    return f"<pre>{logs}</pre>"


# LOGOUT

@app.route("/logout")
def logout():

    log_event(
        "INFO",
        "LOGOUT",
        "user logout"
    )

    session.clear()

    return redirect("/login")


# RUN

app.run(debug=True)