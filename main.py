import subprocess
from flask import request, flask
app = Flask(__name__)

@app.route("/ping")
def ping():
    target = request.args.get("host", "127.0.0.1")
    # vulnerable: untrusted input passed to shell
    subprocess.check_output(f"ping -c l {target}", shell=True)
    return "OK"

# FIX: avoid shell, pass a list; validate/whitelist target
# subprocess.check_output(["ping", "-c", "l"])