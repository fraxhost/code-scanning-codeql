# vuln_samples.py
"""
Ten intentionally-vulnerable Python examples for CodeQL testing.
This variant CALLS each example from main() so static analyzers (CodeQL)
can see actual call sites/flows.

Do NOT run this in production. These are intentionally insecure patterns.
"""

import sqlite3
import hashlib
import random
import subprocess
import os
import pickle
import logging
import traceback
import requests
import tempfile
from typing import Any

# 1) SQL Injection (string concatenation)
def sql_injection_example(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users(name TEXT)")
    query = "SELECT * FROM users WHERE name = '%s'" % user_input  # vulnerable concat
    cur.execute(query)  # vulnerable to SQL injection
    conn.close()

# 2) Hard-coded secret / credential
API_KEY = "AKIAEXAMPLESECRETKEY123456"  # Hard-coded secret (detectable)
def hardcoded_secret_example() -> str:
    return API_KEY

# 3) Weak cryptography usage (MD5)
def weak_crypto_example(password: str) -> str:
    h = hashlib.md5()  # weak hash
    h.update(password.encode("utf-8"))
    return h.hexdigest()

# 4) Insecure random for security-sensitive token
def insecure_random_example() -> int:
    return random.randint(100000, 999999)  # insecure OTP

# 5) Command injection via subprocess with shell=True or string concatenation
def command_injection_example(cmd_from_user: str) -> None:
    subprocess.Popen("echo " + cmd_from_user, shell=True)  # uses shell with user input

# 6) Path traversal / insecure file access
BASE_DATA_DIR = "/var/data/"
def path_traversal_example(filename: str) -> str:
    path = os.path.join(BASE_DATA_DIR, filename)  # naive join
    with open(path, "r") as f:
        return f.read()

# 7) Insecure deserialization (pickle)
def insecure_deserialization_example(serialized: bytes) -> Any:
    obj = pickle.loads(serialized)  # insecure deserialization
    return obj

# 8) Disabling SSL certificate verification
def disable_ssl_verification_example(url: str) -> requests.Response:
    resp = requests.get(url, verify=False)  # disabled TLS verification
    return resp

# 9) Logging sensitive data
def sensitive_logging_example(username: str, password: str) -> None:
    logging.warning("User login attempt: user=%s password=%s", username, password)

# 10) Exposing stack trace / information disclosure
def expose_stack_trace_example() -> None:
    try:
        raise ValueError("simulated failure")
    except Exception:
        print("Error occurred:", traceback.format_exc())

# 11) eval() on user input
def eval_example(user_expr: str) -> Any:
    # Vulnerable: executes arbitrary Python code from untrusted input
    return eval(user_expr)

# 12) exec() on constructed string (code injection)
def exec_example(user_var: str) -> None:
    code = f"print('Hello ' + '{user_var}')"
    # Vulnerable: executing constructed code
    exec(code)

# 13) Unsafe YAML loading (yaml.load) which can construct arbitrary objects
def yaml_load_example(yaml_text: str) -> Any:
    # Vulnerable: yaml.load can instantiate arbitrary objects if unsafe loader used
    return yaml.load(yaml_text, Loader=yaml.FullLoader)  # insecure pattern historically

# 14) XML External Entity (XXE) example using DOM parse of untrusted XML
def xxe_example(xml_text: str) -> None:
    # Vulnerable: parsing untrusted XML with entity expansion can lead to XXE
    doc = xml.dom.minidom.parseString(xml_text)
    # If xml_text contains an external entity reference, it may be resolved by some parsers

# 15) Use of tempfile.mktemp (predictable temp filename)
def mktemp_example() -> str:
    """Create a secure temporary file, write data, and return its path.
    Caller is responsible for removing the file when finished.
    """
    # Create a NamedTemporaryFile that we can close but keep on disk (delete=False)
    with tempfile.NamedTemporaryFile(prefix="tmpvuln_", delete=False) as tf:
        tf.write(b"data")
        tmpname = tf.name

    # Optional: tighten permissions to be user-only (rw-------)
    try:
        os.chmod(tmpname, 0o600)
    except OSError:
        # best-effort: some platforms may not allow chmod; ignore if it fails
        pass

    return tmpname

# 16) Setting world-writable permissions on a sensitive file
def insecure_chmod_example(path: str) -> None:
    # Vulnerable: setting mode to 0o777 gives write permissions to everyone
    os.chmod(path, 0o777)

# 17) Open redirect: returning user-controlled URL in a redirect
def open_redirect_example(next_url: str) -> str:
    # Vulnerable: sending users to unvalidated external URL
    # In a web framework this would be: redirect(next_url)
    return f"Redirect to: {next_url}"

# 18) Plain HTTP request (sensitive data over unencrypted channel)
def insecure_http_example(url: str) -> requests.Response:
    # Vulnerable: sending sensitive data over http is insecure (MITM)
    # Here we use requests for the demonstration
    return requests.get(url)  # no verify param: plain HTTP or insecure transport

# 19) os.system with user input (command injection)
def os_system_example(user_cmd: str) -> int:
    # Vulnerable: passing user input to os.system executes shell commands
    return os.system(user_cmd)

# 20) Dangerous recursive delete using unvalidated user path (risky use of shutil.rmtree)
def rmtree_example(user_path: str) -> None:
    # Vulnerable: deleting user-supplied path could delete arbitrary files
    shutil.rmtree(user_path)


def main() -> None:
    """
    Call each vulnerable example with safe/benign inputs.
    Calls are wrapped in try/except so the script is safe to run in CI.
    """
    print("Calling vulnerable examples (safe/benign inputs) — test-only code.")

    # 1) SQL injection: benign input
    try:
        sql_injection_example("alice")  # static flow: user input -> SQL command
    except Exception as e:
        print("sql_example error:", e)

    # 2) Hard-coded secret: read it
    try:
        secret = hardcoded_secret_example()
        print("Read hardcoded secret length:", len(secret))
    except Exception as e:
        print("hardcoded secret error:", e)

    # 3) Weak crypto (MD5)
    try:
        print("MD5:", weak_crypto_example("password123"))
    except Exception as e:
        print("weak_crypto error:", e)

    # 4) Insecure random
    try:
        print("Insecure OTP:", insecure_random_example())
    except Exception as e:
        print("insecure_random error:", e)

    # 5) Command injection — use harmless input
    try:
        command_injection_example("hello_world")
    except Exception as e:
        print("command_injection error:", e)

    # 6) Path traversal — create a safe temp directory and file, then point BASE_DATA_DIR to it
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # monkeypatch the BASE_DATA_DIR to a writable temp dir for this call
            global BASE_DATA_DIR
            orig_base = BASE_DATA_DIR
            BASE_DATA_DIR = tmpdir
            fname = "safe_file.txt"
            safe_path = os.path.join(BASE_DATA_DIR, fname)
            with open(safe_path, "w") as f:
                f.write("safe content")
            # call the vulnerable function with the safe filename (still uses join)
            content = path_traversal_example(fname)
            print("Path traversal read (safe):", content)
            # restore original base dir
            BASE_DATA_DIR = orig_base
    except Exception as e:
        print("path_traversal error:", e)

    # 7) Insecure deserialization — use a harmless pickle payload
    try:
        payload = pickle.dumps({"ok": True})
        obj = insecure_deserialization_example(payload)
        print("Deserialized object keys:", list(obj.keys()) if isinstance(obj, dict) else type(obj))
    except Exception as e:
        print("insecure_deserialization error:", e)

    # 8) Disable SSL verification — patch requests.get to avoid network call in CI
    try:
        real_get = requests.get
        # lightweight fake response object
        class FakeResp:
            status_code = 200
            text = "fake"
        requests.get = lambda url, verify=True: FakeResp()
        resp = disable_ssl_verification_example("https://example.com")
        print("Fake requests.get called, status:", resp.status_code)
        # restore
        requests.get = real_get
    except Exception as e:
        print("disable_ssl_verification error:", e)
        # ensure restoration
        try:
            requests.get = real_get
        except Exception:
            pass

    # 9) Sensitive logging
    try:
        sensitive_logging_example("alice", "p@ssw0rd")
    except Exception as e:
        print("sensitive_logging error:", e)

    # 10) Expose stack trace
    try:
        expose_stack_trace_example()
    except Exception as e:
        print("expose_stack_trace error:", e)

    # 11) eval - call with a safe literal expression
    try:
        print("eval result:", eval_example("1 + 2"))
    except Exception as e:
        print("eval_example error:", e)

    # 12) exec - benign string
    try:
        exec_example("world")
    except Exception as e:
        print("exec_example error:", e)

    # 13) yaml.load - provide harmless yaml string
    try:
        safe_yaml = "a: 1\nb: 2"
        print("yaml load:", yaml_load_example(safe_yaml))
    except Exception as e:
        print("yaml_load_example error:", e)

    # 14) XXE - pass a harmless XML string (do NOT include external entities)
    try:
        safe_xml = "<root><child>ok</child></root>"
        xxe_example(safe_xml)
        print("xxe_example parsed safe xml")
    except Exception as e:
        print("xxe_example error:", e)

    # 15) mktemp - create and remove temporary file safely
    try:
        tmpname = mktemp_example()
        print("mktemp created:", tmpname)
        # Clean up
        if os.path.exists(tmpname):
            os.remove(tmpname)
    except Exception as e:
        print("mktemp_example error:", e)

    # 16) insecure chmod - create a temp file then chmod (will be cleaned up)
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            p = tf.name
            tf.write(b"test")
        insecure_chmod_example(p)
        print("insecure_chmod set on:", p)
        os.remove(p)
    except Exception as e:
        print("insecure_chmod_example error:", e)

    # 17) open redirect - show returned URL
    try:
        print(open_redirect_example("https://evil.example.com"))
    except Exception as e:
        print("open_redirect_example error:", e)

    # 18) insecure http - monkeypatch requests.get to avoid network call
    try:
        real_get = requests.get
        class FakeResp:
            status_code = 200
            text = "ok"
        requests.get = lambda url: FakeResp()
        r = insecure_http_example("http://example.com")
        print("insecure_http_example fake status:", r.status_code)
        requests.get = real_get
    except Exception as e:
        print("insecure_http_example error:", e)
        try:
            requests.get = real_get
        except Exception:
            pass

    # 19) os.system - run a harmless command string
    try:
        os_system_example("echo safe_cmd")
    except Exception as e:
        print("os_system_example error:", e)

    # 20) rmtree - create temporary directory and safely remove it (but function demonstrates the dangerous pattern)
    try:
        tmpdir = tempfile.mkdtemp()
        # create a file to ensure directory exists
        open(os.path.join(tmpdir, "x"), "w").close()
        # Call with safe path (but function itself is dangerous if used with untrusted input)
        rmtree_example(tmpdir)
        print("rmtree_example removed:", tmpdir)
    except Exception as e:
        print("rmtree_example error:", e)

    print("Finished calling vulnerable examples. Inspect source and run CodeQL.")


if __name__ == "__main__":
    main()
