"""Regression matrix for AAC ordinary-user Qoder permissions."""
import http.server
import threading
import urllib.error
import urllib.request
import sys

ROOT = __import__('os').path.dirname(__import__('os').path.dirname(__file__))
sys.path.insert(0, ROOT)
from _suite_head import declare_suite
import qoder_proxy as P
import qoder_tasks


class Principal:
    role = "user"
    principal_type = "aac-user"
    aac_user_id = "user-1"
    qoder_user_id = "user-1"


def request(base, method, path):
    req = urllib.request.Request(
        base + path,
        method=method,
        data=b"{}" if method == "POST" else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main():
    declare_suite(__file__, ["qoder_proxy.py", "dashboard.html"])
    originals = (
        P._oauth_principal,
        P.Handler._authorized,
        P.Handler._handle_accounts,
        qoder_tasks.fetch_tasks_view,
    )
    P._oauth_principal = lambda handler: Principal()
    P.Handler._authorized = lambda self: True
    P.Handler._handle_accounts = lambda self, path, payload: self._json(
        200, {"ok": True, "path": path}
    )
    qoder_tasks.fetch_tasks_view = lambda pool, realm=None, uid=None: {
        "ok": True, "tasks": [], "realm": realm
    }
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), P.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    checks = [
        ("GET /tasks", "GET", "/tasks", 200),
        ("POST /tasks/run", "POST", "/tasks/run", 200),
        ("POST /tasks/travel", "POST", "/tasks/travel", 200),
        ("GET /scheduler remains admin-only", "GET", "/scheduler", 403),
        ("GET /scheduler/trigger remains admin-only", "GET", "/scheduler/trigger", 403),
        ("GET /logs remains admin-only", "GET", "/logs", 403),
        ("GET /logs/export remains admin-only", "GET", "/logs/export", 403),
        ("POST /accounts/set remains tenant-scoped", "POST", "/accounts/set", 200),
    ]
    failures = []
    for label, method, path, expected in checks:
        actual = request(base, method, path)
        print("  [%s] %s -> %s" % ("PASS" if actual == expected else "FAIL", label, actual))
        if actual != expected:
            failures.append(label)
    server.shutdown()
    server.server_close()
    (P._oauth_principal, P.Handler._authorized,
     P.Handler._handle_accounts, qoder_tasks.fetch_tasks_view) = originals
    passed = len(checks) - len(failures)
    print("SUMMARY: TOTAL %d checks, %d passed, %d failed" %
          (len(checks), passed, len(failures)))
    print("RESULT: %s (exit %d)" % ("RED" if failures else "GREEN",
                                    1 if failures else 0))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
