"""API Key account-scope regression checks."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import qoder_accounts
import qoder_settings


class FakeAccount:
    def __init__(self, uid):
        self.uid = uid
        self.realm = "cn"
        self.enabled = True
        self.access_token = "token"
        self.cooldown_until = 0
        self.model_cooldowns = {}
        self.expiring_window_days = 0

    def ready(self, model=None):
        return self.enabled and bool(self.access_token)

    def degraded(self, now=None):
        return False

    def in_expiring_window(self):
        return False


def check(label, condition, failures):
    print("  [%s] %s" % ("PASS" if condition else "FAIL", label))
    if not condition:
        failures.append(label)


def main():
    failures = []
    pool = qoder_accounts.AccountPool(tempfile.mkdtemp())
    first, second = FakeAccount("acct-a"), FakeAccount("acct-b")
    pool.accounts = [first, second]

    check("allow list selects only permitted account",
          pool.pick(realm="cn", allow={"acct-b"}) is second, failures)
    pool.affinity.bind("conversation", "acct-a")
    check("session affinity cannot bypass allow list",
          pool.pick_for_session(realm="cn", session_key="conversation",
                                allow={"acct-b"}) is second, failures)
    check("disallowed affinity is rebound to permitted account",
          pool.affinity.get("conversation") == "acct-b", failures)
    check("empty allow list fails closed",
          pool.pick(realm="cn", allow=set()) is None, failures)

    directory = tempfile.mkdtemp()
    qoder_settings.set_api_keys(directory, [{"id": "k1", "key": "secret",
                                              "accounts": ["acct-a"]}])
    stored = qoder_settings.api_keys(directory)[0]
    check("accounts whitelist survives settings round trip",
          stored.get("accounts") == ["acct-a"], failures)

    print("SUMMARY: %d passed, %d failed" %
          (5 - len(failures), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
