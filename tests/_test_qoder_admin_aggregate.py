import os
import sys
import tempfile
import threading
import time
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import qoder_proxy
import qoder_scheduler
import qoder_tenants


def check(name, condition, detail=None):
    if not condition:
        raise SystemExit("FAIL: %s %r" % (name, detail))
    print("PASS: " + name)


class FakeAccount:
    def __init__(self, uid):
        self.uid = uid
        self.realm = "cn"
        self.enabled = True
        self.access_token = "token"

    def public(self):
        return {"uid": self.uid, "realm": self.realm}

    def ready(self, model=None):
        return self.enabled and bool(self.access_token)


class FakePool:
    def __init__(self, directory, accounts):
        self.dir = directory
        self.accounts = accounts
        self.removed = []
        self.enabled = []
        self.added = []
        self.refreshed = []

    def load(self):
        return self.accounts

    def add(self, account):
        self.added.append(account)
        self.accounts.append(account)
        return account

    def remove(self, uid):
        account = next(
            (item for item in self.accounts if item.uid == uid), None
        )
        if account is None:
            return False
        self.accounts.remove(account)
        self.removed.append(uid)
        return True

    def set_enabled(self, uid, enabled):
        self.enabled.append((uid, enabled))
        return {"uid": uid, "enabled": enabled}

    def set_all_enabled(self, enabled, realm=None):
        self.enabled.extend((item.uid, enabled) for item in self.accounts)

    def refresh_account(self, account):
        self.refreshed.append(account.uid)
        return True

    def apply_settings(self, limits_data=None, free_models=None):
        return []

    def import_rows(self, rows, realm=None, overwrite=False):
        return {"added": [], "updated": [], "skipped": [], "invalid": []}

    def preview_import_rows(self, rows, realm=None, overwrite=False):
        return {"added": [], "updated": [], "skipped": [], "invalid": []}

    def start_login(self, realm="cn", platform="CLI"):
        return {"state": "one"}

    def poll_login(self, state):
        return {"status": "pending"}

    def cancel_login(self, state):
        return True

    def import_desktop_credential(self, path=None, realm=None):
        return FakeAccount("desktop")


legacy = FakePool(
    "/global", [FakeAccount("shared"), FakeAccount("global-only")]
)
first_tenant = FakePool(
    "/tenant-a", [FakeAccount("shared"), FakeAccount("tenant-only")]
)
second_tenant = FakePool(
    "/tenant-b", [FakeAccount("second-only")]
)
pool = qoder_tenants.AggregateAccountPool(
    [legacy, first_tenant, second_tenant],
    metadata=[
        {"scope": "global", "tenant_id": "", "owner_label": "全局"},
        {"scope": "tenant", "tenant_id": "aac-a",
         "owner_label": "租户 qd-a"},
        {"scope": "tenant", "tenant_id": "aac-b",
         "owner_label": "租户 qd-b"},
    ],
)

check("admin view includes global and tenant accounts",
      {item.uid for item in pool.accounts}
      == {"shared", "global-only", "tenant-only", "second-only"})
check("admin view de-duplicates shared accounts",
      [item.uid for item in pool.accounts].count("shared") == 1)
check("admin account rows identify ownership",
      {row["uid"]: row["tenant_id"] for row in pool.list_public()}
      == {"shared": "", "global-only": "", "tenant-only": "aac-a",
          "second-only": "aac-b"})
check("admin view removes from the owning tenant",
      pool.remove("tenant-only")
      and first_tenant.removed == ["tenant-only"]
      and legacy.removed == [])
check("admin view toggles through the owning tenant",
      pool.set_enabled("second-only", False) is not None
      and second_tenant.enabled == [("second-only", False)])
check("admin view refreshes through the owning tenant",
      pool.refresh_account(pool.get("global-only"))
      and legacy.refreshed == ["global-only"])
check("admin view still writes new accounts to global",
      pool.add(FakeAccount("new-global"))
      and legacy.added[-1].uid == "new-global")


class SlowPool(FakePool):
    """Concrete AccountPool shape: load mutates accounts while holding _lock."""

    def __init__(self, directory, accounts):
        super().__init__(directory, accounts)
        self._lock = threading.RLock()

    def load(self):
        with self._lock:
            source = list(self.accounts)
            self.accounts = []
            for account in source:
                time.sleep(0.002)
                self.accounts.append(account)
            return list(self.accounts)


slow_pools = [
    SlowPool("/slow-%d" % index, [
        FakeAccount("slow-%d-a" % index),
        FakeAccount("slow-%d-b" % index),
    ])
    for index in range(6)
]


def concurrent_admin_snapshot(_):
    current = qoder_tenants.AggregateAccountPool(slow_pools)
    current.reload()
    return tuple(sorted(item.uid for item in current.accounts))


with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
    snapshots = list(executor.map(concurrent_admin_snapshot, range(48)))
check("concurrent admin refresh never observes partially loaded pools",
      all(len(snapshot) == 12 for snapshot in snapshots)
      and len(set(snapshots)) == 1,
      {len(snapshot): snapshots.count(snapshot) for snapshot in set(snapshots)})

with tempfile.TemporaryDirectory() as root:
    manager = qoder_tenants.TenantRuntimeManager(root)
    tenant = manager.get_or_create("aac-admin-view", "qd-admin-view")
    tenant._pool = FakePool(
        "/private-tenant", [FakeAccount("private-account")]
    )
    primary = FakePool("/legacy", [FakeAccount("legacy-account")])
    old_manager = qoder_proxy.TENANT_MANAGER
    old_legacy = qoder_proxy._LEGACY_POOL
    old_principal = qoder_proxy._oauth_principal
    qoder_proxy.TENANT_MANAGER = manager
    qoder_proxy._LEGACY_POOL = primary
    try:
        runtime = qoder_proxy._admin_aggregate_runtime()
        check("admin request runtime aggregates tenant pools",
              runtime is not None
              and {item.uid for item in runtime.pool.accounts}
              == {"legacy-account", "private-account"})

        class AdminPrincipal:
            principal_type = "aac-user"
            role = "admin"
            aac_user_id = "aac-admin"
            qoder_user_id = "qd-admin"

        class Handler(qoder_proxy.Handler):
            headers = {}
            path = "/settings"

            def _supplied_key(self):
                return ""

            def _panel_ok(self):
                return False

        qoder_proxy._oauth_principal = lambda handler: AdminPrincipal()
        handler = object.__new__(Handler)
        check("AAC admin request binds the aggregate runtime",
              handler._key_ok()
              and qoder_proxy._REQUEST_RUNTIME.get() is handler.tenant_runtime
              and handler.tenant_runtime.is_admin_aggregate)
    finally:
        qoder_proxy.TENANT_MANAGER = old_manager
        qoder_proxy._LEGACY_POOL = old_legacy
        qoder_proxy._oauth_principal = old_principal
        qoder_proxy._REQUEST_RUNTIME.set(None)

with tempfile.TemporaryDirectory() as root:
    manager = qoder_tenants.TenantRuntimeManager(root)
    first = manager.get_or_create("aac-scheduler-1", "qd-scheduler-1")
    second = manager.get_or_create("aac-scheduler-2", "qd-scheduler-2")
    original_start = qoder_scheduler.Scheduler.start

    def fake_start(self):
        self.started_for_test = True

    qoder_scheduler.Scheduler.start = fake_start
    try:
        started = manager.start_schedulers()
        check("startup starts schedulers for every persisted tenant",
              len(started) == 2
              and first.scheduler.started_for_test
              and second.scheduler.started_for_test)
    finally:
        qoder_scheduler.Scheduler.start = original_start

print("PASS: qoder admin aggregate")
