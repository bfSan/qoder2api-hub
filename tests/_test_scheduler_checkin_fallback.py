"""Scheduler check-in fallback and accounting regression suite."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _suite_head import *  # noqa: F401,F403

_, A = bootstrap()
import qoder_scheduler as S
import qoder_tasks as T

declare_suite(__file__, ["qoder_tasks.py", "qoder_scheduler.py"])


class FakeAccount(object):
    def __init__(self, uid, campaign, legacy):
        self.uid = uid
        self.nickname = uid
        self.enabled = True
        self.access_token = "token"
        self.campaign = campaign
        self.legacy = legacy
        self.legacy_calls = 0
        self.credits = {"remain": 100}

    def campaign_checkin(self, gap=None, only_kinds=None):
        return dict(self.campaign)

    def checkin(self):
        self.legacy_calls += 1
        return dict(self.legacy)

    def fetch_credits(self):
        return {"ok": True, "credits": self.credits}

    def fetch_plan(self):
        return {"ok": True}


print("[scheduler check-in] campaign miss falls back to legacy check-in")
acc = FakeAccount(
    "fallback-user",
    {"ok": True, "claimed": [], "already": [], "blocked": [],
     "message": "当前账号暂无可领取的官方活动"},
    {"ok": True, "reward_credits": 100, "msg": "签到成功 +100 积分"},
)
res = T.run_checkin(acc, gap=0)
check("campaign ok but no eligible activity still calls legacy check-in",
      acc.legacy_calls == 1, acc.legacy_calls)
check("legacy reward is returned to scheduler",
      res.get("ok") and res.get("earned_credit") == 100, res)


print("[scheduler check-in] completed campaign does not duplicate legacy claim")
claimed = FakeAccount(
    "campaign-user",
    {"ok": True, "claimed": [{"campaign_key": "daily"}], "already": [],
     "blocked": [], "earned": 100, "message": "活动领取成功 +100 Credits"},
    {"ok": True, "reward_credits": 100},
)
claimed_res = T.run_checkin(claimed, gap=0)
check("campaign claim short-circuits legacy endpoint",
      claimed.legacy_calls == 0, claimed.legacy_calls)
check("campaign claim keeps earned credits",
      claimed_res.get("earned_credit") == 100, claimed_res)


print("[scheduler check-in] batch accounting separates outcomes")
batch = T.run_batch_checkin([
    FakeAccount("new", {"ok": True, "claimed": [{"campaign_key": "daily"}],
                        "already": [], "blocked": [], "earned": 100,
                        "message": "claimed"},
                {"ok": True, "reward_credits": 100}),
    FakeAccount("old", {"ok": True, "claimed": [], "already": [],
                        "blocked": [], "message": "none"},
                {"ok": True, "already": True, "msg": "今日已签到"}),
    FakeAccount("skip", {"ok": True, "claimed": [], "already": [],
                         "blocked": [], "message": "none"},
                {"ok": True, "unavailable": True, "msg": "not available"}),
    FakeAccount("fail", {"ok": False, "claimed": [], "already": [],
                         "blocked": [], "error": "network"},
                {"ok": False, "error": "still down"}),
], gap=0, inter_gap=0)
check("attempted count remains compatible",
      batch.get("accounts_count") == 4, batch)
check("new/already/unavailable/failed counts are accurate",
      (batch.get("succeeded_count"), batch.get("already_count"),
       batch.get("unavailable_count"), batch.get("failed_count")) == (1, 1, 1, 1),
      batch)
check("batch still returns an error when every account fails",
      T.run_batch_checkin([
          FakeAccount("fail-only", {"ok": False, "claimed": [], "already": [],
                                    "blocked": [], "error": "down"},
                      {"ok": False, "error": "down"})
      ], gap=0)["ok"] is False)


print("[scheduler check-in] tenant task loggers are thread-local")
root = tempfile.mkdtemp(prefix="qd-scheduler-log-")
try:
    pool = A.AccountPool(root)
    pool.accounts = []
    scheduler = S.Scheduler(pool, state_dir=root)
    scheduler.logs = []

    def fake_keepalive(pool_arg, force=False):
        return {"refreshed": 0, "failed": 0, "failed_uids": [], "logs": []}

    def fake_batch(targets, gap=1.0, inter_gap=1.0):
        T._log("tenant-detail")
        return {"logs": ["  ✓ tenant-detail"], "credit_added": 0,
                "accounts_count": 1, "succeeded_count": 1,
                "already_count": 0, "unavailable_count": 0, "failed_count": 0}

    fake = FakeAccount("tenant-user", {"ok": True, "claimed": [], "already": [],
                                       "blocked": [], "message": "none"},
                       {"ok": True, "reward_credits": 100})
    fake.can_checkin = lambda: True
    pool.accounts = [fake]
    old_keepalive, old_batch = S.run_keepalive, S.run_batch_checkin
    S.run_keepalive, S.run_batch_checkin = fake_keepalive, fake_batch
    try:
        scheduler._execute_cycle("test", S.CYCLE_MANUAL)
    finally:
        S.run_keepalive, S.run_batch_checkin = old_keepalive, old_batch
    check("scheduler persists indented batch details",
          any("tenant-detail" in line for line in scheduler.logs), scheduler.logs)
    check("scheduler labels attempts separately from successful claims",
          any("签到尝试 1 个" in line for line in scheduler.logs), scheduler.logs)
finally:
    shutil.rmtree(root, ignore_errors=True)

finish()
