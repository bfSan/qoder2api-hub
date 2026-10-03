"""Deterministic offline tests for the Qoder gateway.

No network: verifies the crypto primitives (AES FIPS vectors, RSA padding
structure, Qoder custom base64 round-trip), COSY signature layout, request
body construction, SSE envelope unwrapping, Responses-API custom-tool
translation, and check-in response normalization.

    python _test_qoder.py

外部 fixture（可选）：[4.5] 组的官方加解密 KAT 需要协议 fixture 目录
（内含 credential.json 与 model-cache.json）。目录按以下顺序自动探测：
    1) 环境变量 QD_TEST_FIXTURE_DIR
    2) <仓库>/testdata/protocol/1.1.34
    3) <仓库>/tests/fixtures/protocol/1.1.34
    4) <仓库>/../qoder-ref/cli2api/testdata/protocol/1.1.34
    5) %TEMP%/qoder-ref/cli2api/testdata/protocol/1.1.34
    6) ~/qoder-ref/cli2api/testdata/protocol/1.1.34
缺 fixture 时依赖它的 3 条断言打印 [SKIP]（不计失败），**绝不静默**：
[SKIP] 行、候选清单、末行汇总都会报出跳过数量。同组的 AES-256
密钥表 / 互逆 KAT 不依赖 fixture，永远执行。

退出码：0 = 无 FAIL（允许存在 SKIP）；1 = 存在 FAIL。
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("ACCOUNTS_DIR",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "_acc"))
os.environ.setdefault("USAGE_DIR",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "_use"))
# 离线测试不拉起客户端原生二进制（活动平台的机器身份桥）；测试里显式关闭
os.environ.setdefault("QD_NATIVE_IDENTITY", "0")

import qoder_proxy as P
import qoder_sign as S
import qoder_catalog as C
import qoder_accounts as A
import qoder_tasks as T

PASS = FAIL = SKIP = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def skip(label, reason=""):
    """显式跳过（缺外部 fixture / 缺环境），绝不静默。

    SKIP 不改变退出码（退出码只看 FAIL），但会打印醒目行并计入末行汇总，
    所以"这组没跑"永远可见；补齐 fixture 后必须重跑到它真的 PASS。
    """
    global SKIP
    SKIP += 1
    print("  [SKIP] " + label + (("  -- " + str(reason)) if reason else ""))


print("[1] Qoder custom base64 variant")
enc = S.qoder_encode(b"{}")
check("encode({}) deterministic", enc == S.qoder_encode(b"{}"))
check("decode(encode(x)) == x", S.qoder_decode(enc) == b"{}")
sample = json.dumps({"b": 1, "a": "中文测试", "c": [1, 2, 3]}).encode()
check("roundtrip with unicode/json", S.qoder_decode(S.qoder_encode(sample)) == sample)
check("output uses only custom alphabet",
      all(c in S.QODER_CUSTOM_ALPHABET or c == S.QODER_PAD for c in enc))
check("padding is $", S.qoder_encode(b"a" * 100).count("$") >= 0 and "=" not in enc)

print()
print("[2] AES-128 (FIPS-197 / NIST vectors)")
k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt = bytes.fromhex("00112233445566778899aabbccddeeff")
ct = S._encrypt_block(pt, S._expand_key(k)).hex()
check("FIPS-197 C.1 block", ct == "69c4e0d86a7b0430d8cdb78070b4c55a", ct)
k2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
pt2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
xored = bytes(a ^ b for a, b in zip(pt2, iv))
c2 = S._encrypt_block(xored, S._expand_key(k2)).hex()
check("SP800-38A CBC first block", c2 == "7649abac8119b246cee98e9b12e9197d", c2)
# CBC chaining through aes_cbc_encrypt (key==iv style input, PKCS7)
blob = S.aes_cbc_encrypt(b"hello qoder", b"0123456789abcdef", b"0123456789abcdef")
check("aes_cbc_encrypt block-aligned", len(blob) % 16 == 0 and len(blob) >= 16)
# 11 字节明文 -> PKCS7 补 5 -> 一个密文块
check("pkcs7 grows 11B input to one 16B block", len(blob) == 16, len(blob))
check("16B input grows to two blocks",
      len(S.aes_cbc_encrypt(b"0123456789abcdef", b"0123456789abcdef",
                             b"0123456789abcdef")) == 32)

print()
print("[3] RSA PKCS#1 v1.5 public encryption")
import base64 as _b64m
_der = _b64m.b64decode("".join(l for l in S.SERVER_PUB_PEM.splitlines()
                                if "BEGIN" not in l and "END" not in l))
check("PEM parses to 1024-bit modulus", S._RSA_N.bit_length() == 1024,
      S._RSA_N.bit_length())
check("DER carries 129-byte INTEGER", b"\x02\x81\x81" in _der)
check("exponent 65537", S._RSA_E == 65537)
ct_rsa = S.rsa_pkcs1v15_encrypt(b"0123456789abcdef")
check("ciphertext length = k = 128", len(ct_rsa) == 128, len(ct_rsa))
m_int = int.from_bytes(ct_rsa, "big")
check("ciphertext < n", m_int < S._RSA_N)
check("pkcs1v15 PS length formula",
      len(S.rsa_pkcs1v15_encrypt(b"x")) == 128)

print()
print("[4] COSY session & bearer signature")
sess = S.CosySession(uid="test-uid-001", nickname="tester",
                     access_token="dt-abc", refresh_token="drt-xyz")
url = "https://gateway.qoder.com.cn" + P.CHAT_PATH
body_enc = S.qoder_encode(b'{"x":1}')
h = sess.headers(body_enc, url, model_key="qmodel", sse=True)
check("has full cosy header set",
      all(kk in h for kk in ("authorization", "cosy-key", "cosy-user",
                             "cosy-machineid", "cosy-machinetoken",
                             "cosy-machinetype", "cosy-date", "cosy-version")))
check("x-model-key set", h.get("x-model-key") == "qmodel")
check("cache-control for sse", h.get("cache-control") == "no-cache")
check("bearer format COSY.payload.sig",
      h["authorization"].startswith("Bearer COSY.")
      and len(h["authorization"].split(".")) == 3)
parts = h["authorization"][len("Bearer "):].split(".")
payload_b64, sig = parts[1], parts[2]
path_stripped = "/api/v2/service/pro/sse/agent_chat_generation"
raw = payload_b64 + "\n" + sess.cosy_key + "\n" + h["cosy-date"] + "\n" \
    + body_enc + "\n" + path_stripped
check("md5 signature over body+path", sig == hashlib.md5(raw.encode()).hexdigest())
check("machine id stable per uid",
      S.CosySession(uid="test-uid-001").machine_id == sess.machine_id)
check("machine ids differ across uid",
      S.CosySession(uid="other-uid").machine_id != sess.machine_id)
import base64 as _b64
payload = json.loads(_b64.b64decode(payload_b64))
check("payload keys sorted-compact",
      sorted(payload.keys()) == ["cosyVersion", "ideVersion", "info",
                                 "requestId", "version"])
check("payload cosyVersion", payload["cosyVersion"] == S.COSY_VERSION)

print()
print("[5] model alias resolution (official keys)")
check("qwen3.8-max -> qmodel_38max",
      C.resolve_upstream_key("qwen3.8-max") == "qmodel_38max")
check("old key qmodel_preview -> qmodel_38max",
      C.resolve_upstream_key("qmodel_preview") == "qmodel_38max")
check("qwen3.8-flash -> qfmodel",
      C.resolve_upstream_key("qwen3.8-flash") == "qfmodel")
check("deepseek-v4-pro -> dmodel",
      C.resolve_upstream_key("deepseek-v4-pro") == "dmodel")
check("shared key passthrough",
      C.resolve_upstream_key("qmodel") == "qmodel")
check("aliased qoder/ prefix",
      C.resolve_upstream_key("qoder/qwen3.7-max") == "qmodel_latest")
check("unknown model passthrough",
      C.resolve_upstream_key("mystery-model") == "mystery-model")
check("empty -> auto", C.resolve_upstream_key("") == "auto")
check("realm-aware: official key of that realm accepted",
      C.resolve_upstream_key("q37fmodel", realm="cn") == "q37fmodel")

print()
print("[5.5] per-realm catalogs follow the official client (must DIFFER)")
intl_keys = [m["key"] for m in C.STATIC_INTL_MODELS]
cn_keys = [m["key"] for m in C.STATIC_CN_MODELS]
check("intl catalog not empty (>=17)", len(intl_keys) >= 17, len(intl_keys))
check("cn catalog not empty (14)", len(cn_keys) == 14, len(cn_keys))
check("two realms' catalogs differ", intl_keys != cn_keys)
check("intl-only: smodel present, absent from cn",
      "smodel" in intl_keys and "smodel" not in cn_keys)
check("cn-only: q37fmodel present, absent from intl",
      "q37fmodel" in cn_keys and "q37fmodel" not in intl_keys)
check("cn-only: gm51model present, absent from intl",
      "gm51model" in cn_keys and "gm51model" not in intl_keys)
intl_en = {m["key"] for m in C.STATIC_INTL_MODELS if m.get("enable")}
cn_en = {m["key"] for m in C.STATIC_CN_MODELS if m.get("enable")}
check("intl enabled flags = {qmodel_38max, qfmodel} (official plan state)",
      intl_en == {"qmodel_38max", "qfmodel"}, sorted(intl_en))
check("cn all 14 enabled", len(cn_en) == 14, sorted(cn_en))
# 全量列出（不按 enable 过滤）
merged_i = P.merge_catalog([], realm="intl")
merged_c = P.merge_catalog([], realm="cn")
check("merge keeps FULL intl list (17, no enable filtering)", len(merged_i) == 17,
      len(merged_i))
check("merge keeps FULL cn list (14)", len(merged_c) == 14, len(merged_c))
# 清单以官方动态/本机目录为准（桌面版此刻显示什么就显示什么）
dyn_keys = [("cmodel", {"key": "cmodel", "display_name": "Cantus"})]  # 反例占位
primary15 = [(m["key"], dict(m)) for m in C.STATIC_INTL_MODELS
             if m["key"] not in ("cmodel", "smodel")]   # 模拟动态返回的 15 条
merged_dyn = P.merge_catalog(primary15, realm="intl")
check("merge follows primary set (dynamic 15 wins, static-only excluded)",
      len(merged_dyn) == 15 and
      {k for k, _ in merged_dyn} == {m["key"] for m in C.STATIC_INTL_MODELS}
      - {"cmodel", "smodel"}, len(merged_dyn))

print()
print("[5.7] official full-fidelity fields: display id / pricing / windows / efforts")
entry_i = next(m for m in C.STATIC_INTL_MODELS if m["key"] == "smodel")
check("intl exclusive entry retains full fields",
      {"context_config", "thinking_config", "is_free", "is_new"} <= set(entry_i.keys()),
      sorted(entry_i.keys()))
cn38 = next(m for m in C.STATIC_CN_MODELS if m["key"] == "qmodel_38max")
promo = cn38.get("promotion") or {}
# 注意：promo.active / price_factor 是**快照抓取时刻**的官方值（低谷时段抓的
# 快照 active=True 且 price=峰价×折扣；高峰时段抓的 active=False 且 price=峰价）。
# 断言官方不变量，而不是断言"抓取时正好在打折"，否则测试随抓取时刻漂移。
check("cn qmodel_38max carries off-peak promotion metadata",
      bool(promo) and promo.get("rule_id") == "idle_time_model_credit_discount"
      and isinstance(promo.get("active"), bool), promo.get("rule_id"))
check("off-peak window = 22:00-08:00",
      promo.get("window_start") == "22:00" and promo.get("window_end") == "08:00")
check("peak factor (before_promotion) = 0.5", promo.get("before_promotion_price_factor") == 0.5,
      promo.get("before_promotion_price_factor"))
check("current price_factor is peak or valley (0.5 / 0.2)",
      cn38.get("price_factor") in (0.5, 0.2), cn38.get("price_factor"))
check("price_factor matches promo.active (peak when inactive)",
      (cn38.get("price_factor") == 0.2) is bool(promo.get("active")),
      (cn38.get("price_factor"), promo.get("active")))
check("discount_factor = 0.4 (4折)", promo.get("discount_factor") == 0.4)
check("promotion badge/description localized",
      bool((promo.get("badge") or {}).get("en")) and bool((promo.get("description") or {}).get("en")))
qf = next(m for m in C.STATIC_CN_MODELS if m["key"] == "qfmodel")
check("qfmodel free + original factor kept",
      qf.get("is_free") is True and qf.get("original_price_factor") == 0.1)
check("context_config multi-window (3) with default 200K",
      len(cn38.get("context_config") or {}) == 3
      and (cn38["context_config"].get("200K") or {}).get("is_default") is True)
tc = (cn38.get("thinking_config") or {}).get("enabled") or {}
effs = tc.get("efforts") or {}
check("thinking efforts low/medium/xhigh with default medium",
      set(effs) == {"low", "medium", "xhigh"}
      and (effs.get("medium") or {}).get("is_default") is True, sorted(effs))

# 展示 id 与解析
check("display id format key (Name)",
      C.display_id(cn38) == "qmodel_38max (Qwen3.8-Max)", C.display_id(cn38))
check("resolve display id -> key",
      C.resolve_upstream_key("qmodel_38max (Qwen3.8-Max)", realm="cn") == "qmodel_38max")
check("resolve official display name (case-insensitive)",
      C.resolve_upstream_key("qwen3.8-max", realm="cn") == "qmodel_38max"
      and C.resolve_upstream_key("GLM-5.2", realm="cn") == "gm51model")
check("resolve bare display name DeepSeek-V4-Pro",
      C.resolve_upstream_key("DeepSeek-V4-Pro", realm="cn") == "dmodel")
check("format_model_id helper",
      C.format_model_id("gm51model", realm="cn") == "gm51model (GLM-5.2)",
      C.format_model_id("gm51model", realm="cn"))

# model_entry 输出
me = P.model_entry("qmodel_38max", cn38)
check("model_entry id = OFFICIAL model name (the value clients fill in)",
      me["id"] == "Qwen3.8-Max", me["id"])
check("model_entry upstream_key kept", me["upstream_key"] == "qmodel_38max")
check("model_entry aliases cover key + bracket form + friendly alias",
      "qmodel_38max" in me["aliases"] and "qmodel_38max (Qwen3.8-Max)" in me["aliases"]
      and "qwen3.8-max" in me["aliases"], me.get("aliases"))
check("model_entry description = official desktop copy",
      "千问" in (me.get("description") or ""), (me.get("description") or "")[:60])
check("model_entry enabled flag", me["enabled"] is True)
check("model_entry peak/valley factors",
      me["price_factor_peak"] == 0.5 and me["price_factor_valley"] == 0.2)
check("model_entry off_peak window+badge",
      me["off_peak_window"] == "22:00-08:00" and bool(me["off_peak"]["badge"]))
check("model_entry context labels default 200K",
      me["context_window_labels"] == ["200K", "400K", "1M"] or set(me["context_window_labels"]) == {"200K", "400K", "1M"},
      me.get("context_window_labels"))
check("model_entry context_window_default", me.get("context_window_default") == "200K")
check("model_entry reasoning efforts + default",
      me.get("reasoning_efforts") == ["low", "medium", "xhigh"]
      and me.get("reasoning_default_effort") == "medium",
      (me.get("reasoning_efforts"), me.get("reasoning_default_effort")))
check("model_entry can_disable", me.get("reasoning_can_disable") is True)
check("model_entry is_free/is_new", me.get("is_free") is True and me.get("is_new") is True)
check("model_entry does NOT fabricate max_output_tokens (official data has none)",
      "max_output_tokens" not in me and "max_completion_tokens" not in me,
      sorted(k for k in me if "output" in k))
me_off = P.model_entry("smodel", entry_i)
check("model_entry disabled shows enabled=false (badge, not filtered)",
      me_off["enabled"] is False)
check("model_entry disabled_reason = OFFICIAL copy (not '未开放')",
      me_off.get("disabled_reason") == "需要升级或购买千问官方套餐开放",
      me_off.get("disabled_reason"))
check("model_entry disabled_message_key passthrough (codeSafeModelReason)",
      me_off.get("disabled_message_key") == "codeSafeModelReason",
      me_off.get("disabled_message_key"))
check("official text loader: 17 zh descriptions",
      len(C.load_official_text()["descriptions"]) == 17)
check("official local name ultimate -> zh",
      C.official_local_name("ultimate") != "" and C.official_local_name("ultimate") != "Ultimate",
      C.official_local_name("ultimate"))
me_u = P.model_entry("ultimate", next(m for m in C.STATIC_INTL_MODELS if m["key"] == "ultimate"))
check("model_entry name_local emitted for intl mode preset",
      bool(me_u.get("name_local")), me_u.get("name_local"))
check("resolve official local label (Kimi-K2.7-Code)",
      C.resolve_upstream_key("Kimi-K2.7-Code", realm="intl") == "kmodel")
check("cross-region guard accepts display id form",
      P.exclusive_realm("gm51model (GLM-5.2)") == "cn")

print()
print("[5.8] off-peak (低谷) window detection — cross-midnight 22:00-08:00 UTC+8")
import datetime as _dt
def _ts(h, m):
    # 构造 UTC+8 指定时刻对应的 epoch（固定 +8 与官方时区一致）
    utc_naive = _dt.datetime.utcnow() if False else None
    base = _dt.datetime.now(_dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    target_local_naive = _dt.datetime.now().replace(hour=h, minute=m, second=0, microsecond=0)
    return target_local_naive.timestamp() - (_dt.datetime.now().astimezone().utcoffset().total_seconds()
                                             - 8 * 3600)
for hh, mm, expect, label in [
        (1, 0, True, "01:00 inside window"),
        (12, 0, False, "12:00 outside"),
        (21, 59, False, "21:59 before window"),
        (22, 0, True, "22:00 window start (inclusive)"),
        (23, 30, True, "23:30 inside"),
        (7, 59, True, "07:59 last minute inside"),
        (8, 0, False, "08:00 window end (exclusive)")]:
    got = P.off_peak_active_now("22:00", "08:00", tz="Asia/Shanghai",
                                now=_ts(hh, mm))
    check(f"window {label}", got is expect, f"got={got} expect={expect}")
check("invalid window -> None",
      P.off_peak_active_now(None, "08:00") is None)
check("same start/end -> always active",
      P.off_peak_active_now("00:00", "00:00", now=_ts(13, 0)) is True)
# promotion fields surface off_peak_active_now via model_entry
me_promo = P.model_entry("qmodel_38max", cn38)
check("model_entry exposes off_peak_active_now (bool)",
      isinstance(me_promo.get("off_peak_active_now"), bool),
      me_promo.get("off_peak_active_now"))

# None must not clobber static snapshot values in merge
dyn_null = [("qmodel_38max", {"key": "qmodel_38max",
                               "context_config": None,
                               "thinking_config": None,
                               "price_factor": 0.2})]
merged_null = dict(P.merge_catalog(dyn_null, realm="cn"))["qmodel_38max"]
check("merge: dynamic None does NOT clobber static context_config",
      isinstance(merged_null.get("context_config"), dict)
      and "200K" in (merged_null.get("context_config") or {}),
      type(merged_null.get("context_config")).__name__)
check("merge: dynamic None does NOT clobber static thinking_config",
      isinstance(merged_null.get("thinking_config"), dict))
check("merge: dynamic real value still overrides",
      merged_null.get("price_factor") == 0.2)

print()
print("[5.9] ALL off-peak (低谷) promotion models — must be complete, not just one")
PROMO_KEYS = {"qmodel_38max", "qmodel_latest", "qmodel"}
for realm_name in ("cn", "intl"):
    # 促销集合按"是否带官方 promotion 元数据"判定；promo.active 是快照抓取
    # 时刻是否处于低谷时段（22:00-08:00），不该作为集合成员条件。
    promo_models = {m["key"] for m in C.models_for_realm(realm_name)
                    if m.get("promotion")}
    check(f"[{realm_name}] official promo set == the 3 off-peak models",
          promo_models == PROMO_KEYS, sorted(promo_models))
    # 每个促销模型都要产出完整 off_peak 输出（不止一个）
    for k in sorted(PROMO_KEYS):
        src = next(m for m in C.models_for_realm(realm_name) if m["key"] == k)
        e = P.model_entry(k, src)
        check(f"[{realm_name}] {k} entry carries off_peak window+badge",
              bool(e.get("off_peak")) and e.get("off_peak_window") == "22:00-08:00"
              and bool(e.get("off_peak", {}).get("badge")),
              e.get("off_peak_window"))
        check(f"[{realm_name}] {k} entry has off_peak_active_now bool",
              isinstance(e.get("off_peak_active_now"), bool))
        check(f"[{realm_name}] {k} entry exposes peak/valley pair",
              e.get("price_factor_peak") is not None
              and e.get("price_factor_valley") is not None,
              (e.get("price_factor_peak"), e.get("price_factor_valley")))
# Qwen3.8-Max: is_free=true 绝不能吞掉它的 promotion（看板曾把它渲染成
# 0.00x 免费并吃掉低谷高亮）
me_freeflag = P.model_entry("qmodel_38max",
                            next(m for m in C.STATIC_CN_MODELS
                                 if m["key"] == "qmodel_38max"))
check("qmodel_38max is_free=true still carries promotion (peak 0.5 / valley 0.2)",
      me_freeflag.get("is_free") is True and me_freeflag.get("price_factor_peak") == 0.5
      and me_freeflag.get("price_factor_valley") == 0.2,
      (me_freeflag.get("is_free"), me_freeflag.get("price_factor_peak"),
       me_freeflag.get("price_factor_valley")))

# 看板分支顺序回归：promo 分支必须在 0 价分支之前
_dash = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "dashboard.html"), encoding="utf-8").read()
_i_promo = _dash.find("if(promo && valley != null)")
_i_free = _dash.find("valley === 0")
check("dashboard: promotion branch BEFORE free branch (highlight no longer swallowed)",
      0 <= _i_promo < _i_free, {"promo": _i_promo, "free": _i_free})
check("dashboard: is_free no longer triggers the 0.00x branch",
      "m.is_free || valley === 0" not in _dash)

print()
print("[11] transient upstream errors (418/provider_error) — retry not punish")
import time as _time_for_11
time = _time_for_11   # 本块直接使用 time.time()/sleep
# 分类判定
check("418 + provider_error is transient",
      P._is_transient_upstream(418, '{"code":"provider_error","message":"Error in upstream response"}'))
check("503 is transient", P._is_transient_upstream(503, ""))
check("client param error (invalid_parameter) NEVER transient",
      not P._is_transient_upstream(400,
          '{"code":"provider_error","details":"data: {\\"error\\":{\\"code\\":'
          '\\"invalid_parameter_error\\",\\"message\\":\\"Range of max_tokens should be [1, 131072]\\"}"'))
check("plain 400 without provider_error not transient",
      not P._is_transient_upstream(400, '{"code":"bad_request"}'))
check("401 never transient", not P._is_transient_upstream(401, "provider_error"))

# 行为级：第一次 418(瞬时) → 重试后成功，账号不背锅
import urllib.error as _ue3, io as _io3
_orig_urlopen = P.urllib.request.urlopen
_calls = {"n": 0}

class _FakeResp(object):
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *a): return b"{}"

def _urlopen_fail_once(req, timeout=None):
    _calls["n"] += 1
    if _calls["n"] == 1:
        raise _ue3.HTTPError(req.full_url, 418, "teapot", {},
                             _io3.BytesIO(b'{"code":"provider_error","message":"Error in upstream response"}'))
    return _FakeResp()

try:
    P.urllib.request.urlopen = _urlopen_fail_once
    # 构造单账号池
    import tempfile as _tf
    _td = _tf.mkdtemp(prefix="qdpool_")
    _pool = A.AccountPool(_td)
    _pool.add(A.Account({"uid": "retry-test-uid", "realm": "cn",
                         "accessToken": "dt-test", "refreshToken": "drt-test",
                         "expiresAt": 9999999999}))
    _orig_pool = P.POOL
    P.POOL = _pool
    _acc = _pool.accounts[0]
    _acc.cooldown_until = 0
    t0 = time.time()
    resp, used, _ = P.open_upstream(
        {"model": "qfmodel", "messages": [{"role": "user", "content": "hi"}],
         "stream": False}, target_realm="cn")
    took = time.time() - t0
    check("418-then-success: open_upstream returns after in-place retry",
          resp is not None and _calls["n"] == 2,
          {"calls": _calls["n"]})
    check("418-then-success: account NOT cooled down",
          _acc.cooldown_until <= time.time(),
          round(_acc.cooldown_until - time.time(), 1))
    check("418-then-success: backoff took ~1s (not instant, not 60s)",
          0.8 <= took <= 4.0, round(took, 2))
finally:
    P.urllib.request.urlopen = _orig_urlopen

# 行为级：持续 418 → 重试耗尽后短冷却（单账号 3s 而非 60s）并抛出原错误
def _urlopen_always_418(req, timeout=None):
    _calls["n"] += 1
    raise _ue3.HTTPError(req.full_url, 418, "teapot", {},
                         _io3.BytesIO(b'{"code":"provider_error","message":"Error in upstream response"}'))

_calls["n"] = 0
try:
    P.urllib.request.urlopen = _urlopen_always_418
    P.POOL = _pool          # 上一块 finally 还原了 None，这里重新挂上临时池
    _acc.cooldown_until = 0
    _acc.last_error = ""
    raised = None
    t0 = time.time()
    try:
        P.open_upstream({"model": "qfmodel",
                         "messages": [{"role": "user", "content": "hi"}],
                         "stream": False}, target_realm="cn")
    except _ue3.HTTPError as e:
        raised = e
    took = time.time() - t0
    check("persistent 418: raised after exactly 3 tries",
          raised is not None and raised.code == 418 and _calls["n"] == 3,
          {"calls": _calls["n"], "code": getattr(raised, "code", None)})
    check("persistent 418: short cooldown (<=5s, single-account pool)",
          0 < (_acc.cooldown_until - time.time()) <= 5.5,
          round(_acc.cooldown_until - time.time(), 2))
    check("persistent 418: bounded backoff time (~3s)",
          2.0 <= took <= 6.0, round(took, 2))
finally:
    P.urllib.request.urlopen = _orig_urlopen
    P.POOL = _orig_pool
    import shutil as _sh
    _sh.rmtree(_td, ignore_errors=True)

# 传输层瞬时故障分类（TLS EOF 等）
import urllib.error as _ue4
import ssl as _ssl_for_11
check("URLError wrapping SSL EOF is transient transport",
      P._is_transient_transport(_ue4.URLError(_ssl_for_11.SSLError(
          "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF"))))
check("ConnectionResetError is transient transport",
      P._is_transient_transport(ConnectionResetError("reset")))
check("plain ValueError NOT transient transport",
      not P._is_transient_transport(ValueError("nope")))
check("predicate: URLError+provider401 not transient-http",
      not P._is_transient_upstream(401, "x"))

# 友好错误映射
_m, _t = P.friendly_upstream_error(418,
    '{"code":"provider_error","message":"Error in upstream response"}')
check("friendly: 418 provider_error -> Chinese retry guidance",
      "上游瞬时故障" in _m and "请稍后重试" in _m, _m[:60])
check("friendly: err_type tagged transient",
      _t == "upstream_transient_error", _t)
_m2, _t2 = P.friendly_upstream_error(400,
    '{"code":"provider_error","details":"invalid_parameter_error Range"}')
check("friendly: client param error NOT reframed as transient",
      _t2 == "upstream_error" and "上游瞬时故障" not in _m2, (_t2, _m2[:50]))
check("friendly: detail preserved in message",
      "provider_error" in _m)

# qoder_detail passthrough（错误体只读一次的修复）——挂在持续418的断言上补充
check("raised HTTPError carries qoder_detail for handlers",
      hasattr(raised, "qoder_detail") and "provider_error" in raised.qoder_detail,
      getattr(raised, "qoder_detail", "")[:60])

print()
print("[12] in-stream envelope retry (200-then-418 form — the reported log shape)")
# 状态归一化
check("_to_int_status str/int/fallback", P._to_int_status("418") == 418
      and P._to_int_status(503) == 503 and P._to_int_status("xx") == 502)

_env418 = P.UpstreamStatus(
    418, '{"code":"provider_error","message":"Error in upstream response"}')
check("fresh envelope 418 transient -> retry",
      P.should_retry_envelope(_env418, emitted_bytes=False, attempt=0))
check("already emitted bytes -> NO retry",
      not P.should_retry_envelope(_env418, emitted_bytes=True, attempt=0))
check("budget exhausted -> NO retry",
      not P.should_retry_envelope(_env418, False, P.TRANSIENT_MAX_RETRIES))
_env_param = P.UpstreamStatus(400, "invalid_parameter_error Range of max_tokens")
check("client param envelope -> NO retry",
      not P.should_retry_envelope(_env_param, False, 0))

# aggregate_with_envelope_retry: 第一次信封418 → 重开上游 → 成功
_sleeps = []
_orig_sleep2 = P.time.sleep
_orig_open2 = P.open_upstream
_pools = {"calls": 0}

class _GoodResp(object):
    def __iter__(self):
        inner = json.dumps({"choices": [{"delta": {"content": "recovered"}}]})
        yield ("data: " + json.dumps({"statusCodeValue": 200, "body": inner})
               + "\n\n").encode("utf-8")
        yield b'data: {"statusCodeValue":200,"body":"[DONE]"}\n\n'

    def close(self):
        pass


class _ErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 418,
            "body": '{"code":"provider_error","message":"Error in upstream response"}'})
            + "\n\n").encode("utf-8")

    def close(self):
        pass


def _fake_open(payload, session_key=None, target_realm=None):
    _pools["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


class _A(object):
    uid = "acct-1"


try:
    P.time.sleep = lambda s: _sleeps.append(s)
    P.open_upstream = _fake_open
    obj, acc = P.aggregate_with_envelope_retry(
        _ErrResp(), {"model": "qfmodel"}, None, "cn", "qfmodel",
        {"usage": None}, _A())
    check("envelope 418 -> reopened upstream and recovered",
          obj["choices"][0]["message"]["content"] == "recovered",
          obj["choices"][0]["message"].get("content"))
    check("reopen happened exactly once", _pools["calls"] == 1, _pools["calls"])
    check("backoff 1s recorded", _sleeps == [1], _sleeps)
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

# 非瞬时信封（客户端参数错）不重开、原样上抛
_sleeps2 = []
_pools2 = {"calls": 0}

print()
print("[13] content-policy rejection (DataInspectionFailed — 02:27 log root cause)")
_DI_DETAIL = ('{"error":{"message":"\\u003c400\\u003e InternalError.Algo.'
              'DataInspectionFailed: Input text data may contain inappropriate '
              'content.","type":"UnknownError"}}')
check("DataInspection detail -> NOT transient (no wasted retries)",
      not P._is_transient_upstream(418, _DI_DETAIL))
check("DataInspection envelope -> should_retry_envelope False",
      not P.should_retry_envelope(
          P.UpstreamStatus(418, _DI_DETAIL), emitted_bytes=False, attempt=0))
_m13, _t13 = P.friendly_upstream_error(418, _DI_DETAIL)
check("friendly: content-policy Chinese explanation",
      "内容安全审核未通过" in _m13 and "重试无效" in _m13, _m13[:70])
check("friendly: err_type content_policy_rejected",
      _t13 == "content_policy_rejected", _t13)
check("friendly: original detail preserved",
      "DataInspectionFailed" in _m13)

print()
print("[14] error-cooldown vs upstream-frequency (no misleading 429)")
import time as _t14
# 构造临时池：账号仅处于错误冷却
_td14 = __import__("tempfile").mkdtemp(prefix="qd14_")
_pool14 = A.AccountPool(_td14)
_acc14 = A.Account({"uid": "u14", "realm": "cn", "accessToken": "dt-x",
                    "refreshToken": "drt-x", "expiresAt": 9999999999})
_pool14.add(_acc14)
_orig_pool14 = P.POOL
P.POOL = _pool14
try:
    # (a) 仅账号错误冷却 -> 不算频控
    _acc14.cooldown_until = _t14.time() + 5
    _acc14.model_cooldowns.clear()
    throttled, w = P.realm_model_throttled("cn", "qfmodel")
    check("account error-cooldown is NOT a frequency-limit (no 429)",
          throttled is False, (throttled, w))
    check("retry_after_seconds ignores account cooldown",
          P.retry_after_seconds("qfmodel", "cn") == 60,
          P.retry_after_seconds("qfmodel", "cn"))
    wait = P._short_error_cooldown_wait("cn", "qfmodel")
    check("short error-cooldown wait surfaced (<=10s, >0)",
          0 < wait <= 10, wait)
    # (b) 上游频控 -> 正当429
    _acc14.cooldown_until = 0
    _acc14.model_cooldowns["qfmodel"] = _t14.time() + 60
    throttled2, w2 = P.realm_model_throttled("cn", "qfmodel")
    check("model_cooldowns (upstream 429) IS frequency-limit",
          throttled2 is True and w2 >= 59, (throttled2, w2))
    check("short wait suppressed while frequency-limited",
          P._short_error_cooldown_wait("cn", "qfmodel") == 0.0)
    check("retry_after reflects frequency wait",
          59 <= P.retry_after_seconds("qfmodel", "cn") <= 61,
          P.retry_after_seconds("qfmodel", "cn"))
    # (c) 行为：错误短冷却 -> 等待后续上（真实 sleep ~0.3s）而不是429
    _acc14.model_cooldowns.clear()
    _acc14.cooldown_until = _t14.time() + 0.3
    _orig_urlopen14 = P.urllib.request.urlopen

    class _R14(object):
        def __iter__(self):
            inner = json.dumps({"choices": [{"delta": {"content": "after-wait"}}]})
            yield ("data: " + json.dumps({"statusCodeValue": 200, "body": inner})
                   + "\n\n").encode()
            yield b'data: {"statusCodeValue":200,"body":"[DONE]"}\n\n'
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def _ok_urlopen(req, timeout=None):
        return _R14()

    try:
        P.urllib.request.urlopen = _ok_urlopen
        _sleep_used = []
        _t0 = _t14.time()
        try:
            resp, used, _ = P.open_upstream(
                {"model": "qfmodel",
                 "messages": [{"role": "user", "content": "hi"}],
                 "stream": False}, target_realm="cn")
            _served = True
            _rate = None
        except Exception as _e:
            _served = False
            _rate = _e
        took = _t14.time() - _t0
        check("short cooldown: request WAITS and serves (no 429/503)",
              _served and _rate is None,
              {"served": _served, "err": repr(_rate)})
        check("wait lasted ~0.3-1s (bounded)", 0.25 <= took <= 2.0,
              round(took, 2))
    finally:
        P.urllib.request.urlopen = _orig_urlopen14
    # (d) 频控行为不变：真429 仍然立刻 RateLimited
    _acc14.cooldown_until = 0
    _acc14.model_cooldowns["qfmodel"] = _t14.time() + 60
    try:
        P.urllib.request.urlopen = _ok_urlopen
        _raised14 = None
        try:
            P.open_upstream({"model": "qfmodel",
                             "messages": [{"role": "user", "content": "hi"}],
                             "stream": False}, target_realm="cn")
        except Exception as e14:
            _raised14 = e14
        check("genuine frequency limit still raises RateLimited fast",
              isinstance(_raised14, P.RateLimited)
              and "frequency" in str(getattr(_raised14, "detail", "")),
              repr(_raised14))
    finally:
        P.urllib.request.urlopen = _orig_urlopen14
finally:
    P.POOL = _orig_pool14
    _acc14.model_cooldowns.clear()
    _acc14.cooldown_until = 0
    import shutil as _sh14
    _sh14.rmtree(_td14, ignore_errors=True)

# favicon 404 静默
check("log_message silences favicon regardless of status (code present)",
      'req_path == "/favicon.ico"' in open(
          os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "qoder_proxy.py"), encoding="utf-8").read())

print()
print("[15] HTTP/1.1 SSE framing — keep-alive friendly (no more reconnect loop)")
_src15 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()
check("handler defines chunked SSE helpers",
      all(k in _src15 for k in ("def _sse_begin", "def _sse_write",
                                "def _sse_end")))
check("_sse_begin sends Transfer-Encoding: chunked",
      'self.send_header("Transfer-Encoding", "chunked")' in _src15)
check("_sse_end writes terminating zero chunk",
      'b"0\\r\\n\\r\\n"' in _src15)
check("no 'Connection: close' on streaming responses (root cause of reconnect loop)",
      'self.send_header("Connection", "close")' not in _src15)
check("streaming writes go through _sse_write (chunk-encoded)",
      "self.wfile.write(line)" not in _src15
      and "self.wfile.write(clean_responses_frame(frame))" not in _src15)
check("chunked streams are terminated on every exit path",
      _src15.count("self._sse_end()") >= 4, _src15.count("self._sse_end()"))

print()
print("[16] liveness probe endpoints (GET /ping was 404 -> clients reconnect loop)")
check("/ping served without auth/panel",
      'if path in ("/ping", "/healthz", "/livez", "/readyz"):' in _src15)
check("/ping returns plain pong", 'body = b"pong\\n"' in _src15)
check("/ping sits before the /health handler (earliest match)",
      _src15.find('if path in ("/ping"') < _src15.find('if path == "/health":'))

print()
print("[17] SSE heartbeat during long upstream silence (TTFT up to 71s observed)")
check("sse_with_heartbeat helper exists",
      "def sse_with_heartbeat(" in _src15)
check("heartbeat emits SSE comment frames (': ping')",
      'b": ping\\n\\n"' in _src15)
check("heartbeat enabled by default with env override",
      'os.environ.get("QD_SSE_HEARTBEAT"' in _src15)
check("both streaming paths wrap their source with heartbeat",
      _src15.count("sse_with_heartbeat(") >= 3,
      _src15.count("sse_with_heartbeat("))

# 行为级：数据透传 / 空闲补心跳 / 上游异常原样抛出 / 可关闭
_sent2, _slow = [], []


def _slow_gen():
    time.sleep(0.4)                     # 模拟长首字延迟（上游静默）
    yield b"data: late\n\n"
    time.sleep(0.4)                     # 模拟帧间静默
    yield b"data: late2\n\n"


for item in P.sse_with_heartbeat(_slow_gen(), _sent2.append, interval=0.15,
                                 idle_limit=10):
    _slow.append(item)
check("heartbeat: data passes through unchanged",
      _slow == [b"data: late\n\n", b"data: late2\n\n"], _slow)
check("heartbeat: comment frames sent during both silences",
      len(_sent2) >= 2 and all(f == b": ping\n\n" for f in _sent2),
      (len(_sent2), _sent2))


class _BoomErr(RuntimeError):
    pass


def _boom_gen():
    yield b"data: first\n\n"
    raise _BoomErr("upstream died")


_sent3, _got3, _raised3 = [], [], None
try:
    for item in P.sse_with_heartbeat(_boom_gen(), _sent3.append, interval=0.15,
                                     idle_limit=5):
        _got3.append(item)
except Exception as exc:
    _raised3 = exc
check("heartbeat: upstream error propagates unchanged",
      isinstance(_raised3, _BoomErr) and _got3 == [b"data: first\n\n"],
      (type(_raised3).__name__, _got3))


def _one_gen():
    yield b"data: only\n\n"


_sent4, _got4 = [], []
for item in P.sse_with_heartbeat(_one_gen(), _sent4.append, interval=0,
                                 idle_limit=5):
    _got4.append(item)
check("heartbeat: interval=0 disables (pure pass-through)",
      _got4 == [b"data: only\n\n"] and _sent4 == [], (_got4, _sent4))

# 行为：内容审核信封 -> 一次都不重开（open_upstream 不被再次调用）并上抛
class _DiErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 418, "body": _DI_DETAIL}) + "\n\n").encode()

    def close(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


_pools13 = {"calls": 0}
_sleeps13 = []


def _fake_open_never13(payload, session_key=None, target_realm=None):
    _pools13["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


try:
    P.time.sleep = lambda s: _sleeps13.append(s)
    P.open_upstream = _fake_open_never13
    _raised13 = None
    try:
        P.aggregate_with_envelope_retry(
            _DiErrResp(), {"model": "Qwen3.8-Flash"}, None, "cn",
            "Qwen3.8-Flash", {"usage": None}, _A())
    except P.UpstreamStatus as e13:
        _raised13 = e13
    check("content-policy envelope: raised immediately, ZERO reopen, ZERO sleep",
          _raised13 is not None and _pools13["calls"] == 0 and not _sleeps13,
          {"raised": _raised13 is not None, "reopen": _pools13["calls"],
           "sleeps": _sleeps13})
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

# 非瞬时信封（客户端参数错）不重开、原样上抛
_sleeps2 = []
_pools2 = {"calls": 0}

class _ParamErrResp(object):
    def __iter__(self):
        yield ("data: " + json.dumps({
            "statusCodeValue": 400,
            "body": "invalid_parameter_error Range of max_tokens [1, 131072]"})
            + "\n\n").encode("utf-8")

    def close(self):
        pass


def _fake_open_never(payload, session_key=None, target_realm=None):
    _pools2["calls"] += 1
    return _GoodResp(), "acct-1", "enc"


try:
    P.time.sleep = lambda s: _sleeps2.append(s)
    P.open_upstream = _fake_open_never
    _raised_env = None
    try:
        P.aggregate_with_envelope_retry(
            _ParamErrResp(), {"model": "qfmodel"}, None, "cn", "qfmodel",
            {"usage": None}, _A())
    except P.UpstreamStatus as e0:
        _raised_env = e0
    check("param envelope raises immediately (no reopen)",
          _raised_env is not None and _pools2["calls"] == 0,
          {"raised": _raised_env is not None, "reopen": _pools2["calls"]})
finally:
    P.time.sleep = _orig_sleep2
    P.open_upstream = _orig_open2

ctx = {m["key"]: m.get("max_input_tokens") for m in C.STATIC_CN_MODELS}
check("cn dmodel ctx = official 96000 (NOT a guess)", ctx.get("dmodel") == 96000,
      ctx.get("dmodel"))
ctx_i = {m["key"]: m.get("max_input_tokens") for m in C.STATIC_INTL_MODELS}
check("intl dmodel ctx = official 1000000", ctx_i.get("dmodel") == 1000000,
      ctx_i.get("dmodel"))
pf = {m["key"]: m.get("price_factor") for m in C.STATIC_CN_MODELS}
check("price_factor carried from official catalog",
      pf.get("qfmodel") == 0.0 and pf.get("dmodel") == 0.5, pf.get("dmodel"))
check("exclusive sets derived from catalogs",
      "gm51model" in C.CN_EXCLUSIVE and "smodel" in C.INTL_EXCLUSIVE)
check("exclusive realm detection: gm51model -> cn",
      P.exclusive_realm("gm51model") == "cn")
check("exclusive realm detection: smodel -> intl",
      P.exclusive_realm("smodel") == "intl")
check("alias resolves before exclusive check: glm-5.2 -> cn",
      P.exclusive_realm("glm-5.2") == "cn")
check("shared key has no exclusive owner", P.exclusive_realm("qmodel") == "")
check("detect_model_realm routes cn-exclusive to cn even under intl default",
      P.detect_model_realm("q37fmodel") == "cn")
check("detect_model_realm routes intl-exclusive to intl",
      P.detect_model_realm("performance") == "intl")
check("shared model follows current default realm",
      P.detect_model_realm("qmodel") == P.CURRENT_REALM)

print()
print("[5.6] check-in capability is probed at runtime (not hard-coded per realm)")
import qoder_accounts as _A
import urllib.error as _ue2, io as _io2
check("cn has_checkin hint True", _A.get_realm_config("cn")["has_checkin"] is True)
check("intl has_checkin hint False (still only a hint)",
      _A.get_realm_config("intl")["has_checkin"] is False)
acc_intl = _A.Account({"uid": "i1", "realm": "intl", "accessToken": "dt-x"})
acc_cn = _A.Account({"uid": "c1", "realm": "cn", "accessToken": "dt-y"})
# 未探测前不按区域拒绝：国际版同样会真的去尝试一次（实测国际版接口 404，
# 由探测结果决定后续跳过，而不是"看区域直接不做"）
check("intl account is attempted before probing (realm is not a gate)",
      acc_intl.can_checkin() is True and acc_intl.checkin_capability()[0] is None)
check("cn account can checkin", acc_cn.can_checkin() is True)

# 国际版形态：/daily-check-in/* 404 -> 能力记录为不可用 + 明确原因（不是静默）
def fake_status_404(url, **kw):
    raise _ue2.HTTPError(url, 404, "nf", {}, _io2.BytesIO(b'{"errorCode":"NotFound"}'))
_orig_hj = _A.http_json
_A.http_json = fake_status_404
res_intl = acc_intl.checkin()
cap_intl, reason_intl = acc_intl.checkin_capability()
_A.http_json = _orig_hj
check("404 status -> (ok, unavailable) with explicit reason",
      res_intl.get("ok") is True and res_intl.get("unavailable") is True
      and res_intl.get("reason") == _A.CHECKIN_REASON_NOT_FOUND, res_intl)
check("404 message names the missing endpoint + hand-off to official client",
      "daily-check-in" in str(res_intl.get("msg"))
      and "客户端" in str(res_intl.get("msg")), res_intl.get("msg"))
check("capability cached as unavailable -> can_checkin False (no repeated 404s)",
      cap_intl is False and acc_intl.can_checkin() is False and "404" in reason_intl)
# TTL 到期后回到"未探测"，下一次调用会真的重探（活动上线即自动恢复）
acc_intl._checkin_cap_at -= (_A.CHECKIN_PROBE_TTL + 1)
check("TTL 过期 -> capability 回到 unknown，下一次触发重探",
      acc_intl.checkin_capability()[0] is None and acc_intl.can_checkin() is True)

# 官方活动停用 (DISABLED) -> 不 claim、按跳过成功处理
def fake_status_disabled(url, **kw):
    return {"campaignKey": "cn_daily_check_in_legacy", "status": "DISABLED",
            "rewardCredits": 100, "currentStreakDays": 0, "totalClaimDays": 0,
            "totalRewardCredits": 0}
_A.http_json = fake_status_disabled
acc_dis = _A.Account({"uid": "d1", "realm": "cn", "accessToken": "dt-x"})
res_dis = acc_dis.checkin()
cap_ok, _why = acc_dis.checkin_capability()
_A.http_json = _orig_hj
check("DISABLED campaign -> ok+disabled (no claim POST)",
      res_dis.get("ok") is True and res_dis.get("disabled") is True, res_dis)
check("realm-capable status response marks capability available",
      cap_ok is True, cap_ok)
# pro eligibility 404 -> 查询成功但不可领取
def fake_pro_404(url, **kw):
    raise _ue2.HTTPError(url, 404, "nf", {}, _io2.BytesIO(b""))
_A.http_json = fake_pro_404
ok_p, elig_p = acc_dis.pro_eligibility()
_A.http_json = _orig_hj
check("pro eligibility 404 -> (queried, not eligible)",
      ok_p is True and elig_p is False, (ok_p, elig_p))

print()
print("[5.7] campaign platform (/sash/api/v1/me/campaigns) — the new daily-claim home")
_acc_camp = _A.Account({"uid": "cp1", "realm": "intl", "accessToken": "dt-x"})
check("campaigns path constant present (same path on cn + intl)",
      _A.PATH_CAMPAIGNS == "/sash/api/v1/me/campaigns")


def fake_campaigns(url, **kw):
    check("campaigns hit the openapi base of the account realm",
          url.startswith(_A.get_realm_config("intl")["openapi"]), url)
    return {"uid": "cp1", "showCampaign": True, "claimable": True,
            "campaignUrl": "https://qoder.com/activities/daily-credits",
            "campaigns": [{"campaignId": "c-1", "campaignKey": "client_launch_26",
                           "startAt": 1789000000000, "endAt": 1789500000000,
                           "placements": [{"type": "usage_panel"}]}]}


_A.http_json = fake_campaigns
camp = _acc_camp.campaigns()
_A.http_json = _orig_hj
check("campaigns normalized: show/claimable/url",
      camp["ok"] and camp["show_campaign"] and camp["claimable"]
      and camp["campaign_url"].endswith("/daily-credits"), camp)
check("campaigns normalized: id/key/epoch(ms->s)/placements",
      camp["campaigns"][0]["campaign_id"] == "c-1"
      and camp["campaigns"][0]["campaign_key"] == "client_launch_26"
      and camp["campaigns"][0]["start_at"] == 1789000000
      and camp["campaigns"][0]["placements"], camp["campaigns"])
check("campaign snapshot cached on the account", _acc_camp.campaign_status is camp)


def fake_campaigns_404(url, **kw):
    raise _ue2.HTTPError(url, 404, "nf", {}, _io2.BytesIO(b'{"errorCode":"NotFound"}'))


_A.http_json = fake_campaigns_404
camp404 = _acc_camp.campaigns(force=True)   # 绕过 20s 短缓存，验证真实请求路径
_A.http_json = _orig_hj
check("campaigns 404 -> ok False + available False (no crash)",
      camp404["ok"] is False and camp404["available"] is False, camp404)

print()
print("[6] request body construction")
body = P.build_qoder_body({
    "model": "qmodel_38max",
    "messages": [{"role": "system", "content": "You are X."},
                 {"role": "user", "content": "hello"}],
}, None, "qmodel_38max", realm="cn")
check("client system replaces template system",
      body["messages"][0]["content"] == "You are X.")
check("conversation appended",
      [m["role"] for m in body["messages"]] == ["system", "user"])
check("request/session ids fresh uuids",
      body["request_id"] and body["session_id"]
      and body["request_id"] != body["session_id"])
check("stream forced true", body["stream"] is True)
check("agent_id agent_common", body["agent_id"] == "agent_common")
check("model_config key", body["model_config"]["key"] == "qmodel_38max")
check("model_config display_name from official catalog",
      body["model_config"]["display_name"] == "Qwen3.8-Max",
      body["model_config"]["display_name"])
check("model_config ctx from official catalog (cn 180000)",
      body["model_config"]["max_input_tokens"] == 180000)
check("model_config is_vl from official catalog",
      body["model_config"]["is_vl"] is True)
check("chat_context.text follows latest user prompt",
      body["chat_context"]["text"]["text"] == "hello")
check("no client tools -> tools emptied (template agent tools dropped)",
      body["tools"] == [])
check("business.name from prompt", body["business"]["name"] == "hello")

body2 = P.build_qoder_body({
    "model": "qmodel",
    "messages": [{"role": "user", "content": "a"},
                 {"role": "assistant", "content": "b"},
                 {"role": "user", "content": "c"}],
    "max_tokens": 500,
    "reasoning_effort": "high",
    "tools": [{"type": "function", "function": {"name": "f",
                                                 "parameters": {}}}],
}, None, "qmodel")
check("keeps template system when client has none",
      body2["messages"][0]["role"] == "system")
check("multi-turn order kept",
      [m["role"] for m in body2["messages"]] == ["system", "user", "assistant", "user"])
check("max_tokens forwarded", body2["parameters"].get("max_tokens") == 500)
# 思考档位按官方词表归一化（见 [20]）：qmodel 只有开/关、无档位表，
# 下发档位会被上游静默忽略，故此处不再透传（none 仍可用于关闭思考）
check("level-less model drops reasoning_effort (upstream ignores it anyway)",
      "reasoning_effort" not in body2["parameters"],
      body2["parameters"].get("reasoning_effort"))
check("client tools kept", len(body2["tools"]) == 1)
check("latest prompt is c", body2["chat_context"]["text"]["text"] == "c")

# tool 角色降级 + assistant tool_calls 序列化
body3 = P.build_qoder_body({
    "model": "qmodel",
    "messages": [
        {"role": "user", "content": "run"},
        {"role": "assistant", "content": "",
         "tool_calls": [{"id": "c1", "type": "function",
                         "function": {"name": "Bash", "arguments": "{\"cmd\":\"ls\"}"}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "Bash", "content": "file1"},
    ],
}, None, "qmodel")
roles3 = [m["role"] for m in body3["messages"]]
check("tool role degraded to user", roles3 == ["system", "user", "assistant", "user"])
check("assistant tool_calls serialized into content",
      "Bash" in body3["messages"][2]["content"])
check("tool result carried as user text",
      "file1" in body3["messages"][3]["content"])

print()
print("[6.5] DeepSeek reasoning_content backfill keys off the UPSTREAM model key")
# 复现 issue #2 的根因：客户端按文档写「内部 key: dfmodel」时，旧实现只按
# 名字前缀 "deepseek" 判断 -> 不做多轮 reasoning_content 兼容 -> 偶发失败。
_ds_trace = [
    {"role": "user", "content": "1+1=?"},
    {"role": "assistant", "content": "2", "reasoning_content": "简单加法"},
    {"role": "user", "content": "再+1"},
]
check("is_deepseek_model: upstream keys", 
      P.is_deepseek_model("", "dfmodel") and P.is_deepseek_model("", "dmodel"))
check("is_deepseek_model: client-visible names",
      P.is_deepseek_model("DeepSeek-Flash") and P.is_deepseek_model("deepseek-v4-pro")
      and P.is_deepseek_model("DeepSeek-V4-Pro"))
check("is_deepseek_model: display id form",
      P.is_deepseek_model("dfmodel (DeepSeek-Flash)"))
check("is_deepseek_model: non-DeepSeek models stay untouched",
      not P.is_deepseek_model("qmodel") and not P.is_deepseek_model("Qwen3.8-Max"))

_bf_key = P.backfill_reasoning_content([dict(m) for m in _ds_trace], "dfmodel",
                                       "dfmodel")
check("client using key 'dfmodel' NOW gets the backfill (regression)",
      all("reasoning_content" in m for m in _bf_key
          if m.get("role") == "assistant"), _bf_key)
_bf_name = P.backfill_reasoning_content([dict(m) for m in _ds_trace],
                                        "DeepSeek-Flash", "dfmodel")
check("display name path still works (no regression)",
      any(m.get("reasoning_content") == "简单加法" for m in _bf_name))
_bf_other = P.backfill_reasoning_content(
    [{"role": "user", "content": "q"},
     {"role": "assistant", "content": "a", "reasoning_content": "trace"}],
    "qmodel", "qmodel")
check("non-DeepSeek model: no reasoning_content added by the backfill",
      _bf_other[1] == {"role": "assistant", "content": "a",
                       "reasoning_content": "trace"})
_st_other, _flat_other, _ = P.flatten_messages(_bf_other, keep_reasoning=False)
check("flatten drops reasoning_content for non-DeepSeek upstreams",
      all("reasoning_content" not in m for m in _flat_other), _flat_other)
_st_ds, _flat_ds, _ = P.flatten_messages(
    [{"role": "user", "content": "q"},
     {"role": "assistant", "content": "a", "reasoning_content": "trace"}],
    keep_reasoning=True)
check("flatten KEEPS reasoning_content for DeepSeek upstreams (was dropped)",
      _flat_ds[1].get("reasoning_content") == "trace", _flat_ds)
_no_trace = P.backfill_reasoning_content(
    [{"role": "user", "content": "hi"}], "dfmodel", "dfmodel")
check("no reasoning trace in history -> no synthetic field",
      all("reasoning_content" not in m for m in _no_trace))

# 端到端：build_qoder_body 用显式 key 调用时也会补
_body_ds = P.build_qoder_body({
    "model": "dfmodel",
    "messages": [
        {"role": "user", "content": "1+1=?"},
        {"role": "assistant", "content": "2", "reasoning_content": "简单加法"},
        {"role": "user", "content": "再+1"},
    ],
}, None, "dfmodel", realm="cn")
_ds_assistants = [m for m in _body_ds["messages"] if m.get("role") == "assistant"]
check("build_qoder_body('dfmodel') backfills assistant history",
      _ds_assistants and all("reasoning_content" in m for m in _ds_assistants),
      _ds_assistants)

print()
print("[7] SSE envelope unwrapping & aggregation")


class FakeResp(object):
    def __iter__(self):
        inner = json.dumps({"id": "cc1", "model": "qmodel", "created": 1,
                            "choices": [{"delta": {"content": "hi"}}]})
        inner2 = json.dumps({"choices": [{"delta": {},
                                          "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 3, "completion_tokens": 2,
                                       "total_tokens": 5}})
        return iter([
            ("data: " + json.dumps({"headers": {}, "body": inner,
                                    "statusCodeValue": 200}) + "\n\n").encode(),
            ("data: " + json.dumps({"body": inner2,
                                    "statusCodeValue": 200}) + "\n\n").encode(),
            b'data:{"body":"[DONE]"}\n\n',
            b'event:finish{"totalTime":10}\n',
        ])


holder = {}
lines = list(P.iter_inner_sse(FakeResp(), holder=holder))
check("unwrapped to standard data lines", len(lines) == 2
      and lines[0].startswith(b"data: "))
check("usage captured in holder", (holder.get("usage") or {}).get("total_tokens") == 5)
agg = P.aggregate_stream(FakeResp(), "qmodel", None, holder={})
check("aggregate content", agg["choices"][0]["message"]["content"] == "hi")
check("aggregate finish stop", agg["choices"][0]["finish_reason"] == "stop")
check("aggregate usage", agg.get("usage", {}).get("total_tokens") == 5)


class ErrResp(object):
    def __iter__(self):
        return iter([("data: " + json.dumps({"body": "quota exceeded",
                                             "statusCodeValue": 503})
                      + "\n\n").encode()])


try:
    list(P.iter_inner_sse(ErrResp()))
    check("non-200 envelope raises UpstreamStatus", False)
except P.UpstreamStatus as exc:
    check("non-200 envelope raises UpstreamStatus",
          str(exc.status) == "503" and "quota" in exc.detail)

# 空 tool_call 占位清洗
noisy = json.dumps({"choices": [{"delta": {"function_call": {"name": "",
                                                             "arguments": ""},
                                           "reasoning_content": ""}}]})
cleaned = P.clean_chunk(noisy)
check("empty function_call noise stripped",
      cleaned == "" or "function_call" not in cleaned, cleaned)

print()
print("[8] Responses API custom tool translation")
CUSTOM_TOOL = {"type": "custom", "name": "apply_patch",
               "description": "Use the patch format to edit files",
               "format": {"type": "grammar", "syntax": "lark",
                          "definition": "start: /.*/s"}}
FUNC_TOOL = {"type": "function", "name": "get_weather",
             "description": "weather",
             "parameters": {"type": "object", "properties": {}}}
chat = P.responses_to_chat({"model": "m", "input": "hi",
                            "tools": [CUSTOM_TOOL, FUNC_TOOL]})
tools = chat["tools"]
check("custom tool became type=function", tools[0]["type"] == "function",
      tools[0].get("type"))
check("custom tool single 'input' param",
      list((tools[0]["parameters"]["properties"] or {}).keys()) == ["input"])
check("freeform hint present", "freeform tool" in tools[0]["description"])
check("grammar forwarded", "start: /.*/s" in tools[0]["description"])
check("ordinary function tool untouched", tools[1] == FUNC_TOOL)

hist = {"model": "m", "input": [
    {"role": "user", "content": "edit the file"},
    {"type": "custom_tool_call", "name": "apply_patch", "call_id": "call_1",
     "input": "*** Begin Patch\n+hi\n*** End Patch"},
    {"type": "custom_tool_call_output", "call_id": "call_1", "output": "Done!"},
]}
c2msgs = P.responses_to_chat(hist)["messages"]
asst = [m for m in c2msgs if m.get("role") == "assistant" and m.get("tool_calls")]
check("assistant carries the tool call", len(asst) == 1)
check("payload wrapped as {input: ...}",
      json.loads(asst[0]["tool_calls"][0]["function"]["arguments"])["input"]
      .startswith("*** Begin Patch"))
tool_msgs = [m for m in c2msgs if m.get("role") == "tool"]
check("tool result appended", len(tool_msgs) == 1
      and tool_msgs[0]["tool_call_id"] == "call_1")

chat_obj = {"choices": [{"finish_reason": "tool_calls", "message": {
    "role": "assistant", "content": "",
    "tool_calls": [{"id": "call_7", "type": "function", "function": {
        "name": "apply_patch",
        "arguments": json.dumps({"input": "*** Begin Patch\n+ok\n*** End Patch"})}}]}}]}
r = P.chat_to_response(chat_obj, "m", {"apply_patch"})
item = r["output"][0]
check("non-stream re-inflated to custom_tool_call",
      item["type"] == "custom_tool_call", item.get("type"))
check("input unwrapped verbatim",
      item["input"] == "*** Begin Patch\n+ok\n*** End Patch")

# reasoning item 处理 (Issue #17 parity)
hist_r = {"model": "m", "input": [
    {"role": "user", "content": "solve math"},
    {"type": "reasoning", "id": "rs_1",
     "summary": [{"type": "summary_text", "text": "let me think"}]},
    {"type": "message", "role": "assistant", "content": "4"},
]}
cr = P.responses_to_chat(hist_r)["messages"]
asst_r = [m for m in cr if m.get("role") == "assistant"]
check("reasoning attached to assistant",
      len(asst_r) == 1 and asst_r[0].get("reasoning_content") == "let me think")

# 流式 Responses 事件序列
def chunk(delta, finish=None):
    return ("data: " + json.dumps({"choices": [{"delta": delta,
                                                "finish_reason": finish}]})
            + "\n\n").encode()

stream = [
    chunk({"tool_calls": [{"index": 0, "id": "call_9",
                           "function": {"name": "apply_patch",
                                        "arguments": ""}}]}),
    chunk({"tool_calls": [{"index": 0,
                           "function": {"arguments": '{"input":"*** Begin'}}]}),
    chunk({"tool_calls": [{"index": 0,
                           "function": {"arguments": ' Patch\\n+hi\\n*** End Patch"}'}}]}),
    chunk({}, "tool_calls"),
]
holder2 = {"usage": None, "custom_names": {"apply_patch"}}
raw_events = b"".join(P.stream_responses_events(iter(stream), "m", holder2))
text = raw_events.decode()
check("created event first", "response.created" in text)
check("custom_tool_call_input.delta present",
      "response.custom_tool_call_input.delta" in text)
check("custom_tool_call_input.done present",
      "response.custom_tool_call_input.done" in text)
check("no stray function_call_arguments for custom",
      "response.function_call_arguments" not in text)
check("completed terminal event", "response.completed" in text)
done = [json.loads(l[6:]) for l in text.splitlines()
        if l.startswith("data: ")
        and '"response.custom_tool_call_input.done"' in l]
check("done carries unwrapped input",
      done and done[0]["input"] == "*** Begin Patch\n+hi\n*** End Patch")

print()
print("[9] checkin / keepalive normalization (offline fixtures)")
acc = A.Account({"uid": "fx-1", "realm": "cn", "domain": "qoder.com.cn",
                 "accessToken": "jt-x", "refreshToken": "jrt-y",
                 "expiresAt": 9999999999})
# status: CLAIMED today
import time as _t
_today = _t.time()
ok, st = acc.checkin_status.__wrapped__ if False else (True, None)


class _FixStatus(object):
    pass


# 直接测归一化分支：monkeypatch http_json
orig_http_json = A.http_json


def fake_status_ok(url, **kw):
    return {"status": "CLAIMABLE", "rewardCredits": 100,
            "currentStreakDays": 3, "totalClaimDays": 10,
            "totalRewardCredits": 900, "lastClaimedAt": 0}


def fake_claim_ok(url, **kw):
    return {"success": True, "rewardCredits": 100}


A.http_json = fake_status_ok
res = acc.checkin()
check("claim path awards 100", res.get("ok") and res.get("reward_credits") == 100,
      res)
check("last_checkin stamped", bool(acc.last_checkin))

# 409 ALREADY_CLAIMED -> 已签到
import urllib.error as _ue
import io as _io


def fake_claim_conflict(url, **kw):
    if "daily-check-in/status" in url:
        # 昨天签过 -> 状态端点正常返回，claim 端点才是 409
        return {"status": "CLAIMED", "rewardCredits": 100,
                "currentStreakDays": 3, "totalClaimDays": 10,
                "totalRewardCredits": 900,
                "lastClaimedAt": int(_t.time()) - 86400}
    raise _ue.HTTPError(url, 409, "conflict", {},
                        _io.BytesIO(b'{"result":"ALREADY_CLAIMED"}'))


A.http_json = fake_claim_conflict
acc2 = A.Account({"uid": "fx-2", "realm": "cn", "accessToken": "jt-x",
                  "refreshToken": "jrt-y", "expiresAt": 9999999999})
res2 = acc2.checkin()
check("409 ALREADY_CLAIMED normalized to ok/already",
      res2.get("ok") and res2.get("already"), res2)
A.http_json = orig_http_json

# session dead markers
check("TOKEN_EXPIRE detected", A.session_dead("TOKEN_EXPIRE expired"))
check("12153 detected", A.session_dead('{"code":"12153"}'))
check("normal error not dead", not A.session_dead("connection reset"))

# token family routing
acc_d = A.Account({"uid": "d", "accessToken": "dt-1", "refreshToken": "drt-1"})
acc_j = A.Account({"uid": "j", "accessToken": "jt-1", "refreshToken": "jrt-1"})
check("device family", A.token_family(acc_d) == "device")
check("job family", A.token_family(acc_j) == "job")

print()
print("[4.5] credential / model-cache crypto KATs (official fixtures)")
import base64 as _b64
# fixture 探测：环境变量优先，其次按候选顺序找；不再硬编码单个 %TEMP% 路径。
_HERE = os.path.dirname(os.path.abspath(__file__))
_FIX_ENV = os.environ.get("QD_TEST_FIXTURE_DIR") or ""
_FIX_CANDIDATES = [
    _FIX_ENV,
    os.path.join(_HERE, "testdata", "protocol", "1.1.34"),
    os.path.join(_HERE, "tests", "fixtures", "protocol", "1.1.34"),
    os.path.join(_HERE, os.pardir, "qoder-ref", "cli2api", "testdata",
                 "protocol", "1.1.34"),
    os.path.join(os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp",
                 "qoder-ref", "cli2api", "testdata", "protocol", "1.1.34"),
    os.path.join(os.path.expanduser("~"), "qoder-ref", "cli2api",
                 "testdata", "protocol", "1.1.34"),
]
if _FIX_ENV and not os.path.isdir(_FIX_ENV):
    print("  [WARN] QD_TEST_FIXTURE_DIR 指向的目录不存在：%s" % _FIX_ENV)
_FIX, _FIX_TRIED = "", []
for _cand in _FIX_CANDIDATES:
    if not _cand:
        continue
    _cand_abs = os.path.abspath(_cand)
    _FIX_TRIED.append(_cand_abs)
    if os.path.isdir(_cand_abs):
        _FIX = _cand_abs
        break
if _FIX:
    print("  fixture 目录: %s" % _FIX)
else:
    print("  fixture 目录: 未找到；已探测 %d 条候选：" % len(_FIX_TRIED))
    for _p in _FIX_TRIED:
        print("      -  %s" % _p)
    print("      指定方式: QD_TEST_FIXTURE_DIR=<dir> python _test_qoder.py")

_CRED_FP = os.path.join(_FIX, "credential.json") if _FIX else ""
_MCACHE_FP = os.path.join(_FIX, "model-cache.json") if _FIX else ""

if _CRED_FP and os.path.isfile(_CRED_FP):
    fx = json.load(open(_CRED_FP, encoding="utf-8"))
    mkey = fx["input"]["machine_key"].encode()
    fx_ct = _b64.b64decode(fx["expected"]["encrypted"])
    dec = S.aes_cbc_decrypt(fx_ct, mkey, mkey)
    check("credential fixture decrypt byte-exact",
          dec.decode() == fx["expected"]["decrypted"])
    enc = _b64.b64encode(S.aes_cbc_encrypt(dec, mkey, mkey)).decode()
    check("credential fixture encrypt byte-exact",
          enc == fx["expected"]["encrypted"])
else:
    _miss_cred = "缺 credential.json" if _FIX else "缺 fixture 目录"
    skip("credential fixture decrypt byte-exact", _miss_cred)
    skip("credential fixture encrypt byte-exact", _miss_cred)

if _MCACHE_FP and os.path.isfile(_MCACHE_FP):
    mf = json.load(open(_MCACHE_FP, encoding="utf-8"))
    plain = S.qmc_decrypt(mf["expected"]["encrypted"], mf["input"]["uid"])
    check("model-cache (QMC v1) fixture decrypt byte-exact",
          plain.decode() == mf["expected"]["decrypted"])
else:
    skip("model-cache (QMC v1) fixture decrypt byte-exact",
         "缺 model-cache.json" if _FIX else "缺 fixture 目录")

# AES-256 互逆（QMC 用 32 字节 key -> 15 个轮密钥）：纯算法、不依赖 fixture，
# 因此永远执行（此前被误放进 fixture 分支，缺 fixture 时连算法 KAT 都一起没跑）。
k256 = bytes(range(32))
blk = bytes(range(16))
rks = S._expand_key(k256)
check("AES-256 key schedule = 15 round keys", len(rks) == 15, len(rks))
check("AES-256 block roundtrip",
      S._decrypt_block(S._encrypt_block(blk, rks), rks) == blk)

print()
print("[4.6] local credential scan (reads THIS machine's official stores)")
try:
    import qoder_accounts as _QA
    detected = _QA.scan_desktop_credentials()
    check("scan returns both realms", len(detected) >= 2, len(detected))
    realms_seen = {d["realm"] for d in detected}
    check("scan covers intl + cn", realms_seen == {"intl", "cn"}, realms_seen)
    valid = [d for d in detected if d.get("valid")]
    # 本机是否登录过属于环境状态：登录过则必须解出 uid/dt- 前缀
    if valid:
        check("valid entries carry uid + dt- token prefix",
              all(d["uid"] and d.get("kind") for d in valid),
              [(d["realm"], d.get("kind"), d.get("uid", "")[:8]) for d in valid])
        check("app entries decrypted via os_crypt (kind=app uid present)",
              all(d.get("uid") for d in valid if d["kind"] == "app"))
    else:
        check("scan ran without crash (no valid creds on this machine)", True)
except Exception as exc:
    check("local credential scan", False, exc)

print()
print("[10] gateway plumbing")
check("detect_model_realm fallback to current",
      P.detect_model_realm("mystery-model") == P.CURRENT_REALM)
check("CORS on API path", P.cors_origin_allowed("/v1/chat/completions"))
check("no CORS on management", not P.cors_origin_allowed("/accounts"))
check("no CORS on /v1/usage", not P.cors_origin_allowed("/v1/usage"))
check("realm persisted file name", P.REALM_STATE_FILE.endswith("active_realm.json"))
# 会话亲和键稳定性
k1 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "u1"}])
k2 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "u1"},
                             {"role": "assistant", "content": "a"}])
k3 = P.derive_affinity_key([{"role": "system", "content": "s"},
                             {"role": "user", "content": "different"}])
check("affinity key stable across turns", k1 == k2)
check("affinity key differs per conversation", k1 != k3)
# prompt fingerprint privacy
fp = P.prompt_fingerprint([{"role": "system", "content": "secret system"}])
check("fingerprint has no raw text",
      "secret" not in json.dumps(fp) and len(fp.get("system_sha", "")) == 12)

# flatten / sanitize
sys_text, flat, images = P.flatten_messages([
    {"role": "system", "content": "base"},
    {"role": "user", "content": [{"type": "text", "text": "part1"},
                                  {"type": "image_url",
                                   "image_url": {"url": "data:image/png;base64,AAA"}}]},
])
check("system extracted", sys_text == "base")
check("text parts joined", flat[0]["content"] == "part1")
check("image collected", images == ["data:image/png;base64,AAA"])
check("fingerprint string sanitized",
      "You are Claude Code, Anthropic's official CLI tool" in
      P.sanitize_text("You are Claude Code, Anthropic's official CLI tool for Claude"))

print()
print("[18] task center lists every realm (issue #1: intl check-in was filtered out)")
_t_intl = A.Account({"uid": "t-intl", "realm": "intl", "domain": "qoder.com",
                     "accessToken": "dt-x", "nickname": "intl-user"})
_t_cn = A.Account({"uid": "t-cn", "realm": "cn", "domain": "qoder.com.cn",
                   "accessToken": "dt-y", "nickname": "cn-user"})
_t_pool = A.AccountPool(os.path.join(os.environ["ACCOUNTS_DIR"], "unused"))
_t_pool.accounts = [_t_intl, _t_cn]
# 离线打桩：状态 404（intl 真实形态）+ 活动平台可用
_orig_status = A.Account.checkin_status
_orig_camp = A.Account.campaigns
_orig_credits = A.Account.fetch_credits
_orig_plan = A.Account.fetch_plan
_orig_elig = A.Account.pro_eligibility


def _stub_status(self):
    if self.realm == "intl":
        self._mark_checkin_capability(False, "%s (HTTP 404)"
                                      % A.CHECKIN_REASON_NOT_FOUND)
        return False, {"unavailable": True, "reason": A.CHECKIN_REASON_NOT_FOUND,
                       "http": 404, "error": "HTTP 404 NotFound"}
    return True, {"status": "DISABLED", "active": False, "today_checked_in": False,
                  "streak_days": 0, "total_claim_days": 0, "reward_credits": 100,
                  "total_reward_credits": 0, "next_claim_at": 0,
                  "last_claimed_at": 0, "reward_expires_at": 0}


A.Account.checkin_status = _stub_status
# 活动平台：intl 已领取、cn 可领取（100 Credits）—— 与官方桌面端真实形态一致
_A_CAMPAIGNS = {
    "intl": {"ok": True, "available": True, "show_campaign": True,
             "claimable": False, "campaign_url": "https://openapi.qoder.sh/growth-page/activity-iframe",
             "campaigns": [
                 {"campaign_id": "c-intl", "campaign_key": "act-intl",
                  "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMED",
                  "title_zh": "每天领 100 Credits",
                  "start_at": 0, "end_at": 0,
                  "benefit": {"kind": "CREDITS", "amount": 100},
                  "required_achievement_key": "",
                  "achievement_completed": False, "unavailable_reason": "",
                  "placements": []},
                 # 详情类活动（无奖励）：不应被算作"签到奖励"
                 {"campaign_id": "c-detail", "campaign_key": "act-detail",
                  "action_type": "VIEW_DETAILS", "claim_status": "CLAIMED",
                  "start_at": 0, "end_at": 0,
                  "benefit": {"kind": "", "amount": 0},
                  "required_achievement_key": "",
                  "achievement_completed": False, "unavailable_reason": "",
                  "placements": []}]},
    "cn": {"ok": True, "available": True, "show_campaign": True,
           "claimable": True, "campaign_url": "https://openapi.qoder.com.cn/growth-page/activity-iframe",
           "campaigns": [{"campaign_id": "c-cn", "campaign_key": "act-daily-100",
                          "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                          "start_at": 0, "end_at": 0,
                          "benefit": {"kind": "CREDITS", "amount": 100},
                          "required_achievement_key": "",
                          "achievement_completed": False, "unavailable_reason": "",
                          "placements": []}]},
}
A.Account.campaigns = lambda self, force=False: dict(_A_CAMPAIGNS[self.realm])
A.Account.fetch_credits = lambda self: {"ok": True, "credits": {}}
A.Account.fetch_plan = lambda self: ""
A.Account.pro_eligibility = lambda self: (True, False)
try:
    _view_intl = T.fetch_tasks_view(_t_pool, uid="t-intl")
    _view_cn = T.fetch_tasks_view(_t_pool, uid="t-cn")
    _view_all = T.fetch_tasks_view(_t_pool)
finally:
    A.Account.checkin_status = _orig_status
    A.Account.campaigns = _orig_camp
    A.Account.fetch_credits = _orig_credits
    A.Account.fetch_plan = _orig_plan
    A.Account.pro_eligibility = _orig_elig

check("intl account is selectable in the task center",
      _view_intl.get("account", {}).get("uid") == "t-intl", _view_intl.get("msg"))
check("task center lists BOTH realms",
      {a["realm"] for a in _view_all["accounts"]} == {"cn", "intl"},
      _view_all["accounts"])
_intl_row = [t for t in _view_intl["tasks"] if t["task_code"] == "daily_checkin"][0]
_cn_row = [t for t in _view_cn["tasks"] if t["task_code"] == "daily_checkin"][0]
check("intl: claimed 每日 Credits renders as 今日已领取（中文活动名）",
      _intl_row["status"] == "claimed" and "今日已领取" in _intl_row["description"]
      and "每天领 100 Credits" in _intl_row["description"], _intl_row)
check("每日行不计入详情类活动（VIEW_DETAILS 不算签到奖励）",
      "act-detail" not in _intl_row["description"], _intl_row["description"])
check("cn: CLAIMABLE campaign renders as 待领奖 + reward amount",
      _cn_row["status"] == "completed" and _cn_row["reward_credit"] == 100
      and "领取" in _cn_row["description"], _cn_row)
check("legacy DISABLED endpoint no longer produces a noise row",
      "daily_checkin_legacy" not in [t["task_code"] for t in _view_cn["tasks"]],
      [t["task_code"] for t in _view_cn["tasks"]])
_codes = [t["task_code"] for t in _view_intl["tasks"]]
check("campaign state surfaced in summary (show/claimable/url/items)",
      _view_intl["summary"]["campaigns"]["show"] is True
      and _view_intl["summary"]["campaigns"]["items"][0]["key"] == "act-intl",
      _view_intl["summary"]["campaigns"])
check("daily row carries a jump url (campaignUrl or activities page)",
      bool(_intl_row.get("jump_url")) and "qoder" in _intl_row["jump_url"],
      _intl_row.get("jump_url"))

print()
print("[19] gateway host failover (official intl api1 -> api2; CN single host)")
check("gateway_candidates: intl primary is api1 with api2/api3 fallbacks",
      A.gateway_candidates("intl") == ["https://api1.qoder.sh",
                                       "https://api2.qoder.sh",
                                       "https://api3.qoder.sh"],
      A.gateway_candidates("intl"))
check("gateway_candidates: cn has a single official host",
      A.gateway_candidates("cn") == ["https://gateway.qoder.com.cn"],
      A.gateway_candidates("cn"))

# 行为：api1 传输层失败 -> 自动切到 api2 并在同一请求内成功
import ssl as _ssl19
_orig_urlopen19 = P.urllib.request.urlopen
_hits19 = []


class _Resp19(object):
    status = 200

    def read(self):
        return b""

    def close(self):
        pass


def _fake_urlopen19(req, timeout=None):
    _hits19.append(req.full_url)
    if "api1.qoder.sh" in req.full_url:
        raise _ssl19.SSLError("simulated TLS EOF on primary host")
    return _Resp19()


_orig_pool19 = P.POOL
_pool19 = A.AccountPool(os.path.join(os.environ["ACCOUNTS_DIR"], "unused19"))
_pool19.accounts = [A.Account({"uid": "h19", "realm": "intl",
                               "domain": "qoder.com",
                               "accessToken": "dt-x"})]
P.POOL = _pool19
P.urllib.request.urlopen = _fake_urlopen19
try:
    _resp19, _acc19, _ = P.open_upstream(
        {"model": "qmodel", "stream": True,
         "messages": [{"role": "user", "content": "hi"}]},
        target_realm="intl")
    _err19 = None
except Exception as exc:                      # pragma: no cover - failure path
    _err19 = exc
finally:
    P.urllib.request.urlopen = _orig_urlopen19
    P.POOL = _orig_pool19

check("failover: request succeeded after primary host transport error",
      _err19 is None and _acc19.uid == "h19", _err19)
check("failover: both hosts were tried in order (api1 then api2)",
      len(_hits19) == 2 and "api1.qoder.sh" in _hits19[0]
      and "api2.qoder.sh" in _hits19[1], _hits19)
check("failover: signature path unchanged across hosts",
      _hits19[0].split("?")[0].endswith(P.CHAT_PATH.split("?")[0]),
      _hits19[0])

print()
print("[20] campaign check-in (the real daily-claim API) + effort normalization")

# --- 20.1 桌面端请求头（活动平台必需；缺了服务端返回空列表） ---
_hdrs = _t_cn.desktop_headers()
check("desktop headers carry Cosy-ClientType=10 + Cosy-Version + UA Qoder",
      _hdrs["cosy-clienttype"] == "10" and _hdrs["User-Agent"] == "Qoder"
      and bool(_hdrs["cosy-version"]), _hdrs.get("cosy-clienttype"))
# 前提：文件头已设 QD_NATIVE_IDENTITY=0，且本机 runtime_info_exe("cn") 返回空 ->
# 本进程内的身份来源必为 "derived"（:1679 那条断言独立守这一点）。
# issue #10：**derived** 身份不得携带 cosy-machine* 六头——服务端一旦看到一整套
# 派生机器头，就会把 CN 的「每日领取 100 Credits」等可领取活动整条过滤掉（列表变空）。
# 语义 = 服务端可见值必须为空/缺失（实现删除键或置空都满足）；"能红"面 = 回退成
# 无条件发头即失败。
_MACHINE_HDRS20 = ("cosy-machineid", "cosy-machinetoken", "cosy-machinetype",
                   "cosy-machineos", "cosy-machinehostname", "cosy-machinecode")
check("derived 身份不得发送 cosy-machine* 六头（issue #10：全套派生机器头会让服务端"
      "过滤掉可领取的 Credits 活动）",
      not any(_hdrs.get(k) for k in _MACHINE_HDRS20),
      {k: _hdrs.get(k) for k in _MACHINE_HDRS20 if _hdrs.get(k)})
check("native identity bridge can be disabled (derived fallback)",
      os.environ.get("QD_NATIVE_IDENTITY") == "0"
      and _t_cn.machine_identity_source == "derived"
      and A.runtime_info_exe("cn") == "",
      _t_cn.machine_identity_source)
check("desktop headers keep the Bearer token",
      _hdrs["Authorization"].startswith("Bearer "))
# issue #10 的正向面：修复只能收窄 derived，**native 原生身份必须照旧发六头**。
# 打桩原生身份返回值（当前 desktop_headers 以 native_machine_identity() 的返回
# 为判据；若实现改判据，这条会红——这正是要它守住的契约）。
_orig_nmi20 = A.native_machine_identity
try:
    A.native_machine_identity = lambda realm, account_id, force=False: {
        "machineToken": "nt-token", "machineType": "3",
        "machineCode": "nc-1", "source": "runtime-info"}
    _t_native20 = A.Account({"uid": "h20native", "realm": "cn",
                             "accessToken": "dt-x"})
    _h_native20 = _t_native20.desktop_headers()
finally:
    A.native_machine_identity = _orig_nmi20
check("原生桥身份分支（source=runtime-info）仍发送 cosy-machine* 六头"
      "（issue #10 只收窄 derived，不砍原生能力）",
      _t_native20.machine_identity_source == "runtime-info"
      and all(_h_native20.get(k) for k in _MACHINE_HDRS20),
      {k: _h_native20.get(k) for k in _MACHINE_HDRS20})
check("campaign claim/reward path templates (official growth-page contract)",
      A.PATH_CAMPAIGN_CLAIM == "/sash/api/v1/me/campaigns/%s/claim"
      and A.PATH_CAMPAIGN_REWARD == "/sash/api/v1/me/campaigns/%s/reward")

# --- 20.2 campaign_checkin: 只领取 CLAIMABLE + CLAIM_BENEFIT，幂等视为已领 ---
_orig_claim = A.Account.claim_campaign
_calls20 = []


def _stub_claim(self, campaign_id):
    _calls20.append(campaign_id)
    return {"ok": True, "status": "CLAIMED", "replayed": False, "grant_id": "g1",
            "amount": 100, "message": "领取成功"}


A.Account.claim_campaign = _stub_claim
A.Account.campaigns = lambda self, force=False: {
    "ok": True, "available": True, "show_campaign": True, "claimable": True,
    "campaign_url": "https://openapi.qoder.com.cn/growth-page/activity-iframe",
    "campaigns": [
        {"campaign_id": "c1", "campaign_key": "act-daily-100",
         "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
         "start_at": 0, "end_at": 0, "benefit": {"kind": "CREDITS", "amount": 100},
         "placements": []},
        {"campaign_id": "c2", "campaign_key": "act-view-only",
         "action_type": "VIEW_DETAILS", "claim_status": "CLAIMABLE",
         "start_at": 0, "end_at": 0, "benefit": {"kind": "", "amount": 0},
         "placements": []},
        {"campaign_id": "c3", "campaign_key": "act-done",
         "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMED",
         "start_at": 0, "end_at": 0, "benefit": {"kind": "CREDITS", "amount": 100},
         "placements": []},
    ]}
_acc20 = A.Account({"uid": "cp20", "realm": "cn", "accessToken": "dt-x"})
try:
    _res20 = _acc20.campaign_checkin(gap=0)
finally:
    A.Account.claim_campaign = _orig_claim
    A.Account.campaigns = _orig_camp

check("only CLAIMABLE CLAIM_BENEFIT campaigns are claimed",
      _calls20 == ["c1"], _calls20)
check("VIEW_DETAILS campaign is not claimed", "c2" not in _calls20)
check("already-CLAIMED campaign is not re-posted", "c3" not in _calls20)
check("campaign_checkin reports earned credits + already list",
      _res20["earned"] == 100 and len(_res20["claimed"]) == 1
      and len(_res20["already"]) == 1, _res20.get("message"))
check("campaign_checkin stamps last_checkin on success", bool(_acc20.last_checkin))
check("campaign_checkin message names the claimed campaign",
      "act-daily-100" in _res20["message"], _res20["message"])

# --- 20.3 幂等：上游 replayed=true 视为已领取而不是新领取 ---
A.Account.campaigns = lambda self, force=False: {
    "ok": True, "available": True, "show_campaign": True, "claimable": True,
    "campaign_url": "", "campaigns": [
        {"campaign_id": "c9", "campaign_key": "act-x",
         "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
         "start_at": 0, "end_at": 0, "benefit": {"kind": "CREDITS", "amount": 100},
         "placements": []}]}
A.Account.claim_campaign = lambda self, cid: {
    "ok": True, "status": "CLAIMED", "replayed": True, "grant_id": "g9",
    "amount": 100, "message": "已领取"}
try:
    _res21 = _acc20.campaign_checkin(gap=0)
finally:
    A.Account.claim_campaign = _orig_claim
    A.Account.campaigns = _orig_camp
check("replayed claim counted as already (no phantom credits)",
      _res21["earned"] == 0 and len(_res21["already"]) == 1
      and not _res21["claimed"], _res21.get("message"))

# --- 20.3b 同人去重（实测 failureCode=SAME_PERSON_ALREADY_CLAIMED）：同机多号
#     共享每轮一次的额度，被拦的号不算错误但也不能虚报积分 ---
def _fake_blocked(url, **kw):
    return {"grantId": "g-b", "status": "BLOCKED", "replayed": False,
            "failureCode": "SAME_PERSON_ALREADY_CLAIMED",
            "benefit": {"kind": "CREDITS", "amount": 100}}


_orig_http20 = A.http_json
A.http_json = _fake_blocked
try:
    _res_blk = _acc20.claim_campaign("cb")
finally:
    A.http_json = _orig_http20
check("claim_campaign parses BLOCKED/SAME_PERSON as blocked (not ok)",
      _res_blk["ok"] is False and _res_blk["blocked"] is True
      and _res_blk["failure_code"] == "SAME_PERSON_ALREADY_CLAIMED", _res_blk)
check("blocked claim keeps the benefit amount for reporting",
      _res_blk["amount"] == 100, _res_blk.get("amount"))

A.Account.campaigns = lambda self, force=False: {
    "ok": True, "available": True, "show_campaign": True, "claimable": True,
    "campaign_url": "", "campaigns": [
        {"campaign_id": "cb", "campaign_key": "act-daily",
         "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
         "start_at": 0, "end_at": 0, "benefit": {"kind": "CREDITS", "amount": 100},
         "placements": []}]}
A.Account.claim_campaign = lambda self, cid: {
    "ok": False, "blocked": True, "status": "BLOCKED", "replayed": False,
    "failure_code": "SAME_PERSON_ALREADY_CLAIMED", "amount": 100,
    "message": "同人已领取（同一设备/身份下其他账号本轮已领，服务端按人去重）"}
try:
    _res22 = _acc20.campaign_checkin(gap=0)
finally:
    A.Account.claim_campaign = _orig_claim
    A.Account.campaigns = _orig_camp
check("BLOCKED claim is not counted as earned (person-level dedup)",
      _res22["earned"] == 0 and not _res22["claimed"]
      and len(_res22["blocked"]) == 1, _res22.get("message"))
check("blocked message explains SAME_PERSON dedup",
      "同人已领取" in _res22["message"], _res22["message"])

# --- 20.5 身份轮换：show=false 时强制刷新身份并重试一次 ---
_orig_get = A.Account._campaigns_get
_orig_native = A.native_machine_identity
_seq = []


def _stub_get(self):
    _seq.append(1)
    if len(_seq) == 1:
        return {"showCampaign": False, "claimable": False, "campaigns": []}, 200, ""
    return {"showCampaign": True, "claimable": True, "campaignUrl": "u",
            "campaigns": [{"campaignId": "cx", "campaignKey": "act-x",
                           "actionType": "CLAIM_BENEFIT", "claimStatus": "CLAIMABLE",
                           "startAt": 0, "endAt": 0,
                           "benefit": {"kind": "CREDITS", "amount": 100},
                           "placements": []}]}, 200, ""


_forced = []


def _stub_native(realm, account_id, force=False):
    if force:
        _forced.append(account_id)
    return {"machineToken": "t", "machineType": "ty", "machineCode": "c",
            "source": "runtime-info"}


A.Account._campaigns_get = _stub_get
A.native_machine_identity = _stub_native
_acc25 = A.Account({"uid": "cp25", "realm": "cn", "accessToken": "dt-x"})
# Lead 口径裁决：machine_identity_source 合法值只有 "runtime-info"（原生桥可用）
# 与 "derived"（回退）；此处桩值必须是真实取值——过去写成 "native" 会让实现里
# 永不命中的死逻辑（== "native"）被测试掩盖成"已验证"。
_acc25.machine_identity_source = "runtime-info"
try:
    _st25 = _acc25.campaigns()
finally:
    A.Account._campaigns_get = _orig_get
    A.native_machine_identity = _orig_native
check("filtered list (show=false) triggers one forced identity refresh + retry",
      len(_seq) == 2 and _forced == ["cp25"]
      and _st25["show_campaign"] is True and _st25["claimable"] is True,
      (len(_seq), _forced))
check("retry keeps the second (populated) payload",
      len(_st25.get("campaigns") or []) == 1
      and _st25["campaigns"][0]["campaign_key"] == "act-x")

# --- 20.6 campaign_checkin 先强制刷新身份（轮换后不漏领） ---
_orig_get2 = A.Account._campaigns_get
_orig_native2 = A.native_machine_identity
_forced2 = []


def _stub_native2(realm, account_id, force=False):
    if force:
        _forced2.append(account_id)
    return {"machineToken": "t", "machineType": "ty", "machineCode": "c",
            "source": "runtime-info"}


A.Account._campaigns_get = lambda self: (
    {"showCampaign": True, "claimable": False, "campaignUrl": "", "campaigns": []},
    200, "")
A.native_machine_identity = _stub_native2
A.Account.claim_campaign = _orig_claim
try:
    A.Account({"uid": "cp26", "realm": "cn", "accessToken": "dt-x"}).campaign_checkin(gap=0)
finally:
    A.Account._campaigns_get = _orig_get2
    A.native_machine_identity = _orig_native2
check("campaign_checkin force-refreshes the machine identity first",
      _forced2 == ["cp26"], _forced2)

# --- 20.4 思考档位归一化（官方词表因模型而异，未命中会被上游静默忽略） ---
_meta_df = next(m for m in C.models_for_realm("cn") if m["key"] == "dfmodel")
_meta_qf = next(m for m in C.models_for_realm("cn") if m["key"] == "qfmodel")
_meta_qm = next(m for m in C.models_for_realm("cn") if m["key"] == "qmodel")
check("supported_efforts reads the official levels",
      P.supported_efforts(_meta_qf) == ["low", "medium", "xhigh"]
      and P.supported_efforts(_meta_df) == ["low", "high", "max"]
      and P.supported_efforts(_meta_qm) == [], P.supported_efforts(_meta_df))
check("default_effort reads the official is_default mark",
      P.default_effort(_meta_qf) == "medium" and P.default_effort(_meta_df) == "max",
      (P.default_effort(_meta_qf), P.default_effort(_meta_df)))
_v, _n = P.normalize_reasoning_effort("none", _meta_qf)
check("none stays none (universal off switch)", _v == "none")
_v, _n = P.normalize_reasoning_effort("medium", _meta_qf)
check("supported level passes through untouched", _v == "medium" and not _n, _n)
_v, _n = P.normalize_reasoning_effort("medium", _meta_df)
check("unsupported level maps to the nearest legal one (dfmodel medium->high)",
      _v == "high" and "unsupported" in _n, (_v, _n))
_v, _n = P.normalize_reasoning_effort("xhigh", _meta_df)
check("dfmodel xhigh -> max (nearest to request/default)", _v == "max", (_v, _n))
_v, _n = P.normalize_reasoning_effort("max", _meta_qf)
check("qfmodel max -> xhigh", _v == "xhigh", (_v, _n))
_v, _n = P.normalize_reasoning_effort("high", _meta_qf)
check("qfmodel high -> medium (tie broken toward the default)",
      _v == "medium", (_v, _n))
_v, _n = P.normalize_reasoning_effort("low", _meta_qm)
check("model without levels: effort param is dropped (not sent blindly)",
      _v is None and "dropped" in _n, (_v, _n))
_v, _n = P.normalize_reasoning_effort("none", _meta_qm)
check("model without levels still honours none", _v == "none")
# 路由器（auto 等）目录里没有 thinking_config：不猜测，原样透传
_meta_auto = next(m for m in C.models_for_realm("cn") if m["key"] == "auto")
check("router model without thinking_config passes the value through verbatim",
      P.normalize_reasoning_effort("high", _meta_auto) == ("high", "")
      and P.normalize_reasoning_effort("bogus", _meta_auto) == ("bogus", ""),
      P.normalize_reasoning_effort("high", _meta_auto))
# 未命中取最近合法档位：逐模型校验（同距偏向默认档）
for _key, _want in (("dmodel", {"medium": "high", "xhigh": "max", "low": "high"}),
                    ("gfmodel", {"medium": "high", "xhigh": "max"}),
                    ("kmodel", {"medium": "high", "xhigh": "max"})):
    _m = next(m for m in C.models_for_realm("cn") if m["key"] == _key)
    _got = {e: P.normalize_reasoning_effort(e, _m)[0] for e in _want}
    check("nearest-legal mapping on %s" % _key, _got == _want, (_got, _want))
# Responses API 路径：reasoning.effort / reasoning_effort 都要能到上游
_rchat = P.responses_to_chat({"model": "Qwen3.8-Flash", "input": "hi",
                              "reasoning": {"effort": "xhigh"}})
_rbody = P.build_qoder_body(dict(_rchat, model="Qwen3.8-Flash"), None,
                            "qfmodel", realm="cn")
check("Responses API reasoning.effort reaches upstream (normalized)",
      (_rbody.get("parameters") or {}).get("reasoning_effort") == "xhigh",
      (_rbody.get("parameters") or {}).get("reasoning_effort"))

# build_qoder_body: 端到端确认发到上游的档位已归一化 + thinking.* 兼容
_body_eff = P.build_qoder_body(
    {"model": "dfmodel", "messages": [{"role": "user", "content": "hi"}],
     "reasoning_effort": "medium"}, None, "dfmodel", realm="cn")
check("build_qoder_body sends the normalized effort upstream",
      (_body_eff.get("parameters") or {}).get("reasoning_effort") == "high",
      (_body_eff.get("parameters") or {}).get("reasoning_effort"))
_body_th = P.build_qoder_body(
    {"model": "qfmodel", "messages": [{"role": "user", "content": "hi"}],
     "thinking": {"effort": "xhigh"}}, None, "qfmodel", realm="cn")
check("thinking.effort is accepted as an alias",
      (_body_th.get("parameters") or {}).get("reasoning_effort") == "xhigh",
      (_body_th.get("parameters") or {}).get("reasoning_effort"))
_body_off = P.build_qoder_body(
    {"model": "qmodel", "messages": [{"role": "user", "content": "hi"}],
     "reasoning_effort": "high"}, None, "qmodel", realm="cn")
check("unsupported effort on a level-less model is dropped from the body",
      "reasoning_effort" not in (_body_off.get("parameters") or {}),
      _body_off.get("parameters"))

print()
print("[21] 本机虚拟化检测（中文输出：官方风控桥 vmInfo + 本机交叉校验）")
import qoder_fingerprint as F

check("vm_brand_cn: 已知平台译中文，未知品牌原样",
      F.vm_brand_cn("Hyper-V") == "Hyper-V（微软）"
      and F.vm_brand_cn("VMware, Inc.") == "VMware"
      and F.vm_brand_cn("SomeVendor") == "SomeVendor"
      and F.vm_brand_cn("") == "")
check("风控评分 -> 中文档位（高/中/低/无/未知）",
      [F._vm_level_cn(x) for x in (77, 50, 10, 0, None)]
      == ["高", "中", "低", "无", "未知"])

# 有官方风控结果：以它为权威
_st_vm = F.vm_status(bridge_vm_info={"isVm": True, "brand": "Hyper-V",
                                     "percentage": 77, "vmTypeCode": 14},
                     bridge_available=True)
check("bridge data wins: is_vm/level/score/brand_cn/source",
      _st_vm["is_vm"] is True and _st_vm["level"] == "高"
      and _st_vm["score"] == 77 and _st_vm["brand_cn"] == "Hyper-V（微软）"
      and _st_vm["vm_type_code"] == 14 and _st_vm["source"] == "runtime-info",
      _st_vm)
check("中文结论包含平台与评分",
      "本机运行在虚拟机中" in _st_vm["summary"]
      and "Hyper-V（微软）" in _st_vm["summary"] and "77" in _st_vm["summary"],
      _st_vm["summary"])
check("证据首条为官方风控判定（中文）",
      _st_vm["evidence"] and "官方风控判定" in _st_vm["evidence"][0],
      _st_vm["evidence"][:1])

# 无官方结果：退化为本机交叉校验，结论里明确说明
_st_local = F.vm_status(bridge_vm_info=None, bridge_available=False)
check("no bridge -> local cross-check + 中文说明",
      _st_local["source"] == "local" and isinstance(_st_local["is_vm"], bool)
      and "本机交叉校验" in _st_local["summary"], _st_local["summary"])

# 看板契约：这些键必须都在（前端 /diag/vm 直接消费）
check("dashboard contract keys present",
      set(("is_vm", "level", "score", "brand", "brand_cn", "vm_type_code",
           "source", "evidence", "summary")) <= set(_st_vm.keys()),
      sorted(_st_vm.keys()))
_st_api = A.local_vm_status("cn", force=True)
check("A.local_vm_status adds realm + bridge_available",
      _st_api.get("realm") in ("cn", "intl")
      and isinstance(_st_api.get("bridge_available"), bool), 
      (A.local_vm_status("cn") is not None, _st_api.get("bridge_available")))

# /diag/* 必须走面板鉴权（此前漏加会被无鉴权读取）
_src21 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "qoder_proxy.py"), encoding="utf-8").read()
check("/diag routes are panel-guarded",
      'if path.startswith("/diag"):' in _src21
      and _src21.find('if path.startswith("/diag"):')
      < _src21.find('return False', _src21.find('def _is_panel_route')),
      "guard missing" if 'if path.startswith("/diag"):' not in _src21 else "")

print()
print("[22] 面板加速（短缓存 / 区域分区）与新版本检测")
check("version_tuple 容忍 v 前缀与不足位数",
      P.version_tuple("v1.2.3") == (1, 2, 3)
      and P.version_tuple("1.1") == (1, 1, 0)
      and P.version_tuple("") == (0, 0, 0))
check("新版本比较：更高/相同/更低",
      P.version_tuple("v1.2.0") > P.version_tuple("1.1.4")
      and P.version_tuple("v1.1.4") == P.version_tuple("1.1.4")
      and P.version_tuple("1.0.9") < P.version_tuple("1.1.0"))

_orig_urlopen_u = P.urllib.request.urlopen


class _UpdResp(object):
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_release(tag):
    return {"tag_name": tag, "html_url": "https://example.invalid/rel/" + tag,
            "published_at": "2026-10-01T00:00:00Z", "name": "rel " + tag}


P.urllib.request.urlopen = lambda req, timeout=None: _UpdResp(_fake_release("v9.9.9"))
_up_new = P.check_for_update(force=True)
P.urllib.request.urlopen = lambda req, timeout=None: _UpdResp(_fake_release("v" + P.VERSION))
_up_same = P.check_for_update(force=True)


def _boom(req, timeout=None):
    raise OSError("network down")


P.urllib.request.urlopen = _boom
_up_err = P.check_for_update(force=True)
P.urllib.request.urlopen = _orig_urlopen_u
check("check_for_update: 检测到更高版本 -> has_update",
      _up_new["ok"] and _up_new["has_update"] and _up_new["latest"] == "v9.9.9", _up_new)
check("check_for_update: 同版本 -> 无更新", _up_same["ok"] and not _up_same["has_update"])
check("check_for_update: 网络失败 -> ok=False + error（不误报有更新）",
      _up_err["ok"] is False and bool(_up_err["error"])
      and not _up_err["has_update"], _up_err)
_src22 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()
check("/update 路由纳入面板鉴权",
      'if path.startswith("/update"):' in _src22)
check("/tasks 支持 ?realm= 区域过滤（账号池分区）",
      'view = qoder_tasks.fetch_tasks_view(POOL, realm=realm_q, uid=uid)' in _src22)

T.invalidate_panel_cache()
_hits22 = {"campaigns": 0}


class _Acc22(object):
    uid = "cache22"
    realm = "cn"

    def campaigns(self, force=False):
        _hits22["campaigns"] += 1
        return {"ok": True, "available": True, "show_campaign": True,
                "claimable": False, "campaign_url": "", "campaigns": []}

    def checkin_status(self):
        return False, {"unavailable": True, "error": "nf"}

    def pro_eligibility(self):
        return False, "nf"

    def fetch_credits(self):
        return {"ok": True}

    def fetch_plan(self):
        return ""


_a22 = _Acc22()
T._fetch_upstream_parallel(_a22)
T._fetch_upstream_parallel(_a22)
check("面板短缓存：TTL 内第二次不再打上游",
      _hits22["campaigns"] == 1, _hits22)
T.invalidate_panel_cache()
T._fetch_upstream_parallel(_a22)
check("invalidate_panel_cache：失效后重新取",
      _hits22["campaigns"] == 2, _hits22)
T.invalidate_panel_cache()

_p22 = A.AccountPool(os.path.join(os.environ["ACCOUNTS_DIR"], "unused22"))
_cn22 = A.Account({"uid": "cn22", "realm": "cn", "accessToken": "dt-x"})
_intl22 = A.Account({"uid": "intl22", "realm": "intl", "accessToken": "dt-y"})
_p22.accounts = [_intl22, _cn22]
_orig_ftv = T.fetch_task_view
T.fetch_task_view = lambda acc: ([], {"campaigns": {}})
try:
    _v_cn = T.fetch_tasks_view(_p22, realm="cn")
    _v_intl = T.fetch_tasks_view(_p22, realm="intl")
    _v_all = T.fetch_tasks_view(_p22)
finally:
    T.fetch_task_view = _orig_ftv
check("fetch_tasks_view(realm=cn) 只列国内版账号",
      [a["realm"] for a in _v_cn["accounts"]] == ["cn"], _v_cn["accounts"])
check("fetch_tasks_view(realm=intl) 只列国际版账号",
      [a["realm"] for a in _v_intl["accounts"]] == ["intl"], _v_intl["accounts"])
check("不传 realm 时保持原行为（全部账号）",
      len(_v_all["accounts"]) == 2, _v_all["accounts"])

print()
print("[23] 兑换码/券类活动（奶茶免单卡 act-20260928-620）")
# --- 23.1 领取响应：捕获 redemptionCode 并持久化 ---
_orig_hj23 = A.http_json


def _fake_claim_code(url, **kw):
    return {"status": "CLAIMED", "replayed": False,
            "grantId": "g-coffee", "redemptionCode": "MT-ABCD-1234",
            "benefit": {"kind": "REDEMPTION_CODE", "amount": 1}}


A.http_json = _fake_claim_code
_acc23 = A.Account({"uid": "coffee23", "realm": "cn", "accessToken": "dt-x"})
_res23 = _acc23.claim_campaign("c-coffee")
A.http_json = _orig_hj23
check("claim 响应捕获兑换码", _res23["ok"] and _res23["redemption_code"] == "MT-ABCD-1234",
      _res23)
check("兑换码写入账号（可持久化，重启不丢）",
      _acc23.campaign_codes.get("c-coffee") == "MT-ABCD-1234"
      and _acc23.to_dict().get("campaignCodes", {}).get("c-coffee") == "MT-ABCD-1234",
      _acc23.campaign_codes)
_acc23b = A.Account(_acc23.to_dict())
check("新 Account 能读回兑换码",
      _acc23b.campaign_codes.get("c-coffee") == "MT-ABCD-1234")
check("领取成功消息带上兑换码", "兑换码" in _res23["message"], _res23["message"])

# --- 23.2 CLAIMED 但无码 -> 发放确认中 ---
def _fake_claim_nocode(url, **kw):
    return {"status": "CLAIMED", "replayed": False, "grantId": "g2",
            "benefit": {"kind": "REDEMPTION_CODE", "amount": 1}}


A.http_json = _fake_claim_nocode
_res23b = _acc23.claim_campaign("c-coffee2")
check("CLAIMED 无兑换码 -> confirming 标记", _res23b.get("confirming") is True, _res23b)
A.http_json = _orig_hj23

# --- 23.3 失败码映射（名额发完 / 成就未完成）---
def _fake_claim_oos(url, **kw):
    return {"status": "NOT_ELIGIBLE", "failureCode": "REDEMPTION_CODE_OUT_OF_STOCK"}


A.http_json = _fake_claim_oos
_res23c = _acc23.claim_campaign("c-coffee")
A.http_json = _orig_hj23
check("名额发完 -> 失败码 + 中文说明",
      not _res23c["ok"] and _res23c["failure_code"] == "REDEMPTION_CODE_OUT_OF_STOCK"
      and "名额已发完" in _res23c["message"], _res23c)

# --- 23.4 campaign_checkin 分类：pending / locked / codes ---
_orig_camp23 = A.Account.campaigns
_orig_native23 = A.native_machine_identity


def _stub_campains23(self, force=False):
    return {"ok": True, "available": True, "show_campaign": True, "claimable": False,
            "campaign_url": "https://openapi.qoder.com.cn/growth-page/activity-iframe",
            "identity": "runtime-info",
            "campaigns": [
                {"campaign_id": "c-daily", "campaign_key": "act-daily",
                 "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMED",
                 "start_at": 0, "end_at": 0,
                 "benefit": {"kind": "CREDITS", "amount": 100},
                 "required_achievement_key": "", "achievement_completed": True,
                 "unavailable_reason": "", "placements": []},
                {"campaign_id": "c-coffee", "campaign_key": "act-20260928-620",
                 "action_type": "CLAIM_BENEFIT", "claim_status": "NOT_ELIGIBLE",
                 "start_at": 0, "end_at": 0,
                 "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                 "required_achievement_key": "sites_first_use",
                 "achievement_completed": True,
                 "unavailable_reason": "REDEMPTION_CODE_OUT_OF_STOCK",
                 "placements": []},
                {"campaign_id": "c-task", "campaign_key": "act-locked",
                 "action_type": "CLAIM_BENEFIT", "claim_status": "NOT_ELIGIBLE",
                 "start_at": 0, "end_at": 0,
                 "benefit": {"kind": "CREDITS", "amount": 50},
                 "required_achievement_key": "goal_first_use",
                 "achievement_completed": False,
                 "unavailable_reason": "ACHIEVEMENT_NOT_COMPLETED",
                 "placements": []}]}


A.Account.campaigns = _stub_campains23
A.native_machine_identity = lambda realm, uid, force=False: {
    "machineToken": "t", "machineType": "ty", "machineCode": "c", "source": "runtime-info"}
_acc23c = A.Account({"uid": "coffee23c", "realm": "cn", "accessToken": "dt-x"})
try:
    _res23d = _acc23c.campaign_checkin(gap=0)
finally:
    A.Account.campaigns = _orig_camp23
    A.native_machine_identity = _orig_native23
check("名额发完的活动进 pending（不是被当成无活动）",
      [c["campaign_key"] for c in _res23d["pending"]] == ["act-20260928-620"],
      _res23d.get("pending"))
check("成就未完成的活动进 locked",
      [c["campaign_key"] for c in _res23d["locked"]] == ["act-locked"],
      _res23d.get("locked"))
check("结论里带次日重试提示", "次日 10:00" in _res23d["message"], _res23d["message"])

# --- 23.5 独立任务行（奶茶免单卡）+ 兑换码回显 ---
_orig_camp23b = A.Account.campaigns
A.Account.campaigns = _stub_campains23
_acc23e = A.Account({"uid": "coffee23e", "realm": "cn", "accessToken": "dt-x"})
_acc23e.campaign_codes = {"c-coffee": "MT-ZZZZ-9999"}
try:
    _rows23 = T._extra_campaign_rows(_acc23e, _acc23e.campaigns())
finally:
    A.Account.campaigns = _orig_camp23b
_codes23 = [r["task_code"] for r in _rows23]
check("券类活动单独成行（只含非 Credits 奖励）",
      _codes23 == ["campaign:act-20260928-620"], _codes23)
_crow = _rows23[0]
check("行内含中文名额状态 + 奖励文本",
      "名额已发完" in _crow["description"] and _crow["reward_text"] == "兑换码 ×1",
      _crow)
check("券类行不误报积分", _crow["reward_credit"] == 0, _crow["reward_credit"])


def _stub_campains_claimed23(self, force=False):
    out = _stub_campains23(self, force)
    out["campaigns"][1]["claim_status"] = "CLAIMED"
    out["campaigns"][1]["unavailable_reason"] = ""
    return out


A.Account.campaigns = _stub_campains_claimed23
try:
    _rows23b = T._extra_campaign_rows(_acc23e, _acc23e.campaigns())
finally:
    A.Account.campaigns = _orig_camp23b
check("已领取的券类活动回显兑换码",
      _rows23b[0]["status"] == "claimed"
      and "MT-ZZZZ-9999" in _rows23b[0]["description"], _rows23b[0])

# --- 23.6 多账号：同人已领 -> 冷却，不再重复 POST ---
_orig_camp23c = A.Account.campaigns
_orig_claim23 = A.Account.claim_campaign
_orig_native23b = A.native_machine_identity
_posts = []


def _stub_camp_claimable23(self, force=False):
    return {"ok": True, "available": True, "show_campaign": True, "claimable": True,
            "campaign_url": "", "identity": "runtime-info",
            "campaigns": [{"campaign_id": "c-cup", "campaign_key": "act-cup",
                           "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                           "start_at": 0, "end_at": 0,
                           "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                           "required_achievement_key": "", "achievement_completed": True,
                           "unavailable_reason": "", "placements": []}]}


def _stub_claim_blocked23(self, campaign_id):
    _posts.append(campaign_id)
    return {"ok": False, "blocked": True, "status": "BLOCKED",
            "failure_code": "SAME_PERSON_ALREADY_CLAIMED",
            "message": "同人已领取"}


A.Account.campaigns = _stub_camp_claimable23
A.Account.claim_campaign = _stub_claim_blocked23
A.native_machine_identity = lambda realm, uid, force=False: {
    "machineToken": "t", "machineType": "ty", "machineCode": "c", "source": "runtime-info"}
_acc23f = A.Account({"uid": "multi23", "realm": "cn", "accessToken": "dt-x"})
try:
    _r1 = _acc23f.campaign_checkin(gap=0)
    _r2 = _acc23f.campaign_checkin(gap=0)      # 冷却内：不应再 POST
finally:
    A.Account.campaigns = _orig_camp23c
    A.Account.claim_campaign = _orig_claim23
    A.native_machine_identity = _orig_native23b
check("同人已领 -> 记录冷却并如实上报（不是失败）",
      _r1["ok"] and _r1["blocked"] and _r1["blocked"][0]["failure_code"]
      == "SAME_PERSON_ALREADY_CLAIMED", _r1.get("blocked"))
check("冷却内的第二次不再重复 POST（多账号同机器不空转）",
      _posts == ["c-cup"], _posts)
check("冷却写入账号（可持久化）",
      _acc23f.campaign_blocked_until.get("c-cup", 0) > time.time()
      and _acc23f.campaign_blocked_until.get("c-cup", 0)
      <= time.time() + 6 * 3600 + 5, _acc23f.campaign_blocked_until)

# --- 23.7 summary.codes：按账号暴露已领兑换码 ---
_orig_ftv23 = T._fetch_upstream_parallel
T._fetch_upstream_parallel = lambda account, force=False: (
    {"ok": True, "available": True, "show_campaign": True, "claimable": False,
     "campaign_url": "", "identity": "runtime-info", "campaigns": []},
    (False, {"error": "nf"}), (False, "nf"), {"ok": True}, "")
_acc23g = A.Account({"uid": "codes23", "realm": "cn", "accessToken": "dt-x"})
_acc23g.campaign_codes = {"c-cup": "MT-1111-2222"}
try:
    _t23g, _s23g = T.fetch_task_view(_acc23g)
finally:
    T._fetch_upstream_parallel = _orig_ftv23
check("summary.codes 按账号给出兑换码",
      _s23g.get("codes") == [{"campaign": "c-cup", "code": "MT-1111-2222"}],
      _s23g.get("codes"))

print()
print("[24] 全部账号视图：按活动聚合 + 每账号资格明细 + 多账号各自独立领取")
# --- 24.1 聚合：能领的、名额发完的、无资格的三种账号同屏列出 ---
_orig_camp24 = A.Account.campaigns
_orig_native24 = A.native_machine_identity


def _camp_for(uid):
    base = {"ok": True, "available": True, "show_campaign": True,
            "claimable": False, "campaign_url": "https://openapi.qoder.com.cn/growth-page/activity-iframe",
            "identity": "runtime-info", "campaigns": []}
    if uid == "a24":            # 有资格，可领
        base["campaigns"] = [{"campaign_id": "c-cup", "campaign_key": "act-cup",
                              "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                              "start_at": 0, "end_at": 0,
                              "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                              "required_achievement_key": "", "achievement_completed": True,
                              "unavailable_reason": "", "placements": []}]
    elif uid == "b24":          # 有资格但名额发完
        base["campaigns"] = [{"campaign_id": "c-cup", "campaign_key": "act-cup",
                              "action_type": "CLAIM_BENEFIT", "claim_status": "NOT_ELIGIBLE",
                              "start_at": 0, "end_at": 0,
                              "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                              "required_achievement_key": "", "achievement_completed": True,
                              "unavailable_reason": "REDEMPTION_CODE_OUT_OF_STOCK",
                              "placements": []}]
    return base                    # c24：列表里没有该活动 = 无资格


A.Account.campaigns = lambda self, force=False: _camp_for(self.uid[:3])
A.native_machine_identity = lambda realm, uid, force=False: {
    "machineToken": "t", "machineType": "ty", "machineCode": "c", "source": "runtime-info"}
_a24 = A.Account({"uid": "a24", "realm": "cn", "accessToken": "dt-x", "nickname": "可领号"})
_b24 = A.Account({"uid": "b24", "realm": "cn", "accessToken": "dt-x", "nickname": "补货号"})
_c24 = A.Account({"uid": "c24", "realm": "cn", "accessToken": "dt-x", "nickname": "无资格号"})
_b24.campaign_codes = {"c-cup": "MT-FROM-B24"}
try:
    _rows24, _codes24 = T.aggregate_campaign_rows([_a24, _b24, _c24])
finally:
    A.Account.campaigns = _orig_camp24
    A.native_machine_identity = _orig_native24
check("聚合为每个活动一行（3 个账号只出 1 行活动）",
      len(_rows24) == 1 and _rows24[0]["task_code"] == "campaign:act-cup", _rows24)
_desc24 = _rows24[0]["description"]
check("描述里逐账号标注：可领/名额发完/无资格",
      "可领 1/3：可领号" in _desc24 and "名额发完 1/3：补货号" in _desc24
      and "无资格(不在定向) 1/3：无资格号" in _desc24, _desc24)
check("聚合行状态：有可领账号 -> 待领奖",
      _rows24[0]["status"] == "completed" and _rows24[0]["reward_text"] == "兑换码 ×1",
      _rows24[0])
check("聚合结果按账号收集已领兑换码",
      _codes24 and _codes24[0]["code"] == "MT-FROM-B24"
      and _codes24[0]["nickname"] == "补货号"
      and _codes24[0]["realm"] == "cn", _codes24)

# --- 24.2 关键语义：上游没返回 SAME_PERSON_ALREADY_CLAIMED -> 各账号都能领 ---
_orig_camp24b = A.Account.campaigns
_orig_claim24 = A.Account.claim_campaign
_orig_native24b = A.native_machine_identity
_calls24 = []


def _camp_claimable24(self, force=False):
    return {"ok": True, "available": True, "show_campaign": True, "claimable": True,
            "campaign_url": "", "identity": "runtime-info",
            "campaigns": [{"campaign_id": "c-cup-" + self.uid,
                           "campaign_key": "act-cup",
                           "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                           "start_at": 0, "end_at": 0,
                           "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                           "required_achievement_key": "", "achievement_completed": True,
                           "unavailable_reason": "", "placements": []}]}


def _claim_http24(url, data=None, method=None, headers=None, timeout=None,
                  retries=None, log=None):
    # 只打桩 HTTP 层：让真实的 claim_campaign（含兑换码提取/落盘）跑起来
    cid = url.rsplit("/", 2)[-2]
    _calls24.append((headers.get("cosy-user", "?"), cid))
    return {"status": "CLAIMED", "replayed": False, "grantId": "g-" + cid,
            "redemptionCode": "CODE-" + cid.split("-")[-1],
            "benefit": {"kind": "REDEMPTION_CODE", "amount": 1}}


_orig_http24 = A.http_json
A.Account.campaigns = _camp_claimable24
A.http_json = _claim_http24
A.native_machine_identity = lambda realm, uid, force=False: {
    "machineToken": "t", "machineType": "ty", "machineCode": "c", "source": "runtime-info"}
try:
    _x24 = A.Account({"uid": "X24", "realm": "cn", "accessToken": "dt-x"})
    _y24 = A.Account({"uid": "Y24", "realm": "cn", "accessToken": "dt-x"})
    _rx24 = _x24.campaign_checkin(gap=0)
    _ry24 = _y24.campaign_checkin(gap=0)
finally:
    A.Account.campaigns = _orig_camp24b
    A.http_json = _orig_http24
    A.native_machine_identity = _orig_native24b
check("同机器两个账号：上游未判同人 -> 两个账号都发起领取",
      [c[1] for c in _calls24] == ["c-cup-X24", "c-cup-Y24"], _calls24)
check("各自拿到自己的兑换码（互不覆盖）",
      _x24.campaign_codes.get("c-cup-X24") == "CODE-X24"
      and _y24.campaign_codes.get("c-cup-Y24") == "CODE-Y24",
      (_x24.campaign_codes, _y24.campaign_codes))
check("两条都算领取成功（没有被我方预判拦截）",
      _rx24["claimed"] and _ry24["claimed"]
      and not _rx24["blocked"] and not _ry24["blocked"],
      (_rx24.get("blocked"), _ry24.get("blocked")))

print()
print("[25] 活动中文名 / 每日签到只领积分 / 领取全部福利")
# --- 25.1 中文名：官方标题优先，其次兜底表，最后 kind 兜底 ---
check("campaign_title: 官方 content.zh.title 优先",
      T.campaign_title({"title_zh": "发布 Qoder 站点，免费领取奶茶免单卡",
                        "campaign_key": "act-x"}) == "发布 Qoder 站点，免费领取奶茶免单卡")
check("campaign_title: 已知 key 走内置兜底",
      T.campaign_title({"campaign_key": "act-20260928-620"})
      == "新人任务：发布 Qoder 站点领奶茶免单卡", 
      T.campaign_title({"campaign_key": "act-20260928-620"}))
check("campaign_title: 前缀兜底（每日 100）",
      T.campaign_title({"campaign_key": "act-20260930-999"}) == "每天领 100 Credits")
check("campaign_title: 未知 key 按奖励类型兜底",
      T.campaign_title({"campaign_key": "act-unknown-1",
                        "benefit": {"kind": "REDEMPTION_CODE"}}) == "限时活动（兑换码）"
      and T.campaign_title({"campaign_key": "act-unknown-2",
                            "benefit": {"kind": "CREDITS"}}) == "限时活动（Credits）")

# --- 25.2 账号面板「每日签到」只领积分：券类活动不被触碰 ---
_orig_camp25 = A.Account.campaigns
_orig_claim25 = A.Account.claim_campaign
_orig_native25 = A.native_machine_identity
_posts25 = []


def _camp_mixed25(self, force=False):
    return {"ok": True, "available": True, "show_campaign": True, "claimable": True,
            "campaign_url": "", "identity": "runtime-info",
            "campaigns": [
                {"campaign_id": "c-daily", "campaign_key": "act-daily",
                 "title_zh": "每天领 100 Credits",
                 "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                 "start_at": 0, "end_at": 0,
                 "benefit": {"kind": "CREDITS", "amount": 100},
                 "required_achievement_key": "", "achievement_completed": True,
                 "unavailable_reason": "", "placements": []},
                {"campaign_id": "c-cup", "campaign_key": "act-cup",
                 "title_zh": "发布 Qoder 站点，免费领取奶茶免单卡",
                 "action_type": "CLAIM_BENEFIT", "claim_status": "CLAIMABLE",
                 "start_at": 0, "end_at": 0,
                 "benefit": {"kind": "REDEMPTION_CODE", "amount": 1},
                 "required_achievement_key": "", "achievement_completed": True,
                 "unavailable_reason": "", "placements": []}]}


def _claim_spy25(self, campaign_id):
    _posts25.append(campaign_id)
    return {"ok": True, "status": "CLAIMED", "replayed": False, "amount": 100,
            "redemption_code": "CODE-1" if "cup" in campaign_id else "",
            "message": "领取成功"}


A.Account.campaigns = _camp_mixed25
A.Account.claim_campaign = _claim_spy25
A.native_machine_identity = lambda realm, uid, force=False: {
    "machineToken": "t", "machineType": "ty", "machineCode": "c", "source": "runtime-info"}
try:
    _acc25 = A.Account({"uid": "daily25", "realm": "cn", "accessToken": "dt-x"})
    _r_daily = _acc25.campaign_checkin(gap=0, only_kinds=("", "CREDITS"))
    _posts25.clear()
    _r_all = _acc25.campaign_checkin(gap=0)
finally:
    A.Account.campaigns = _orig_camp25
    A.Account.claim_campaign = _orig_claim25
    A.native_machine_identity = _orig_native25
check("only_kinds=CREDITS：只领每日积分，不碰券类活动",
      _r_daily["claimed"] and len(_r_daily["claimed"]) == 1
      and _r_daily["claimed"][0]["campaign_key"] == "act-daily", _r_daily.get("claimed"))
check("不带 only_kinds：积分与券类都领",
      [c["campaign_key"] for c in _r_all["claimed"]] == ["act-daily", "act-cup"],
      [c["campaign_key"] for c in _r_all["claimed"]])

# --- 25.3 面板/接口接线：账号面板走 only_daily，福利中心走全量 ---
_src25 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()
check("账号面板 /accounts/checkin 只做每日签到，且间隔传 CHECKIN_MIN_GAP 常量本身",
      # 恢复被弱化的精确语义：调用点必须写 CHECKIN_MIN_GAP，常量定义值必须与
      # **运行时** P.CHECKIN_MIN_GAP 一致（引用运行时值，不把 1.0 硬编码进字符串，
      # 下次调间隔只改实现一处）。
      "run_checkin(account, gap=CHECKIN_MIN_GAP" in _src25
      and "only_daily=True" in _src25
      and ("CHECKIN_MIN_GAP = %r" % P.CHECKIN_MIN_GAP) in _src25)
check("签到与福利中心 /tasks/run 仍是全量领取",
      "run_batch_checkin(targets, gap=1.0)" in _src25)
_dash25 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "dashboard.html"), encoding="utf-8").read()
check("按钮文案：领取全部福利 / 仅领 Pro 福利包",
      ">领取全部福利<" in _dash25 and ">仅领 Pro 福利包<" in _dash25
      and "一键签到领积分" not in _dash25)
check("领取全部福利 = 活动全量 + Pro 福利包（run + travel）",
      'postJSON("/tasks/run"' in _dash25 and 'postJSON("/tasks/travel"' in _dash25)

print()
print("[26] PR#7 合并回归：信封层 403(10605 排队) -> 账号冷却 + 解绑 + 轮换")
class _Aff26:
    def __init__(self): self.calls = []
    def unbind(self, key): self.calls.append(key)
class _Pool26:
    def __init__(self):
        self.affinity = _Aff26(); self.accounts = [1, 2, 3]
class _Acc26:
    def __init__(self):
        self.uid = "pr7acc12"; self.enabled = True; self.notes = []; self.saved = 0
        self.path = ""
    def note_error(self, msg, cooldown=60, single_account=False, model=None, until=None):
        self.notes.append({"msg": str(msg)[:60], "cooldown": cooldown, "model": model})
    def save(self, d): self.saved += 1
class _UpErr26(Exception):
    def __init__(self, status, detail):
        self.status = status; self.detail = detail

_orig_pool26 = P.POOL
_acc26 = _Acc26()
P.POOL = _Pool26()
P.ACCOUNTS_DIR = os.environ["ACCOUNTS_DIR"]
try:
    P._handle_envelope_account_cooldown(_acc26, _UpErr26(
        403, '{"code":"10605","message":"{\"isQueued\":true,\"retryAfterSeconds\": 30}"}'),
        model="qfmodel", session_key="sk-pr7")
    _n1 = _acc26.notes[-1]
    P._handle_envelope_account_cooldown(_acc26, _UpErr26(403, "permission denied"),
                                        model="qfmodel", session_key="sk-pr7")
    _n2 = _acc26.notes[-1]
    P._handle_envelope_account_cooldown(_acc26, _UpErr26(429, "rate limit"),
                                        model="qfmodel", session_key="sk-pr7")
    _n3 = _acc26.notes[-1]
    _acc26.enabled = True
    P._handle_envelope_account_cooldown(_acc26, _UpErr26(401, "TOKEN_EXPIRE session dead"),
                                        model=None, session_key="sk-pr7")
    _n4 = _acc26.notes[-1]
    _aff26_calls = list(P.POOL.affinity.calls)
finally:
    P.POOL = _orig_pool26
check("10605 排队 -> 模型级冷却 30s（按上游 retryAfterSeconds）+ 解绑会话",
      _n1["cooldown"] == 30 and _n1["model"] == "qfmodel"
      and set(_aff26_calls) == {"sk-pr7"} and len(_aff26_calls) >= 1,
      (_n1, _aff26_calls))
check("403 非排队 -> 账号级冷却 60s", _n2["cooldown"] == 60 and _n2["model"] is None, _n2)
check("429 -> 模型级冷却 30s", _n3["cooldown"] == 30 and _n3["model"] == "qfmodel", _n3)
check("死会话 -> 300s + 停用账号（与 open_upstream 同语义）",
      _acc26.enabled is False and _n4["cooldown"] == 300, _n4)
for st, detail, want in ((403, "10605", True), (401, "x", True), (429, "x", True),
                         (418, "DataInspectionFailed", False),
                         (400, "invalid_parameter_error", False), (500, "x", True)):
    got = P.should_retry_envelope(P.UpstreamStatus(st, detail), False, 0)
    check("未吐字节可重开：%s -> %s" % (st, want), got is want, (st, got))
_src26 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()
check("三处信封捕获点都接入账号冷却",
      _src26.count("_handle_envelope_account_cooldown(") >= 4,
      _src26.count("_handle_envelope_account_cooldown("))

print()
print("[27] 泄漏文本回读（issue #8：模型照格式复述 tool_calls 序列化）")
_M27 = P.LEAK_MARKER
_CALLS27 = json.dumps([{"name": "terminal",
                        "arguments": json.dumps({"cmd": "ls"}, ensure_ascii=False)}],
                      ensure_ascii=False)
_LEAK27 = _M27 + "\n" + _CALLS27

_rec27, _clean27 = P.parse_leaked_tool_calls(_LEAK27, {"terminal"})
check("严格形态：marker+JSON 数组 -> 还原为结构化调用且正文清空",
      bool(_rec27) and _clean27 == ""
      and _rec27[0]["function"]["name"] == "terminal"
      and json.loads(_rec27[0]["function"]["arguments"])["cmd"] == "ls",
      (_rec27, _clean27))
check("围栏形态（```json ... ```）同样还原",
      bool(P.parse_leaked_tool_calls("```json\n" + _LEAK27 + "\n```", {"terminal"})[0]))
check("无语言标记围栏（``` ... ```）同样还原",
      bool(P.parse_leaked_tool_calls("```\n" + _LEAK27 + "\n```", {"terminal"})[0]))
check("普通正文（讨论该标记）不误判",
      P.parse_leaked_tool_calls("网关会写入 " + _M27 + " 这样的提示，不是调用。")[0] is None)
check("数组后带多余文本不还原",
      P.parse_leaked_tool_calls(_LEAK27 + "\n以上。", {"terminal"})[0] is None)
check("未声明的工具名不还原（守卫：只认本次声明的 tools）",
      P.parse_leaked_tool_calls(_LEAK27, {"other"})[0] is None)
check("空数组不还原", P.parse_leaked_tool_calls(_M27 + "\n[]")[0] is None)
check("arguments 为对象 -> 规范化为 JSON 字符串",
      json.loads(P.parse_leaked_tool_calls(
          _M27 + "\n" + json.dumps([{"name": "t", "arguments": {"a": 1}}],
                                   ensure_ascii=False),
          {"t"})[0][0]["function"]["arguments"]) == {"a": 1})
check("arguments 非法 JSON 字符串 -> 不还原",
      P.parse_leaked_tool_calls(
          _M27 + "\n" + json.dumps([{"name": "t", "arguments": "{not-json"}]),
          {"t"})[0] is None)
check("声明工具名提取兼容 chat 与 responses 两种 tools 形态",
      P._tool_names_from_payload({"tools": [
          {"type": "function", "function": {"name": "a"}},
          {"type": "function", "name": "b"}]}) == {"a", "b"})


def _raw27(content=None, fin=None, **kw):
    delta = {}
    if content is not None:
        delta["content"] = content
    delta.update(kw)
    inner = {"id": "c27", "model": "m27", "created": 1, "choices": [
        {"index": 0, "delta": delta, "finish_reason": fin}]}
    return ("data: " + json.dumps(inner, ensure_ascii=False)
            + "\n\n").encode("utf-8")


def _env27(content=None, fin=None, **kw):
    inner = json.loads(_raw27(content, fin, **kw)[6:])
    return ("data: " + json.dumps(
        {"statusCodeValue": 200, "body": json.dumps(inner, ensure_ascii=False)},
        ensure_ascii=False) + "\n\n").encode("utf-8")


class _Resp27:
    def __init__(self, items):
        self.items = list(items)

    def __iter__(self):
        return iter(self.items)

    def close(self):
        pass


_obj27 = P.aggregate_stream(
    _Resp27([_env27(_LEAK27[:12]), _env27(_LEAK27[12:]),
             _env27("", "stop")]),
    "m27", None, allowed_names={"terminal"})
_msg27 = _obj27["choices"][0]["message"]
check("非流式聚合：泄漏正文 -> 结构化 tool_calls，finish_reason=tool_calls",
      _obj27["choices"][0]["finish_reason"] == "tool_calls"
      and _msg27.get("content") == ""
      and ((_msg27.get("tool_calls") or [{}])[0].get("function")
           or {}).get("name") == "terminal", _obj27)

_frames27 = [json.loads(f[6:]) for f in P.recover_leaked_tool_calls(
    iter([_raw27(_LEAK27[:9]), _raw27(_LEAK27[9:]), _raw27("", "stop")]),
    {"terminal"})]
_c27 = [_f["choices"][0] for _f in _frames27]
check("流式：marker 跨增量分段仍回读为 tool_calls 增量 + 收尾帧改写",
      not any(_d.get("delta", {}).get("content") for _d in _c27)
      and any(_d.get("delta", {}).get("tool_calls") for _d in _c27)
      and _c27[-1]["finish_reason"] == "tool_calls", _c27)

_frames27b = [json.loads(f[6:]) for f in P.recover_leaked_tool_calls(
    iter([_raw27("[1, 2"), _raw27(", 3] 这是正文"), _raw27("", "stop")]))]
check("流式：以 [ 开头但被证伪 -> 原样补发正文，不改 finish",
      "".join(_f["choices"][0]["delta"].get("content") or ""
              for _f in _frames27b) == "[1, 2, 3] 这是正文"
      and _frames27b[-1]["choices"][0]["finish_reason"] == "stop", _frames27b)

_frames27c = [json.loads(f[6:]) for f in P.recover_leaked_tool_calls(
    iter([_raw27(_LEAK27), _raw27("", "stop")]), {"other_tool"})]
check("流式：未声明工具名 -> 不吞正文，按普通文本透传",
      "".join(_f["choices"][0]["delta"].get("content") or ""
              for _f in _frames27c) == _LEAK27, _frames27c)

_ev27 = [f.decode() for f in P.stream_responses_events(
    iter([_raw27(_LEAK27), _raw27("", "stop")]), "m27",
    {"usage": None, "custom_names": set(), "allowed_names": {"terminal"}})]
_parsed27 = [json.loads(_ln[6:]) for _fr in _ev27
             for _ln in _fr.splitlines() if _ln.startswith("data: ")]
_text27 = "".join(e.get("delta") or "" for e in _parsed27
                  if e.get("type") == "response.output_text.delta")
_fc27 = [e["item"] for e in _parsed27
         if e.get("type") == "response.output_item.done"
         and (e.get("item") or {}).get("type") == "function_call"]
check("Responses 流式：泄漏不回显为 output_text，转为 function_call 项",
      _text27 == "" and _fc27 and _fc27[0].get("name") == "terminal",
      (_text27, _fc27))

_src27 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()
check("写入侧只引用 LEAK_MARKER 常量（无重复字面量）",
      _src27.count(json.dumps(P.LEAK_MARKER, ensure_ascii=False)) == 1
      and "LEAK_MARKER + " in _src27,
      _src27.count(json.dumps(P.LEAK_MARKER, ensure_ascii=False)))

print()
print("[27.5] issue #9：截断的 marker+JSON 回声必须吞掉、不得透传（P0）")
_TRUNC27 = _M27 + "\n" + _CALLS27[:40]      # 未闭合字符串的截断回声（issue #9 样本形态）
check("判据：截断数组 -> True",
      P._leaked_partial_droppable(_TRUNC27, {"terminal"}) is True)
check("判据：只有 marker -> True",
      P._leaked_partial_droppable(_M27, {"terminal"}) is True)
check("判据：围栏 + 截断数组 -> True",
      P._leaked_partial_droppable("```json\n" + _TRUNC27, {"terminal"}) is True)
check("判据：marker + 散文 -> False",
      P._leaked_partial_droppable(_M27 + "\n这是一段解释文字。",
                                 {"terminal"}) is False)
check("判据：不以 marker 开头的讨论回复 -> False",
      P._leaked_partial_droppable("网关会写入 " + _M27 + " 这样的提示。",
                                 {"terminal"}) is False)
check("判据：未声明 tools / 空 names -> False",
      P._leaked_partial_droppable(_TRUNC27, None) is False
      and P._leaked_partial_droppable(_TRUNC27, set()) is False)
check("判据：完整但未声明工具名的数组 -> False（保持 fail-open 透传）",
      P._leaked_partial_droppable(_LEAK27, {"other"}) is False)

_frames_trunc = [json.loads(f[6:]) for f in P.recover_leaked_tool_calls(
    iter([_raw27(_TRUNC27[:12]), _raw27(_TRUNC27[12:]), _raw27("", "stop")]),
    {"terminal"})]
_text_trunc = "".join(_f["choices"][0]["delta"].get("content") or ""
                      for _f in _frames_trunc)
check("流式：截断回声被吞（正文既无 marker、也无 terminal 明文）",
      _text_trunc == ""
      and P.LEAK_MARKER not in json.dumps(_frames_trunc, ensure_ascii=False),
      _text_trunc)
check("流式：吞掉后 finish_reason 仍为 stop（Lead 裁定）",
      _frames_trunc[-1]["choices"][0]["finish_reason"] == "stop",
      _frames_trunc)

_obj_trunc = P.aggregate_stream(
    _Resp27([_env27(_TRUNC27[:12]), _env27(_TRUNC27[12:]), _env27("", "stop")]),
    "m27", None, allowed_names={"terminal"})
_msg_trunc = _obj_trunc["choices"][0]["message"]
check("非流式：截断回声 -> content 清空、无 tool_calls、finish=stop",
      _msg_trunc.get("content") == "" and not _msg_trunc.get("tool_calls")
      and _obj_trunc["choices"][0]["finish_reason"] == "stop", _obj_trunc)

_ev_trunc = [f.decode() for f in P.stream_responses_events(
    iter([_raw27(_TRUNC27[:12]), _raw27(_TRUNC27[12:]), _raw27("", "stop")]),
    "m27", {"usage": None, "custom_names": set(),
            "allowed_names": {"terminal"}})]
_joined_trunc = "".join(_ev_trunc)
_parsed_trunc_lk = [json.loads(_ln[6:]) for _fr in _ev_trunc
                       for _ln in _fr.splitlines() if _ln.startswith("data: ")]
_text_delta_trunc = "".join(e.get("delta") or "" for e in _parsed_trunc_lk
                            if isinstance(e, dict)
                            and e.get("type") == "response.output_text.delta")
check("Responses 流式：截断回声不出现在正文增量里（不再用短词匹配整个事件流）",
      _text_delta_trunc == "" and P.LEAK_MARKER not in _joined_trunc,
      (_text_delta_trunc[:120], _joined_trunc[:120]))

_frames_falsify = [json.loads(f[6:]) for f in P.recover_leaked_tool_calls(
    iter([_raw27(_M27), _raw27("\n这是一段解释文字。"), _raw27("", "stop")]),
    {"terminal"})]
_text_falsify = "".join(_f["choices"][0]["delta"].get("content") or ""
                        for _f in _frames_falsify)
check("流式：证伪（marker 后接散文）-> 仍 fail-open 补发原文",
      _M27 in _text_falsify and "解释文字" in _text_falsify, _text_falsify)

print()
print("[28] 发布前补强：终局验证 §10.7#5 的零覆盖项（防止静默回归）")
import ast as _ast28
import re as _re28
import shutil as _sh28
import tempfile as _tf28
import time as _t28
import qoder_scheduler as _S28

_src28 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qoder_proxy.py"), encoding="utf-8").read()


def _arg_src28(src_text, func_name):
    """AST 级提取：func_name(...) 每个调用的位置参数源码片段（离线可变异的判据）。"""
    tree = _ast28.parse(src_text)
    out = []
    for node in _ast28.walk(tree):
        if isinstance(node, _ast28.Call) and isinstance(node.func, _ast28.Name) \
                and node.func.id == func_name:
            out.append([_ast28.get_source_segment(src_text, a) for a in node.args])
    return out


# --- 28.1 Responses 重试上下文：两处重开必须用转换后的 chat_req ---
_i0_28 = _src28.index("chat_req = responses_to_chat(payload)")
_i1_28 = _src28.index("\n    def ", _i0_28 + 10)
_resp_block28 = _src28[_i0_28:_i1_28]
check("Responses 重开：两处重试都以 chat_req 发起"
      "（open_upstream 与 aggregate_with_envelope_retry）",
      "chat_req, session_key=session_key" in _resp_block28
      and "upstream, chat_req, session_key" in _resp_block28)
_strip28 = _resp_block28.replace("chat_req = responses_to_chat(payload)", "")
_idents28 = _re28.findall(r"(?<![\w.])payload(?![\w])", _strip28)
_gets28 = len(_re28.findall(r"payload\.get\(", _strip28))
check("Responses 分支：原始 payload 只用于读字段（payload.get），不再作为上游请求体"
      "——回退成 payload 即红",
      len(_idents28) == _gets28 and _gets28 >= 1,
      (_idents28, _gets28))
_agg_args28 = _arg_src28(_src28, "aggregate_with_envelope_retry")
check("AST：aggregate_with_envelope_retry 实参里 chat_req（Responses）与 payload"
      "（chat）各司其职——单一断言同时锁住两条链路",
      any(len(a) > 1 and a[1] == "chat_req" for a in _agg_args28)
      and any(len(a) > 1 and a[1] == "payload" for a in _agg_args28),
      [a[:2] for a in _agg_args28])

# --- 28.2 response.failed 终态事件与 sequence_number 续号 ---
_h28 = {"usage": None, "custom_names": set(), "allowed_names": {"terminal"}}
_ev28 = [json.loads(_ln[6:])
         for _f in P.stream_responses_events(
             iter([_raw27("hi"), _raw27("", "stop")]), "m27", _h28)
         for _ln in _f.decode().splitlines() if _ln.startswith("data: ")]
_max28 = max(e["sequence_number"] for e in _ev28)
_fail_raw28 = P._responses_failed_frame(_h28, 418, "upstream boom")
_fail_obj28 = json.loads([_l for _l in _fail_raw28.decode().splitlines()
                          if _l.startswith("data: ")][0][6:])
check("response.failed：终态事件名 / status / error.code 正确",
      _fail_raw28.decode("utf-8").startswith("event: response.failed\n")
      and _fail_obj28["type"] == "response.failed"
      and _fail_obj28["response"]["status"] == "failed"
      and _fail_obj28["response"]["error"]["code"] == "418",
      _fail_obj28)
check("response.failed：sequence_number 严格大于此前所有事件（续号，不回退到 0）",
      _fail_obj28["sequence_number"] > _max28,
      (_fail_obj28["sequence_number"], _max28))
_h28b = {"usage": None, "custom_names": set(), "allowed_names": {"terminal"}}
_ev28b1 = [json.loads(_ln[6:])
           for _f in P.stream_responses_events(
               iter([_raw27("a"), _raw27("", "stop")]), "m27", _h28b)
           for _ln in _f.decode().splitlines() if _ln.startswith("data: ")]
_ev28b2 = [json.loads(_ln[6:])
           for _f in P.stream_responses_events(
               iter([_raw27("b"), _raw27("", "stop")]), "m27", _h28b)
           for _ln in _f.decode().splitlines() if _ln.startswith("data: ")]
check("Responses 重开后 sequence_number 续号（第二条流从第一条流的 max+1 开始）",
      min(e["sequence_number"] for e in _ev28b2)
      == max(e["sequence_number"] for e in _ev28b1) + 1,
      (max(e["sequence_number"] for e in _ev28b1),
       min(e["sequence_number"] for e in _ev28b2)))

# --- 28.3 catalog_source 只读来源标注 ---
_SRC_SET28 = ("external-json", "embedded-frozen", "unknown")
check("catalog_source：snapshot_source() 取值在允许集合内，未知 realm 走 cn 分支",
      C.snapshot_source("cn") in _SRC_SET28
      and C.snapshot_source("intl") in _SRC_SET28
      and C.snapshot_source("bogus-realm") == C.snapshot_source("cn"),
      (C.snapshot_source("cn"), C.snapshot_source("intl")))
check("catalog_source：/v1/models 既有字段未变、新增来源标注（含异常兜底 unknown）",
      '"object": "list", "data": data' in _src28
      and '"catalog_source": catalog_source' in _src28
      and 'catalog_source = "unknown"' in _src28,
      [_l.strip() for _l in _src28.splitlines() if "catalog_source" in _l][:4])

# --- 28.4 Scheduler：状态落盘子目录 + 启动补签闸门（mark-before-act） ---
_tmp28 = _tf28.mkdtemp(prefix="qd-test-sched-")
_sched_err28 = None
try:
    _pool28 = A.AccountPool(_tmp28)
    _s1_28 = _S28.Scheduler(_pool28, state_dir=_tmp28)
    _gate_first28 = _s1_28._allow_complement_checkin(_S28.CYCLE_STARTUP)
    _state_path28 = _s1_28._state_path()
    _state_exists28 = os.path.isfile(_state_path28)
    with open(_state_path28, encoding="utf-8") as _fh28:
        _state_json28 = json.load(_fh28)
    _gate_second28 = _s1_28._allow_complement_checkin(_S28.CYCLE_STARTUP)
    _s2_28 = _S28.Scheduler(_pool28, state_dir=_tmp28)     # 模拟进程重启
    _gate_restart28 = _s2_28._allow_complement_checkin(_S28.CYCLE_STARTUP)
    _gate_hour28 = _s2_28._allow_complement_checkin(_S28.CYCLE_HOUR)
    _accounts28 = _pool28.load()
except Exception as _exc28:
    _sched_err28 = _exc28
    _state_path28 = ""
    _state_exists28 = False
    _state_json28 = {}
    _gate_first28 = _gate_second28 = _gate_restart28 = _gate_hour28 = None
    _accounts28 = []
finally:
    _sh28.rmtree(_tmp28, ignore_errors=True)

check("Scheduler：state.json 落在账号目录的子目录，且不会被 AccountPool.load 当成账号",
      _sched_err28 is None
      and _state_path28 == os.path.join(_tmp28, "scheduler", "state.json")
      and _state_exists28 and _accounts28 == [],
      (_sched_err28, _state_path28, len(_accounts28)))
check("Scheduler：mark-before-act——首次启动补签返回 True，且当日标记已先落盘",
      _gate_first28 is True
      and _state_json28.get("startup_claim_date") == _t28.strftime("%Y-%m-%d"),
      _state_json28.get("startup_claim_date"))
check("Scheduler：同一天第二次启动补签被闸门拒绝（False）",
      _gate_second28 is False, _gate_second28)
check("Scheduler：进程重启后不重放（新实例读同一 state.json 仍为 False）",
      _gate_restart28 is False, _gate_restart28)
check("Scheduler：整点巡回来由不受启动闸门限制（True）",
      _gate_hour28 is True, _gate_hour28)

# --- 28.5 身份来源口径（Lead 裁决：合法值只有 runtime-info / derived） ---
_acc_src28 = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "qoder_accounts.py"), encoding="utf-8").read()
_acc_code28 = "\n".join(_l for _l in _acc_src28.splitlines()
                          if not _l.lstrip().startswith("#"))
check("身份来源口径：自愈条件用真实取值 runtime-info，代码里不得再有 == \"native\" 死逻辑"
      "（注释里的历史说明不算）",
      '"runtime-info"' in _acc_code28 and '== "native"' not in _acc_code28,
      [_l.strip() for _l in _acc_code28.splitlines() if '== "native"' in _l][:2])
print()
print("[29] issue #10 三态可观测性：实际发送行为（native/omitted）+ INTL 已知限制提示")
_MH29 = ("cosy-machineid", "cosy-machinetoken", "cosy-machinetype",
         "cosy-machineos", "cosy-machinehostname", "cosy-machinecode")
_orig_nmi29 = A.native_machine_identity
_orig_cget29 = A.Account._campaigns_get


def _camp29(realm, native):
    """构造账号：返回 (account, desktop_headers 结果, 机器头状态, campaigns() 结果)。

    native=True 打桩原生桥返回带 machineToken 的真身份；native=False 返回空 dict
    （= 无原生桥，issue #10 的 derived 场景）。
    """
    if native:
        A.native_machine_identity = lambda r, u, force=False: {
            "machineToken": "tok29", "machineType": "3", "machineCode": "c29",
            "source": A.MACHINE_IDENTITY_NATIVE}
    else:
        A.native_machine_identity = lambda r, u, force=False: {}
    acc29 = A.Account({"uid": "u29-%s-%s" % (realm, "n" if native else "d"),
                       "realm": realm, "accessToken": "dt-x"})
    hdrs29 = acc29.desktop_headers()
    state29 = acc29.machine_headers_state
    A.Account._campaigns_get = lambda self: (
        {"campaigns": [], "showCampaign": True, "claimable": False}, 200, "")
    try:
        st29 = acc29.campaigns(force=True)
    finally:
        A.Account._campaigns_get = _orig_cget29
    return hdrs29, state29, st29


try:
    _h_cn_n29, _s_cn_n29, _c_cn_n29 = _camp29("cn", True)
    _h_cn_d29, _s_cn_d29, _c_cn_d29 = _camp29("cn", False)
    _h_in_n29, _s_in_n29, _c_in_n29 = _camp29("intl", True)
    _h_in_d29, _s_in_d29, _c_in_d29 = _camp29("intl", False)
    A.Account._campaigns_get = lambda self: (None, 500, "boom29")
    _acc_fail29 = A.Account({"uid": "u29fail", "realm": "cn", "accessToken": "dt-x"})
    _st_fail29 = _acc_fail29.campaigns(force=True)
finally:
    A.native_machine_identity = _orig_nmi29
    A.Account._campaigns_get = _orig_cget29

check("三态 cn×native：真发六头 + desktop_headers 与 campaigns() 都报 native",
      all(_h_cn_n29.get(k) for k in _MH29)
      and _s_cn_n29 == A.MACHINE_HEADERS_NATIVE
      and _c_cn_n29.get("machine_headers") == A.MACHINE_HEADERS_NATIVE,
      (_s_cn_n29, _c_cn_n29.get("machine_headers")))
check("三态 cn×derived：一个机器头都不发 + 状态 omitted",
      not any(_h_cn_d29.get(k) for k in _MH29)
      and _s_cn_d29 == A.MACHINE_HEADERS_OMITTED
      and _c_cn_d29.get("machine_headers") == A.MACHINE_HEADERS_OMITTED,
      (_s_cn_d29, _c_cn_d29.get("machine_headers")))
check("三态 intl×native：真发六头 + 状态 native",
      all(_h_in_n29.get(k) for k in _MH29)
      and _s_in_n29 == A.MACHINE_HEADERS_NATIVE
      and _c_in_n29.get("machine_headers") == A.MACHINE_HEADERS_NATIVE,
      (_s_in_n29, _c_in_n29.get("machine_headers")))
check("三态 intl×derived：一个机器头都不发 + 状态 omitted",
      not any(_h_in_d29.get(k) for k in _MH29)
      and _s_in_d29 == A.MACHINE_HEADERS_OMITTED
      and _c_in_d29.get("machine_headers") == A.MACHINE_HEADERS_OMITTED,
      (_s_in_d29, _c_in_d29.get("machine_headers")))
check("INTL×omitted 必须带已知限制提示（非空字符串，含 UMID 与「已知限制」措辞）",
      isinstance(_c_in_d29.get("hint"), str)
      and "UMID" in _c_in_d29["hint"] and "已知限制" in _c_in_d29["hint"],
      _c_in_d29.get("hint"))
check("CN×omitted 的 hint 键存在且为空串（限制提示不得扩散到国内版）",
      "hint" in _c_cn_d29 and _c_cn_d29.get("hint") == "",
      _c_cn_d29.get("hint"))
check("native（两个区域）的 hint 均为空串：只有 INTL×omitted 才提示",
      _c_cn_n29.get("hint") == "" and _c_in_n29.get("hint") == "",
      (_c_cn_n29.get("hint"), _c_in_n29.get("hint")))
check("两个维度正交：derived 身份与 omitted 机器头可同时成立"
      "（identity 不再被当作「能不能发头」的信号）",
      _c_cn_d29.get("identity") == "derived"
      and _c_cn_d29.get("machine_headers") == A.MACHINE_HEADERS_OMITTED,
      (_c_cn_d29.get("identity"), _c_cn_d29.get("machine_headers")))
check("失败返回（ok=False）同样带 machine_headers 与 hint 键（消费端无需分支）",
      _st_fail29.get("ok") is False
      and _st_fail29.get("machine_headers") == A.MACHINE_HEADERS_OMITTED
      and "hint" in _st_fail29 and _st_fail29.get("hint") == "",
      (_st_fail29.get("machine_headers"), sorted(_st_fail29.keys())))

print()
print("SUMMARY: TOTAL %d checks, %d passed, %d failed, %d skipped"
      % (PASS + FAIL + SKIP, PASS, FAIL, SKIP))
print("RESULT: %s (exit %d)  SKIP=%d  |  语义: 0=GREEN(无 FAIL，允许 SKIP)；"
      "1=RED(存在 FAIL)；SKIP 永不计入通过"
      % ("RED" if FAIL else "GREEN", 1 if FAIL else 0, SKIP))
# 口径自证：静态源码里以 check(/skip( 开头的顶层断言点 vs 运行时执行数。
# 两者差值来自循环展开（多执行）与条件分支未走（少执行）；以运行时数字为准。
try:
    with open(os.path.abspath(__file__), encoding="utf-8") as _fh:
        _self_src = _fh.read()
    _static = len([_ln for _ln in _self_src.splitlines()
                   if _ln.lstrip().startswith(("check(", "skip("))])
    print("CHECK-SOURCES: static-top-level=%d, runtime-executed=%d, skipped=%d, "
          "delta=%+d (循环展开/条件分支)"
          % (_static, PASS + FAIL, SKIP, (PASS + FAIL) - _static))
except Exception as _exc:
    print("CHECK-SOURCES: 静态口径统计失败（%s）" % _exc)
if SKIP:
    print("NOTE: %d 条断言被跳过（缺 fixture/环境），没有被当成通过；"
          "补齐后请重跑确认它们真的通过。" % SKIP)
sys.exit(1 if FAIL else 0)
