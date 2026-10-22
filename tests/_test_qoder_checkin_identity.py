"""Qoder campaign identity and check-in contract regression tests."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _suite_head import *  # noqa: F401,F403

P, A = bootstrap()
declare_suite(__file__, ["Dockerfile", "qoder_accounts.py", "qoder_sign.py",
                         "qoder_proxy.py"])
import qoder_sign as S  # noqa: E402


def _headers(uid, sse=True):
    return S.CosySession(uid).headers(
        "{}", "https://api3.qoder.sh/algo/x", sse=sse)


_sse = _headers("uid-a")
_no_sse = _headers("uid-a", sse=False)
check("COSY 1.1.75 headers match the desktop/CLI outbound shape",
      S.COSY_VERSION == "1.1.75"
      and _sse.get("cosy-business-product") == "cli"
      and _sse.get("cosy-business-type") == "agent"
      and _sse.get("cosy-scene") == "assistant"
      and _sse.get("cosy-data-policy") == "agree"
      and _sse.get("user-agent") == "undici"
      and "cosy-machinehostname" in _sse
      and "cosy-machineos" in _no_sse
      and "cosy-machinehostname" not in _no_sse,
      _sse)

_proxy_src = open(os.path.join(ROOT, "qoder_proxy.py"), encoding="utf-8").read()
check("proxy does not overwrite the signed COSY User-Agent",
      'headers["User-Agent"] =' not in _proxy_src
      and 'headers["user-agent"] =' not in _proxy_src)

_rt_calls = []


def _fake_run(cmd, input=None, **kwargs):
    _rt_calls.append((list(cmd), input))
    return subprocess.CompletedProcess(cmd, 0, b'{"machineToken":"t"}\n', b"")


_orig = (A.runtime_info_exe, subprocess.run, sys.platform)
A.runtime_info_exe = lambda realm: "/opt/umid/runtime-info"
subprocess.run = _fake_run
try:
    sys.platform = "linux"
    A.run_runtime_info("cn", "uid-x")
    sys.platform = "darwin"
    A.run_runtime_info("intl", "uid-x")
    A.run_runtime_info("intl", "")
finally:
    A.runtime_info_exe, subprocess.run, sys.platform = _orig

check("runtime-info uses regional environment codes and desktop stdin contract",
      _rt_calls[0] == (["/opt/umid/runtime-info", "0"], b"")
      and _rt_calls[1] == (["/opt/umid/runtime-info", "3", "--account-stdin"],
                           b'{"account":"uid-x"}\n')
      and _rt_calls[2] == (["/opt/umid/runtime-info", "3"], b""),
      _rt_calls)

_desktop_base = {
    "Accept", "User-Agent", "Authorization", "cosy-clienttype", "cosy-version",
}
_desktop_machine = {
    "cosy-machineid", "cosy-machinetoken", "cosy-machinetype",
    "cosy-machinecode", "cosy-machineos", "cosy-machinehostname",
}
_identity_orig = A.native_machine_identity
try:
    A.native_machine_identity = lambda realm, account_id, force=False: {
        "machineToken": "nt",
        "machineType": "3",
        "machineCode": "nc",
        "source": A.MACHINE_IDENTITY_NATIVE,
    }
    account = A.Account({
        "uid": "desk-u", "realm": "intl", "accessToken": "tok",
    })
    native = account.desktop_headers()
    A.native_machine_identity = lambda realm, account_id, force=False: {}
    derived = account.desktop_headers()
finally:
    A.native_machine_identity = _identity_orig

check("native campaign headers equal the official desktop set",
      set(native) == _desktop_base | _desktop_machine
      and native["Accept"] == "application/json"
      and native["User-Agent"] == "Qoder"
      and native["Authorization"] == "Bearer tok"
      and native["cosy-machinehostname"] == A.MACHINE_HOSTNAME,
      native)
check("derived campaign headers omit every machine identity header",
      set(derived) == _desktop_base, sorted(derived))

_claim_headers = []
_claim_orig = (A.http_json, A.Account.desktop_headers)
A.http_json = lambda url, **kwargs: (
    _claim_headers.append(kwargs.get("headers")) or {"status": "CLAIMED"})
A.Account.desktop_headers = lambda self: {"Accept": "application/json"}
try:
    A.Account({
        "uid": "claim-u", "realm": "cn", "accessToken": "t",
    }).claim_campaign("c1")
finally:
    A.http_json, A.Account.desktop_headers = _claim_orig
check("campaign claim adds Content-Type without sending a GET-style body header",
      _claim_headers
      and _claim_headers[0] == {
          "Accept": "application/json",
          "Content-Type": "application/json",
      },
      _claim_headers)

_dockerfile = open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8").read()
check("Docker build fails closed when the UMID runtime component is missing",
      "test -x /build/umid/runtime-info" in _dockerfile
      and "UMID extraction failed" not in _dockerfile)

finish()
