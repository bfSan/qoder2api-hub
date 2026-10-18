import time
from urllib.parse import parse_qs, urlparse

import qoder_auth


def check(name, condition, detail=None):
    if not condition:
        raise SystemExit("FAIL: %s%s" % (name, (" -> %r" % detail) if detail is not None else ""))
    print("PASS: %s" % name)

value = qoder_auth.build_authorize_url("https://aac.example", "qoder2api-hub", "https://wb.example/auth/callback", "state-1", "challenge-1")
query = parse_qs(urlparse(value).query)
check("authorize URL path", urlparse(value).path == "/oauth/authorize")
check("authorize URL client", query["client_id"] == ["qoder2api-hub"])
check("authorize URL PKCE", query["code_challenge_method"] == ["S256"])

old_post = qoder_auth._post_json
try:
    qoder_auth._post_json = lambda *args, **kwargs: {"active": True, "aud": "qoder2api-hub", "client_id": "qoder2api-hub", "sub": "aac-1", "grants": ["qoder:access"]}
    claims = qoder_auth.introspect_access_token("https://aac.example", "token", "qoder2api-hub")
    check("access scope maps user", claims.aac_user_id == "aac-1" and claims.role == "user")
    qoder_auth._post_json = lambda *args, **kwargs: {"active": True, "aud": "other", "client_id": "qoder2api-hub", "sub": "aac-1", "grants": ["qoder:access"]}
    try:
        qoder_auth.introspect_access_token("https://aac.example", "token", "qoder2api-hub")
    except qoder_auth.AuthError:
        check("wrong audience rejected", True)
    else:
        check("wrong audience rejected", False)
finally:
    qoder_auth._post_json = old_post

session = qoder_auth.create_oauth_session({"sub": "aac-2", "aud": "qoder2api-hub", "client_id": "qoder2api-hub", "grants": ["qoder:access", "qoder:admin"], "exp": int(time.time()) + 100})
principal = qoder_auth.resolve_principal({}, {"QD-Session": session["session_id"]}, {session["session_id"]: session})
check("admin scope maps admin", principal.principal_type == "aac-user" and principal.role == "admin")
try:
    qoder_auth.resolve_principal({}, {"QD-Session": session["session_id"]}, {session["session_id"]: dict(session, expires_at=time.time() - 1)})
except qoder_auth.AuthError:
    check("expired session rejected", True)
else:
    check("expired session rejected", False)
