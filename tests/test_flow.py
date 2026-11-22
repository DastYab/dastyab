#!/usr/bin/env python3
"""Tests for the Google Flow bridge helper (`dastyab-flow.py`).

Run with:  python3 -m pytest tests/test_flow.py -q

These are OFFLINE tests: they never open a tunnel and never touch the
network. They pin down the logic that decides whether a route is usable,
because a wrong answer there is either a wasted tunnel or — worse — a
browser that silently hits the region gate:

  * the country gate must match Google's official Flow rollout list
  * an egress whose geo cannot be proven must FAIL, not pass
  * a one-hop and a two-hop route must produce the right xray topology
    (the entry dials; the exit is the egress Google sees)
  * ranking must prefer clean IPs over proxy-flagged ones, and passing
    gates over failing ones
  * parser/bean conversion must reject junk instead of raising
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name="dastyab-flow.py", alias="fl"):
    path = os.path.join(ROOT, name)
    spec = importlib.util.spec_from_file_location(alias, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def fl():
    return load()


# --- L3: the country gate --------------------------------------------------

def test_gate_matches_google_official_rollout(fl):
    """The embedded set must equal support.google.com/flow/answer/16353544."""
    official = """
    AL DZ AS AO AG AR AM AW AU AT AZ BS BH BD BE BZ BJ BM BO BA BW BR BG BF
    CV KH CM CA KY CL CO CR CI HR CY CZ DK DO EC EG SV EE FJ FI FR GA DE GH
    GI GR GU GT GW HT HN HK HU IS IN ID IQ IE IL IT JM JP JO KZ KE KW KG LA
    LV LB LI LT LU MO MY MV ML MT MU MX MD MC MA MZ NA NP NL NZ NI NE NG MK
    MP NO OM PK PW PA PG PY PE PH PL PT PR QA RO RW SM SA SN RS SC SL SG SK
    SI ZA KR ES LK SE CH TW TJ TZ TH TG TO TT TN TR TM VI UG UA AE GB US UY
    UZ VE VN VG YE ZM ZW
    """
    assert set(fl.SUPPORTED_COUNTRIES) == set(official.split())
    assert len(fl.SUPPORTED_COUNTRIES) == 151


@pytest.mark.parametrize("code", ["DE", "US", "SG", "GB", "AE", "TR"])
def test_supported_countries_pass_the_gate(fl, code):
    assert code in fl.SUPPORTED_COUNTRIES


@pytest.mark.parametrize("code", ["IR", "CN", "RU", "KP", "SY", "CU"])
def test_unsupported_countries_fail_the_gate(fl, code):
    """These are the egress countries that produce the region error."""
    assert code not in fl.SUPPORTED_COUNTRIES


# --- L0: parsing / supply --------------------------------------------------

def test_parse_vless_keeps_transport_keys(fl):
    u = fl.parse_vless(
        "vless://uuid-1@1.2.3.4:443?security=reality&type=tcp"
        "&sni=a.example&pbk=KEY&fp=firefox&flow=xtls-rprx-vision"
    )
    assert u["proto"] == "vless"
    assert u["addr"] == "1.2.3.4"
    assert u["port"] == 443
    assert u["q"]["security"] == "reality"
    assert u["q"]["flow"] == "xtls-rprx-vision"


def test_parse_vless_strips_fragment_label(fl):
    u = fl.parse_vless("vless://u@h.example:1?security=none#my%20node")
    assert u["addr"] == "h.example"
    assert "#" not in json.dumps(u)


@pytest.mark.parametrize("bad", [
    "garbage",
    "",
    "vless://@1.2.3.4:443?security=none",          # empty uuid
    "vless://uuid@host:notaport?security=none",    # non-numeric port
])
def test_parse_vless_rejects_malformed(fl, bad):
    assert fl.parse_vless(bad) is None


def test_bean_conversion_carries_stream_settings(fl):
    bean = {"addr": "h.example", "port": 443, "pass": "pw",
            "name": "test",
            "stream": {"sec": "tls", "net": "ws",
                       "host": "cdn.example", "path": "/ws"}}
    srv = fl._bean_to_server(bean, "trojan")
    assert srv["proto"] == "trojan"
    assert srv["password"] == "pw"
    assert srv["q"]["security"] == "tls"
    assert srv["q"]["type"] == "ws"
    assert srv["q"]["host"] == "cdn.example"


def test_bean_conversion_rejects_incomplete(fl):
    assert fl._bean_to_server({"port": 443}, "vless") is None
    assert fl._bean_to_server({"addr": "h"}, "vless") is None


def test_candidates_are_deduped_and_bounded(fl):
    cands = fl.load_candidates(limit=50)
    assert len(cands) <= 50
    keys = [(c["addr"], int(c["port"])) for c in cands]
    assert len(keys) == len(set(keys)), "duplicate addr:port in candidate union"


# --- L1/L2: topology -------------------------------------------------------

def _vless(addr="1.2.3.4", **q):
    base = {"security": "none", "type": "tcp"}
    base.update(q)
    return {"proto": "vless", "uuid": "uuid-1", "addr": addr, "port": 443,
            "q": base}


def test_single_hop_topology(fl):
    cfg = fl.build_config([_vless()], 10860)
    assert cfg["inbounds"][0]["port"] == 10860
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert len(cfg["outbounds"]) == 1
    assert cfg["outbounds"][0]["tag"] == "exit"
    assert "sockopt" not in cfg["outbounds"][0]


def test_two_hop_chain_makes_entry_dial_for_exit(fl):
    """L2: the local network sees only the entry; Google sees the exit."""
    exit_node = _vless("5.5.5.5")
    entry_node = _vless("9.9.9.9")
    cfg = fl.build_config([exit_node, entry_node], 10860)
    tags = [ob["tag"] for ob in cfg["outbounds"]]
    assert tags == ["exit", "entry"]
    assert cfg["outbounds"][0]["sockopt"] == {"dialerProxy": "entry"}
    # The egress outbound is the EXIT address; the entry only carries it.
    assert cfg["outbounds"][0]["settings"]["vnext"][0]["address"] == "5.5.5.5"
    assert cfg["outbounds"][1]["settings"]["vnext"][0]["address"] == "9.9.9.9"


def test_chain_is_not_self_referential(fl):
    """A chain whose entry and exit are the same host is a config error."""
    same = _vless("1.1.1.1")
    cfg = fl.build_config([same, dict(same)], 10860)
    addrs = {ob["settings"]["vnext"][0]["address"] for ob in cfg["outbounds"]}
    assert cfg["outbounds"][0]["sockopt"]["dialerProxy"] == "entry"


def test_build_config_refuses_unsupported_protocol(fl):
    assert fl.build_config([{"proto": "wireguard", "addr": "h", "port": 1,
                             "q": {}}], 10860) is None


def test_vision_flow_dropped_without_tls(fl):
    """`flow` on a non-TLS transport makes xray reject the whole config."""
    cfg = fl.build_config([_vless("1.2.3.4", flow="xtls-rprx-vision")], 10860)
    user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert "flow" not in user


# --- L4: verdict logic -----------------------------------------------------

def _stub_browser(fl, monkeypatch, ok=True, detail="stubbed"):
    """Keep probe_gates hermetic: never launch a real browser in unit tests."""
    monkeypatch.setattr(fl, "browser_gate", lambda *a, **k: (ok, detail))


def _gates(**over):
    base = {"egress": "1.2.3.4", "country": "DE", "country_name": "Germany",
            "proxy": False, "hosting": False, "flow_ok": True,
            "accounts_ok": True, "app_shell_ok": True, "latency_ms": 900,
            "verdict": True, "reason": "ok"}
    base.update(over)
    return base


def test_probe_fails_when_geo_unknown(fl, monkeypatch):
    """An unprovable country is a FAIL: that is the whole point of the gate."""
    monkeypatch.setattr(fl, "_curl", lambda args, timeout: type(
        "R", (), {"stdout": "1.2.3.4" if "ipify" in args[-1] else "not-json"})())
    _stub_browser(fl, monkeypatch)
    g = fl.probe_gates()
    assert g["verdict"] is False
    assert "geo lookup failed" in g["reason"]


def test_probe_fails_for_unsupported_country(fl, monkeypatch):
    calls = {"n": 0}

    def fake_curl(args, timeout):
        calls["n"] += 1
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Iran",
                 "countryCode": "IR", "proxy": False, "hosting": False})})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch)
    g = fl.probe_gates()
    assert g["verdict"] is False
    assert "not on Google's Flow list" in g["reason"]


def test_probe_fails_when_flow_unreachable(fl, monkeypatch):
    def fake_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "proxy": False, "hosting": False})})()
        return type("R", (), {"stdout": "000"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch)
    g = fl.probe_gates()
    assert g["verdict"] is False
    assert "flow.google.com unreachable" in g["reason"]


def test_probe_passes_on_supported_country(fl, monkeypatch):
    def fake_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "proxy": True, "hosting": True})})()
        if url.rstrip("/") == "https://flow.google.com":
            return type("R", (), {"stdout": "<html>AiSandboxAngularFrontend</html>"})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch)
    g = fl.probe_gates()
    assert g["verdict"] is True
    assert g["country"] == "DE"


def test_probe_honours_country_filter(fl, monkeypatch):
    def fake_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "proxy": False, "hosting": False})})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch)
    g = fl.probe_gates(want_country="US")
    assert g["verdict"] is False
    assert "!= requested US" in g["reason"]


# --- L5: ranking -----------------------------------------------------------

def test_ranking_prefers_clean_ips_over_flagged(fl):
    clean = _gates(proxy=False, hosting=False, latency_ms=5000)
    flagged = _gates(proxy=True, hosting=True, latency_ms=500)
    assert fl.gate_score(clean) < fl.gate_score(flagged)


def test_ranking_prefers_pass_over_fail(fl):
    failing = _gates(verdict=False, latency_ms=10)
    passing = _gates(verdict=True, latency_ms=9000)
    assert fl.gate_score(passing) < fl.gate_score(failing)


def test_ranking_breaks_ties_on_latency(fl):
    fast = _gates(latency_ms=300)
    slow = _gates(latency_ms=3000)
    assert fl.gate_score(fast) < fl.gate_score(slow)


# --- pool safety -----------------------------------------------------------

def test_empty_scan_never_clobbers_a_working_pool(fl, tmp_path, monkeypatch):
    pool_file = tmp_path / "flow_pool.json"
    pool_file.write_text(json.dumps([{"nodes": [_vless()], "egress": "1.2.3.4"}]))
    monkeypatch.setattr(fl, "FLOW_POOL", str(pool_file))

    with pytest.raises(SystemExit) as exc:
        fl.save_pool([])
    assert "keeping the existing pool" in str(exc.value)
    assert json.loads(pool_file.read_text()), "existing pool must survive"


def test_save_pool_writes_ranked_routes(fl, tmp_path, monkeypatch):
    pool_file = tmp_path / "flow_pool.json"
    monkeypatch.setattr(fl, "FLOW_POOL", str(pool_file))
    routes = [{"nodes": [_vless()], "egress": "1.2.3.4", "country": "DE"}]
    fl.save_pool(routes)
    assert json.loads(pool_file.read_text()) == routes


def test_load_pool_ignores_malformed_entries(fl, tmp_path, monkeypatch):
    pool_file = tmp_path / "flow_pool.json"
    pool_file.write_text(json.dumps([
        {"nodes": [_vless()]},   # good
        {"egress": "9.9.9.9"},   # no nodes -> unusable
        "garbage",               # not a dict
    ]))
    monkeypatch.setattr(fl, "FLOW_POOL", str(pool_file))
    assert len(fl.load_pool()) == 1


def test_read_json_survives_missing_and_corrupt_files(fl, tmp_path):
    assert fl.read_json(str(tmp_path / "nope.json"), []) == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert fl.read_json(str(bad), []) == []


# --- browser gate (the decisive check) -------------------------------------

def test_gate_markers_cover_the_exact_error_the_user_sees(fl):
    """The user's message is 'Flow is not available in your country yet.'"""
    assert any("not available in your country" in m.lower()
               for m in fl.GATE_MARKERS)
    assert any("unsupported-country-title" == m for m in fl.GATE_MARKERS)


def test_browser_gate_flags_rejection_page(fl, monkeypatch):
    """A page carrying the rejection title must FAIL, never pass."""
    dom = ("<html><body><h2 class='unsupported-country-title'>"
           "Flow is not available in your country yet.</h2></body></html>")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is False
    assert "rejected" in detail.lower()


def test_browser_gate_accepts_the_real_app(fl, monkeypatch):
    dom = "<html>" + "x" * 1200 + "AiSandboxAngularFrontend</html>"
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is True
    assert "no region or account gate" in detail


def test_browser_gate_reports_empty_render_as_failure(fl, monkeypatch):
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": ""})())
    ok, detail = fl.browser_gate()
    assert ok is False
    assert "rendered nothing" in detail


def test_browser_gate_returns_unknown_without_a_browser(fl, monkeypatch):
    """No browser means the gate is UNKNOWN — it must not silently pass."""
    monkeypatch.setattr(fl, "find_browser", lambda: None)
    ok, detail = fl.browser_gate()
    assert ok is None
    assert "no Chromium" in detail


def test_probe_fails_when_browser_sees_rejection(fl, monkeypatch):
    """Country + reachability can pass while the browser still gets blocked."""
    def fake_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "proxy": False, "hosting": False})})()
        if url.rstrip("/") == "https://flow.google.com":
            return type("R", (), {"stdout": "<html>AiSandboxAngularFrontend</html>"})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch, ok=False,
                  detail="Flow rejected this egress in the browser")
    g = fl.probe_gates()
    assert g["verdict"] is False
    assert "rejected" in g["reason"]


def test_probe_says_so_when_browser_gate_could_not_run(fl, monkeypatch):
    """An unrun browser gate is never silently upgraded to a clean pass."""
    def fake_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "1.2.3.4"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "proxy": False, "hosting": False})})()
        if url.rstrip("/") == "https://flow.google.com":
            return type("R", (), {"stdout": "<html>AiSandboxAngularFrontend</html>"})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_curl)
    _stub_browser(fl, monkeypatch, ok=None, detail="no Chromium browser found")
    g = fl.probe_gates()
    assert g["browser_ok"] is None
    assert "NOT run" in g["reason"]


# --- the two distinct gates ------------------------------------------------

def test_both_gate_markers_are_distinct(fl):
    """/unavailable (account) must not be confused with /unsupported-country."""
    region = set(fl.GATE_MARKERS)
    account = set(fl.UNAVAILABLE_MARKERS)
    assert not (region & account), "marker sets must not overlap"
    assert any("unavailable-title" == m for m in account)


def test_browser_gate_classifies_account_gate(fl, monkeypatch):
    """The exact page the user hit when signed in."""
    dom = ('<html><body><h2 class="unavailable-title"> It looks like you '
           "don't have access to Flow. Check availability here and reach "
           "out to support for issues. </h2></body></html>")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is False
    assert detail.startswith("ACCOUNT-GATE:")
    assert "16353333" in detail, "must cite the requirements document"


def test_browser_gate_classifies_region_gate(fl, monkeypatch):
    dom = ('<html><body><h2 class="unsupported-country-title">Flow is not '
           "available in your country yet.</h2></body></html>")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is False
    assert detail.startswith("REGION-GATE:")


def test_account_gate_does_not_trip_the_region_markers(fl, monkeypatch):
    """A clean app shell with no gate markers is still a pass."""
    dom = "<html>" + "x" * 1200 + "AiSandboxAngularFrontend</html>"
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is True


def test_browser_gate_timeout_is_unknown_not_blocked(fl, monkeypatch):
    """A slow route must not be reported as a gate failure."""
    import subprocess as sp

    class _Timeout(sp.TimeoutExpired):
        def __init__(self):
            super().__init__(cmd=["chrome"], timeout=150)
            self.stdout = ""

    def boom(*a, **k):
        raise _Timeout()

    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run", boom)
    ok, detail = fl.browser_gate()
    assert ok is None
    assert "timed out" in detail


def test_browser_gate_uses_partial_output_after_timeout(fl, monkeypatch):
    """If Chrome was killed mid-dump, a real rejection page still counts."""
    import subprocess as sp

    class _Timeout(sp.TimeoutExpired):
        def __init__(self):
            super().__init__(cmd=["chrome"], timeout=150)
            self.stdout = ('<html><body><h2 class="unavailable-title">'
                           "don't have access to Flow</h2></body></html>")

    def boom(*a, **k):
        raise _Timeout()

    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run", boom)
    ok, detail = fl.browser_gate()
    assert ok is False
    assert detail.startswith("ACCOUNT-GATE:")


def test_signed_out_landing_is_unknown_not_a_pass(fl, monkeypatch):
    """The marketing page has no gate markers — but proves nothing either.

    Copied profiles lose the keyring-encrypted cookies, so a headless run
    renders "Sign in". Scoring that as success is what made `prove` claim
    the account gate was fine while it had never been tested.
    """
    dom = ("<html>" + "x" * 1200 + "AiSandboxAngularFrontend"
           "<a>Sign in</a></html>")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is None
    assert "NOT signed in" in detail


def test_signed_in_app_is_a_pass(fl, monkeypatch):
    dom = ("<html>" + "x" * 1200 + "AiSandboxAngularFrontend"
           "credits remaining</html>")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate()
    assert ok is True


def test_locked_profile_is_reported_clearly(fl, monkeypatch):
    dom = ("Faile" + "d to create SingletonLock: File exists")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": dom})())
    ok, detail = fl.browser_gate(profile_dir="/tmp/some-profile")
    assert ok is None
    assert "in use by a running Chrome" in detail


def test_provided_profile_is_not_deleted(fl, monkeypatch, tmp_path):
    """Never delete a profile the caller handed us."""
    prof = tmp_path / "signed-in"
    prof.mkdir()
    (prof / "marker").write_text("keep me")
    monkeypatch.setattr(fl, "find_browser", lambda: "/usr/bin/chrome")
    monkeypatch.setattr(fl.subprocess, "run",
                        lambda *a, **k: type("R", (), {"stdout": ""})())
    fl.browser_gate(profile_dir=str(prof))
    assert (prof / "marker").exists(), "caller's profile must survive"


def test_probe_gates_forwards_the_profile(fl, monkeypatch):
    seen = {}

    def fake_gate(*a, **k):
        seen.update(k)
        return True, "ok"

    monkeypatch.setattr(fl, "browser_gate", fake_gate)
    monkeypatch.setattr(fl, "_curl", lambda args, timeout: type(
        "R", (), {"stdout": (
            "1.2.3.4" if "ipify" in args[-1]
            else json.dumps({"status": "success", "country": "United States",
                             "countryCode": "US", "proxy": False,
                             "hosting": False}) if "ip-api" in args[-1]
            else "<html>AiSandboxAngularFrontend</html>")})())
    fl.probe_gates(browser_profile="/tmp/p")
    assert seen.get("profile_dir") == "/tmp/p"


# --- Warrior brutal multi-layer extensions --------------------------------

def test_warrior_four_hop_and_tls_fragment_topology(fl):
    n_exit = _vless("203.0.113.10", security="tls")
    n_r1 = _vless("198.51.100.20", security="tls")
    n_r2 = {"proto": "trojan", "addr": "192.0.2.30", "port": 443,
            "password": "pw", "q": {"security": "tls", "type": "tcp"}}
    n_en = {"proto": "socks", "addr": "127.0.0.1", "port": 9050, "local": True, "q": {}}
    cfg4 = fl.build_config([n_exit, n_r1, n_r2, n_en], 10860, fragment=True)
    assert [o["tag"] for o in cfg4["outbounds"]] == ["exit", "relay-1", "relay-2", "entry"]
    assert cfg4["outbounds"][0]["sockopt"]["dialerProxy"] == "relay-1"
    assert cfg4["outbounds"][1]["sockopt"]["dialerProxy"] == "relay-2"
    assert cfg4["outbounds"][2]["sockopt"]["dialerProxy"] == "entry"

    cfg3 = fl.build_config([n_exit, n_r1, n_r2], 10860, fragment=True)
    tags3 = [o["tag"] for o in cfg3["outbounds"]]
    assert tags3 == ["exit", "relay-1", "entry", "frag-dialer"]
    assert cfg3["outbounds"][2]["sockopt"]["dialerProxy"] == "frag-dialer"
    assert cfg3["outbounds"][3]["settings"]["fragment"]["packets"] == "tlshello"


def test_warrior_rejects_warp_exit_and_labs_region_gate(fl, monkeypatch):
    def fake_warp_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "104.28.5.5"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "United States",
                 "countryCode": "US", "isp": "Cloudflare", "org": "Cloudflare",
                 "proxy": False, "hosting": False})})()
        if "cdn-cgi/trace" in url:
            return type("R", (), {"stdout": "ip=104.28.5.5\nwarp=on\n"})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_warp_curl)
    _stub_browser(fl, monkeypatch)
    gw = fl.probe_gates()
    assert gw["verdict"] is False
    assert "WARP egress rejected" in gw["reason"]

    def fake_labs_gate_curl(args, timeout):
        url = args[-1]
        if "ipify" in url:
            return type("R", (), {"stdout": "198.51.100.7"})()
        if "ip-api" in url:
            return type("R", (), {"stdout": json.dumps(
                {"status": "success", "country": "Germany",
                 "countryCode": "DE", "isp": "Deutsche Telekom", "org": "DTAG",
                 "proxy": False, "hosting": False})})()
        if url.rstrip("/") == "https://flow.google.com":
            return type("R", (), {"stdout": "<html>AiSandboxAngularFrontend</html>"})()
        if "labs.google/fx/tools/flow" in url:
            return type("R", (), {"stdout": "<h2>Flow is not available in your country yet.</h2>"})()
        return type("R", (), {"stdout": "200"})()

    monkeypatch.setattr(fl, "_curl", fake_labs_gate_curl)
    gl = fl.probe_gates()
    assert gl["verdict"] is False
    assert "labs.google" in gl["reason"]


def test_warrior_hardened_browser_and_blacklist(fl, tmp_path, monkeypatch):
    args = fl.hardened_browser_args("/usr/bin/chrome", "/tmp/fp", "https://flow.google.com/", "GB")
    joined = " ".join(args)
    assert "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in joined
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in joined
    assert "--lang=en-GB" in joined

    bl = tmp_path / "flow_blacklist.json"
    monkeypatch.setattr(fl, "WARRIOR_BLACKLIST", str(bl))
    fl._remember_blocked_exit("vless:8.8.8.8:443")
    assert fl._is_blacklisted("vless:8.8.8.8:443") is True


def test_warrior_unpacks_npv_ovpn_wireguard_and_clash_yaml(fl):
    vless = "vless://22222222-2222-2222-2222-222222222222@203.0.113.45:443?security=tls"
    npv_bytes = b"\x00NPV4\x01" + vless.encode() + b"\xff"
    assert any(n["addr"] == "203.0.113.45" for n in fl.parse_config_file_bytes("w.npv4", npv_bytes))

    wg_conf = (
        b"[Interface]\nPrivateKey = privkey123=\nAddress = 10.7.0.2/32\nMTU = 1280\n"
        b"[Peer]\nPublicKey = pubkey456=\nEndpoint = 198.51.100.89:51820\n"
    )
    wg_nodes = fl.parse_config_file_bytes("warp.conf", wg_conf)
    assert len(wg_nodes) == 1 and wg_nodes[0]["proto"] == "wireguard"

    ovpn = b"client\ndev tun\nsocks-proxy 192.0.2.10 1080\n"
    assert any(n["proto"] == "socks" and n["port"] == 1080
               for n in fl.parse_config_file_bytes("edge.ovpn", ovpn))


def test_warrior_eight_hop_and_wireguard_outbound(fl):
    wg_hop = {
        "proto": "wireguard", "addr": "198.51.100.89", "port": 51820,
        "secret": "wg-priv", "q": {"publickey": "wg-pub", "address": "10.7.0.2/32"},
    }
    chain = [fl.mutate_fp(_vless(f"203.0.113.{i}", security="tls"), "random") for i in range(1, 8)] + [wg_hop]
    cfg8 = fl.build_config(chain, 10860, fragment=True)
    obs = cfg8["outbounds"]
    assert [o["tag"] for o in obs] == [
        "exit", "relay-1", "relay-2", "relay-3", "relay-4", "relay-5", "relay-6", "entry"
    ]
    assert obs[7]["protocol"] == "wireguard"
    assert obs[7]["settings"]["peers"][0]["publicKey"] == "wg-pub"
    assert obs[0]["streamSettings"]["tlsSettings"]["fingerprint"] == "random"


def test_flow_telegram_619_txt_and_all_extensions(fl):
    tg_text = (
        "داخل فایل 619 عدد سرور از تمام کشورها هست ری اکشن فراموش نکنید\n"
        "بااین برنامه اجرا کنید PattNG (https://t.me/proxy_kafee/48582?single)👉👉 کیلیک کنید\n"
        "https://github.com/patterniha/PattNG/releases/tag/2.3.8-P50\n"
        "🔺آموزش fragment+fingerprint (https://t.me/proxy_kafee/46097)\n"
        "@proxy_kafee\n"
    ) + "\n".join(
        f"vless://aaaaaaaa-bbbb-cccc-dddd-{i:012d}@203.0.113.{(i % 250) + 1}:{443 + (i % 40)}?security=tls#n{i}"
        for i in range(619)
    )
    extracted = fl.parse_config_file_bytes("619_servers.txt", tg_text.encode("utf-8"))
    assert len(extracted) == 619
    assert not any(n["addr"] in ("t.me", "github.com") for n in extracted)

    singbox = json.dumps({
        "outbounds": [
            {"type": "hy2", "server": "198.51.100.61", "server_port": 8443, "password": "pw"},
            {"type": "direct", "tag": "direct"},
        ]
    }).encode()
    assert fl.parse_config_file_bytes("sbox.singbox", singbox)[0]["proto"] == "hy2"


def test_flow_pattng_entry_exit_chain_and_android_parity(fl, tmp_path, monkeypatch):
    warp_entry = fl.parse_node_uri("warp://privK%3D@162.159.192.1:2408?publickey=pubK%3D")
    exit_node = _vless("203.0.113.80", security="tls")
    cfg = fl.build_entry_exit_chain(warp_entry, exit_node, port=10860, fragment=True, fp="chrome")
    obs = cfg["outbounds"]
    assert obs[0]["tag"] == "exit"
    assert obs[0]["sockopt"]["dialerProxy"] == "entry"
    assert obs[1]["tag"] == "entry"
    assert obs[1]["protocol"] == "wireguard"

    import sys
    android_py = os.path.join(ROOT, "android", "app", "src", "main", "python")
    if android_py not in sys.path:
        sys.path.insert(0, android_py)
    a_fl = load(os.path.join("android", "app", "src", "main", "python", "dastyab_flow.py"), "android_fl")
    assert len(a_fl.parse_config_file_bytes("bulk.txt", "\n".join(
        f"vless://55555555-5555-5555-5555-{i:012d}@192.0.2.{(i % 200) + 1}:{443 + i}?security=tls"
        for i in range(619)
    ).encode())) == 619
    assert a_fl.build_config([{"proto": "wireguard", "addr": "h", "port": 1, "q": {}}], 10860) is None
    a_cfg = a_fl.build_entry_exit_chain(warp_entry, exit_node, port=10860, fragment=True, fp="firefox")
    assert a_cfg["outbounds"][0]["sockopt"]["dialerProxy"] == "entry"
    assert a_cfg["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"] == "firefox"
    assert a_cfg["outbounds"][1]["protocol"] == "wireguard"

    import dastyab_terminal_shell as shell
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(shell._shim, "profile_dir", lambda: str(tmp_path / "prof"))
    (tmp_path / "prof").mkdir(parents=True, exist_ok=True)
    cnt = shell.sync_nodes([
        "warp://privK%3D@162.159.192.1:2408?publickey=pubK%3D",
        "trojan://pw@203.0.113.10:443?sni=a.example",
    ])
    assert cnt == 2
    assert len(json.loads((tmp_path / "prof" / "fresh_vless.json").read_text())) == 2


