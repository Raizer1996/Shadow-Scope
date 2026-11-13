"""E-mail addresses as an indicator type, URL structure analysis, and their pivots. No network."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from ioc_tool.core import database as _db
from ioc_tool.core import enrich, parser, related, score, urlinfo, userlists
from ioc_tool.web import api

client = TestClient(api.app)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSCOPE_API_TOKEN", raising=False)
    monkeypatch.delenv("ALLOWLIST_DOMAINS", raising=False)
    monkeypatch.setattr(_db, "DB_PATH", str(tmp_path / "ioc.db"))
    _db.init_db()


def _flags(data):
    return {f["id"]: f["points"] for f in data["flags"]}


# --------------------------------------------------------------------- URL

def test_url_breakdown():
    d = urlinfo.analyse_url("https://Login.Secure.Evil.Example:8444/wp-content/Gate.PHP?id=7&next=https%3A%2F%2Fbank.example")
    assert (d["scheme"], d["host"], d["registered_domain"], d["port"]) == ("https", "login.secure.evil.example", "evil.example", 8444)
    assert d["path"] == "/wp-content/Gate.PHP" and d["extension"] == "php" and d["params"] == ["id", "next"]
    assert d["ip_host"] is False


@pytest.mark.parametrize(
    ("url", "flag", "points"),
    [
        ("http://paypal.com@203.0.113.10/x", "credentials", 60),
        ("http://203.0.113.10/x", "ip_host", 40),
        ("https://cdn.example/files/invoice.exe", "executable", 50),
        ("https://cdn.example/files/Report.DOCM", "macro_document", 40),
        ("https://cdn.example/files/pack.zip", "archive", 25),
        ("https://xn--pypal-4ve.example/", "punycode", 40),
        ("https://good.example/out?url=https://evil.example/", "redirect", 35),
        ("https://good.example/out?next=%2F%2Fevil.example", "redirect", 35),
        ("https://good.example:8444/", "port", 30),
        ("https://bit.ly/3abc", "shortener", 25),
        ("https://a.b.c.d.evil.example/", "deep_subdomain", 25),
        ("http://evil.example/secure/login", "lure_words", 30),
        ("https://evil.example/secure/login", "lure_words", 15),
        ("https://evil.example/" + "a" * 220, "long_or_encoded", 20),
        ("http://plain.example/", "plain_http", 10),
    ],
)
def test_url_flags(url, flag, points):
    assert _flags(urlinfo.analyse_url(url)).get(flag) == points


def test_url_clean_and_unparseable():
    clean = urlinfo.analyse_url("https://www.example.org/docs/index.html?page=2")
    assert clean["flags"] == [] and clean["score"] == 0
    # A redirect parameter with an ordinary value is not a redirect.
    assert "redirect" not in _flags(urlinfo.analyse_url("https://good.example/?next=home"))
    for bad in ("ftp://files.example/x", "not a url", "https://", "http://[bad"):
        assert urlinfo.analyse_url(bad) is None


def test_structure_score_is_strongest_flag_plus_a_little_and_capped():
    two = urlinfo.analyse_url("http://203.0.113.10/x")          # ip_host 40 + plain_http 10
    assert two["score"] == 45
    many = urlinfo.analyse_url("http://user@203.0.113.10:81/secure/login/update.exe?url=http://x.example")
    assert many["score"] == urlinfo.SCORE_CAP
    assert score.calculate_structure_score(many) == urlinfo.SCORE_CAP
    assert score.calculate_structure_score(None) == 0 and score.calculate_structure_score({"score": "x"}) == 0


# ------------------------------------------------------------------- email

def test_email_breakdown_and_flags():
    d = urlinfo.analyse_email("Billing+Invoices@Mail.Evil.Example")
    assert (d["local"], d["domain"], d["registered_domain"]) == ("billing+invoices", "mail.evil.example", "evil.example")
    assert (d["free_provider"], d["disposable"], d["role_account"], d["tag"], d["enrich_domain"]) == (False, False, True, "invoices", True)
    assert _flags(d) == {"role_account": 0, "plus_tag": 0} and d["score"] == 0

    free = urlinfo.analyse_email("someone@gmail.com")
    assert free["free_provider"] is True and free["enrich_domain"] is False and free["score"] == 0

    burner = urlinfo.analyse_email("x@mailinator.com")
    assert burner["disposable"] is True and burner["score"] == 60

    assert _flags(urlinfo.analyse_email("a8f3k29d0x77z1@corp.example"))["random_local"] == 20
    for bad in ("no-at-sign", "two@@example.org", "@example.org", "x@localhost", "a@b@c.example"):
        assert urlinfo.analyse_email(bad) is None


def test_email_lookalike_domain_uses_the_typosquat_check(monkeypatch):
    monkeypatch.setattr(urlinfo.heuristics, "typosquat_check", lambda d: {"score": 95, "match": "paypal"})
    d = urlinfo.analyse_email("service@paypa1.example")
    assert _flags(d)["lookalike"] == urlinfo.SCORE_CAP
    assert any("looks like paypal" in f["label"] for f in d["flags"])
    # Never run against a shared mailbox host.
    monkeypatch.setattr(urlinfo.heuristics, "typosquat_check", lambda d: pytest.fail("checked a free provider"))
    urlinfo.analyse_email("someone@gmail.com")


def test_email_detection_and_normalisation():
    assert parser.detect_type("Someone@Example.ORG") == "email"
    assert parser.normalize_value("Someone@Example[.]ORG", "email") == "someone@example.org"


# ------------------------------------------------------------ orchestrator

def test_url_enrichment_plans_the_structure_module(db):
    ioc_id = _db.add_or_update_ioc("http://203.0.113.10/a.exe", "url")
    tasks, _ = enrich._build_enrich_tasks("http://203.0.113.10/a.exe", "url", ioc_id)
    names = [n for n, _ in tasks]
    for _, coro in tasks:
        coro.close()
    assert "URL" in names and "Email" not in names


def _stub_domain_pipeline(monkeypatch, calls, *, degraded=False):
    real_build = enrich._build_enrich_tasks

    def build(value, ioc_type, ioc_id):
        if ioc_type == "email":
            return real_build(value, ioc_type, ioc_id)
        calls.append((value, ioc_type))

        async def vt():
            return ("VirusTotal", {"last_analysis_stats": {"malicious": 9}}, 80, True)

        async def shodan():
            return ("Shodan", {"ports": [25]}, 55, False)   # context source with an incidental score

        async def dead():
            return enrich.Unavailable("OTX", "timeout")

        return [("VirusTotal", vt()), ("Shodan", shodan())] + ([("OTX", dead())] if degraded else []), set()

    monkeypatch.setattr(enrich, "_build_enrich_tasks", build)


def test_email_enrichment_folds_in_its_domain(db, monkeypatch):
    calls: list = []
    _stub_domain_pipeline(monkeypatch, calls)
    out = asyncio.run(enrich._enrich_ioc_inner("billing@corp.example", "email"))
    assert calls == [("corp.example", "domain")]
    assert out["type"] == "email" and out["via_domain"] == "corp.example"
    assert {"Email", "VirusTotal", "Shodan"} <= set(out["modules"])
    assert out["modules"]["Email"]["data"]["role_account"] is True
    # 80 x 0.9 from VirusTotal; Shodan's incidental 55 is context and ignored.
    assert out["final_score"] == score.calculate_final_risk([("VirusTotal", 80)])
    assert out["degraded"] is False
    # Both are now indicators in their own right, each with a stored score.
    assert _db.get_ioc_id("corp.example") is not None
    con = _db.get_db_connection()
    stored = dict(con.execute("SELECT value, last_score FROM iocs").fetchall())
    con.close()
    assert stored["billing@corp.example"] == out["final_score"] == stored["corp.example"]


def test_free_mailbox_addresses_do_not_touch_the_domain(db, monkeypatch):
    calls: list = []
    _stub_domain_pipeline(monkeypatch, calls)
    out = asyncio.run(enrich._enrich_ioc_inner("someone@gmail.com", "email"))
    assert calls == [] and set(out["modules"]) == {"Email"} and out["final_score"] == 0
    assert "via_domain" not in out and _db.get_ioc_id("gmail.com") is None


def test_degraded_domain_run_marks_the_address_and_keeps_its_old_score(db, monkeypatch):
    calls: list = []
    _stub_domain_pipeline(monkeypatch, calls, degraded=True)
    out = asyncio.run(enrich._enrich_ioc_inner("billing@corp.example", "email"))
    assert out["degraded"] is True and out["unavailable"] == {"OTX": "timeout"}
    assert _db.get_last_unavailable(_db.get_ioc_id("billing@corp.example")) == {"OTX": "timeout"}


def test_streaming_path_also_folds_in_the_domain(db, monkeypatch):
    calls: list = []
    _stub_domain_pipeline(monkeypatch, calls)

    async def run():
        return [e async for e in enrich.enrich_ioc_stream("billing@corp.example", "email")]

    final = [e for e in asyncio.run(run()) if e["event"] == "final"][0]["result"]
    assert final["via_domain"] == "corp.example" and "VirusTotal" in final["modules"]


def test_cached_view_of_an_address_includes_its_domains_sources(db):
    dom = _db.add_or_update_ioc("corp.example", "domain")
    _db.add_enrichment(dom, "virustotal", {"last_analysis_stats": {"malicious": 9, "harmless": 60}}, 80)
    mail = _db.add_or_update_ioc("billing@corp.example", "email")
    info = urlinfo.analyse_email("billing@corp.example")
    _db.add_enrichment(mail, "email", info, info["score"])
    _db.update_last_score(mail, 72, 2)

    modules, scores = api._build_modules_from_cache(mail)
    assert set(modules) == {"Email", "VirusTotal"} and ("VirusTotal", 80) in scores
    row = next(r for r in client.get("/api/ui/recent", params={"limit": 5}).json() if r["type"] == "email")
    assert row["ioc"] == "billing@corp.example" and row["final_score"] == 72
    assert row["modules"]["Email"]["detail"] == "domain corp.example · nothing unusual in its structure"


def test_detail_text():
    url = urlinfo.analyse_url("http://203.0.113.10/a.exe")
    assert api._ui_detail("URL", url["score"], url) == "203.0.113.10/a.exe · links straight to a program or script (.exe) +2"
    free = urlinfo.analyse_email("someone@gmail.com")
    assert api._ui_detail("Email", 0, free) == "free mailbox provider · nothing unusual in its structure"


# ------------------------------------------------------------------ pivots

def test_related_links_addresses_domains_and_shared_paths(db):
    def add(value, kind, score_=50):
        ioc_id = _db.add_or_update_ioc(value, kind)
        _db.update_last_score(ioc_id, score_, 2)
        return ioc_id

    mail = add("billing@corp.example", "email", 70)
    dom = add("corp.example", "domain", 60)
    add("ceo@mail.corp.example", "email", 40)
    add("someone@other.example", "email")
    u1 = add("https://a.example/wp-content/plugins/x/gate.php?id=1", "url", 90)
    add("http://b.example/wp-content/plugins/x/gate.php", "url", 80)
    add("https://a.example/wp-content/plugins/x/gate.php?id=2", "url")      # same host: not a pivot
    add("https://c.example/other/gate.php", "url")
    add("https://d.example/a/b", "url")

    def groups(ioc_id, value, kind):
        return {g["key"]: g for g in related.related_for(ioc_id, value, kind)}

    g = groups(mail, "billing@corp.example", "email")
    assert g["domain"]["pivot"] == "corp.example"
    assert [i["ioc"] for i in g["domain"]["items"]] == ["corp.example", "ceo@mail.corp.example"]
    assert [(i["ioc"], i["cached"]) for i in g["seen_with"]["items"]] == [("corp.example", True)]

    g = groups(dom, "corp.example", "domain")
    assert [i["ioc"] for i in g["domain"]["items"]] == ["billing@corp.example", "ceo@mail.corp.example"]

    g = groups(u1, "https://a.example/wp-content/plugins/x/gate.php?id=1", "url")
    assert g["path"]["pivot"] == "/wp-content/plugins/x/gate.php"
    assert [i["ioc"] for i in g["path"]["items"]] == ["http://b.example/wp-content/plugins/x/gate.php"]
    # A short, generic path is not a pivot.
    short = add("https://e.example/a/b", "url")
    assert "path" not in groups(short, "https://e.example/a/b", "url")


def test_user_lists_understand_addresses(db):
    assert userlists.normalize("Billing@Corp.Example") == ("email", "billing@corp.example")
    userlists.add("block", "corp.example")
    assert userlists.match("billing@corp.example", "email")["pattern"] == "corp.example"
    userlists.add("allow", "ceo@corp.example")
    hit = userlists.match("ceo@corp.example", "email")
    assert (hit["list"], hit["pattern"]) == ("allow", "ceo@corp.example")   # exact beats the domain rule
    assert userlists.match("someone@other.example", "email") is None


def test_batch_extract_and_import_accept_addresses(db):
    out = client.post("/api/ui/extract", json={"text": "From: Billing@Corp[.]Example\nsee http://evil.example/x"}).json()
    assert {"value": "billing@corp.example", "type": "email"} in out["iocs"]
    rows = client.post("/api/ui/import/preview", json={"text": "indicator,note\nceo@corp.example,spoofed sender\n"}).json()["rows"]
    assert (rows[0]["ioc"], rows[0]["type"], rows[0]["note"]) == ("ceo@corp.example", "email", "spoofed sender")
