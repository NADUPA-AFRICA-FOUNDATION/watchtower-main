"""Security and ethics guards for the hunter: behaviours, and static rules that stop regressions."""
import asyncio
import ipaddress
import re
import subprocess
from pathlib import Path

import pytest

from hunter.normalize import is_public, normalize
from hunter.config import load
from watchtower.discovery.safe_fetch import UnsafeTarget, is_public_ip, resolve_public

ROOT = Path(__file__).resolve().parent.parent
HUNTER_FILES = sorted((ROOT / "hunter").rglob("*.py")) + [ROOT / "web" / "hunter_routes.py"]


def src(path):
    return path.read_text()


# -- SSRF: one definition of "public", applied everywhere -------------------------------------------------------------------

NOT_PUBLIC = [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1",
    "100.64.0.1", "100.100.100.200", "100.127.255.255",                      # carrier-grade NAT, incl. Alibaba Cloud metadata
    "0.0.0.0", "0.1.2.3", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.5", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "::1", "::", "fe80::1", "fd00::1", "fc00::1", "ff02::1", "2001:db8::1",
    "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",                  # IPv4-mapped is refused outright
    "2002:a00:1::1", "2002:7f00:1::1",                                        # 6to4 embeds 10.0.0.1 / 127.0.0.1
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",                                   # Teredo
    "64:ff9b::a00:1",                                                         # NAT64
]
PUBLIC = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.216.34", "2606:4700::1111", "2001:4860:4860::8888"]


@pytest.mark.parametrize("address", NOT_PUBLIC)
def test_non_public_addresses_are_refused_everywhere(address):
    assert is_public_ip(address) is False
    assert is_public(normalize(f"http://[{address}]/" if ":" in address else f"http://{address}/")) is False


@pytest.mark.parametrize("address", PUBLIC)
def test_public_addresses_are_allowed(address):
    assert is_public_ip(address) is True
    assert is_public(normalize(f"http://[{address}]/" if ":" in address else f"http://{address}/")) is True


def test_the_check_agrees_with_the_standard_library_wherever_it_is_stricter():
    for a in NOT_PUBLIC + PUBLIC:
        if is_public_ip(a):
            assert ipaddress.ip_address(a).is_global                              # never allows what Python calls non-global
    assert is_public_ip("not an ip") is False and is_public_ip("") is False


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "localhost.localdomain", "127.0.0.1", "100.100.100.200", "[::1]", "0.0.0.0"])
def test_resolve_public_refuses_loopback_metadata_and_literals(host):
    with pytest.raises(UnsafeTarget):
        asyncio.run(resolve_public(host.strip("[]")))


def test_candidates_pointing_at_internal_space_are_rejected_at_the_queue(tmp_path):
    from hunter.store import HuntStore
    s = HuntStore(str(tmp_path / "h.db"))
    for value in ("http://169.254.169.254/latest/meta-data/", "http://100.100.100.200/latest", "http://[::1]/", "http://10.1.2.3/admin",
                  "http://internal.local/x", "localhost", "http://[2002:a00:1::1]/"):
        r = s.submit(value, "page-links")
        assert not r.accepted, value
    assert s.stats()["total"] == 0 and s.stats()["rejected"] == 7


# -- the hunter observes; it never acts ---------------------------------------------------------------------------------------

def test_the_only_outbound_post_in_the_hunter_is_the_opt_in_alert_webhook():
    for path in HUNTER_FILES:
        code = src(path)
        hits = re.findall(r"\.(post|put|patch|delete)\(", code)
        if path.name in {"alerts.py", "hunter_routes.py"}:
            continue                                                               # alerts: webhook; routes: its own FastAPI decorators
        assert not hits, f"{path.name} makes a {hits} request: the hunter only reads"
    alerts = src(ROOT / "hunter" / "alerts.py")
    assert alerts.count("httpx.post(") == 1 and "https://" in alerts                     # one place, https only


def test_forms_are_parsed_never_filled_or_submitted():
    sig, acq = src(ROOT / "hunter" / "signals.py"), src(ROOT / "hunter" / "acquire.py")
    assert 'method="post"' not in acq.lower() and "data=" not in acq and "json=" not in acq
    assert "never" in sig.lower() and "submitted" in sig.lower()                         # the invariant is documented where it applies
    assert not re.search(r"\.(click|submit|fill|type)\(", acq + sig)


def test_no_script_execution_no_shelling_out_no_dynamic_code():
    for path in HUNTER_FILES:
        code = src(path)
        for banned in ("eval(", "exec(", "subprocess", "os.system", "pickle.loads", "__import__(\"os\")", "importlib.import_module"):
            assert banned not in code, f"{path.name} uses {banned}"
    assert "playwright" not in "".join(src(p) for p in HUNTER_FILES).lower()                # no browser: nothing executes page JavaScript
    assert "selenium" not in "".join(src(p) for p in HUNTER_FILES).lower()


def test_no_captcha_bypass_or_credential_handling_vocabulary():
    code = "".join(src(p) for p in HUNTER_FILES).lower()
    for word in ("solve_captcha", "captcha_solver", "2captcha", "anti-captcha", "login(", "authenticate(", "stealth"):
        assert word not in code


# -- scope guards -------------------------------------------------------------------------------------------------------------------

def test_no_firecrawl_anywhere():
    files = [ROOT / "requirements.txt", ROOT / "pyproject.toml", ROOT / ".env.example", ROOT / "hunter.yaml", ROOT / "package.json"] + HUNTER_FILES
    for path in files:
        if path.exists():
            assert "firecrawl" not in src(path).lower(), path.name


def test_no_mandatory_paid_service_is_configured():
    code = "".join(src(p) for p in HUNTER_FILES)
    for name in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "BRAVE", "SERPAPI", "VIRUSTOTAL", "SHODAN", "OPENSANCTIONS"):
        assert name not in code, f"the hunter must work without {name}"
    assert "WATCHTOWER_ALERT_WEBHOOK" in code                                         # the only credential-like setting, and it is optional


def test_secrets_are_never_hardcoded_or_committed():
    pattern = re.compile(r"(sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
    for path in HUNTER_FILES + [ROOT / "hunter.yaml", ROOT / "web" / "static" / "hunter.js", ROOT / "web" / "static" / "hunter.css"]:
        assert not pattern.search(src(path)), path.name
    ignored = subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=ROOT).returncode
    assert ignored == 0, ".env must be gitignored"
    tracked = subprocess.run(["git", "ls-files", ".env"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    assert tracked == ""


def test_the_engines_still_do_not_import_each_other():
    for path in HUNTER_FILES:
        code = src(path)
        assert not re.search(r"^\s*(from|import)\s+scamscan\b", code, re.M), f"{path.name} imports scamscan"
    for other in [ROOT / "scamscan.py", *(ROOT / "core").glob("*.py")]:
        assert not re.search(r"^\s*(from|import)\s+hunter\b", src(other), re.M), f"{other.name} imports the hunter"


def test_the_config_file_holds_no_secrets_and_the_default_robots_stance_is_the_documented_one():
    import yaml

    def keys(node):
        if isinstance(node, dict):
            for k, v in node.items():
                yield str(k).lower()
                yield from keys(v)
        elif isinstance(node, list):
            for v in node:
                yield from keys(v)
    names = list(keys(yaml.safe_load((ROOT / "hunter.yaml").read_text())))
    assert names and not [k for k in names if any(w in k for w in ("password", "secret", "token", "apikey", "api_key", "bearer", "credential"))]
    cfg = load("hunter.yaml")
    assert cfg.acquisition.obey_robots_landing is False                                    # landing page: recorded, not enforced (HUNTER_PLAN.md)
    assert cfg.pivots.reverse_ip is False and cfg.scheduler.benign_refresh_days >= 30       # off-by-default, polite-by-default
    assert cfg.alerts.webhook_env == "WATCHTOWER_ALERT_WEBHOOK" and cfg.retention.personal_data_days <= 365


def test_the_api_exposes_no_configuration_paths_or_environment(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from test_hunter_campaigns import phishing_net
    from web.hunter_routes import build_router
    path = str(tmp_path / "hunter.db")
    phishing_net(path)
    monkeypatch.setenv("WATCHTOWER_ALERT_WEBHOOK", "https://hooks.example/secret-token-123")
    monkeypatch.setenv("WATCHTOWER_PASSWORD", "hunter2-password")
    app = FastAPI()
    app.include_router(build_router(lambda: path, lambda: load("hunter.yaml"), lambda r, c: ("a", "self_asserted")))
    client = TestClient(app)
    for url in ("/api/hunter/status", "/api/hunter/candidates", "/api/hunter/queue", "/api/hunter/providers", "/api/hunter/alerts",
                "/api/hunter/campaigns", "/api/hunter/insights"):
        text = client.get(url).text
        assert "secret-token-123" not in text and "hunter2-password" not in text and str(tmp_path) not in text and "hunter.yaml" not in text, url
